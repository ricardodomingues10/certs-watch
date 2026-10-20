"""Jobs: ingestão CMDB, scan, avaliação e pipeline completo."""
from __future__ import annotations

import logging
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .collectors.ucmdb import fetch_certificates
from .config import Settings
from .db import LOCK_PIPELINE, JobBusy, advisory_lock, session_scope, utcnow
from .evaluator import evaluate
from .models import Certificate, CmdbRecord, Endpoint, JobRun, ScanResult
from .normalize import classify, is_ip, is_valid_hostname, norm_host, norm_issuer, parse_iso
from .scanner import ScanOutcome, scan_endpoint, summarize
from .trust import build_bundle

log = logging.getLogger(__name__)

JOBS = ("pipeline", "ingest_cmdb", "scan", "evaluate")
SCAN_RETENTION_DAYS = 90


class IngestAborted(RuntimeError):
    pass


# ---------------------------------------------------------------- ingestão CMDB
def ingest_cmdb(session: Session, settings: Settings, records: list[dict] | None = None) -> dict:
    if records is None:
        records = fetch_certificates(settings)
    valid = [r for r in records if r.get("ucmdb_id")]
    if len(valid) < settings.ucmdb_min_cis:
        raise IngestAborted(
            f"A UCMDB devolveu {len(valid)} certificados (mínimo configurado: {settings.ucmdb_min_cis}). "
            "Ingestão abortada para não desativar registos por engano."
        )

    now = utcnow()
    existing = {r.ucmdb_id: r for r in session.scalars(select(CmdbRecord))}
    seen: set[str] = set()
    created = updated = no_cn = 0

    for r in valid:
        cn = r.get("common_name") or ""
        if not cn:
            no_cn += 1
            continue
        cn_norm = norm_host(cn)
        rec = existing.get(r["ucmdb_id"])
        if rec is None:
            rec = CmdbRecord(ucmdb_id=r["ucmdb_id"], first_seen=now)
            session.add(rec)
            existing[r["ucmdb_id"]] = rec
            created += 1
        else:
            updated += 1
        rec.global_id = r.get("global_id")
        rec.common_name = cn
        rec.cn_norm = cn_norm
        rec.kind = classify(cn_norm)
        rec.issuer = r.get("issuer") or ""
        rec.issuer_name = r.get("issuer_name") or ""
        rec.issuer_norm = norm_issuer(rec.issuer_name or rec.issuer)
        rec.valid_to = parse_iso(r.get("valid_to"))
        rec.active = True
        rec.last_seen = now
        seen.add(r["ucmdb_id"])

    deactivated = 0
    for ucmdb_id, rec in existing.items():
        if ucmdb_id not in seen and rec.active:
            rec.active = False
            deactivated += 1
    session.flush()

    # Endpoints derivados da CMDB (apenas CN com forma de host ou IP)
    active_cns = {
        rec.cn_norm for rec in existing.values() if rec.active and rec.kind in ("host", "ip")
    }
    endpoints = {(e.host, e.port): e for e in session.scalars(select(Endpoint))}
    ep_created = ep_disabled = 0
    for cn in active_cns:
        key = (cn, settings.scan_default_port)
        if key not in endpoints:
            session.add(Endpoint(host=cn, port=settings.scan_default_port, expected_cn_norm=cn, source="cmdb"))
            ep_created += 1
    for (host, _port), ep in endpoints.items():
        if ep.source == "cmdb" and ep.enabled and host not in active_cns:
            ep.enabled = False
            ep.note = "desativado: CN já não existe na CMDB"
            ep_disabled += 1

    return {
        "recebidos": len(records),
        "novos": created,
        "atualizados": updated,
        "sem_common_name": no_cn,
        "desativados": deactivated,
        "endpoints_criados": ep_created,
        "endpoints_desativados": ep_disabled,
    }


# ---------------------------------------------------------------- scan
def _valid_target(ep: Endpoint, settings: Settings) -> bool:
    return (is_valid_hostname(ep.host) or is_ip(ep.host)) and ep.port in settings.scan_allowed_ports


def _store_outcome(session: Session, ep: Endpoint, out: ScanOutcome) -> ScanResult:
    now = utcnow()
    summaries = []
    for der in out.chain_der:
        try:
            summaries.append(summarize(der))
        except Exception as exc:  # certificado malformado: registar e continuar
            log.warning("Certificado não interpretável em %s:%s: %s", ep.host, ep.port, exc)

    for s in summaries:
        cert = session.get(Certificate, s["sha256"])
        if cert is None:
            cert = Certificate(sha256=s["sha256"], first_seen=now)
            session.add(cert)
        for k, v in s.items():
            if k != "sha256":
                setattr(cert, k, v)
        cert.last_seen = now

    status = out.status
    if status == "ok" and not summaries:
        status = "tls_error"

    sr = ScanResult(
        endpoint_id=ep.id,
        scanned_at=now,
        status=status,
        error=out.error,
        tls_version=out.tls_version,
        cipher=out.cipher,
        verify_ok=out.verify_ok,
        verify_code=out.verify_code,
        verify_message=out.verify_message,
        leaf_sha256=summaries[0]["sha256"] if summaries else None,
        chain=[
            {
                "sha256": s["sha256"],
                "subject_cn": s["subject_cn"],
                "issuer_cn": s["issuer_cn"],
                "not_after": s["not_after"].isoformat(),
                "sig_hash": s["sig_hash"],
                "key_type": s["key_type"],
                "key_bits": s["key_bits"],
                "is_ca": s["is_ca"],
                "self_issued": s["self_issued"],
            }
            for s in summaries
        ],
        duration_ms=out.duration_ms,
    )
    session.add(sr)
    session.flush()
    ep.last_scan_id = sr.id
    ep.consecutive_failures = 0 if status == "ok" else ep.consecutive_failures + 1
    return sr


def run_scan(session: Session, settings: Settings) -> dict:
    endpoints = list(session.scalars(select(Endpoint).where(Endpoint.enabled.is_(True))))
    targets = [e for e in endpoints if _valid_target(e, settings)]
    invalid = len(endpoints) - len(targets)
    cafile = build_bundle(settings)

    with ThreadPoolExecutor(max_workers=max(1, settings.scan_workers)) as pool:
        futures = {
            e.id: pool.submit(scan_endpoint, e.host, e.port, cafile, settings.scan_timeout) for e in targets
        }
        results = {eid: f.result() for eid, f in futures.items()}

    counts: dict[str, int] = {}
    by_id = {e.id: e for e in targets}
    for eid, out in results.items():
        sr = _store_outcome(session, by_id[eid], out)
        counts[sr.status] = counts.get(sr.status, 0) + 1

    session.execute(
        delete(ScanResult).where(ScanResult.scanned_at < utcnow() - timedelta(days=SCAN_RETENTION_DAYS))
    )
    return {"alvos": len(targets), "alvos_invalidos": invalid, **counts}


# ---------------------------------------------------------------- execução de jobs
def _run(job: str, settings: Settings) -> dict:
    if job == "ingest_cmdb":
        with session_scope() as s:
            return {"ingest_cmdb": ingest_cmdb(s, settings)}
    if job == "scan":
        with session_scope() as s:
            return {"scan": run_scan(s, settings)}
    if job == "evaluate":
        with session_scope() as s:
            return {"evaluate": evaluate(s, settings)}
    if job == "pipeline":
        summary: dict = {}
        try:
            with session_scope() as s:
                summary["ingest_cmdb"] = ingest_cmdb(s, settings)
        except Exception as exc:  # continua com os dados que já existem
            log.exception("Ingestão CMDB falhou")
            summary["ingest_cmdb"] = {"erro": str(exc)}
        with session_scope() as s:
            summary["scan"] = run_scan(s, settings)
        with session_scope() as s:
            summary["evaluate"] = evaluate(s, settings)
        return summary
    raise ValueError(f"Job desconhecido: {job}")


def enqueue(job: str, requested_by: str) -> int:
    if job not in JOBS:
        raise ValueError(f"Job desconhecido: {job}")
    with session_scope() as s:
        jr = JobRun(job=job, requested_by=requested_by, status="pending")
        s.add(jr)
        s.flush()
        return jr.id


def execute_job_run(job_run_id: int, settings: Settings) -> None:
    with session_scope() as s:
        jr = s.get(JobRun, job_run_id)
        if jr is None or jr.status != "pending":
            return
        jr.status, jr.started_at = "running", utcnow()
        job = jr.job

    status, summary = "ok", {}
    try:
        with advisory_lock(LOCK_PIPELINE):
            summary = _run(job, settings)
    except JobBusy:
        # Outro job a correr (ex.: CLI): volta para a fila e o worker tenta no próximo ciclo
        with session_scope() as s:
            jr = s.get(JobRun, job_run_id)
            jr.status, jr.started_at = "pending", None
            jr.summary = {"aviso": "em espera: outro job em execução"}
        return
    except Exception as exc:
        status = "error"
        summary = {"erro": str(exc)[:2000], "trace": traceback.format_exc()[-4000:]}
        log.exception("Job %s falhou", job)

    with session_scope() as s:
        jr = s.get(JobRun, job_run_id)
        jr.status, jr.finished_at, jr.summary = status, utcnow(), summary


def run_now(job: str, requested_by: str, settings: Settings) -> JobRun:
    jid = enqueue(job, requested_by)
    execute_job_run(jid, settings)
    with session_scope() as s:
        return s.get(JobRun, jid)

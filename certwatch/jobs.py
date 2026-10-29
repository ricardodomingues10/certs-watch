"""Jobs: ingestão CMDB, scan, avaliação e pipeline completo."""
from __future__ import annotations

import logging
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .conectores import cmdb_connector, tickets_on
from .fontes.ucmdb import fetch_apis, fetch_certificates
from .config import Settings
from .db import LOCK_PIPELINE, JobBusy, advisory_lock, session_scope, utcnow
from .evaluator import evaluate
from .models import ApiRecord, Certificate, CmdbRecord, Endpoint, JobRun, ScanResult
from .normalize import classify, is_ip, is_valid_hostname, norm_host, norm_issuer, parse_iso
from .fontes.servidores import ScanOutcome, scan_endpoint, summarize
from .trust import build_bundle

log = logging.getLogger(__name__)

JOBS = ("pipeline", "ingest_cmdb", "ingest_apis", "ingest_smax", "ingest_ct", "scan", "ssllabs", "evaluate")
SCAN_RETENTION_DAYS = 90


class IngestAborted(RuntimeError):
    pass


# ---------------------------------------------------------------- ingestão CMDB
def ingest_cmdb(session: Session, settings: Settings, records: list[dict] | None = None) -> dict:
    conn = cmdb_connector(settings)
    minimum = conn.min_records if records is None else settings.ucmdb_min_cis
    if records is None:
        # UCMDB (o de sempre), ServiceNow, SQL, REST ou ficheiro: todos no mesmo formato
        records = fetch_certificates(settings) if conn.kind == "ucmdb" else conn.fetch_certificates()
    valid = [r for r in records if r.get("ucmdb_id")]
    if len(valid) < minimum:
        raise IngestAborted(
            f"A CMDB ({conn.label}) devolveu {len(valid)} certificados (mínimo configurado: {minimum}). "
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


# ---------------------------------------------------------------- ingestão de APIs
def ingest_apis(session: Session, settings: Settings, records: list[dict] | None = None,
                fields: dict | None = None) -> dict:
    if records is None:
        records, fields = load_api_records(settings)
    valid = [r for r in records if r.get("ucmdb_id")]
    if len(valid) < settings.apis_min:
        raise IngestAborted(f"A lista de APIs devolveu {len(valid)} registos (mínimo: {settings.apis_min}).")

    now = utcnow()
    existing = {a.ucmdb_id: a for a in session.scalars(select(ApiRecord))}
    seen: set[str] = set()
    created = sem_url = 0
    for r in valid:
        api = existing.get(r["ucmdb_id"])
        if api is None:
            api = ApiRecord(ucmdb_id=r["ucmdb_id"], first_seen=now)
            session.add(api)
            existing[r["ucmdb_id"]] = api
            created += 1
        for k in ("name", "application", "location", "cmdb_expired", "registered_at",
                  "url", "scheme", "host", "port", "expiry", "extra"):
            setattr(api, k, (r.get(k) or "") if k in ("application", "location") else r.get(k))
        api.active, api.last_seen = True, now
        if not api.host:
            sem_url += 1
        seen.add(r["ucmdb_id"])
    for uid, api in existing.items():
        if uid not in seen:
            api.active = False
    session.flush()

    # Endpoints: um por host:porta das APIs com TLS
    targets: dict[tuple[str, int], str] = {}
    for api in existing.values():
        if not api.active or not api.host or api.scheme == "http":
            continue
        if not (is_valid_hostname(api.host) or is_ip(api.host)):
            continue
        targets[(api.host, api.port or settings.scan_default_port)] = api.host
    endpoints = {(e.host, e.port): e for e in session.scalars(select(Endpoint))}
    ep_created = 0
    for (host, port), cn in targets.items():
        ep = endpoints.get((host, port))
        note = "" if port in settings.scan_allowed_ports else \
            f"porta {port} não está em CERTWATCH_SCAN_ALLOWED_PORTS"
        if ep is None:
            session.add(Endpoint(host=host, port=port, expected_cn_norm=cn, source="api", note=note))
            ep_created += 1
        elif not ep.enabled and ep.source == "api":
            ep.enabled, ep.note = True, note
    for (host, port), ep in endpoints.items():
        if ep.source == "api" and ep.enabled and (host, port) not in targets:
            ep.enabled, ep.note = False, "desativado: API já não está na lista"

    return {"recebidos": len(records), "novos": created, "sem_url": sem_url,
            "com_validade": sum(1 for r in valid if r.get("expiry")),
            "endpoints_criados": ep_created, "campos": fields or {}}


def apis_configured(settings: Settings) -> bool:
    from .reconcile import find_api_file
    return _apis_rest(settings) or find_api_file(settings) is not None


def _apis_rest(settings: Settings) -> bool:
    """A lista de APIs por REST é da UCMDB; com outra CMDB fica o ficheiro api-cmdb* em import/."""
    return bool(settings.ucmdb_tql_apis) and cmdb_connector(settings).kind == "ucmdb"


def load_api_records(settings: Settings) -> tuple[list[dict], dict]:
    """REST (TQL + enriquecimento) primeiro; se não houver datas de expiração, o ficheiro api-cmdb* em import/."""
    from .fontes.ucmdb import UcmdbError
    from .reconcile import find_api_file, read_api_file
    records, fields, rest_error = None, {}, None
    if _apis_rest(settings):
        try:
            records, fields = fetch_apis(settings)
        except UcmdbError as exc:
            rest_error = exc
    has_dates = bool(records) and any(r.get("expiry") for r in records)
    path = find_api_file(settings)
    if path is not None and not has_dates:
        records, file_fields = read_api_file(path, settings)
        motivo = (f"REST falhou: {rest_error}" if rest_error else
                  "REST sem datas de expiração" if settings.ucmdb_tql_apis else "TQL não configurado")
        return records, {**file_fields, "motivo": motivo}
    if records is None:
        raise rest_error or IngestAborted("Lista de APIs não configurada (TQL ou ficheiro api-cmdb em import/)")
    return records, fields


def sync_ct_endpoints(session: Session, settings: Settings) -> dict:
    """Cria servidores a verificar a partir dos nomes encontrados na internet (Certificate Transparency):
    só nomes concretos (sem wildcard) dos domínios configurados, de certificados ainda válidos."""
    from .models import CtCert
    if not settings.ct_scan or not settings.ct_domains:
        return {"aviso": "desligado"}
    now = utcnow()
    names: set[str] = set()
    for c in session.scalars(select(CtCert).where(CtCert.not_after >= now)):
        for n in c.names or []:
            if n.startswith("*.") or not is_valid_hostname(n):
                continue
            if any(n == d or n.endswith("." + d) for d in settings.ct_domains):
                names.add(n)
    existing = {e.host for e in session.scalars(select(Endpoint))}
    port = settings.scan_default_port
    created = 0
    for n in sorted(names - existing):
        if created >= settings.ct_scan_max:
            break
        session.add(Endpoint(host=n, port=port, expected_cn_norm=n, source="ct",
                             note="Encontrado na internet (Certificate Transparency)"))
        created += 1
    return {"nomes": len(names), "novos": created, "limite": settings.ct_scan_max}


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
        resolved_ip=out.resolved_ip,
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
        ep = by_id[eid]
        sr = _store_outcome(session, ep, out)
        counts[sr.status] = counts.get(sr.status, 0) + 1
        # Nomes vindos da internet que não respondem: desligados sem alerta (muitos já não existem)
        if ep.source == "ct" and sr.status != "ok" and ep.consecutive_failures >= settings.unreachable_after:
            ep.enabled = False
            ep.note = (f"Encontrado na internet; sem resposta TLS em {ep.consecutive_failures} verificações "
                       f"({sr.status}). Desligado automaticamente.")[:512]
            counts["ct_desligados"] = counts.get("ct_desligados", 0) + 1

    session.execute(
        delete(ScanResult).where(ScanResult.scanned_at < utcnow() - timedelta(days=SCAN_RETENTION_DAYS))
    )
    return {"alvos": len(targets), "alvos_invalidos": invalid, **counts}


def created_not_in_cmdb(session: Session) -> list[str]:
    """Certificados criados na UCMDB pelo certwatch que a leitura da CMDB (o TQL) não devolve: foram criados, mas
    o TQL filtra-os (ex.: estado ou outro atributo diferente dos certificados ativos)."""
    from .models import UcmdbWrite
    active = set(session.scalars(select(CmdbRecord.ucmdb_id).where(CmdbRecord.active.is_(True))))
    if not active:
        return []
    out = []
    for w in session.scalars(select(UcmdbWrite).where(UcmdbWrite.acao == "criar", UcmdbWrite.parte == "cert",
                                                      UcmdbWrite.estado.in_(("ok", "aviso")))):
        if w.ucmdb_id and w.ucmdb_id not in active:
            out.append(f"{w.cn} ({w.ucmdb_id})")
    return out


# ---------------------------------------------------------------- execução de jobs
def _reevaluate(out: dict, settings: Settings) -> dict:
    """Depois de ler uma fonte, os alertas refletem logo os dados novos (ex.: um certificado acabado de entrar na
    CMDB deixa de estar "em uso sem registo na CMDB")."""
    try:
        with session_scope() as s:
            out["evaluate"] = evaluate(s, settings)
    except Exception as exc:   # a leitura já ficou gravada; a reavaliação corre de novo no próximo ciclo
        log.warning("Reavaliação depois de %s falhou: %s", next(iter(out), "?"), exc)
    return out


def _run(job: str, settings: Settings) -> dict:
    if job == "ingest_cmdb":
        with session_scope() as s:
            out = {"ingest_cmdb": ingest_cmdb(s, settings)}
        with session_scope() as s:
            missing = created_not_in_cmdb(s)
        if missing:
            out["ingest_cmdb"]["criados_fora_do_tql"] = missing[:50]
        return _reevaluate(out, settings)
    if job == "ingest_apis":
        with session_scope() as s:
            return _reevaluate({"ingest_apis": ingest_apis(s, settings)}, settings)
    if job == "ingest_smax":
        from .tickets import ingest_smax
        with session_scope() as s:
            return _reevaluate({"ingest_smax": ingest_smax(s, settings)}, settings)
    if job == "ingest_ct":
        from .discovery import ingest_ct
        with session_scope() as s:
            return _reevaluate({"ingest_ct": ingest_ct(s, settings)}, settings)
    if job == "scan":
        with session_scope() as s:
            return _reevaluate({"scan": run_scan(s, settings)}, settings)
    if job == "ssllabs":
        from .external import run_ssllabs
        return {"ssllabs": run_ssllabs(settings)}
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
        if apis_configured(settings):
            try:
                with session_scope() as s:
                    summary["ingest_apis"] = ingest_apis(s, settings)
            except Exception as exc:
                log.exception("Ingestão de APIs falhou")
                summary["ingest_apis"] = {"erro": str(exc)}
        from .discovery import ingest_ct
        if tickets_on(settings):
            from .tickets import ingest_smax
            try:
                with session_scope() as s:
                    summary["ingest_smax"] = ingest_smax(s, settings)
            except Exception as exc:
                log.exception("Leitura do SMAX falhou")
                summary["ingest_smax"] = {"erro": str(exc)}
        if settings.ct_domains:
            try:
                with session_scope() as s:
                    summary["ingest_ct"] = ingest_ct(s, settings)
                with session_scope() as s:
                    summary["ct_servidores"] = sync_ct_endpoints(s, settings)
            except Exception as exc:
                log.exception("Descoberta CT falhou")
                summary["ingest_ct"] = {"erro": str(exc)}
        with session_scope() as s:
            summary["scan"] = run_scan(s, settings)
        if settings.ssllabs_email:
            from .external import run_ssllabs
            try:
                summary["ssllabs"] = run_ssllabs(settings)
            except Exception as exc:
                log.exception("SSL Labs falhou")
                summary["ssllabs"] = {"erro": str(exc)}
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
        # Um passo que falhou dentro do pipeline marca o job como erro (o resumo mantém o detalhe)
        if any(isinstance(v, dict) and "erro" in v for v in summary.values()):
            status = "error"
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

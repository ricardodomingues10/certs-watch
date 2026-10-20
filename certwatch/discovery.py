"""Descoberta: guarda os certificados encontrados em CT e compara-os com a CMDB e com os servidores."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .collectors.ct import CtRecord, fetch_all, serial_key, time_key, time_name_keys
from .config import Settings
from .db import as_utc, utcnow
from .models import Certificate, CmdbRecord, CtCert
from .normalize import norm_host

CT_STATES = {
    "desconhecido": "Nome não existe na CMDB",
    "nome_conhecido": "Nome existe na CMDB, mas este certificado não",
    "na_cmdb": "Já registado na CMDB",
}
CT_TABS = {"desconhecido": "Nome desconhecido", "nome_conhecido": "Certificado diferente", "na_cmdb": "Já na CMDB"}
CT_STATE_HELP = {
    "desconhecido": "Ninguém registou este nome. Pode ser um serviço novo, de um fornecedor, ou um certificado emitido sem conhecimento da equipa.",
    "nome_conhecido": "O nome está na CMDB, mas com outra data de fim: uma renovação que não foi registada, um segundo certificado para o mesmo nome, ou outra CA a emitir.",
    "na_cmdb": "Este certificado corresponde a um registo da CMDB (mesmo nome e mesma data de fim).",
}
TRIAGE_LABELS = {"por_triar": "Por triar", "adicionar": "Adicionar à CMDB", "investigar": "Investigar", "ignorar": "Ignorar"}


class DiscoveryError(RuntimeError):
    pass


def ingest_ct(session: Session, settings: Settings, records: list[CtRecord] | None = None,
              report: dict | None = None) -> dict:
    if not settings.ct_domains:
        raise DiscoveryError("Defina CERTWATCH_CT_DOMAINS no .env (ex.: exemplo.pt,exemplo.com)")
    if records is None:
        records, report = fetch_all(settings)
    report = report or {}
    if report and all(isinstance(v, str) for v in report.values()):
        raise DiscoveryError("Todas as fontes CT falharam: " + "; ".join(f"{k}: {v}" for k, v in report.items()))

    now = utcnow()
    existing = list(session.scalars(select(CtCert)))
    by_serial: dict[str, CtCert] = {}
    by_tn: dict[tuple[str, str], CtCert] = {}

    def index(c: CtCert) -> None:
        if serial_key(c.serial_hex):
            by_serial[serial_key(c.serial_hex)] = c
        for k in time_name_keys(as_utc(c.not_before), as_utc(c.not_after), c.names):
            by_tn.setdefault(k, c)

    for c in existing:   # chaves recalculadas: registos de versões anteriores fundem-se com os novos
        index(c)
    created = 0
    for r in records:
        c = by_serial.get(r.key_serial) if r.key_serial else None
        if c is None:
            c = next((by_tn[k] for k in sorted(r.time_name_keys()) if k in by_tn), None)
        if c is None:
            c = CtCert(first_seen=now, names=[], sources=[], source_ids={}, triage="por_triar")
            session.add(c)
            created += 1
        c.names = sorted(set(c.names or []) | set(r.names), key=lambda n: (n.startswith("*."), n.count("."), n))
        c.primary_name = c.names[0] if c.names else ""
        c.sources = sorted(set(c.sources or []) | {r.source})
        c.source_ids = {**(c.source_ids or {}), r.source: r.source_id}
        if r.serial_hex and not c.serial_hex:
            c.serial_hex = r.serial_hex
        # O DN completo (crt.sh / Cert Spotter) é preferível ao nome da organização (ctlogs.dev)
        if len(r.issuer_dn) > len(c.issuer_dn or "") and "=" in r.issuer_dn:
            c.issuer_dn, c.issuer_cn = r.issuer_dn, r.issuer_cn or c.issuer_cn
        if not c.issuer_dn and r.issuer_dn:
            c.issuer_dn = r.issuer_dn
        c.issuer_cn = c.issuer_cn or r.issuer_cn
        c.not_before = c.not_before or r.not_before
        c.not_after = c.not_after or r.not_after
        c.domain = c.domain or r.domain
        c.key_serial = serial_key(c.serial_hex)
        c.key_time = time_key(as_utc(c.not_before), as_utc(c.not_after))
        c.last_seen = now
        index(c)
    session.flush()
    return {"registos_recebidos": len(records), "novos": created, "total": session.query(CtCert).count(),
            "fontes": report}


def _day_diff(a: datetime | None, b: datetime | None) -> int | None:
    if a is None or b is None:
        return None
    return abs((as_utc(a).date() - as_utc(b).date()).days)


def classify_ct(session: Session, settings: Settings, now: datetime | None = None,
                include_expired: bool = False) -> list[dict]:
    now = now or utcnow()
    by_cn: dict[str, list[CmdbRecord]] = defaultdict(list)
    for r in session.scalars(select(CmdbRecord).where(CmdbRecord.active.is_(True))):
        by_cn[r.cn_norm].append(r)
    live_serial, live_date = set(), set()
    for c in session.scalars(select(Certificate).where(Certificate.is_ca.is_(False))):
        if serial_key(c.serial_hex):
            live_serial.add(serial_key(c.serial_hex))
        if c.not_after:
            live_date.add((norm_host(c.subject_cn or ""), as_utc(c.not_after).date()))

    rows = []
    min_after = now - timedelta(days=max(0, settings.ct_include_expired_days))
    for ct in session.scalars(select(CtCert)):
        expired = ct.not_after is not None and as_utc(ct.not_after) < now
        if expired and not include_expired and as_utc(ct.not_after) < min_after:
            continue
        matches = [rec for n in ct.names for rec in by_cn.get(n, [])]
        # Mesmo nome e mesma data de fim (±1 dia). O emissor não é exigido: a CMDB pode ter "R10",
        # "Let's Encrypt" ou o DN completo para o mesmo certificado.
        exact = [m for m in matches if m.valid_to is not None and (_day_diff(m.valid_to, ct.not_after) or 0) <= 1]
        state = "na_cmdb" if exact else ("nome_conhecido" if matches else "desconhecido")
        live = bool(serial_key(ct.serial_hex)) and serial_key(ct.serial_hex) in live_serial
        live = live or (ct.not_after is not None
                        and any((n, as_utc(ct.not_after).date()) in live_date for n in ct.names))
        rows.append({
            "ct": ct, "state": state, "expired": expired, "live": live,
            "days": (as_utc(ct.not_after) - now).days if ct.not_after else None,
            "cmdb": sorted({(m.common_name, as_utc(m.valid_to).date() if m.valid_to else None, m.issuer_name or m.issuer)
                            for m in matches}, key=lambda x: (x[0], x[1] or now.date())),
        })
    order = {"desconhecido": 0, "nome_conhecido": 1, "na_cmdb": 2}
    rows.sort(key=lambda r: (order[r["state"]], r["ct"].triage != "por_triar", r["ct"].primary_name))
    return rows

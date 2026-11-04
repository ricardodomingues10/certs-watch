"""Domínios da organização (RDAP): guarda o último registo de cada um e regista as alterações (validade, registrar,
nameservers, estados). Uma alteração de registrar, nameservers ou estados que ninguém pediu é um alerta de segurança."""
from __future__ import annotations

from datetime import datetime

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings
from .db import as_utc, utcnow
from .models import DomainChange, DomainRecord

FIELDS = {"expires": "Validade do registo", "registrar": "Registrar", "nameservers": "Nameservers", "status": "Estados"}
SENSITIVE = ("registrar", "nameservers", "status")         # mudanças que podem ser sequestro
LOCK = "client transfer prohibited"


def _fmt(field: str, v) -> str:
    if field == "expires":
        return as_utc(v).date().isoformat() if v else ""
    if isinstance(v, list):
        return ", ".join(v)
    return str(v or "")


def run(session: Session, settings: Settings, client: httpx.Client | None = None) -> dict:
    from .fontes import rdap
    own = client is None
    c = client or httpx.Client(timeout=15.0, trust_env=True, follow_redirects=True)
    out = {"dominios": len(settings.domains), "lidos": 0, "erros": 0, "alteracoes": 0}
    try:
        servers = rdap.bootstrap(c, settings.rdap_bootstrap_url)
        existing = {d.domain: d for d in session.scalars(select(DomainRecord))}
        now = utcnow()
        for dom in settings.domains:
            rec = existing.get(dom)
            if rec is None:
                rec = DomainRecord(domain=dom)
                session.add(rec)
            rec.checked_at = now
            try:
                info = rdap.lookup(dom, servers, c)
            except rdap.RdapError as exc:
                rec.erro = str(exc)
                out["erros"] += 1
                continue
            first = rec.id is None or not rec.data
            if not first:
                for f in FIELDS:
                    old, new = _fmt(f, getattr(rec, f)), _fmt(f, info[f])
                    if old != new:
                        session.add(DomainChange(domain=dom, detected_at=now, field=f, old=old, new=new))
                        out["alteracoes"] += 1
            rec.expires, rec.registrar = info["expires"], info["registrar"]
            rec.nameservers, rec.status = info["nameservers"], info["status"]
            rec.data = {k: (as_utc(v).isoformat() if isinstance(v, datetime) else v) for k, v in info.items()}
            rec.erro = ""
            out["lidos"] += 1
        session.flush()
    finally:
        if own:
            c.close()
    return out


def overview(session: Session, settings: Settings, now: datetime | None = None, days: int = 90) -> dict:
    now = now or utcnow()
    recs = list(session.scalars(select(DomainRecord).order_by(DomainRecord.domain)))
    since = now.timestamp() - days * 86400
    changes = [c for c in session.scalars(select(DomainChange).order_by(DomainChange.id.desc()).limit(200))
               if as_utc(c.detected_at).timestamp() >= since]
    rows = []
    for r in recs:
        dias = (as_utc(r.expires) - now).days if r.expires else None
        rows.append({"domain": r.domain, "expires": r.expires, "dias": dias, "registrar": r.registrar,
                     "nameservers": r.nameservers or [], "status": r.status or [], "erro": r.erro,
                     "bloqueado": LOCK in (r.status or []) or "clienttransferprohibited" in "".join(r.status or []).replace(" ", ""),
                     "checked_at": r.checked_at, "dnssec": (r.data or {}).get("dnssec"),
                     "alerta": (dias is not None and dias <= settings.domain_alert_days) or bool(r.erro)})
    return {"rows": rows, "changes": [{"domain": c.domain, "quando": c.detected_at, "campo": FIELDS.get(c.field, c.field),
                                       "sensivel": c.field in SENSITIVE, "old": c.old, "new": c.new} for c in changes],
            "alertas": sum(1 for r in rows if r["alerta"]) + sum(1 for c in changes if c.field in SENSITIVE)}

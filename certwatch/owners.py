"""Donos dos certificados: equipa e pessoa responsáveis.

O dono vem de duas origens, por esta ordem:
  1. atribuído no Atalaia Cert (página do certificado ou Donos → Atribuir em bloco);
  2. sugerido pelo SMAX: o grupo e o responsável do pedido mais recente desse certificado (se o grupo tiver o mesmo
     nome do "grupo no SMAX" de uma equipa, fica ligado a essa equipa).
Os avisos aos donos (email e Teams) ainda não são enviados sozinhos.
"""
from __future__ import annotations

import fnmatch

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import CertOwner, Team
from .normalize import norm_host


def teams(session: Session) -> list[Team]:
    return list(session.scalars(select(Team).order_by(Team.name)))


def attach(session: Session, rows: list[dict]) -> None:
    """Junta a cada linha do inventário o dono (r["dono"]) ou None."""
    ts = {t.id: t for t in teams(session)}
    by_group = {t.smax_group.strip().lower(): t for t in ts.values() if t.smax_group.strip()}
    manual = {o.cn_norm: o for o in session.scalars(select(CertOwner))}
    for r in rows:
        o = manual.get(r["cn"])
        if o is not None and (o.team_id or o.person):
            t = ts.get(o.team_id)
            r["dono"] = {"equipa": t.name if t else "", "equipa_id": t.id if t else None, "pessoa": o.person,
                         "email": o.person_email or (t.email if t else ""), "origem": "atribuido",
                         "por": o.updated_by, "em": o.updated_at}
            continue
        main = (r.get("smax") or {}).get("main") or {}
        grp = (main.get("grupo") or "").strip()
        if grp or main.get("responsavel"):
            t = by_group.get(grp.lower())
            r["dono"] = {"equipa": t.name if t else grp, "equipa_id": t.id if t else None, "pessoa": main.get("responsavel") or "",
                         "email": t.email if t else "", "origem": "smax", "pedido": main.get("id")}
        else:
            r["dono"] = None


def set_owner(session: Session, cn: str, team_id: int | None, person: str, person_email: str, by: str) -> CertOwner | None:
    cn = norm_host(cn) or cn.strip().lower()
    o = session.scalar(select(CertOwner).where(CertOwner.cn_norm == cn))
    if not team_id and not person.strip():
        if o is not None:
            session.delete(o)
        return None
    if o is None:
        o = CertOwner(cn_norm=cn)
        session.add(o)
    o.team_id, o.person, o.person_email, o.updated_by = team_id, person.strip()[:128], person_email.strip().lower()[:254], by
    from .db import utcnow
    o.updated_at = utcnow()
    return o


def match_pattern(cn: str, pattern: str) -> bool:
    """Padrão de nomes para atribuir em bloco: *.exemplo.local, *intranet*, portal.exemplo.pt (sem maiúsculas)."""
    p = pattern.strip().lower()
    return bool(p) and (fnmatch.fnmatchcase(cn, p) or cn == p)

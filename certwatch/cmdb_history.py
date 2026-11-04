"""Histórico da CMDB: o que mudou entre duas leituras, quem mudou (se a CMDB disser) e se foi o Atalaia.

Em cada leitura da CMDB (a diária, que já existe) guarda-se, por CI, os atributos lidos e um resumo (sha256). Se o
resumo mudou desde a leitura anterior, regista-se cada atributo que mudou. Não há leituras extra: a comparação é em
memória e só se guardam as diferenças.

- Atributos técnicos que mudam sozinhos (último acesso, contadores…) não contam.
- Um atributo que aparece ou desaparece do layout da TQL não é uma alteração (é o layout que mudou).
- «Quem»: o atributo do tipo «Updated By» do CI, se a TQL o trouxer (ou CERTWATCH_CMDB_UPDATED_BY_ATTR). Sem ele,
  fica a data da alteração (last_modified_time) e o quê, mas não quem.
- As escritas feitas pelo Atalaia (Histórico → Feitas pelo Atalaia) são reconhecidas e marcadas como tal.
- Duas alterações ao mesmo atributo entre duas leituras aparecem como uma só (a do valor final).
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .db import as_utc, utcnow
from .models import CmdbChange, UcmdbWrite

VOLATILE = re.compile(r"^(last_|root_|data_last|track_|monitored_by|calculated_|lastaccess)|access_?time|"
                      r"sys_updated_on|sys_mod_count|sys_tags|_lastupdate|last_?scan", re.I)
WHO = re.compile(r"(updated_?by|modified_?by|changed_?by|last_?modifier|sys_updated_by)$", re.I)
WHEN = re.compile(r"^(last_modified_time|sys_updated_on|lastmodifiedtime|modified_?on|updated_?at)$", re.I)
BASE = ("common_name", "valid_to", "issuer", "issuer_name")
MAX_CHANGES = 5000           # por leitura: mais do que isto é quase sempre uma mudança da TQL, não de dados
KEEP_DAYS = 730
LABELS = {"common_name": "CommonName", "valid_to": "ValidTo", "issuer": "Issuer", "issuer_name": "IssuerName"}


def _s(v) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False, sort_keys=True, default=str)
    return str(v).strip()


def snapshot(r: dict, who_attr: str = "") -> tuple[dict, str, str, str]:
    """(atributos a comparar, resumo, quem, quando) de um registo lido da CMDB."""
    props = r.get("props") or {}
    attrs = {k: _s(r.get(k)) for k in BASE}
    who = when = ""
    for k, v in props.items():
        if (who_attr and k == who_attr) or (not who_attr and WHO.search(k)):
            who = who or _s(v)
            continue
        if WHEN.search(k):
            when = when or _s(v)
            continue
        if VOLATILE.search(k) or k in BASE:
            continue
        attrs[k] = _s(v)
    h = hashlib.sha256(json.dumps(attrs, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    return attrs, h, who, when


def _when(v: str) -> datetime | None:
    if not v:
        return None
    from .fontes.ucmdb import _parse_date
    try:
        if v.isdigit():
            return _parse_date(int(v))
        return _parse_date(v)
    except Exception:
        return None


class Tracker:
    """Usado dentro da leitura da CMDB (jobs.ingest_cmdb): compara e regista sem leituras extra."""

    def __init__(self, session: Session, settings, existing: dict):
        self.s, self.now = session, utcnow()
        self.who_attr = getattr(settings, "cmdb_updated_by_attr", "") or ""
        self.baseline = any(rec.attrs_hash for rec in existing.values())
        self.changes: list[CmdbChange] = []
        self.capped = False
        self.who_seen = False
        since = min((as_utc(rec.last_seen) for rec in existing.values() if rec.last_seen), default=self.now) - timedelta(hours=1)
        self.writes: dict[str, list[UcmdbWrite]] = {}
        for w in session.scalars(select(UcmdbWrite).where(UcmdbWrite.estado.in_(("ok", "aviso")),
                                                         UcmdbWrite.feito_em >= since)):
            for key in {w.ucmdb_id, (w.cn or "").lower()}:
                if key:
                    self.writes.setdefault(key, []).append(w)

    def _add(self, **kw):
        if len(self.changes) >= MAX_CHANGES:
            self.capped = True
            return
        c = CmdbChange(detected_at=self.now, **kw)
        self.changes.append(c)
        self.s.add(c)

    def _atalaia(self, ucmdb_id: str, cn: str, attr: str | None, since: datetime | None, acao: str | None = None):
        for w in self.writes.get(ucmdb_id, []) + self.writes.get((cn or "").lower(), []):
            if since and w.feito_em and as_utc(w.feito_em) < since - timedelta(minutes=5):
                continue
            if acao and w.acao != acao:
                continue
            if attr is None or attr in (w.enviado or {}) or LABELS.get(attr, "") in (w.enviado or {}):
                return w
        return None

    def seen(self, rec, r: dict, is_new: bool) -> None:
        attrs, h, who, when = snapshot(r, self.who_attr)
        self.who_seen = self.who_seen or bool(who)
        changed_at = _when(when)
        if is_new:
            if self.baseline:
                w = self._atalaia(rec.ucmdb_id, attrs["common_name"], None, None, "criar")
                self._add(ucmdb_id=rec.ucmdb_id, cn=attrs["common_name"], kind="criado", attribute="", old="",
                          new=attrs.get("valid_to", ""), changed_at=changed_at,
                          changed_by=f"Atalaia ({w.por})" if w else who, by_atalaia=w is not None,
                          write_id=w.id if w else None)
        elif rec.attrs_hash and h != rec.attrs_hash:
            old = rec.attrs or {}
            prev_seen = as_utc(rec.last_seen) if rec.last_seen else None
            for k in sorted(set(attrs) | set(old)):
                if k.startswith("_") or k not in attrs or k not in old:   # o layout da TQL mudou, não os dados
                    continue
                if attrs[k] != old[k]:
                    w = self._atalaia(rec.ucmdb_id, attrs["common_name"], k, prev_seen)
                    self._add(ucmdb_id=rec.ucmdb_id, cn=attrs["common_name"] or rec.common_name, kind="alterado",
                              attribute=k, old=old[k][:2000], new=attrs[k][:2000], changed_at=changed_at,
                              changed_by=f"Atalaia ({w.por})" if w else who, by_atalaia=w is not None,
                              write_id=w.id if w else None)
        rec.attrs, rec.attrs_hash = {**attrs, "_quem": who, "_quando": when}, h

    def gone(self, rec) -> None:
        if self.baseline and rec.attrs_hash:
            self._add(ucmdb_id=rec.ucmdb_id, cn=rec.common_name, kind="removido", attribute="",
                      old=(rec.attrs or {}).get("valid_to", ""), new="", changed_at=None, changed_by="", by_atalaia=False)

    def finish(self) -> dict:
        self.s.execute(delete(CmdbChange).where(CmdbChange.detected_at < self.now - timedelta(days=KEEP_DAYS)))
        out = {"alteracoes": len(self.changes), "fora_do_atalaia": sum(1 for c in self.changes if not c.by_atalaia)}
        if self.capped:
            out["aviso"] = f"mais de {MAX_CHANGES} alterações numa leitura: só as primeiras ficaram (a TQL mudou?)"
        return out


def label(attr: str) -> str:
    return LABELS.get(attr, attr)


def who_available(session: Session) -> bool:
    """A CMDB está a dizer quem alterou os CIs? (o atributo «Updated By» vem na TQL)"""
    from .models import CmdbRecord
    for attrs in session.scalars(select(CmdbRecord.attrs).where(CmdbRecord.active.is_(True)).limit(200)):
        if (attrs or {}).get("_quem"):
            return True
    return False

"""Conectores: a CMDB e o sistema de tickets de cada cliente, atrás de um contrato único.

Cada cliente tem a sua infraestrutura: uma UCMDB, um ServiceNow, uma base de dados própria, uma folha de
Excel; um SMAX, um Jira, um GLPI. O resto da aplicação não sabe com qual está a falar: pede ao conector
ativo os certificados da CMDB (o mesmo formato que a UCMDB sempre devolveu) ou os pedidos de certificados
(o mesmo formato que o SMAX sempre devolveu).

Que conector está ativo:
  1. o escolhido em Sistema → Ligações (tabela connector_configs), se houver;
  2. senão o do .env, como sempre: UCMDB para a CMDB e SMAX para os tickets (se configurado).
Uma instalação que não toca em Ligações funciona exatamente como antes.

  cmdb.py     UCMDB · ServiceNow · base de dados SQL · API REST/JSON · ficheiro CSV/Excel
  tickets.py  SMAX · Jira · ServiceNow · GLPI · nenhum
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any

from ..config import Settings

ROLES = ("cmdb", "tickets")


class ConnectorError(RuntimeError):
    """Erro de ligação ou de configuração, com uma mensagem para a pessoa (sem segredos)."""


@dataclass(frozen=True)
class Field:
    """Um campo do formulário de ligação."""

    name: str
    label: str
    kind: str = "text"          # text | password | select | textarea | number | bool
    required: bool = False
    default: str = ""
    help: str = ""
    options: tuple[tuple[str, str], ...] = ()
    secret: bool = False        # guardado cifrado, nunca mostrado
    advanced: bool = False


@dataclass
class TestResult:
    ok: bool
    message: str
    sample: list[dict] = field(default_factory=list)
    total: int | None = None


class Connector:
    """Base de todos os conectores."""

    role = ""
    kind = ""
    label = ""
    description = ""
    capabilities: frozenset[str] = frozenset()
    FIELDS: tuple[Field, ...] = ()

    def __init__(self, settings: Settings, params: dict | None = None, secrets: dict | None = None,
                 origin: str = "env") -> None:
        self.settings = settings
        self.params = {f.name: f.default for f in self.FIELDS if not f.secret}
        self.params.update({k: v for k, v in (params or {}).items() if v not in (None,)})
        self.secrets = dict(secrets or {})
        self.origin = origin   # env | interface

    # ---- configuração
    def p(self, name: str, default: str = "") -> str:
        v = self.params.get(name)
        return str(v).strip() if v not in (None, "") else default

    def s(self, name: str) -> str:
        return str(self.secrets.get(name) or "")

    def missing(self) -> list[str]:
        out = []
        for f in self.FIELDS:
            if f.required and not (self.s(f.name) if f.secret else self.p(f.name)):
                out.append(f.label)
        return out

    def configured(self) -> bool:
        return not self.missing()

    def can(self, capability: str) -> bool:
        return capability in self.capabilities

    def summary(self) -> str:
        return self.label

    def test(self) -> TestResult:
        raise NotImplementedError


# ---------------------------------------------------------------- utilitários partilhados
def dig(obj: Any, path: str) -> Any:
    """Valor num JSON por caminho com pontos (a.b.0.c). Caminho vazio = o próprio objeto."""
    if not path:
        return obj
    cur = obj
    for part in path.split("."):
        if isinstance(cur, list) and part.isdigit():
            idx = int(part)
            cur = cur[idx] if idx < len(cur) else None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
        if cur is None:
            return None
    return cur


def as_text(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, dict):   # ServiceNow com display_value, Jira com name/displayName
        for k in ("display_value", "displayName", "name", "value"):
            if v.get(k):
                return str(v[k]).strip()
        return ""
    return str(v).strip()


_DATE_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y",
                 "%d-%m-%Y", "%Y-%m-%d", "%Y/%m/%d", "%m/%d/%Y")


def to_datetime(v: Any) -> datetime | None:
    """Datas em qualquer forma comum: ISO, dd/mm/aaaa, epoch (s ou ms), datetime/date de uma base de dados."""
    if v in (None, ""):
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, date):
        return datetime(v.year, v.month, v.day, tzinfo=timezone.utc)
    if isinstance(v, int | float) or (isinstance(v, str) and re.fullmatch(r"\d{9,13}", v.strip())):
        n = float(v)
        if n > 1e11:   # milissegundos
            n /= 1000
        try:
            return datetime.fromtimestamp(n, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(v).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(text[:19], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def iso(v: Any) -> str | None:
    dt = to_datetime(v)
    return dt.isoformat() if dt else None


_HOST = re.compile(r"(?<![\w.-])(\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w-])", re.I)


def host_in_text(text: str) -> str:
    """Primeiro nome de host num texto (ex.: "Renovar certificado www.exemplo.pt" → www.exemplo.pt)."""
    m = _HOST.search(text or "")
    return m.group(0).lower().rstrip(".") if m else ""


# ---------------------------------------------------------------- cifra das credenciais
def _fernet(settings: Settings):
    from cryptography.fernet import Fernet

    # A chave deriva de um segredo que já existe e raramente muda (a ligação à base de dados): não há mais um
    # ficheiro para gerir. Se mudar, as credenciais guardadas deixam de abrir e a página Ligações pede-as outra vez.
    seed = ("atalaia-conectores:" + settings.database_url).encode()
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(seed).digest()))


def encrypt(settings: Settings, data: dict) -> str:
    if not data:
        return ""
    return _fernet(settings).encrypt(json.dumps(data).encode()).decode()


def decrypt(settings: Settings, token: str) -> dict:
    if not token:
        return {}
    from cryptography.fernet import InvalidToken

    try:
        return json.loads(_fernet(settings).decrypt(token.encode()))
    except (InvalidToken, ValueError):
        return {}


# ---------------------------------------------------------------- registo e conector ativo
def registry() -> dict[str, dict[str, type[Connector]]]:
    from . import cmdb, tickets

    return {"cmdb": cmdb.TYPES, "tickets": tickets.TYPES}


def load_config(role: str):
    from ..db import session_scope
    from ..models import ConnectorConfig

    try:
        with session_scope() as s:
            row = s.get(ConnectorConfig, role)
            if row is None or not row.enabled:
                return None
            return {"kind": row.kind, "params": dict(row.params or {}), "secrets_enc": row.secrets_enc,
                    "updated_at": row.updated_at, "updated_by": row.updated_by}
    except Exception:   # base de dados ainda sem a tabela (arranque) ou em baixo: fica o .env
        return None


def build(settings: Settings, role: str, kind: str, params: dict | None = None, secrets: dict | None = None,
          origin: str = "interface") -> Connector:
    types = registry()[role]
    if kind not in types:
        raise ConnectorError(f"Tipo de ligação desconhecido: {kind}")
    return types[kind](settings, params, secrets, origin=origin)


_ACTIVE: dict = {}
ACTIVE_TTL = 15.0  # segundos: as páginas pedem o conector muitas vezes (um link por pedido)


def invalidate() -> None:
    _ACTIVE.clear()


def active(settings: Settings, role: str) -> Connector:
    """O conector em uso para a CMDB ou para os tickets."""
    import time

    key = (role, id(settings))
    hit = _ACTIVE.get(key)
    if hit and time.monotonic() - hit[0] < ACTIVE_TTL:
        return hit[1]
    conn = _resolve(settings, role)
    _ACTIVE[key] = (time.monotonic(), conn)
    return conn


def _resolve(settings: Settings, role: str) -> Connector:
    cfg = load_config(role)
    if cfg:
        try:
            return build(settings, role, cfg["kind"], cfg["params"], decrypt(settings, cfg["secrets_enc"]))
        except ConnectorError:
            pass
    from . import cmdb, tickets

    if role == "cmdb":
        return cmdb.UcmdbCmdb(settings, origin="env")
    from ..fontes.smax import configured as smax_configured

    return tickets.SmaxTickets(settings, origin="env") if smax_configured(settings) else tickets.NoTickets(settings)


def cmdb_connector(settings: Settings) -> Connector:
    return active(settings, "cmdb")


def ticket_connector(settings: Settings) -> Connector:
    return active(settings, "tickets")


def tickets_on(settings: Settings) -> bool:
    """Há um sistema de tickets ligado e pronto a ler pedidos."""
    c = ticket_connector(settings)
    return c.can("ler") and c.configured()


def tickets_label(settings: Settings) -> str:
    c = ticket_connector(settings)
    return c.label if c.kind != "nenhum" else "SMAX"


def ticket_url(settings: Settings, ticket_id: str) -> str:
    c = ticket_connector(settings)
    return c.ticket_url(ticket_id) if hasattr(c, "ticket_url") else ""


def discussions_url(settings: Settings, ticket_id: str) -> str:
    """Só o SMAX tem a página de discussão separada."""
    if ticket_connector(settings).kind != "smax":
        return ""
    from ..fontes.smax import discussions_url as smax_discussions

    return smax_discussions(settings, ticket_id)

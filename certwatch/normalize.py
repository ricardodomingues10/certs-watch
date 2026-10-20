"""Normalização de nomes, emissores, seriais e datas.

Todos os valores vindos da CMDB ou de outras fontes são tratados como não confiáveis:
um hostname só é considerado alvo de scan se passar a validação estrita.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone

_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://")
_CN_RE = re.compile(r"(?:^|[,/;])\s*CN\s*=\s*((?:\\.|[^,/;])+)", re.IGNORECASE)


def _idna(value: str) -> str:
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError:
        return value


def norm_host(value: str | None) -> str:
    """Minúsculas, sem esquema/caminho/porta, sem ponto final, IDN em punycode."""
    s = (value or "").strip().lower()
    s = _SCHEME_RE.sub("", s)
    s = s.split("/")[0]
    if s.count(":") == 1:  # host:porta (não mexer em IPv6)
        s = s.split(":")[0]
    s = s.rstrip(".")
    if s.startswith("*."):
        rest = _idna(s[2:])
        return f"*.{rest}" if rest else ""
    return _idna(s)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_hostname(value: str) -> bool:
    return bool(_HOST_RE.match(value or ""))


def classify(cn_norm: str) -> str:
    """host | wildcard | ip | other"""
    if not cn_norm:
        return "other"
    if cn_norm.startswith("*."):
        return "wildcard" if is_valid_hostname(cn_norm[2:]) else "other"
    if is_ip(cn_norm):
        return "ip"
    if is_valid_hostname(cn_norm):
        return "host"
    return "other"


def norm_issuer(value: str | None) -> str:
    """Extrai o CN se vier um DN completo; minúsculas e espaços colapsados."""
    s = (value or "").strip()
    m = _CN_RE.search(s)
    if m:
        s = m.group(1).replace("\\,", ",")
    return re.sub(r"\s+", " ", s).strip().lower()


def norm_serial(value: str | None) -> str:
    s = re.sub(r"[^0-9a-fA-F]", "", value or "").upper().lstrip("0")
    return s or ("0" if value else "")


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).strip())
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def hostname_matches(host: str, dns_names: list[str], ip_names: list[str] | None = None) -> bool:
    """Correspondência RFC 6125 simplificada: exata ou wildcard de um só rótulo à esquerda."""
    host = norm_host(host)
    if is_ip(host):
        return host in {str(ipaddress.ip_address(i)) for i in (ip_names or []) if is_ip(i)}
    for name in dns_names or []:
        n = norm_host(name)
        if not n:
            continue
        if n == host:
            return True
        if n.startswith("*."):
            suffix = n[1:]  # ".exemplo.pt"
            left = host[: -len(suffix)] if host.endswith(suffix) else ""
            if left and "." not in left:
                return True
    return False

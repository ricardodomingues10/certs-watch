"""Classificação legível de certificados: tipo (Hostname, Wildcard, IP, API, CA…) e âmbito (interno/externo)."""
from __future__ import annotations

import ipaddress
import re

from .config import Settings

TYPE_LABELS = {
    "api": "API",
    "hostname": "Hostname",
    "wildcard": "Wildcard",
    "ip": "Endereço IP",
    "ca": "Autoridade (CA)",
    "outro": "Outro",
}
TYPE_HELP = {
    "api": "Serviço consumido por outras aplicações, presente na lista de APIs da CMDB.",
    "hostname": "Certificado para um nome de servidor concreto (ex.: portal.exemplo.pt).",
    "wildcard": "Certificado que cobre todos os nomes de um domínio (ex.: *.exemplo.pt).",
    "ip": "Certificado emitido para um endereço IP em vez de um nome.",
    "ca": "Certificado de uma autoridade que emite outros certificados.",
    "outro": "Certificado de utilizador, dispositivo ou com nome não reconhecido.",
}
SCOPE_LABELS = {"interno": "Interno", "externo": "Externo", "desconhecido": "Desconhecido"}
SCOPE_HELP = {
    "interno": "Só acessível dentro da rede da organização, ou emitido por uma CA interna.",
    "externo": "Acessível a partir da internet, normalmente com certificado de uma CA pública.",
    "desconhecido": "Não há informação suficiente para decidir.",
}

_CA_HINT = re.compile(r"(?:^|[\s_-])(ca\d*|root|raiz|authority|autoridade|issuing|intermediate|policy)(?:$|[\s_-])", re.I)


def is_private_ip(value: str | None) -> bool:
    try:
        ip = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def cert_type(cn_norm: str, kind: str, *, is_api: bool = False, issuer_norm: str = "", common_name: str = "") -> str:
    if is_api:
        return "api"
    if kind == "wildcard":
        return "wildcard"
    if kind == "ip":
        return "ip"
    if kind == "host":
        return "hostname"
    name = (common_name or cn_norm or "").strip()
    if (issuer_norm and issuer_norm == name.lower()) or _CA_HINT.search(name):
        return "ca"
    return "outro"


def scope_of(cn_norm: str, kind: str, settings: Settings, *, issuer_norm: str = "", resolved_ip: str = "") -> str:
    """Ordem: sufixo interno configurado → IP privado → IP resolvido privado → CA interna → público."""
    name = (cn_norm or "").lstrip("*.")
    if kind == "ip":
        return "interno" if is_private_ip(name) else "externo"
    if any(name == s.lstrip(".") or name.endswith(s if s.startswith(".") else "." + s) for s in settings.internal_suffixes):
        return "interno"
    if resolved_ip:
        return "interno" if is_private_ip(resolved_ip) else "externo"
    if issuer_norm and any(p in issuer_norm for p in settings.internal_issuer_patterns):
        return "interno"
    if kind in ("host", "wildcard"):
        return "externo"
    return "desconhecido"

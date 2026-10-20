"""Classificação legível de certificados: tipo (Hostname, Wildcard, IP, API, CA…) e âmbito (interno/externo)."""
from __future__ import annotations

import ipaddress
import re
from functools import lru_cache

from .config import Settings
from .normalize import norm_issuer

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


# ------------------------------------------------------------------ renovação automática
AUTO_RENEW_LABELS = {"auto": "Automática", "manual": "Manual"}
AUTO_RENEW_HELP = {
    "auto": "Emitido por Let's Encrypt (ACME): o certificado dura 90 dias ou menos e o servidor renova-o sozinho, "
            "normalmente a 30 dias do fim. Só há alerta se faltarem poucos dias, porque isso significa que a renovação falhou.",
    "manual": "Emitido por uma CA sem renovação automática: alguém tem de pedir, instalar e registar o novo certificado.",
}


@lru_cache(maxsize=64)
def _auto_renew_res(patterns: tuple[str, ...]) -> tuple[re.Pattern, ...]:
    out = []
    for p in patterns:
        try:
            out.append(re.compile(p, re.I))
        except re.error:
            continue
    return tuple(out)


def is_auto_renew(settings: Settings, *issuers: str | None) -> bool:
    """Verdadeiro se algum dos textos de emissor (Issuer, IssuerName, DN ou CN visto no servidor)
    corresponder a uma CA com renovação automática."""
    res = _auto_renew_res(tuple(settings.auto_renew_issuers))
    for value in issuers:
        v = (value or "").strip()
        if not v:
            continue
        for cand in {v, norm_issuer(v)}:
            if any(r.search(cand) for r in res):
                return True
    return False

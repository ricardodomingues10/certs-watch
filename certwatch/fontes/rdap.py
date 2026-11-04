"""Fonte: RDAP (Registration Data Access Protocol), o sucessor do WHOIS: o registo de cada domínio da organização.

JSON por HTTPS, numa estrutura normalizada (RFC 9083). A IANA publica, para cada terminação (.pt, .com…), o servidor
RDAP do registo; o .pt é o da DNS.pt. Dá, por domínio:
- a data de expiração do REGISTO do domínio (não do certificado): se expirar, caem todos os sites e certificados;
- o registrar, os nameservers e os estados (ex.: «client transfer prohibited», o bloqueio contra transferências).
Uma mudança de registrar, nameservers ou estados pode ser sinal de sequestro do domínio.
Só leitura; uma consulta por domínio por dia.
"""
from __future__ import annotations

from datetime import datetime, timezone

import httpx

FONTE = {
    "id": "rdap", "nome": "RDAP (registo dos domínios)", "tipo": "API REST pública", "estado": "em uso",
    "para": "Validade do registo de cada domínio da organização, registrar, nameservers e estados (proteção contra transferência).",
    "config": ["CERTWATCH_DOMAINS (ou CERTWATCH_CT_DOMAINS)", "CERTWATCH_RDAP_BOOTSTRAP", "CERTWATCH_DOMAIN_ALERT_DAYS", "HTTPS_PROXY (se houver)"],
    "chamadas": [
        {"metodo": "GET", "endereco": "https://data.iana.org/rdap/dns.json", "para": "que servidor RDAP responde por cada terminação (.pt, .com…)", "acesso": "leitura", "estado": "em uso", "onde": "fontes/rdap.py · bootstrap"},
        {"metodo": "GET", "endereco": "{servidor RDAP}/domain/{domínio} (ex.: https://rdap.dns.pt/domain/…)", "para": "validade do registo, registrar, nameservers e estados", "acesso": "leitura", "estado": "em uso", "onde": "fontes/rdap.py · lookup"},
    ],
}


class RdapError(RuntimeError):
    pass


def estado(settings) -> tuple[bool, str]:
    n = len(settings.domains)
    return (n > 0), (f"{n} domínio(s): {', '.join(settings.domains[:4])}" if n else "sem domínios (CERTWATCH_DOMAINS)")


def bootstrap(client: httpx.Client, url: str) -> dict[str, str]:
    """Terminação -> URL base do servidor RDAP (o primeiro https da lista da IANA)."""
    try:
        r = client.get(url, headers={"Accept": "application/json"})
    except httpx.HTTPError as exc:
        raise RdapError(f"Lista RDAP da IANA indisponível: {str(exc)[:150]}") from None
    if r.status_code != 200:
        raise RdapError(f"Lista RDAP da IANA: HTTP {r.status_code}")
    out = {}
    for tlds, urls in (r.json() or {}).get("services") or []:
        base = next((u for u in urls if u.startswith("https://")), urls[0] if urls else "")
        for t in tlds:
            out[t.lower()] = base if base.endswith("/") else base + "/"
    return out


def server_for(domain: str, servers: dict[str, str]) -> str:
    labels = domain.lower().strip(".").split(".")
    for i in range(len(labels)):              # o sufixo mais longo primeiro (ex.: com.pt antes de pt)
        suf = ".".join(labels[i:])
        if suf in servers:
            return servers[suf]
    return ""


def _dt(v) -> datetime | None:
    if not v:
        return None
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _vcard_name(entity: dict) -> str:
    card = entity.get("vcardArray") or []
    for item in (card[1] if len(card) > 1 and isinstance(card[1], list) else []):
        if isinstance(item, list) and len(item) >= 4 and item[0] in ("fn", "org") and item[3]:
            return str(item[3])
    return str(entity.get("handle") or "")


def parse(data: dict) -> dict:
    events = {str(e.get("eventAction") or "").lower(): _dt(e.get("eventDate")) for e in data.get("events") or []}
    registrar = ""
    for e in data.get("entities") or []:
        if "registrar" in [str(x).lower() for x in e.get("roles") or []]:
            registrar = _vcard_name(e)
            break
    return {
        "expires": events.get("expiration") or events.get("registration expiration"),
        "registered": events.get("registration"),
        "changed": events.get("last changed"),
        "registrar": registrar,
        "nameservers": sorted({str(n.get("ldhName") or "").lower().rstrip(".") for n in data.get("nameservers") or [] if n.get("ldhName")}),
        "status": sorted({str(s).lower() for s in data.get("status") or []}),
        "dnssec": bool((data.get("secureDNS") or {}).get("delegationSigned")),
    }


def lookup(domain: str, servers: dict[str, str], client: httpx.Client) -> dict:
    base = server_for(domain, servers)
    if not base:
        raise RdapError(f"Nenhum servidor RDAP conhecido para {domain} (a terminação não tem RDAP na lista da IANA).")
    try:
        r = client.get(base + "domain/" + domain, headers={"Accept": "application/rdap+json, application/json"})
    except httpx.HTTPError as exc:
        raise RdapError(f"{base}: {str(exc)[:150]}") from None
    if r.status_code == 404:
        raise RdapError(f"{domain} não existe no registo ({base}).")
    if r.status_code == 429:
        raise RdapError(f"{base} pediu para abrandar (HTTP 429).")
    if r.status_code != 200:
        raise RdapError(f"{base}: HTTP {r.status_code}")
    try:
        data = r.json()
    except ValueError:
        raise RdapError(f"{base}: resposta que não é JSON") from None
    return {**parse(data), "servidor": base}

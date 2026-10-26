"""Descoberta de certificados públicos via Certificate Transparency (CT).

Fontes gratuitas, todas sem chave obrigatória:
  - crt.sh       https://crt.sh/?q=%.dominio&output=json         (Sectigo; pode ser lento)
  - Cert Spotter https://api.certspotter.com/v1/issuances         (SSLMate; limite horário sem chave)
  - ctlogs.dev   https://api.ctlogs.dev/v1/subdomains/{dominio}   (100 pedidos/hora sem chave; últimos 90 dias)

Cada fonte devolve registos normalizados; a fusão entre fontes faz-se por emissor+serial e,
quando a fonte não traz serial (Cert Spotter), por emissor+validade.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import httpx

from ..config import Settings
from ..normalize import norm_host, norm_issuer, norm_serial, parse_iso
from ..trust import build_bundle

log = logging.getLogger(__name__)
USER_AGENT = "AtalaiaCert/0.21 (certificate monitoring for the domain owner)"
MAX_PAGES = 20


class CtError(RuntimeError):
    pass


@dataclass
class CtRecord:
    source: str
    source_id: str
    names: list[str]
    issuer_cn: str
    issuer_dn: str
    serial_hex: str
    not_before: datetime | None
    not_after: datetime | None
    domain: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def issuer_norm(self) -> str:
        return norm_issuer(self.issuer_dn or self.issuer_cn)

    @property
    def key_serial(self) -> str:
        return serial_key(self.serial_hex)

    @property
    def key_time(self) -> str:
        return time_key(self.not_before, self.not_after)

    def time_name_keys(self) -> set[tuple[str, str]]:
        return time_name_keys(self.not_before, self.not_after, self.names)


# Chaves de fusão. As fontes descrevem o emissor de formas diferentes (crt.sh dá o DN, ctlogs.dev só o
# nome da organização, Cert Spotter um DN RFC 2253), por isso o emissor não entra nas chaves:
#   - serial: aleatório com pelo menos 64 bits nas CA públicas; basta sozinho;
#   - validade ao segundo + um nome em comum: para fontes sem serial (Cert Spotter).
def serial_key(serial_hex: str | None) -> str:
    s = norm_serial(serial_hex or "")
    return s if len(s) >= 8 else ""


def time_key(nb: datetime | None, na: datetime | None) -> str:
    f = lambda d: d.astimezone(timezone.utc).strftime("%Y%m%d%H%M%S") if d else ""
    return f"{f(nb)}|{f(na)}" if (nb or na) else ""


def time_name_keys(nb, na, names) -> set[tuple[str, str]]:
    tk = time_key(nb, na)
    return {(tk, n) for n in names or []} if tk else set()


def _dt(value) -> datetime | None:
    d = parse_iso(value) if value else None
    return d.replace(microsecond=0) if d else None


def _cn_from_dn(dn: str) -> str:
    for part in (dn or "").replace(";", ",").split(","):
        k, _, v = part.strip().partition("=")
        if k.strip().upper() == "CN":
            return v.strip()
    return (dn or "").strip()


def _belongs(name: str, domain: str) -> bool:
    n = name.lstrip("*.")
    return n == domain or n.endswith("." + domain)


def _client(settings: Settings) -> httpx.Client:
    import ssl
    ctx = ssl.create_default_context(cafile=build_bundle(settings))
    # trust_env=True: respeita HTTPS_PROXY / NO_PROXY se o servidor sair por proxy
    return httpx.Client(verify=ctx, timeout=httpx.Timeout(30.0, read=180.0), headers={"User-Agent": USER_AGENT},
                        follow_redirects=True, trust_env=True)


# ------------------------------------------------------------------ crt.sh
def fetch_crtsh(client: httpx.Client, domain: str, settings: Settings) -> list[CtRecord]:
    params = {"q": f"%.{domain}", "output": "json", "deduplicate": "Y"}
    if settings.ct_include_expired_days <= 0:
        params["exclude"] = "expired"
    r = client.get("https://crt.sh/", params=params)
    if r.status_code != 200:
        raise CtError(f"crt.sh respondeu HTTP {r.status_code}")
    try:
        data = r.json()
    except ValueError as exc:
        raise CtError("crt.sh devolveu uma resposta que não é JSON (sobrecarga frequente; tentar mais tarde)") from exc
    out = []
    for row in data or []:
        names = {norm_host(n) for n in str(row.get("name_value") or "").split("\n") if n.strip()}
        if row.get("common_name"):
            names.add(norm_host(row["common_name"]))
        issuer_dn = str(row.get("issuer_name") or "")
        out.append(CtRecord(
            source="crtsh", source_id=str(row.get("id") or ""),
            names=sorted(n for n in names if n and _belongs(n, domain)),
            issuer_cn=_cn_from_dn(issuer_dn), issuer_dn=issuer_dn,
            serial_hex=norm_serial(str(row.get("serial_number") or "")),
            not_before=_dt(row.get("not_before")), not_after=_dt(row.get("not_after")), domain=domain,
        ))
    return out


# ------------------------------------------------------------------ Cert Spotter
def fetch_certspotter(client: httpx.Client, domain: str, settings: Settings) -> list[CtRecord]:
    headers = {"Authorization": f"Bearer {settings.certspotter_api_key}"} if settings.certspotter_api_key else {}
    params = [("domain", domain), ("include_subdomains", "true"), ("match_wildcards", "true"),
              ("expand", "dns_names"), ("expand", "issuer")]
    out, after = [], None
    for _ in range(MAX_PAGES):
        q = params + ([("after", after)] if after else [])
        r = client.get("https://api.certspotter.com/v1/issuances", params=q, headers=headers)
        if r.status_code == 429:
            raise CtError("Cert Spotter: limite de pedidos sem chave atingido (configurar certspotter_api_key)")
        if r.status_code != 200:
            raise CtError(f"Cert Spotter respondeu HTTP {r.status_code}")
        rows = r.json() or []
        if not rows:
            break
        for row in rows:
            iss = row.get("issuer") or {}
            issuer_dn = str(iss.get("name") or "")
            out.append(CtRecord(
                source="certspotter", source_id=str(row.get("id") or ""),
                names=sorted({norm_host(n) for n in row.get("dns_names") or [] if _belongs(norm_host(n), domain)}),
                issuer_cn=_cn_from_dn(issuer_dn) or str(iss.get("friendly_name") or ""), issuer_dn=issuer_dn,
                serial_hex="", not_before=_dt(row.get("not_before")), not_after=_dt(row.get("not_after")),
                domain=domain, extra={"revogado": row.get("revoked")},
            ))
        after = rows[-1].get("id")
    return out


# ------------------------------------------------------------------ ctlogs.dev
def fetch_ctlogs(client: httpx.Client, domain: str, settings: Settings) -> list[CtRecord]:
    headers = {"Authorization": f"Bearer {settings.ctlogs_api_key}"} if settings.ctlogs_api_key else {}
    out, cursor = [], None
    for _ in range(10 if not settings.ctlogs_api_key else MAX_PAGES):
        params = {"after": cursor} if cursor else {}
        r = client.get(f"https://api.ctlogs.dev/v1/subdomains/{domain}", params=params, headers=headers)
        if r.status_code == 503:
            time.sleep(5)
            r = client.get(f"https://api.ctlogs.dev/v1/subdomains/{domain}", params=params, headers=headers)
        if r.status_code == 404:
            break
        if r.status_code == 429:
            raise CtError("ctlogs.dev: limite de pedidos atingido (100/hora sem chave)")
        if r.status_code != 200:
            raise CtError(f"ctlogs.dev respondeu HTTP {r.status_code}")
        data = r.json() or {}
        for row in data.get("rows") or []:
            name = norm_host(str(row.get("match") or ""))
            issuer = str(row.get("issuer") or "")
            out.append(CtRecord(
                source="ctlogs", source_id=str(row.get("id") or ""),
                names=[name] if name and _belongs(name, domain) else [],
                issuer_cn=_cn_from_dn(issuer), issuer_dn=issuer,
                serial_hex=norm_serial(str(row.get("serial_hex") or "")),
                not_before=_dt(row.get("not_before")), not_after=_dt(row.get("not_after")), domain=domain,
            ))
        if not data.get("has_next") or not data.get("next_cursor"):
            break
        cursor = data["next_cursor"]
    return out


FETCHERS = {"crtsh": fetch_crtsh, "certspotter": fetch_certspotter, "ctlogs": fetch_ctlogs}
SOURCE_LABELS = {"crtsh": "crt.sh", "certspotter": "Cert Spotter", "ctlogs": "ctlogs.dev"}


def fetch_all(settings: Settings, client: httpx.Client | None = None) -> tuple[list[CtRecord], dict]:
    """Consulta todas as fontes para todos os domínios. Uma fonte que falha não impede as outras."""
    own = client is None
    client = client or _client(settings)
    records: list[CtRecord] = []
    report: dict = {}
    min_after = datetime.now(timezone.utc) - timedelta(days=max(0, settings.ct_include_expired_days))
    try:
        for domain in settings.ct_domains:
            for src in settings.ct_sources:
                fn = FETCHERS.get(src)
                if fn is None:
                    report[f"{domain}/{src}"] = "fonte desconhecida"
                    continue
                try:
                    got = [r for r in fn(client, domain, settings)
                           if r.names and (r.not_after is None or r.not_after >= min_after)]
                    records += got
                    report[f"{domain}/{src}"] = len(got)
                except (CtError, httpx.HTTPError, ValueError) as exc:
                    log.warning("CT %s/%s falhou: %s", domain, src, exc)
                    report[f"{domain}/{src}"] = f"erro: {exc}"
    finally:
        if own:
            client.close()
    return records, report

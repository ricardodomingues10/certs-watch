"""Coletor UCMDB via REST API (/rest-api/authenticate + /rest-api/topology).

Certificados: só se extraem os campos confiáveis (common_name, valid_to, issuer, issuer_name).
APIs: deteção automática dos campos de nome, URL e validade, com filtro de dados sensíveis.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from ..config import Settings
from ..normalize import norm_host, parse_iso
from ..trust import ssl_context_for_api

log = logging.getLogger(__name__)


class UcmdbError(RuntimeError):
    pass


def fetch_topology(settings: Settings, tql: str, client: httpx.Client | None = None) -> list[dict]:
    """Autentica e executa um TQL pelo nome. Devolve a lista de CIs."""
    if not settings.ucmdb_url or not tql:
        raise UcmdbError("Defina CERTWATCH_UCMDB_URL e o nome do TQL no ficheiro .env")
    if not settings.ucmdb_user or not settings.ucmdb_password:
        raise UcmdbError("Credenciais UCMDB em falta (segredos ucmdb_user / ucmdb_password)")

    own_client = client is None
    if own_client:
        client = httpx.Client(
            base_url=settings.ucmdb_url.rstrip("/") + "/rest-api",
            verify=ssl_context_for_api(settings),
            timeout=httpx.Timeout(30.0, read=180.0),
        )
    try:
        r = client.post("/authenticate", json={
            "username": settings.ucmdb_user,
            "password": settings.ucmdb_password,
            "clientContext": settings.ucmdb_client_context,
        })
        if r.status_code != 200:
            raise UcmdbError(f"Autenticação UCMDB falhou: HTTP {r.status_code}")
        token = (r.json() or {}).get("token")
        if not token:
            raise UcmdbError("Autenticação UCMDB sem token na resposta")
        r = client.post("/topology", content=tql.encode("utf-8"),
                        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        if r.status_code != 200:
            raise UcmdbError(f"Execução do TQL '{tql}' falhou: HTTP {r.status_code}")
        data = r.json()
    except httpx.HTTPError as exc:
        raise UcmdbError(f"Erro de comunicação com a UCMDB: {exc}") from exc
    finally:
        if own_client:
            client.close()

    if not isinstance(data, dict) or "cis" not in data:
        raise UcmdbError("Resposta inesperada da UCMDB (sem 'cis')")
    extra = set(data) - {"cis", "relations"}
    if extra:
        log.warning("Resposta UCMDB com chaves adicionais (possível paginação): %s", sorted(extra))
    return list(data.get("cis") or [])


def fetch_certificates(settings: Settings, client: httpx.Client | None = None) -> list[dict]:
    out: list[dict] = []
    for ci in fetch_topology(settings, settings.ucmdb_tql, client):
        props = ci.get("properties") or {}
        out.append({
            "ucmdb_id": str(ci.get("ucmdbId") or ""),
            "global_id": props.get("global_id") or ci.get("globalId"),
            "common_name": (props.get("common_name") or "").strip(),
            "valid_to": props.get("valid_to"),
            "issuer": (props.get("issuer") or "").strip(),
            "issuer_name": (props.get("issuer_name") or "").strip(),
        })
    return out


# ------------------------------------------------------------------ APIs
# Nomes de atributos que podem conter segredos. Só são aceites se forem uma data (ex.: secret_expiration).
SENSITIVE_KEY = re.compile(r"secret|password|passwd|pwd|token|credential|private|api_?key|client_?key|cert_?key|hash|salt", re.I)
DATE_KEY = re.compile(r"expir|valid|validade|end_?date|data_?fim|termin|until|not_?after|renova", re.I)
INTERNAL_KEY = re.compile(r"^(data_|root_|last_|create|tenant|calculated_|global_id$|user_label$)", re.I)
URL_KEY = re.compile(r"url|uri|endpoint|host|link|address|endereco", re.I)
NAME_KEYS = ("display_label", "name", "label", "user_label")
EXTRA_KEY = re.compile(r"aplic|ambiente|owner|respons|descr|fornecedor|vendor|tipo|type|status|estado|grupo|group", re.I)
_URLISH = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:/.*)?$", re.I)


def _is_date(value) -> bool:
    return isinstance(value, str) and parse_iso(value) is not None and len(value) >= 10


def _parse_date(value) -> datetime | None:
    if isinstance(value, (int, float)) and value > 10_000_000_000:  # epoch em ms
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
    return parse_iso(value) if isinstance(value, str) else None


def safe_properties(props: dict) -> dict:
    """Remove tudo o que possa ser segredo: atributos com nome sensível que não sejam datas, e textos longos."""
    out = {}
    for k, v in (props or {}).items():
        if SENSITIVE_KEY.search(k) and not (DATE_KEY.search(k) and _is_date(v)):
            continue
        if isinstance(v, str) and len(v) > 300:
            continue
        out[k] = v
    return out


def detect_api_fields(cis: list[dict], settings: Settings) -> dict[str, str | None]:
    """Escolhe os atributos de nome, URL e validade. Os valores do .env têm prioridade."""
    keys: dict[str, list] = {}
    for ci in cis:
        for k, v in safe_properties(ci.get("properties") or {}).items():
            keys.setdefault(k, []).append(v)

    def pick_name():
        return next((k for k in NAME_KEYS if k in keys), None)

    def pick_url():
        best, best_score = None, 0
        for k, vals in keys.items():
            if INTERNAL_KEY.search(k) or not URL_KEY.search(k):
                continue
            score = sum(1 for v in vals if isinstance(v, str) and _URLISH.match(v.strip()))
            if score > best_score:
                best, best_score = k, score
        return best

    def pick_expiry():
        best, best_score = None, 0
        for k, vals in keys.items():
            if INTERNAL_KEY.search(k) or not DATE_KEY.search(k):
                continue
            score = sum(1 for v in vals if _parse_date(v) is not None)
            if score > best_score:
                best, best_score = k, score
        return best

    return {
        "nome": settings.apis_field_name or pick_name(),
        "url": settings.apis_field_url or pick_url(),
        "validade": settings.apis_field_expiry or pick_expiry(),
    }


def parse_api_url(value: str | None) -> tuple[str, str, int | None]:
    """Devolve (esquema, host, porta). Aceita URL completo ou só host[:porta]."""
    s = (value or "").strip()
    if not s:
        return "", "", None
    if "://" not in s:
        s = "https://" + s
        implicit = True
    else:
        implicit = False
    try:
        parts = urlsplit(s)
        port = parts.port
    except ValueError:
        return "", "", None
    scheme = "" if implicit else (parts.scheme or "").lower()
    return scheme, norm_host(parts.hostname or ""), port


def fetch_apis(settings: Settings, client: httpx.Client | None = None) -> tuple[list[dict], dict]:
    cis = fetch_topology(settings, settings.ucmdb_tql_apis, client)
    fields = detect_api_fields(cis, settings)
    out = []
    for ci in cis:
        props = safe_properties(ci.get("properties") or {})
        raw_url = props.get(fields["url"]) if fields["url"] else None
        scheme, host, port = parse_api_url(raw_url if isinstance(raw_url, str) else None)
        name = props.get(fields["nome"]) if fields["nome"] else None
        out.append({
            "ucmdb_id": str(ci.get("ucmdbId") or ""),
            "name": str(name or ci.get("displayLabel") or "").strip(),
            "url": str(raw_url or "").strip()[:1024],
            "scheme": scheme,
            "host": host,
            "port": port,
            "expiry": _parse_date(props.get(fields["validade"])) if fields["validade"] else None,
            "extra": {k: v for k, v in props.items()
                      if EXTRA_KEY.search(k) and not INTERNAL_KEY.search(k) and isinstance(v, (str, int, bool))
                      and k not in fields.values()},
        })
    return out, fields


def describe_tql(settings: Settings, tql: str, client: httpx.Client | None = None) -> dict:
    """Resumo de um TQL para configuração: atributos, tipos e exemplos não sensíveis."""
    cis = fetch_topology(settings, tql, client)
    keys: dict[str, dict] = {}
    for ci in cis:
        for k, v in (ci.get("properties") or {}).items():
            info = keys.setdefault(k, {"tipo": type(v).__name__, "preenchido": 0, "exemplo": None})
            if v not in (None, "", []):
                info["preenchido"] += 1
                if info["exemplo"] is None:
                    if SENSITIVE_KEY.search(k) and not (DATE_KEY.search(k) and _is_date(v)):
                        info["exemplo"] = "(oculto: nome sensível)"
                    elif _is_date(v) or isinstance(v, (bool, int, float)):
                        info["exemplo"] = v
                    elif isinstance(v, str) and _URLISH.match(v.strip()):
                        _, host, port = parse_api_url(v)
                        info["exemplo"] = f"(URL/host com {len(host)} caracteres{', porta ' + str(port) if port else ''})"
                    else:
                        info["exemplo"] = f"(texto, {len(str(v))} caracteres)"
    return {"tql": tql, "total_cis": len(cis), "tipos_ci": sorted({str(c.get('type')) for c in cis}),
            "atributos": keys, "campos_detetados": detect_api_fields(cis, settings) if cis else {}}

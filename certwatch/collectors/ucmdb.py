"""Coletor UCMDB via REST API (/rest-api/authenticate + /rest-api/topology).

Só extrai os campos considerados confiáveis: common_name, valid_to, issuer, issuer_name.
"""
from __future__ import annotations

import logging

import httpx

from ..config import Settings
from ..trust import ssl_context_for_api

log = logging.getLogger(__name__)


class UcmdbError(RuntimeError):
    pass


def fetch_certificates(settings: Settings, client: httpx.Client | None = None) -> list[dict]:
    if not settings.ucmdb_url or not settings.ucmdb_tql:
        raise UcmdbError("Defina CERTWATCH_UCMDB_URL e CERTWATCH_UCMDB_TQL no ficheiro .env")
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
        r = client.post(
            "/authenticate",
            json={
                "username": settings.ucmdb_user,
                "password": settings.ucmdb_password,
                "clientContext": settings.ucmdb_client_context,
            },
        )
        if r.status_code != 200:
            raise UcmdbError(f"Autenticação UCMDB falhou: HTTP {r.status_code}")
        token = (r.json() or {}).get("token")
        if not token:
            raise UcmdbError("Autenticação UCMDB sem token na resposta")

        r = client.post(
            "/topology",
            content=settings.ucmdb_tql.encode("utf-8"),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        if r.status_code != 200:
            raise UcmdbError(f"Execução do TQL '{settings.ucmdb_tql}' falhou: HTTP {r.status_code}")
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

    out: list[dict] = []
    for ci in data.get("cis") or []:
        props = ci.get("properties") or {}
        out.append(
            {
                "ucmdb_id": str(ci.get("ucmdbId") or ""),
                "global_id": props.get("global_id") or ci.get("globalId"),
                "common_name": (props.get("common_name") or "").strip(),
                "valid_to": props.get("valid_to"),
                "issuer": (props.get("issuer") or "").strip(),
                "issuer_name": (props.get("issuer_name") or "").strip(),
            }
        )
    return out

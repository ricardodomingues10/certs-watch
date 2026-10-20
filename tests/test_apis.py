import json
from dataclasses import replace
from datetime import timedelta

import httpx
from sqlalchemy import select

from certwatch.collectors.ucmdb import describe_tql, fetch_apis, parse_api_url
from certwatch.db import session_scope, utcnow
from certwatch.evaluator import evaluate
from certwatch.jobs import ingest_apis
from certwatch.models import ApiRecord, Endpoint, Finding

SOON = (utcnow() + timedelta(days=10)).isoformat()
LATER = (utcnow() + timedelta(days=300)).isoformat()

CIS = [
    {"ucmdbId": "api1", "type": "exemplo_api", "displayLabel": "API Pagamentos", "properties": {
        "display_label": "API Pagamentos", "endpoint_url": "https://pagamentos.exemplo.pt/v1",
        "client_secret": "S3gr3d0-MUITO-SECRETO", "password": "p4ss", "token_value": "tok-abc",
        "secret_expiration_date": SOON, "aplicacao": "Pagamentos", "root_class": "exemplo_api"}},
    {"ucmdbId": "api2", "type": "exemplo_api", "displayLabel": "API Legada", "properties": {
        "display_label": "API Legada", "endpoint_url": "http://legado.exemplo.local:8080/ws",
        "secret_expiration_date": LATER}},
    {"ucmdbId": "api3", "type": "exemplo_api", "displayLabel": "API Porta", "properties": {
        "display_label": "API Porta", "endpoint_url": "api-porta.exemplo.pt:9443",
        "secret_expiration_date": LATER, "private_key": "-----BEGIN PRIVATE KEY-----..."}},
]


def client(cis):
    def handler(request):
        if request.url.path.endswith("/authenticate"):
            return httpx.Response(200, json={"token": "t"})
        assert request.content == b"APIs_Exemplo"
        return httpx.Response(200, json={"cis": cis, "relations": []})
    return httpx.Client(base_url="https://cmdb.test/rest-api", transport=httpx.MockTransport(handler))


def test_parse_api_url():
    assert parse_api_url("https://Api.Exemplo.pt:8443/v1") == ("https", "api.exemplo.pt", 8443)
    assert parse_api_url("http://x.exemplo.local/ws") == ("http", "x.exemplo.local", None)
    assert parse_api_url("api.exemplo.pt") == ("", "api.exemplo.pt", None)
    assert parse_api_url("") == ("", "", None)


def test_fetch_detects_fields_and_never_keeps_secrets(env):
    settings = replace(env, ucmdb_tql_apis="APIs_Exemplo")
    records, fields = fetch_apis(settings, client(CIS))
    assert fields == {"nome": "display_label", "url": "endpoint_url", "validade": "secret_expiration_date"}
    dump = json.dumps(records, default=str)
    for secret in ("S3gr3d0", "p4ss", "tok-abc", "PRIVATE KEY"):
        assert secret not in dump
    r1 = records[0]
    assert r1["name"] == "API Pagamentos" and r1["host"] == "pagamentos.exemplo.pt" and r1["scheme"] == "https"
    assert r1["expiry"] is not None and r1["extra"] == {"aplicacao": "Pagamentos"}

    info = describe_tql(settings, "APIs_Exemplo", client(CIS))
    assert info["atributos"]["client_secret"]["exemplo"] == "(oculto: nome sensível)"
    assert "S3gr3d0" not in json.dumps(info, default=str)


def test_ingest_endpoints_and_findings(env):
    settings = replace(env, ucmdb_tql_apis="APIs_Exemplo")
    records, fields = fetch_apis(settings, client(CIS))
    with session_scope() as s:
        summary = ingest_apis(s, settings, records, fields)
    assert summary["novos"] == 3 and summary["endpoints_criados"] == 2   # a API http:// não gera alvo TLS
    with session_scope() as s:
        eps = {(e.host, e.port): e for e in s.scalars(select(Endpoint))}
        assert eps[("pagamentos.exemplo.pt", 443)].source == "api"
        assert "não está em CERTWATCH_SCAN_ALLOWED_PORTS" in eps[("api-porta.exemplo.pt", 9443)].note
        assert ("legado.exemplo.local", 8080) not in eps
    with session_scope() as s:
        evaluate(s, settings)
        types = {(f.type, f.subject) for f in s.scalars(select(Finding))}
    assert ("API_SEM_TLS", "API Legada") in types
    assert ("API_EXPIRACAO", "API Pagamentos") in types

    # A API que sai da lista fica inativa e o endpoint é desativado
    with session_scope() as s:
        ingest_apis(s, settings, records[1:], fields)
    with session_scope() as s:
        assert not s.scalar(select(ApiRecord).where(ApiRecord.ucmdb_id == "api1")).active
        assert not s.scalar(select(Endpoint).where(Endpoint.host == "pagamentos.exemplo.pt")).enabled

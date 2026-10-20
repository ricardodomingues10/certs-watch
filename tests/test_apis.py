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
    assert fields == {"nome": "display_label", "url": "endpoint_url", "validade": "secret_expiration_date",
                      "aplicacao": "aplicacao", "expirado": None, "localizacao": None, "registo": None}
    dump = json.dumps(records, default=str)
    for secret in ("S3gr3d0", "p4ss", "tok-abc", "PRIVATE KEY"):
        assert secret not in dump
    r1 = records[0]
    assert r1["name"] == "API Pagamentos" and r1["host"] == "pagamentos.exemplo.pt" and r1["scheme"] == "https"
    assert r1["expiry"] is not None and r1["application"] == "Pagamentos" and r1["extra"] == {}

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


# Forma real da lista "API secrets": client secrets do Azure AD, sem URL, datas DD-MM-AAAA ou epoch,
# campo "Expirado?" e data de registo na CMDB. Os nomes dos atributos variam; a deteção é por nome e conteúdo.
REAL = [
    {"ucmdbId": "s1", "type": "api_secret", "properties": {
        "display_label": "Agente de inventario de rede - 0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c",
        "application_name": "Seguranca", "secret_expiration_date": "13-02-2023 13:00:00",
        "secret_expired": "true", "secret_location": "AzureAD - App Registration - Client Secret",
        "create_time": 1755861232000, "secret_value": "Xy7~Qk2.abcDEF1234567890ghijKLMN"}},
    {"ucmdbId": "s2", "type": "api_secret", "properties": {
        "display_label": "CRM Testes", "application_name": "CRM", "secret_expiration_date": "24-01-2027 13:00:00",
        "secret_expired": "false", "secret_location": "AzureAD - App Registration - Client Secret",
        "create_time": 1755860813000}},
    {"ucmdbId": "s3", "type": "api_secret", "properties": {
        "display_label": "Segredo sem validade", "application_name": "X", "secret_expired": False,
        "secret_location": "AzureAD - App Registration - Client Secret", "create_time": 1755860813000}},
]


def test_real_api_secret_list(env):
    from certwatch.collectors.ucmdb import parse_apis
    from certwatch.normalize import split_api_name
    records, fields = parse_apis(REAL, env)
    assert fields["validade"] == "secret_expiration_date" and fields["expirado"] == "secret_expired"
    assert fields["localizacao"] == "secret_location" and fields["registo"] == "create_time"
    assert fields["aplicacao"] == "application_name" and fields["url"] is None
    assert "Xy7~Qk2" not in json.dumps(records, default=str)
    r1, r2, r3 = records
    assert r1["expiry"].astimezone().year == 2023 and r1["expiry"].isoformat().startswith("2023-02-13T13:00:00+00:00")
    assert r2["expiry"].isoformat().startswith("2027-01-24T13:00:00+00:00")       # inverno: Lisboa = UTC
    assert r1["cmdb_expired"] is True and r2["cmdb_expired"] is False and r3["expiry"] is None
    assert r1["application"] == "Seguranca" and r1["location"].startswith("AzureAD")
    assert r1["registered_at"].year == 2025 and r1["host"] == "" and r1["url"] == ""
    assert split_api_name(r1["name"]) == ("Agente de inventario de rede",
                                          "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c")

    with session_scope() as s:
        out = ingest_apis(s, env, records, fields)
        assert out["com_validade"] == 2 and out["endpoints_criados"] == 0
    with session_scope() as s:
        evaluate(s, env)
        types = {(f.type, f.severity) for f in s.scalars(select(Finding))}
    assert ("API_REGISTO_EXPIRADO", "baixa") in types                 # 2023: limpeza, não emergência
    assert not any(t == "API_EXPIRACAO" for t, _ in types)


def test_api_page_views_and_export(env):
    from fastapi.testclient import TestClient
    from certwatch.collectors.ucmdb import parse_apis
    from certwatch.web.app import app
    records, fields = parse_apis(REAL, env)
    records[1]["cmdb_expired"] = True                                    # CMDB desatualizada
    with session_scope() as s:
        ingest_apis(s, env, records, fields)
    auth = ("admin", "teste-admin-123")
    with TestClient(app) as c:
        page = c.get("/apis", auth=auth).text
        assert "Agente de inventario de rede" in page and "Seguranca" in page
        assert "AzureAD - App Registration - Client Secret" in page
        div = c.get("/apis", params={"vista": "divergentes"}, auth=auth).text
        assert "CRM Testes" in div and "desatualizado" in div and "Segredo sem validade" not in div
        assert "Segredo sem validade" in c.get("/apis", params={"vista": "sem_data"}, auth=auth).text
        csv_text = c.get("/apis/exportar", auth=auth).content.decode("utf-8")
        assert csv_text.startswith("\ufeffNome;Aplicação;Localização") and "CRM" in csv_text

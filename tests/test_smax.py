"""Pedidos do SMAX: leitura só de leitura e ligação aos certificados."""
import json
from dataclasses import replace
from datetime import timedelta

import httpx

from certwatch.collectors import smax
from certwatch.db import session_scope, utcnow
from certwatch.insights import build_inventory
from certwatch.jobs import ingest_cmdb
from certwatch.tickets import ingest_smax

NOW = utcnow().replace(microsecond=0)
SOON = NOW + timedelta(days=20)
FIELDS = {"endpoint": "EndpointCert_c", "expiry": "DataExp_c", "env": "Ambiente_c", "type": "TipoCert_c"}


def settings(env):
    return replace(env, smax_url="https://smax.test", smax_tenant="123", smax_user="svc", smax_password="p'\"w",
                   smax_filter="BasedOnChangeModel='999'", smax_fields=FIELDS)


def entity(tid, endpoint, expiry, phase, updated_days_ago=1, env="NAME6_C"):
    opts = {"complexTypeProperties": [{"properties": {
        "EndpointCert_c": endpoint, "DataExp_c": int(expiry.timestamp() * 1000) if expiry else None,
        "Ambiente_c": [env], "TipoCert_c": "Externo"}}]}
    return {"entity_type": "Change", "properties": {
        "Id": tid, "DisplayLabel": f"Renovar {endpoint}", "PhaseId": phase, "Priority": "MediumPriority",
        "UserOptions": json.dumps(opts), "LastUpdateTime": int((NOW - timedelta(days=updated_days_ago)).timestamp() * 1000)},
        "related_properties": {"OwnedByGroup": {"Name": "Sistemas"}, "OwnedByPerson": {"Name": "Ana"}}}


ENTITIES = [
    entity("1001", "https://www.exemplo.pt/", SOON, "Execute"),
    entity("0900", "www.exemplo.pt", SOON - timedelta(days=365), "Close", updated_days_ago=300),
    entity("1002", "api.exemplo.pt:8443", SOON - timedelta(days=200), "Execute"),   # aberto, outra data
    entity("0800", "velho.exemplo.pt", SOON, "Close"),
    entity("1003", "", None, "Execute"),                                              # sem endpoint
]


def transport(calls):
    def handler(request: httpx.Request):
        calls.append(request)
        if request.url.path == "/auth/authentication-endpoint/authenticate/login":
            assert request.url.params["TENANTID"] == "123"
            assert json.loads(request.content) == {"Login": "svc", "Password": "p'\"w"}
            return httpx.Response(200, text="eyJhbGciOiJ" + "x" * 40)
        assert request.url.path == "/rest/123/ems/Change"
        assert request.headers["cookie"].startswith("LWSSO_COOKIE_KEY=eyJhbGciOiJ") and "TENANTID=123" in request.headers["cookie"]
        assert request.url.params["filter"] == "BasedOnChangeModel='999'"
        skip, size = int(request.url.params["skip"]), int(request.url.params["size"])
        page = ENTITIES[skip:skip + size]
        return httpx.Response(200, json={"entities": page, "meta": {"completion_status": "OK", "total_count": len(ENTITIES)}})
    return httpx.Client(base_url="https://smax.test", transport=httpx.MockTransport(handler))


def test_fetch_paginates_and_parses(env, monkeypatch):
    monkeypatch.setattr(smax, "PAGE_SIZE", 2)
    calls = []
    tickets = smax.fetch_tickets(settings(env), transport(calls))
    assert len(tickets) == 5 and sum(1 for c in calls if "/ems/" in c.url.path) == 3
    t = {x["id"]: x for x in tickets}
    assert t["1001"]["endpoint"] == "www.exemplo.pt" and t["1002"]["endpoint"] == "api.exemplo.pt"
    assert t["1001"]["environment"] == "PRD" and t["1001"]["owner_group"] == "Sistemas"
    assert t["1001"]["cert_expiry"].date() == SOON.date()
    assert smax.ticket_url(settings(env), "1001") == "https://smax.test/saw/Change/1001/general?TENANTID=123"


def test_login_failure(env):
    c = httpx.Client(base_url="https://smax.test", transport=httpx.MockTransport(lambda r: httpx.Response(401)))
    try:
        smax.fetch_tickets(settings(env), c)
        raise AssertionError("devia falhar")
    except smax.SmaxError as exc:
        assert "HTTP 401" in str(exc)
    # 500 com motivo: o motivo aparece na mensagem, a password nunca
    c = httpx.Client(base_url="https://smax.test", transport=httpx.MockTransport(
        lambda r: httpx.Response(500, json={"message": "Bad credentials for p'\"w"})))
    try:
        smax.fetch_tickets(settings(env), c)
        raise AssertionError("devia falhar")
    except smax.SmaxError as exc:
        assert "Bad credentials" in str(exc) and "p'\"w" not in str(exc) and "utilizador de integração" in str(exc)
    c = httpx.Client(base_url="https://smax.test", transport=httpx.MockTransport(
        lambda r: httpx.Response(500, text="<html><body><h1>HTTP Status 500</h1><p>Internal error</p></body></html>")))
    try:
        smax.fetch_tickets(settings(env), c)
    except smax.SmaxError as exc:
        assert "HTTP Status 500 Internal error" in str(exc)


def test_links_pages_filter_and_export(env, monkeypatch):
    s = settings(env)
    with session_scope() as db:
        ingest_cmdb(db, replace(s, ucmdb_min_cis=1), [
            {"ucmdb_id": str(i), "global_id": str(i), "common_name": cn, "valid_to": d.isoformat(), "issuer": "DigiCert",
             "issuer_name": ""} for i, (cn, d) in enumerate([
                ("www.exemplo.pt", SOON), ("api.exemplo.pt", SOON), ("velho.exemplo.pt", SOON),
                ("novo.exemplo.pt", NOW + timedelta(days=10)), ("longe.exemplo.pt", NOW + timedelta(days=300))])])
        out = ingest_smax(db, s, smax.fetch_tickets(s, transport([])))
    assert out == {"tickets": 5, "mudancas": 0, "com_endpoint": 4, "abertos": 3}

    with session_scope() as db:
        inv = {r["cn"]: r["smax"] for r in build_inventory(db, s, utcnow())}
    assert inv["www.exemplo.pt"]["state"] == "em_curso" and inv["www.exemplo.pt"]["main"]["id"] == "1001"
    assert [x["id"] for x in inv["www.exemplo.pt"]["closed"]] == ["0900"]
    assert inv["api.exemplo.pt"]["state"] == "outra_data"
    assert inv["velho.exemplo.pt"]["state"] == "fechado" and inv["velho.exemplo.pt"]["main"]["id"] == "0800"
    assert inv["novo.exemplo.pt"]["state"] == "sem_pedido"

    from fastapi.testclient import TestClient
    from certwatch import config
    from certwatch.web.app import app
    for k, v in {"CERTWATCH_SMAX_URL": "https://smax.test", "CERTWATCH_SMAX_TENANT": "123",
                 "CERTWATCH_SMAX_USER": "svc", "CERTWATCH_SMAX_PASSWORD": "x"}.items():
        monkeypatch.setenv(k, v)
    config.get_settings.cache_clear()
    auth = ("admin", "teste-admin-123")
    with TestClient(app) as c:
        page = c.get("/certificados", auth=auth).text
        assert 'href="https://smax.test/saw/Change/1001/general?TENANTID=123"' in page and "Pedido SMAX" in page
        assert "outra data" in page and "sem pedido" in page
        sem = c.get("/certificados", params={"pedido": "nao_em_curso", "dias": "30"}, auth=auth).text
        assert "novo.exemplo.pt" in sem and "www.exemplo.pt" not in sem and "longe.exemplo.pt" not in sem
        assert "www.exemplo.pt" in c.get("/certificados", params={"q": "1001"}, auth=auth).text
        det = c.get("/certificados/detalhe", params={"cn": "www.exemplo.pt"}, auth=auth).text
        assert "Pedidos no SMAX" in det and "0900" in det and "Sistemas" in det and "Pedido em curso" in det
        dash = c.get("/", auth=auth).text
        assert "Expiram nos próximos 20 dias" in dash and "novo.exemplo.pt" in dash
        assert "Movimento nos pedidos" in dash and "Pedidos em curso" in dash
        csv_text = c.get("/certificados/exportar", auth=auth).content.decode("utf-8")
        head = csv_text.splitlines()[0]
        assert "Pedido SMAX" in head and "Link do pedido" in head
        assert "https://smax.test/saw/Change/1001/general?TENANTID=123" in csv_text
        assert c.get("/arvore", auth=auth).status_code == 404

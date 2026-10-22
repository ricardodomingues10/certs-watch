"""Verificação das permissões da conta da UCMDB: leitura e teste de escrita sem mudar valores."""
import json
from dataclasses import replace

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import select

from certwatch import ucmdb_access as ua
from certwatch.db import session_scope
from certwatch.models import AuditLog, CmdbRecord

CI = {"ucmdbId": "c1", "type": "digital_certificate",
      "properties": {"display_label": "intranet.exemplo.local", "description": "Changed with n8n - x"}}


def fake(write_status=200, write_body=None, auth=200):
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path, request.content))
        p = request.url.path
        if p.endswith("/authenticate"):
            return httpx.Response(auth, json={"token": "t"} if auth == 200 else {"error": "bad"})
        if p.endswith("/topology"):
            return httpx.Response(200, json={"cis": [CI], "relations": []})
        if request.method == "GET" and "/dataModel/ci/" in p:
            return httpx.Response(200, json=CI)
        if request.method == "PUT":
            return httpx.Response(write_status, json=write_body if write_body is not None else
                                  {"addedCis": [], "removedCis": [], "updatedCis": [], "ignoredCis": ["c1"]})
        return httpx.Response(404)
    return httpx.Client(base_url="https://cmdb.test/rest-api", transport=httpx.MockTransport(handler)), calls


def st(env):
    return replace(env, ucmdb_url="https://cmdb.test", ucmdb_user="svc", ucmdb_password="pw",
                   ucmdb_tql="Certificados_Exemplo", ucmdb_tql_apis="")


def test_read_only_does_not_write(env):
    c, calls = fake()
    rep = ua.check(st(env), None, c)
    assert [s.ok for s in rep.steps] == [True, True, True]
    assert not any(m in ("PUT", "POST") and "dataModel" in p for m, p, _ in calls)
    assert rep.verdict("PUT") is None


def test_write_same_value(env):
    c, calls = fake()
    rep = ua.check(st(env), "c1", c)
    assert rep.verdict("PUT") is True
    put = [x for x in calls if x[0] == "PUT"][0]
    body = json.loads(put[2])
    assert put[1].endswith("/dataModel/ci/c1") and body == {"ucmdbId": "c1", "type": "digital_certificate",
                                                              "properties": {"description": "Changed with n8n - x"}}


def test_write_denied_and_unknown(env):
    c, _ = fake(write_status=403, write_body={"error": "Forbidden"})
    assert ua.check(st(env), "c1", c).verdict("PUT") is False
    c, _ = fake(write_status=400, write_body={"error": "User has no permission to update data"})
    assert ua.check(st(env), "c1", c).verdict("PUT") is False
    c, _ = fake(write_status=500, write_body={"error": "boom"})
    assert ua.check(st(env), "c1", c).verdict("PUT") is None
    c, _ = fake(auth=401)
    rep = ua.check(st(env), "c1", c)
    assert rep.steps[0].ok is False and len(rep.steps) == 1


def test_web_page(env, monkeypatch):
    from certwatch.web import app as webapp
    settings = st(env)
    monkeypatch.setattr(webapp, "get_settings", lambda: settings)
    c, calls = fake()
    monkeypatch.setattr(webapp, "UCMDB_CLIENT", c)
    with session_scope() as s:
        s.add(CmdbRecord(ucmdb_id="c1", global_id="g1", common_name="intranet.exemplo.local",
                         cn_norm="intranet.exemplo.local", kind="host"))
    auth = ("admin", "teste-admin-123")
    with TestClient(webapp.app) as tc:
        assert "Verificar leitura" in tc.get("/cmdb-final/permissoes", auth=auth).text
        token = tc.cookies["cw_csrf"]
        r = tc.post("/cmdb-final/permissoes", data={"csrf": token}, auth=auth)
        assert "pode" in r.text and not any(m == "PUT" for m, _, _ in calls)
        r = tc.post("/cmdb-final/permissoes", data={"csrf": token, "escrita": "1", "ci": "intranet.exemplo.local"}, auth=auth)
        assert "Confirme o teste de escrita" in r.text and not any(m == "PUT" for m, _, _ in calls)
        r = tc.post("/cmdb-final/permissoes", data={"csrf": token, "escrita": "1", "ci": "intranet.exemplo.local",
                                                    "confirmo": "1"}, auth=auth)
        assert "pode atualizar CIs" in r.text and any(m == "PUT" for m, _, _ in calls)
        assert "pw" not in r.text
    with session_scope() as s:
        logs = list(s.scalars(select(AuditLog).where(AuditLog.action == "ucmdb.permissoes")))
        assert len(logs) == 3 and "pw" not in json.dumps([l.details for l in logs])

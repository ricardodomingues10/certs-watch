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


def fake_full(create_status=200, added=("new1",), delete_status=200, in_list=False):
    calls = []
    store = {}
    certs = [dict(CI, properties={**CI["properties"], "certificate_status": "Ativo", "common_name": "intranet.exemplo.local",
                                  "issuer_name": "Corp CA01", "serial_number": "AA01"})]

    def handler(request):
        calls.append((request.method, request.url.path, request.content))
        p = request.url.path
        if p.endswith("/authenticate"):
            return httpx.Response(200, json={"token": "t"})
        if p.endswith("/topologyQuery"):
            return httpx.Response(200, json={"cis": [{"ucmdbId": f"a{i}", "properties": {"certificate_status": v}}
                                                     for i, v in enumerate(["Ativo"] * 5 + ["Inativo"] * 2 + [None])]})
        if p.endswith("/topology"):
            extra = [{"ucmdbId": "new1"}] if in_list and "new1" in store else []
            return httpx.Response(200, json={"cis": certs + extra, "relations": []})
        if request.method == "POST" and p.endswith("/dataModel"):
            body = json.loads(request.content)
            if create_status != 200:
                return httpx.Response(create_status, json={"error": "User has no permission to modify data"})
            if added:
                store[added[0]] = body["cis"][0]
            return httpx.Response(200, json={"addedCis": list(added), "updatedCis": [] if added else ["c1"],
                                             "ignoredCis": [], "removedCis": []})
        if request.method == "GET" and "/dataModel/ci/" in p:
            cid = p.rsplit("/", 1)[1]
            if cid in store:
                return httpx.Response(200, json={"ucmdbId": cid, **store[cid]})
            return httpx.Response(200, json=certs[0])
        if request.method == "DELETE":
            return httpx.Response(delete_status, json={} if delete_status == 200 else {"error": "Forbidden"})
        return httpx.Response(404)
    return httpx.Client(base_url="https://cmdb.test/rest-api", transport=httpx.MockTransport(handler)), calls


def test_status_candidates(env):
    c, calls = fake_full()
    info = ua.status_candidates(st(env), c)
    cand = {x["attr"]: x for x in info.candidates}
    assert info.ci_type == "digital_certificate" and cand["certificate_status"]["na_lista"] == "Ativo"
    assert dict(cand["certificate_status"]["valores"]) == {"Ativo": 5, "Inativo": 2, "": 1}
    assert not any(m in ("PUT", "DELETE") or (m == "POST" and p.endswith("/dataModel")) for m, p, _ in calls)


def test_create_and_delete(env):
    c, calls = fake_full()
    res = ua.create_test(st(env), "digital_certificate", "certificate_status", "Inativo", "ana", True, c)
    assert [s.ok for s in res.steps] == [True, True, True, True] and res.created_id == "new1" and not res.left_behind
    body = json.loads([x for x in calls if x[0] == "POST" and x[1].endswith("/dataModel")][0][2])
    props = body["cis"][0]["properties"]
    assert props["certificate_status"] == "Inativo" and props["common_name"].startswith("certwatch-teste-")
    assert props["serial_number"].startswith("CERTWATCH-TESTE-") and props["issuer_name"] == "certwatch teste"
    assert "Pode ser apagado" in props["description"]
    assert [x for x in calls if x[0] == "DELETE"][0][1].endswith("/dataModel/ci/new1")


def test_create_guards(env):
    # valor dos ativos -> não cria
    c, calls = fake_full()
    res = ua.create_test(st(env), "digital_certificate", "certificate_status", "Ativo", "ana", True, c)
    assert res.steps[0].ok is None and not any(m == "POST" and p.endswith("/dataModel") for m, p, _ in calls)
    # sem permissão
    c, _ = fake_full(create_status=403)
    assert ua.create_test(st(env), "digital_certificate", "certificate_status", "Inativo", "ana", True, c).steps[0].ok is False
    # a UCMDB juntou-o a um CI existente (updatedCis) -> nada é apagado
    c, calls = fake_full(added=())
    res = ua.create_test(st(env), "digital_certificate", "certificate_status", "Inativo", "ana", True, c)
    assert res.steps[0].ok is None and not any(m == "DELETE" for m, _, _ in calls)
    # aparece na lista e não se pode apagar -> fica, avisado
    c, _ = fake_full(delete_status=403, in_list=True)
    res = ua.create_test(st(env), "digital_certificate", "certificate_status", "Inativo", "ana", True, c)
    assert res.steps[2].ok is False and res.steps[3].ok is False and res.left_behind


def test_create_web(env, monkeypatch):
    from certwatch.web import app as webapp
    settings = st(env)
    monkeypatch.setattr(webapp, "get_settings", lambda: settings)
    c, calls = fake_full()
    monkeypatch.setattr(webapp, "UCMDB_CLIENT", c)
    auth = ("admin", "teste-admin-123")
    with TestClient(webapp.app) as tc:
        tc.get("/cmdb-final/permissoes", auth=auth)
        token = tc.cookies["cw_csrf"]
        r = tc.post("/cmdb-final/permissoes/criacao/preparar", data={"csrf": token}, auth=auth)
        assert 'value="certificate_status::Inativo"' in r.text and "— ativo" in r.text
        r = tc.post("/cmdb-final/permissoes/criacao", data={"csrf": token, "ci_type": "digital_certificate",
                                                            "escolha": "certificate_status::Inativo", "apagar": "1"}, auth=auth)
        assert "Confirme a criação" in r.text and not any(m == "POST" and p.endswith("/dataModel") for m, p, _ in calls)
        r = tc.post("/cmdb-final/permissoes/criacao", data={"csrf": token, "ci_type": "digital_certificate",
                                                            "escolha": "certificate_status::Inativo", "apagar": "1",
                                                            "confirmo": "1"}, auth=auth)
        assert "pode criar e apagar certificados" in r.text
    with session_scope() as s:
        log = s.scalar(select(AuditLog).where(AuditLog.action == "ucmdb.teste_criacao"))
        assert log.target == "new1" and log.details["ficou"] is False


def test_keep_then_delete(env, monkeypatch):
    from certwatch.web import app as webapp
    settings = st(env)
    monkeypatch.setattr(webapp, "get_settings", lambda: settings)
    c, calls = fake_full(added=("abcdef0123",))
    monkeypatch.setattr(webapp, "UCMDB_CLIENT", c)
    auth = ("admin", "teste-admin-123")
    with TestClient(webapp.app) as tc:
        tc.get("/cmdb-final/permissoes", auth=auth)
        token = tc.cookies["cw_csrf"]
        r = tc.post("/cmdb-final/permissoes/criacao", data={"csrf": token, "ci_type": "digital_certificate",
                                                            "escolha": "certificate_status::Inativo", "confirmo": "1"}, auth=auth)
        assert "ficou na UCMDB" in r.text and "certwatch-teste-" in r.text and not any(m == "DELETE" for m, _, _ in calls)
        r = tc.post("/cmdb-final/permissoes/criacao/apagar", data={"csrf": token, "ci_id": "abcdef0123"}, auth=auth)
        assert "apagado" in r.text and any(m == "DELETE" and p.endswith("/abcdef0123") for m, p, _ in calls)
    # um CI que não é de teste nunca é apagado
    c, calls = fake_full()
    step = ua.delete_test(settings, "4c24f01ad13cdebcbe9fbb238c840452", c)
    assert step.ok is False and not any(m == "DELETE" for m, _, _ in calls)

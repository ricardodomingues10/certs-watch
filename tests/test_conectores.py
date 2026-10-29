"""Conectores de CMDB e de tickets: cada tipo devolve o formato de sempre; a instalação UCMDB+SMAX não muda."""
import json
from dataclasses import replace
from datetime import timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from openpyxl import Workbook
from sqlalchemy import create_engine, select, text

from certwatch import config, conectores as cx
from certwatch import ticket_create as tc
from certwatch.conectores import cmdb, tickets
from certwatch.db import session_scope, utcnow
from certwatch.jobs import ingest_cmdb
from certwatch.models import AuditLog, CmdbRecord, ConnectorConfig, SmaxTicket, TicketDraft

AUTH = ("admin", "teste-admin-123")
NOW = utcnow().replace(microsecond=0)


@pytest.fixture
def mock_http(monkeypatch):
    """Todos os httpx.Client dos conectores passam por um handler programável."""
    routes = {"handler": None, "seen": []}
    real = httpx.Client

    def factory(*a, **k):
        k.pop("verify", None)

        def handle(req):
            routes["seen"].append(req)
            return routes["handler"](req)
        return real(*a, transport=httpx.MockTransport(handle), **k)
    monkeypatch.setattr(httpx, "Client", factory)
    return routes


@pytest.fixture(autouse=True)
def _fresh():
    cx.invalidate()
    yield
    cx.invalidate()


def _save(role, kind, params, secrets=None):
    s = config.get_settings()
    with session_scope() as db:
        db.merge(ConnectorConfig(role=role, kind=kind, params=params, secrets_enc=cx.encrypt(s, secrets or {}),
                                 enabled=True, updated_at=utcnow(), updated_by="teste"))
    cx.invalidate()


# ---------------------------------------------------------------- por omissão: tudo como antes
def test_defaults_ucmdb_e_sem_tickets(env):
    assert cx.cmdb_connector(env).kind == "ucmdb"
    t = cx.ticket_connector(env)
    assert t.kind == "nenhum" and not cx.tickets_on(env)
    assert cx.tickets_label(env) == "SMAX"   # o nome de sempre nas páginas


def test_smax_do_env_continua(env, monkeypatch):
    monkeypatch.setenv("CERTWATCH_SMAX_URL", "https://smax.test")
    monkeypatch.setenv("CERTWATCH_SMAX_TENANT", "1")
    monkeypatch.setenv("CERTWATCH_SMAX_USER", "u")
    monkeypatch.setenv("CERTWATCH_SMAX_PASSWORD", "p")
    config.get_settings.cache_clear()
    s = config.get_settings()
    assert cx.ticket_connector(s).kind == "smax" and cx.tickets_label(s) == "SMAX"


def test_cifra_das_credenciais(env):
    token = cx.encrypt(env, {"token": "segredo-muito-secreto"})
    assert "segredo" not in token and cx.decrypt(env, token) == {"token": "segredo-muito-secreto"}
    assert cx.decrypt(env, "lixo") == {}


def test_datas_em_varios_formatos():
    for v in ("2027-03-01", "01/03/2027", "2027-03-01T10:00:00Z", 1803888000, "1803888000000"):
        assert cx.to_datetime(v).year == 2027
    assert cx.host_in_text("Renovar certificado www.Exemplo.pt hoje") == "www.exemplo.pt"


# ---------------------------------------------------------------- CMDB: SQL
def test_sql_cmdb_sqlite(env, tmp_path):
    db = tmp_path / "cmdb.db"
    e = create_engine(f"sqlite:///{db}")
    with e.begin() as c:
        c.execute(text("CREATE TABLE certs (cid TEXT, nome TEXT, expira TEXT, ca TEXT)"))
        c.execute(text("INSERT INTO certs VALUES ('a1','www.exemplo.pt','31/12/2027','DigiCert'),"
                       "('a2','api.exemplo.pt','2027-06-01','Sectigo'),('a3','intra.exemplo.local','2027-01-10','CA01')"))
    conn = cmdb.SqlCmdb(env, {"url": f"sqlite:///{db}", "consulta": "SELECT * FROM certs", "campo_id": "cid",
                              "campo_cn": "nome", "campo_validade": "expira", "campo_emissor": "ca"})
    res = conn.test()
    assert res.ok and res.total == 3
    assert res.sample[0] == {"ucmdb_id": "a1", "global_id": None, "common_name": "www.exemplo.pt",
                             "valid_to": "2027-12-31T00:00:00+00:00", "issuer": "DigiCert", "issuer_name": ""}
    # só leitura: nada de comandos
    bad = cmdb.SqlCmdb(env, {"url": f"sqlite:///{db}", "consulta": "DELETE FROM certs"})
    assert not bad.test().ok and "SELECT" in bad.test().message
    two = cmdb.SqlCmdb(env, {"url": f"sqlite:///{db}", "consulta": "SELECT 1; DROP TABLE certs"})
    assert not two.test().ok


def test_ingest_usa_o_conector_gravado(env, tmp_path):
    db = tmp_path / "cmdb.db"
    with create_engine(f"sqlite:///{db}").begin() as c:
        c.execute(text("CREATE TABLE v (id TEXT, cn TEXT, valid_to TEXT, issuer TEXT)"))
        for i in range(4):
            c.execute(text(f"INSERT INTO v VALUES ('{i}','s{i}.exemplo.pt','2027-0{i + 1}-01','DigiCert')"))
    _save("cmdb", "sql", {"url": f"sqlite:///{db}", "consulta": "SELECT * FROM v", "min_registos": "2"})
    with session_scope() as s:
        ingest_cmdb(s, config.get_settings())
    with session_scope() as s:
        cns = sorted(c.common_name for c in s.scalars(select(CmdbRecord)))
    assert cns == ["s0.exemplo.pt", "s1.exemplo.pt", "s2.exemplo.pt", "s3.exemplo.pt"]


# ---------------------------------------------------------------- CMDB: REST com paginação
def test_rest_cmdb_offset(env, mock_http):
    data = [{"key": f"k{i}", "attrs": {"name": f"h{i}.exemplo.pt"}, "exp": "2027-05-01", "iss": "LE"} for i in range(5)]

    def handler(req):
        assert req.headers["X-API-Key"] == "chave"
        off, lim = int(req.url.params["offset"]), int(req.url.params["limit"])
        return httpx.Response(200, json={"data": {"items": data[off:off + lim]}})
    mock_http["handler"] = handler
    conn = cmdb.RestCmdb(env, {"url": "https://cmdb.test/api/certs", "autenticacao": "cabecalho", "lista": "data.items",
                               "paginacao": "offset", "tamanho": "2", "campo_id": "key", "campo_cn": "attrs.name",
                               "campo_validade": "exp", "campo_emissor": "iss"}, {"token": "chave"})
    recs = conn.fetch_certificates()
    assert [r["common_name"] for r in recs] == [f"h{i}.exemplo.pt" for i in range(5)]
    assert len(mock_http["seen"]) == 3


def test_rest_cmdb_erros_claros(env, mock_http):
    mock_http["handler"] = lambda req: httpx.Response(401)
    res = cmdb.RestCmdb(env, {"url": "https://cmdb.test/x"}, {"token": "t"}).test()
    assert not res.ok and "recusado" in res.message
    mock_http["handler"] = lambda req: httpx.Response(200, json={"outra": 1})
    res = cmdb.RestCmdb(env, {"url": "https://cmdb.test/x", "lista": "items"}, {"token": "t"}).test()
    assert not res.ok and "lista" in res.message


def test_servicenow_cmdb(env, mock_http):
    def handler(req):
        assert req.url.path == "/api/now/table/cmdb_ci_certificate" and req.headers["authorization"].startswith("Basic ")
        return httpx.Response(200, json={"result": [{"sys_id": "s1", "subject_common_name": "sn.exemplo.pt",
                                                      "valid_to": "2027-02-03 10:00:00", "issuer_common_name": "DigiCert"}]})
    mock_http["handler"] = handler
    res = cmdb.ServiceNowCmdb(env, {"instancia": "https://x.service-now.com", "utilizador": "svc"}, {"token": "p"}).test()
    assert res.ok and res.sample[0]["common_name"] == "sn.exemplo.pt" and res.sample[0]["valid_to"].startswith("2027-02-03")


# ---------------------------------------------------------------- CMDB: ficheiros
def test_ficheiro_csv_e_xlsx(env, tmp_path, monkeypatch):
    imp = tmp_path / "import"
    imp.mkdir()
    monkeypatch.setenv("CERTWATCH_IMPORT_DIR", str(imp))
    config.get_settings.cache_clear()
    s = config.get_settings()
    (imp / "cmdb-certificados-1.csv").write_text("id;cn;valid_to;issuer\n1;a.exemplo.pt;01/02/2027;CA\n", encoding="utf-8")
    conn = cmdb.FileCmdb(s, {"ficheiro": "cmdb-certificados"})
    assert conn.test().ok and conn.fetch_certificates()[0]["common_name"] == "a.exemplo.pt"
    wb = Workbook()
    ws = wb.active
    ws.append(["Identificador", "Nome", "Expira", "Emissor"])
    ws.append(["x9", "b.exemplo.pt", (NOW + timedelta(days=30)).replace(tzinfo=None), "DigiCert"])
    wb.save(imp / "outra-cmdb.xlsx")
    conn = cmdb.FileCmdb(s, {"ficheiro": "outra", "campo_id": "Identificador", "campo_cn": "Nome",
                             "campo_validade": "Expira", "campo_emissor": "Emissor"})
    rec = conn.fetch_certificates()[0]
    assert rec["ucmdb_id"] == "x9" and rec["common_name"] == "b.exemplo.pt" and rec["valid_to"]
    assert not cmdb.FileCmdb(s, {"ficheiro": "nao-existe"}).test().ok


# ---------------------------------------------------------------- tickets
def _jira_issue(key, summary, status="In Progress", done=False):
    return {"key": key, "fields": {"summary": summary, "status": {"name": status, "statusCategory": {"key": "done" if done else "indeterminate"}},
                                   "priority": {"name": "High"}, "assignee": {"displayName": "Ana"},
                                   "updated": "2026-10-01T10:00:00.000+0000", "created": "2026-09-01T10:00:00.000+0000",
                                   "duedate": "2026-12-01", "components": [{"name": "Web"}]}}


def test_jira_cloud_paginado(env, mock_http):
    pages = {None: {"issues": [_jira_issue("CERT-1", "Renovar www.exemplo.pt")], "nextPageToken": "p2", "isLast": False},
             "p2": {"issues": [_jira_issue("CERT-2", "Certificado api.exemplo.pt", "Done", done=True)], "isLast": True}}

    def handler(req):
        assert req.url.path == "/rest/api/3/search/jql" and "project = CERT" in req.url.params["jql"]
        return httpx.Response(200, json=pages[req.url.params.get("nextPageToken")])
    mock_http["handler"] = handler
    j = tickets.JiraTickets(env, {"url": "https://x.atlassian.net", "utilizador": "a@b.pt", "projeto": "CERT"}, {"token": "t"})
    ts = j.fetch_tickets()
    assert [(t["id"], t["endpoint"], t["phase"]) for t in ts] == [("CERT-1", "www.exemplo.pt", "In Progress"),
                                                               ("CERT-2", "api.exemplo.pt", "Done")]
    assert ts[0]["owner_group"] == "Web" and ts[0]["owner_person"] == "Ana" and ts[0]["last_update"].year == 2026
    assert j.ticket_url("CERT-1") == "https://x.atlassian.net/browse/CERT-1"


def test_jira_server(env, mock_http):
    def handler(req):
        assert req.url.path == "/rest/api/2/search" and req.headers["authorization"] == "Bearer pat"
        return httpx.Response(200, json={"issues": [_jira_issue("INF-9", "Renovar intra.exemplo.local")], "total": 1})
    mock_http["handler"] = handler
    j = tickets.JiraTickets(env, {"url": "https://jira.test", "tipo": "server", "projeto": "INF"}, {"token": "pat"})
    assert j.test().ok


def test_servicenow_tickets(env, mock_http):
    def handler(req):
        return httpx.Response(200, json={"result": [
            {"number": {"display_value": "CHG001", "value": "CHG001"},
             "short_description": {"display_value": "Renovar certificado portal.exemplo.pt"},
             "state": {"display_value": "Closed"}, "assignment_group": {"display_value": "Rede"},
             "sys_updated_on": {"value": "2026-10-02 08:00:00"}}]})
    mock_http["handler"] = handler
    sn = tickets.ServiceNowTickets(env, {"instancia": "https://x.service-now.com", "utilizador": "u"}, {"token": "p"})
    t = sn.fetch_tickets()[0]
    assert t["id"] == "CHG001" and t["endpoint"] == "portal.exemplo.pt" and t["phase"] == "Closed" and t["owner_group"] == "Rede"


def test_glpi_sessao_e_filtro(env, mock_http):
    calls = []

    def handler(req):
        calls.append(req.url.path)
        if req.url.path.endswith("/initSession"):
            assert req.headers["authorization"] == "user_token ut" and req.headers["app-token"] == "at"
            return httpx.Response(200, json={"session_token": "S"})
        if req.url.path.endswith("/killSession"):
            return httpx.Response(200, json=True)
        assert req.headers["session-token"] == "S"
        return httpx.Response(200, json=[{"id": 7, "name": "Certificado mail.exemplo.pt", "status": 2},
                                         {"id": 8, "name": "Impressora avariada", "status": 1}])
    mock_http["handler"] = handler
    g = tickets.GlpiTickets(env, {"url": "https://glpi.test/apirest.php"}, {"token": "ut", "app_token": "at"})
    ts = g.fetch_tickets()
    assert [t["id"] for t in ts] == ["7"] and ts[0]["endpoint"] == "mail.exemplo.pt"
    assert calls[-1].endswith("/killSession")
    assert g.ticket_url("7") == "https://glpi.test/front/ticket.form.php?id=7"


def test_ingest_de_pedidos_pelo_jira(env, mock_http):
    mock_http["handler"] = lambda req: httpx.Response(200, json={"issues": [_jira_issue("CERT-5", "Renovar www.exemplo.pt")],
                                                                  "isLast": True})
    _save("tickets", "jira", {"url": "https://x.atlassian.net", "utilizador": "a@b.pt", "projeto": "CERT"}, {"token": "t"})
    s = config.get_settings()
    assert cx.tickets_on(s) and cx.tickets_label(s) == "Jira"
    from certwatch.tickets import ingest_smax
    with session_scope() as db:
        out = ingest_smax(db, s)
    assert out["tickets"] == 1
    with session_scope() as db:
        assert db.get(SmaxTicket, "CERT-5").endpoint == "www.exemplo.pt"


def test_criar_pedidos_no_jira(env, mock_http, monkeypatch):
    created = []

    def handler(req):
        if req.method == "POST":
            body = json.loads(req.content)
            created.append(body)
            return httpx.Response(201, json={"key": f"CERT-{100 + len(created)}"})
        issues = []
        for i, b in enumerate(created):
            it = _jira_issue(f"CERT-{100 + i + 1}", b["fields"]["summary"])
            it["fields"]["duedate"] = b["fields"]["duedate"]   # o Atalaia põe a data de expiração no duedate
            issues.append(it)
        return httpx.Response(200, json={"issues": issues, "isLast": True})
    mock_http["handler"] = handler
    s = config.get_settings()
    with session_scope() as db:
        ingest_cmdb(db, replace(s, ucmdb_min_cis=1), [
            {"ucmdb_id": "1", "global_id": "1", "common_name": "www.exemplo.pt", "valid_to": (NOW + timedelta(days=20)).isoformat(),
             "issuer": "DigiCert", "issuer_name": ""}])
    # sem "criar pedidos" ligado, não deixa
    _save("tickets", "jira", {"url": "https://x.atlassian.net", "utilizador": "a@b.pt", "projeto": "CERT"}, {"token": "t"})
    assert any("criar" in p.lower() for p in tc.config_problems(s))
    _save("tickets", "jira", {"url": "https://x.atlassian.net", "utilizador": "a@b.pt", "projeto": "CERT",
                              "criar_pedidos": "sim"}, {"token": "t"})
    assert tc.config_problems(s) == []
    with session_scope() as db:
        b = tc.create_batch(db, ["www.exemplo.pt"], "admin", s)
        db.flush()
        bid = b.id
        for d in tc.drafts_of(db, bid):
            d.include = True
    preview = None
    with session_scope() as db:
        d = tc.drafts_of(db, bid)[0]
        assert tc.validate(d, s) == {}
        preview = tc.build_payload(d, s)
    assert preview["sistema"] == "Jira" and "www.exemplo.pt" in preview["titulo"]
    tc.start(bid, "admin", s)
    out = tc.execute(bid, "admin", s, pause=0)
    assert out["criados"] == 1 and len(created) == 1
    f = created[0]["fields"]
    assert f["project"] == {"key": "CERT"} and f["description"]["type"] == "doc" and f["labels"] == ["certificado"]
    with session_scope() as db:
        d = db.scalar(select(TicketDraft).where(TicketDraft.batch_id == bid))
        assert d.status == "criado" and d.ticket_id == "CERT-101"
        assert db.scalar(select(AuditLog).where(AuditLog.action == "pedidos.criar")).details["sistema"] == "jira"
    # o mesmo certificado não volta a ser pedido: o lote seguinte vê o pedido em curso
    with session_scope() as db:
        b2 = tc.create_batch(db, ["www.exemplo.pt"], "admin", s)
        db.flush()
        assert not tc.drafts_of(db, b2.id)[0].include


# ---------------------------------------------------------------- página Ligações
def test_pagina_ligacoes(env, tmp_path):
    db = tmp_path / "c.db"
    with create_engine(f"sqlite:///{db}").begin() as c:
        c.execute(text("CREATE TABLE v (id TEXT, cn TEXT, valid_to TEXT, issuer TEXT)"))
        c.execute(text("INSERT INTO v VALUES ('1','z.exemplo.pt','2027-01-01','CA')"))
    from certwatch.web.app import app
    with TestClient(app) as c:
        page = c.get("/ligacoes", auth=AUTH)
        assert page.status_code == 200 and "UCMDB" in page.text and "Sistema de tickets" in page.text
        assert "Ligações" in c.get("/", auth=AUTH).text
        page = c.get("/ligacoes?cmdb=sql", auth=AUTH).text
        assert 'name="f_consulta"' in page
        token = c.cookies["cw_csrf"]
        form = {"csrf": token, "tipo": "sql", "acao": "testar", "f_url": f"sqlite:///{db}", "f_consulta": "SELECT * FROM v",
                "f_password": "pw-secreta", "f_campo_id": "id", "f_campo_cn": "cn", "f_campo_validade": "valid_to",
                "f_campo_emissor": "issuer", "f_min_registos": "1"}
        assert c.post("/ligacoes/cmdb", data={**form, "csrf": "x"}, auth=AUTH).status_code == 403
        r = c.post("/ligacoes/cmdb", data=form, auth=AUTH)
        assert "ligação ok" in r.text and "z.exemplo.pt" in r.text
        with session_scope() as s:
            assert s.get(ConnectorConfig, "cmdb") is None   # testar não grava
        r = c.post("/ligacoes/cmdb", data={**form, "acao": "guardar"}, auth=AUTH)
        assert "Ligação gravada" in r.text and "pw-secreta" not in r.text
        with session_scope() as s:
            row = s.get(ConnectorConfig, "cmdb")
            assert row.kind == "sql" and "pw-secreta" not in row.secrets_enc and "password" not in row.params
            assert cx.decrypt(config.get_settings(), row.secrets_enc) == {"password": "pw-secreta"}
        assert cx.cmdb_connector(config.get_settings()).kind == "sql"
        # gravar outra vez sem palavra-passe mantém a guardada
        c.post("/ligacoes/cmdb", data={**form, "acao": "guardar", "f_password": ""}, auth=AUTH)
        with session_scope() as s:
            assert cx.decrypt(config.get_settings(), s.get(ConnectorConfig, "cmdb").secrets_enc) == {"password": "pw-secreta"}
        r = c.post("/ligacoes/cmdb", data={"csrf": token, "acao": "repor"}, auth=AUTH)
        assert "voltou a usar" in r.text and cx.cmdb_connector(config.get_settings()).kind == "ucmdb"
        # Jira incompleto: não grava
        r = c.post("/ligacoes/tickets", data={"csrf": token, "tipo": "jira", "acao": "guardar", "f_url": "https://j.test"},
                   auth=AUTH)
        assert "Não gravado" in r.text
        with session_scope() as s:
            acts = [a.action for a in s.scalars(select(AuditLog))]
        assert "ligacao.guardar" in acts and "ligacao.repor" in acts

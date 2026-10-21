"""Criação de pedidos no SMAX: payload, lotes, confirmação, duplicados, falhas e repetição."""
import json
from dataclasses import replace
from datetime import timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from certwatch import config
from certwatch import ticket_create as tc
from certwatch.db import session_scope, utcnow
from certwatch.jobs import ingest_cmdb
from certwatch.models import AuditLog, SmaxTicket, TicketBatch, TicketDraft

NOW = utcnow().replace(microsecond=0)
FIELDS = {"endpoint": "EndpointCert_c", "expiry": "DataExp_c", "env": "Ambiente_c", "type": "TipoCert_c"}
ENV = {
    "CERTWATCH_SMAX_URL": "https://smax.test", "CERTWATCH_SMAX_TENANT": "123", "CERTWATCH_SMAX_USER": "svc",
    "CERTWATCH_SMAX_PASSWORD": "pw", "CERTWATCH_SMAX_FILTER": "(BasedOnChangeModel = '999')",
    "CERTWATCH_SMAX_FIELD_ENDPOINT": "EndpointCert_c", "CERTWATCH_SMAX_FIELD_EXPIRY": "DataExp_c",
    "CERTWATCH_SMAX_FIELD_ENV": "Ambiente_c", "CERTWATCH_SMAX_FIELD_TYPE": "TipoCert_c",
    "CERTWATCH_SMAX_CREATE_ENABLED": "true", "CERTWATCH_SMAX_CHANGE_MODEL": "999", "CERTWATCH_SMAX_SERVICE": "555",
    "CERTWATCH_SMAX_DATA_DOMAINS": "DOM_c", "CERTWATCH_SMAX_DEFAULT_RESPONSIBLE": "Equipa Web",
}
AUTH = ("admin", "teste-admin-123")


class FakeSmax:
    """SMAX simulado: lista changes (GET) e cria changes (POST /ems/bulk) com respostas programáveis."""

    def __init__(self):
        self.entities = []
        self.created = []
        self.next_id = 5000
        self.plan = []          # respostas por ordem: "ok" | "fail" | "500" | "timeout"
        self.fail_get = False

    def add(self, tid, endpoint, expiry, phase="Execute", env="Name6_c", tipo="Externo_c", app="77"):
        opts = {"complexTypeProperties": [{"properties": {"EndpointCert_c": endpoint, "DataExp_c": int(expiry.timestamp() * 1000),
                                                          "Ambiente_c": [env], "TipoCert_c": tipo}}]}
        self.entities.append({"entity_type": "Change", "properties": {
            "Id": tid, "DisplayLabel": f"Renovar {endpoint}", "PhaseId": phase, "UserOptions": json.dumps(opts),
            "LastUpdateTime": int(NOW.timestamp() * 1000), "AffectsServiceComponent": app}, "related_properties": {}})

    def handler(self, request: httpx.Request):
        if request.url.path.endswith("/authenticate/login"):
            return httpx.Response(200, text="tok" + "x" * 40)
        assert "LWSSO_COOKIE_KEY=tok" in request.headers["cookie"]
        if request.method == "GET":
            if self.fail_get:
                return httpx.Response(503)
            return httpx.Response(200, json={"entities": self.entities, "meta": {"total_count": len(self.entities)}})
        assert request.url.path == "/rest/123/ems/bulk"
        body = json.loads(request.content)
        self.created.append(body)
        what = self.plan.pop(0) if self.plan else "ok"
        if what == "timeout":
            raise httpx.ReadTimeout("tempo esgotado", request=request)
        if what == "500":
            return httpx.Response(500, text="<html>Internal Server Error</html>")
        if what == "fail":
            return httpx.Response(200, json={"entity_result_list": [{"completion_status": "FAILED",
                                             "errorDetails": {"message": "AffectsServiceComponent inválido"}}]})
        self.next_id += 1
        props = body["entities"][0]["properties"]
        opts = json.loads(props["UserOptions"])["complexTypeProperties"][0]["properties"]
        self.entities.append({"entity_type": "Change", "properties": {
            "Id": str(self.next_id), "DisplayLabel": props["DisplayLabel"], "PhaseId": "Log",
            "UserOptions": props["UserOptions"], "LastUpdateTime": int(NOW.timestamp() * 1000)}, "related_properties": {}})
        assert opts["EndpointCert_c"]
        return httpx.Response(200, json={"entity_result_list": [{"completion_status": "OK",
                                         "entity": {"entity_type": "Change", "properties": {"Id": str(self.next_id)}}}]})

    def client(self, _settings=None):
        return httpx.Client(base_url="https://smax.test", transport=httpx.MockTransport(self.handler))


@pytest.fixture
def smax_env(env, monkeypatch):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    config.get_settings.cache_clear()
    fake = FakeSmax()
    from certwatch.collectors import smax
    monkeypatch.setattr(smax, "client", fake.client)
    # Execução síncrona nos testes (em produção corre numa thread)
    monkeypatch.setattr(tc, "execute_in_background", lambda bid, actor, st: tc.execute(bid, actor, st, pause=0))
    s = config.get_settings()
    with session_scope() as db:
        ingest_cmdb(db, replace(s, ucmdb_min_cis=1), [
            {"ucmdb_id": str(i), "global_id": str(i), "common_name": cn, "valid_to": (NOW + timedelta(days=d)).isoformat(),
             "issuer": iss, "issuer_name": ""} for i, (cn, d, iss) in enumerate([
                ("www.exemplo.pt", 20, "DigiCert"), ("api.exemplo.pt", 25, "DigiCert"),
                ("intra.exemplo.local", 15, "Exemplo Issuing CA01"), ("le.exemplo.pt", 10, "Let's Encrypt"),
                ("dup.exemplo.pt", 12, "DigiCert"), ("longe.exemplo.pt", 300, "DigiCert")])])
    fake.add("4001", "www.exemplo.pt", NOW - timedelta(days=345), phase="Close", env="Name5_c", app="321")
    fake.add("4002", "dup.exemplo.pt", NOW + timedelta(days=12), phase="Execute")
    from certwatch.tickets import ingest_smax
    with session_scope() as db:
        ingest_smax(db, s, smax.fetch_tickets(s, fake.client()))
    return fake


def test_payload_matches_workflow(smax_env):
    s = config.get_settings()
    d = TicketDraft(name="www.exemplo.pt", expiry=NOW + timedelta(days=20), issuer="Digi<Cert>", ambiente="PRD",
                    tipo="Externo", app_id="354", responsavel="Equipa 'Web'", localizacao="DMZ & LB")
    p = tc.build_payload(d, s)
    assert p["operation"] == "CREATE" and p["entities"][0]["entity_type"] == "Change"
    props = p["entities"][0]["properties"]
    assert props["BasedOnChangeModel"] == "999" and props["AffectsActualService"] == "555"
    assert props["AffectsServiceComponent"] == "354" and props["DataDomains"] == ["DOM_c"]
    assert props["RequestedEndTime"] == int(d.expiry.timestamp() * 1000)
    opts = json.loads(props["UserOptions"])["complexTypeProperties"][0]["properties"]
    assert opts == {"changedUserOptionsForSimulation": "Ambiente_c&", "TipoCert_c": "Externo_c",
                    "EndpointCert_c": "www.exemplo.pt", "DataExp_c": props["RequestedEndTime"], "Ambiente_c": "Name6_c"}
    assert "Digi&lt;Cert&gt;" in props["Description"] and "DMZ &amp; LB" in props["Description"]
    assert props["DisplayLabel"].startswith("Renovacao certificado | www.exemplo.pt | Equipa Web | | ")
    assert json.loads(props["TimePeriodBreachDetails"])["hasService"] is True
    # validação
    bad = TicketDraft(name="x", expiry=None, ambiente="XPTO", tipo="", app_id="12a", responsavel="", localizacao="")
    assert set(tc.validate(bad, s)) == {"expiry", "ambiente", "tipo", "app_id", "responsavel", "localizacao"}


def test_full_flow_select_fill_review_create(smax_env):
    fake = smax_env
    from certwatch.web.app import app
    with TestClient(app) as c:
        page = c.get("/certificados", auth=AUTH).text
        assert 'name="cn"' in page and "Preparar para os selecionados" in page
        token = c.cookies["cw_csrf"]
        assert c.post("/pedidos/novo", data={"csrf": "x", "cn": ["www.exemplo.pt"]}, auth=AUTH).status_code == 403
        r = c.post("/pedidos/novo", data={"csrf": token, "modo": "selecionados",
                                          "cn": ["www.exemplo.pt", "intra.exemplo.local", "le.exemplo.pt", "dup.exemplo.pt"]},
                   auth=AUTH, follow_redirects=False)
        assert r.status_code == 303
        bid = int(r.headers["location"].rsplit("/", 1)[1])
        with session_scope() as db:
            d = {x.cn: x for x in db.scalars(select(TicketDraft).where(TicketDraft.batch_id == bid))}
        # Sugestões: ambiente e Application ID do pedido anterior; tipo pelo âmbito; responsável por omissão
        assert d["www.exemplo.pt"].ambiente == "PRE" and d["www.exemplo.pt"].app_id == "321"
        assert d["www.exemplo.pt"].prefill["ambiente"] == "pedido SMAX 4001"
        assert d["intra.exemplo.local"].tipo == "Interno" and d["intra.exemplo.local"].responsavel == "Equipa Web"
        assert not d["le.exemplo.pt"].include and not d["dup.exemplo.pt"].include      # LE e pedido já em curso
        assert any("4002" in w for w in d["dup.exemplo.pt"].warnings)

        lote = c.get(f"/pedidos/{bid}", auth=AUTH).text
        assert "Valores para todos" in lote and "pedido SMAX 4001" in lote
        # Rever sem campos completos volta ao lote
        assert c.get(f"/pedidos/{bid}/rever", auth=AUTH, follow_redirects=False).status_code == 303
        # Preencher: valores para todos + campos por linha
        c.post(f"/pedidos/{bid}/aplicar", data={"csrf": token, "localizacao": "Não indicado", "so_vazios": "1"}, auth=AUTH)
        i, w = d["intra.exemplo.local"].id, d["www.exemplo.pt"].id
        form = {"csrf": token, "acao": "rever", f"linha_{i}": "1", f"incluir_{i}": "1", f"ambiente_{i}": "PRD",
                f"app_id_{i}": "900", f"linha_{w}": "1", f"incluir_{w}": "1", f"ambiente_{w}": "PRD"}
        for x in ("le.exemplo.pt", "dup.exemplo.pt"):
            form[f"linha_{d[x].id}"] = "1"
        r = c.post(f"/pedidos/{bid}/guardar", data=form, auth=AUTH, follow_redirects=False)
        assert r.headers["location"] == f"/pedidos/{bid}/rever"
        rever = c.get(f"/pedidos/{bid}/rever", auth=AUTH).text
        assert "Renovacao certificado | www.exemplo.pt" in rever and "Criar 2 pedido(s) no SMAX" in rever
        assert 'AffectsServiceComponent&#34;: &#34;900&#34;' in rever

        # Sem confirmação explícita, nada acontece
        assert c.post(f"/pedidos/{bid}/criar", data={"csrf": token, "n": "2"}, auth=AUTH).status_code == 400
        assert c.post(f"/pedidos/{bid}/criar", data={"csrf": token, "n": "3", "confirmo": "1"}, auth=AUTH).status_code == 400
        assert not fake.created
        r = c.post(f"/pedidos/{bid}/criar", data={"csrf": token, "n": "2", "confirmo": "1"}, auth=AUTH, follow_redirects=False)
        assert r.status_code == 303 and len(fake.created) == 2
        # Duplo clique: o segundo envio é recusado e não cria nada
        again = c.post(f"/pedidos/{bid}/criar", data={"csrf": token, "n": "2", "confirmo": "1"}, auth=AUTH)
        assert "já foi enviado" in again.text and len(fake.created) == 2

        res = c.get(f"/pedidos/{bid}", auth=AUTH).text
        assert "https://smax.test/saw/Change/5001/general?TENANTID=123" in res and "Concluído" in res
        # Os pedidos novos aparecem já ligados aos certificados
        det = c.get("/certificados/detalhe", params={"cn": "www.exemplo.pt"}, auth=AUTH).text
        assert "Pedido em curso" in det and "5001" in det
        assert "Lote " + str(bid) in c.get("/pedidos/lotes", auth=AUTH).text
    with session_scope() as db:
        b = db.get(TicketBatch, bid)
        assert b.status == "concluido" and b.confirmed_by == "admin"
        acts = [a.action for a in db.scalars(select(AuditLog))]
        assert acts.count("pedidos.criar") == 2 and "pedidos.lote_confirmado" in acts
        assert db.scalar(select(SmaxTicket).where(SmaxTicket.id == "5001")) is not None


def _ready_batch(cns, settings, **fields):
    with session_scope() as db:
        b = tc.create_batch(db, cns, "admin", settings)
        db.flush()
        for d in tc.drafts_of(db, b.id):
            d.include = True
            d.ambiente, d.tipo, d.app_id = "PRD", "Externo", "900"
            d.responsavel, d.localizacao = "Equipa", "Não indicado"
            for k, v in fields.items():
                setattr(d, k, v)
        return b.id


def test_failure_stops_batch_and_retry(smax_env):
    fake, s = smax_env, config.get_settings()
    bid = _ready_batch(["www.exemplo.pt", "api.exemplo.pt", "intra.exemplo.local"], s)
    fake.plan = ["ok", "fail"]
    tc.start(bid, "admin", s)
    out = tc.execute(bid, "admin", s, fake.client(), pause=0)
    assert out["estado"] == "interrompido" and len(fake.created) == 2
    with session_scope() as db:
        st = {d.cn: d for d in tc.drafts_of(db, bid)}
        assert st["www.exemplo.pt"].status == "criado"
        assert st["api.exemplo.pt"].status == "falhou" and "inválido" in st["api.exemplo.pt"].detail["motivo"]
        assert st["intra.exemplo.local"].status == "nao_tentado"
        b = db.get(TicketBatch, bid)
        new = tc.retry_batch(db, b, "admin", s)
        db.flush()
        nd = {d.cn: d for d in tc.drafts_of(db, new.id)}
    assert set(nd) == {"api.exemplo.pt", "intra.exemplo.local"} and nd["api.exemplo.pt"].app_id == "900"


def test_indeterminate_is_never_repeated(smax_env):
    fake, s = smax_env, config.get_settings()
    bid = _ready_batch(["api.exemplo.pt"], s)
    fake.plan = ["500"]
    tc.start(bid, "admin", s)
    tc.execute(bid, "admin", s, fake.client(), pause=0)
    with session_scope() as db:
        d = tc.drafts_of(db, bid)[0]
        assert d.status == "indeterminado" and "Internal Server Error" in d.detail["texto"] and "tokxxx" not in d.detail["texto"]
        with pytest.raises(tc.TicketError):
            tc.retry_batch(db, db.get(TicketBatch, bid), "admin", s)
    # Um lote novo para o mesmo certificado e data põe-no de lado
    bid2 = _ready_batch(["api.exemplo.pt"], s)
    tc.start(bid2, "admin", s)
    tc.execute(bid2, "admin", s, fake.client(), pause=0)
    with session_scope() as db:
        d2 = tc.drafts_of(db, bid2)[0]
        assert d2.status == "excluido" and "indeterminado" in d2.detail["motivo"]
    assert len(fake.created) == 1
    # Tempo esgotado também é indeterminado
    bid3 = _ready_batch(["intra.exemplo.local"], s)
    fake.plan = ["timeout"]
    tc.start(bid3, "admin", s)
    tc.execute(bid3, "admin", s, fake.client(), pause=0)
    with session_scope() as db:
        assert tc.drafts_of(db, bid3)[0].status == "indeterminado"


def test_duplicate_created_meanwhile_and_sync_failure(smax_env):
    fake, s = smax_env, config.get_settings()
    bid = _ready_batch(["www.exemplo.pt", "api.exemplo.pt"], s)
    fake.add("4100", "api.exemplo.pt", NOW + timedelta(days=25))          # criado à mão entretanto
    tc.start(bid, "admin", s)
    tc.execute(bid, "admin", s, fake.client(), pause=0)
    with session_scope() as db:
        st = {d.cn: d for d in tc.drafts_of(db, bid)}
    assert st["api.exemplo.pt"].status == "excluido" and "4100" in st["api.exemplo.pt"].detail["motivo"]
    assert st["www.exemplo.pt"].status == "criado" and len(fake.created) == 1
    # SMAX indisponível na releitura: nada é enviado e o lote volta a rascunho
    bid2 = _ready_batch(["intra.exemplo.local"], s)
    fake.fail_get = True
    tc.start(bid2, "admin", s)
    out = tc.execute(bid2, "admin", s, fake.client(), pause=0)
    assert "erro" in out and len(fake.created) == 1
    with session_scope() as db:
        b = db.get(TicketBatch, bid2)
        assert b.status == "rascunho" and "duplicados" in b.note


def test_view_selection_limits_and_disabled(smax_env, monkeypatch):
    from certwatch.web.app import app
    with TestClient(app) as c:
        c.get("/certificados", auth=AUTH)
        token = c.cookies["cw_csrf"]
        r = c.post("/pedidos/novo", data={"csrf": token, "modo": "vista", "dias": "30"}, auth=AUTH, follow_redirects=False)
        bid = int(r.headers["location"].rsplit("/", 1)[1])
        with session_scope() as db:
            cns = {d.cn for d in tc.drafts_of(db, bid)}
        assert "longe.exemplo.pt" not in cns and {"www.exemplo.pt", "api.exemplo.pt"} <= cns
        monkeypatch.setenv("CERTWATCH_SMAX_CREATE_MAX", "2")
        config.get_settings.cache_clear()
        r = c.post("/pedidos/novo", data={"csrf": token, "modo": "vista", "dias": "30"}, auth=AUTH)
        assert "o máximo por lote é 2" in r.text
        monkeypatch.setenv("CERTWATCH_SMAX_CREATE_ENABLED", "false")
        config.get_settings.cache_clear()
        assert 'name="cn"' not in c.get("/certificados", auth=AUTH).text
        assert c.post("/pedidos/novo", data={"csrf": token, "cn": ["www.exemplo.pt"]}, auth=AUTH).status_code == 409
        assert "desligada" in c.get("/pedidos/lotes", auth=AUTH).text


def test_stale_batch_marks_in_flight_as_indeterminate(smax_env):
    s = config.get_settings()
    bid = _ready_batch(["www.exemplo.pt", "api.exemplo.pt"], s)
    tc.start(bid, "admin", s)
    with session_scope() as db:
        ds = tc.drafts_of(db, bid)
        ds[0].status = "a_enviar"
        db.get(TicketBatch, bid).confirmed_at = utcnow() - timedelta(hours=1)
    assert tc.mark_stale(bid)
    with session_scope() as db:
        st = [d.status for d in tc.drafts_of(db, bid)]
        assert st == ["indeterminado", "nao_tentado"] and db.get(TicketBatch, bid).status == "interrompido"

"""Reconciliar e atualizar: porquê de cada alteração, só na CMDB e Azure (API ou certificado) até à UCMDB."""
import copy
import json
from dataclasses import replace
from datetime import date, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from certwatch import cmdb_final as cf
from certwatch import ucmdb_write as uw
from certwatch.db import session_scope
from certwatch.models import FinalRun, UcmdbWrite
from tests.test_cmdb_final import AVI, CA1, CIS, TODAY, ca2_xlsx, ci, live
from tests.test_ucmdb_write import FakeUcmdb

AUTH = ("admin", "teste-admin-123")
LOC = "AzureAD - App Registration - Client Secret"


def d(n):
    return (TODAY + timedelta(days=n)).strftime("%d/%m/%Y 10:00:00")


API_CIS = [
    {"ucmdbId": "a1", "type": "exemplo_api", "properties": {"display_label": "CRM Testes", "application_name": "CRM",
                                                            "secret_expiration_date": "24-01-2027 13:00:00", "secret_location": LOC}},
    {"ucmdbId": "a2", "type": "exemplo_api", "properties": {"display_label": "Radar - 0123456789abcdef0123", "application_name": "Radar",
                                                            "secret_expiration_date": "01-03-2027 13:00:00", "secret_location": LOC}},
    {"ucmdbId": "a3", "type": "exemplo_api", "properties": {"display_label": "Removida do Azure", "application_name": "Z",
                                                            "secret_expiration_date": "01-05-2027 13:00:00", "secret_location": LOC}},
]
AZURE_CSV = "\n".join([
    '"EnterpriseApplication";"AppRegistration";"AppId";"CredentialType";"KeyId";"StartDate";"EndDate";"Status"',
    '"App_TST";"App_TST";"x";"Secret";"k1";"20/10/2024 14:59:29";"20/10/2025 14:59:29";"Expired"',
    '"CRM";"CRM Testes";"x";"Secret";"k3";"24/01/2025 10:00:00";"24/01/2027 14:59:29";"Valid"',
    '"Radar";"Radar";"x";"Secret";"k4";"01/01/2026 10:00:00";"01/03/2028 10:00:00";"Valid"',
    '"Pagamentos";"Pagamentos API";"x";"Secret";"k6";"01/01/2026 10:00:00";"15/06/2027 10:00:00";"Valid"',
    '"Portal SSO";"Portal SSO";"x";"Certificate";"k7";"01/01/2026 10:00:00";"20/09/2027 10:00:00";"Valid"',
    '"Misterio";"Misterio";"x";"Outro";"k8";"01/01/2026 10:00:00";"20/09/2027 10:00:00";"Valid"',
])


class FakeWithApis(FakeUcmdb):
    def handler(self, request):
        if request.url.path.endswith("/topology"):
            self.calls.append(("POST", request.url.path, None))
            if request.content == b"APIs_Exemplo":
                return httpx.Response(200, json={"cis": [{"ucmdbId": k, **v} for k, v in self.store.items()
                                                         if v["type"] == "exemplo_api"], "relations": []})
            return httpx.Response(200, json={"cis": [], "relations": []})
        return super().handler(request)


@pytest.fixture()
def setup(env, tmp_path, monkeypatch):
    from certwatch.collectors.ucmdb import parse_apis
    from certwatch.jobs import ingest_apis
    imp = tmp_path / "import"
    imp.mkdir()
    st = replace(env, import_dir=imp, ucmdb_min_cis=1, final_ct=False, import_issuers={"CA1": "Corp CA01", "CA2": "Corp CA02"},
                 ucmdb_url="https://cmdb.test", ucmdb_user="svc", ucmdb_password="pw", ucmdb_write=True,
                 ucmdb_tql_apis="APIs_Exemplo")
    records, fields = parse_apis(API_CIS, st)
    with session_scope() as s:
        ingest_apis(s, st, records, fields)
    (imp / "ca1.csv").write_bytes(CA1)
    (imp / "ca2.xlsx").write_bytes(ca2_xlsx())
    (imp / "avi.csv").write_bytes(AVI)
    (imp / "azure.csv").write_text(AZURE_CSV, encoding="utf-8")
    cis = copy.deepcopy(CIS) + [ci(20, "portal-sso", date(2026, 12, 1), serial="P1"),        # Portal SSO? não: outro nome
                                ci(21, "revogado-ca1.exemplo.pt", date(2027, 6, 1), issuer="Corp CA01", serial="RV")]
    with session_scope() as s:
        rid = cf.start_run(s, "admin").id
    cf.generate(rid, st, fetch=lambda x: (cf.build_cmdb_table(copy.deepcopy(cis), x), []),
                live_factory=lambda s, x: live, today=TODAY)
    fake = FakeWithApis(cis + API_CIS)
    from certwatch.web import app as webapp
    monkeypatch.setattr(webapp, "get_settings", lambda: st)
    monkeypatch.setattr(webapp, "UCMDB_CLIENT", fake.client())
    monkeypatch.setattr(webapp, "UCMDB_WRITE_SYNC", True)
    uw._working_format.clear()
    yield st, rid, fake, webapp
    uw._working_format.clear()


def test_reasons_and_only_in_cmdb(setup):
    st, rid, fake, webapp = setup
    with session_scope() as s:
        run = s.get(FinalRun, rid)
        by = {c["cn"]: c for c in run.changes}
        assert by["novo-avi.exemplo.pt"]["motivo"].startswith("Não existe na CMDB")
        assert "AVI, linha 2" in by["novo-avi.exemplo.pt"]["motivo"]
        assert "Na CMDB está 10-11-2026" in by["renovado.exemplo.pt"]["motivo"] and "mais recente" in by["renovado.exemplo.pt"]["motivo"]
        assert "decidiu o certificado que o servidor apresenta" in by["www.exemplo.pt"]["motivo"]
        only = {x["cn"]: x for x in run.vistas["so_na_cmdb"]}
        assert "revogado-ca1.exemplo.pt" in only and only["revogado-ca1.exemplo.pt"]["fonte"] == "CA1"
        assert only["revogado-ca1.exemplo.pt"]["ucmdb_id"] == "u21"
        assert run.summary["so_na_cmdb"] == len(only)
        flow = cf.data_flow(run)
        assert [x["titulo"] for x in flow] == ["Fontes", "CMDB", "Comparação", "Servidor", "Resultado"]
    with TestClient(webapp.app) as c:
        page = c.get(f"/cmdb-final/{rid}?vista=so_na_cmdb", auth=AUTH).text
        assert "revogado-ca1.exemplo.pt" in page and "/ucmdb/certificado/u21" in page and "pode ter sido revogado" in page


def test_azure_classification(setup):
    st, rid, fake, webapp = setup
    with session_scope() as s:
        az = {x["nome"]: x for x in s.get(FinalRun, rid).vistas["azure"]}
        assert s.get(FinalRun, rid).inputs["AZURE"]["validas"] == 6
    assert az["App_TST"]["estado"] == "expirado"
    assert az["CRM Testes"]["estado"] == "igual" and az["CRM Testes"]["classe"] == "api"
    assert az["Radar"]["estado"] == "data_posterior" and az["Radar"]["alvo"] == "a2"
    assert "Já está na lista de APIs" in az["Radar"]["classe_motivo"]
    assert az["Pagamentos API"]["estado"] == "novo" and az["Pagamentos API"]["classe"] == "api"
    assert az["Portal SSO"]["estado"] == "novo" and az["Portal SSO"]["classe"] == "certificado"
    assert az["Misterio"]["classe"] == "?"
    assert az["Removida do Azure"]["estado"] == "so_na_cmdb"
    with TestClient(webapp.app) as c:
        page = c.get(f"/cmdb-final/{rid}?vista=azure", auth=AUTH).text
        assert "Pagamentos API" in page and "Incluir em" in page and "CRM Testes" not in page
        assert "CRM Testes" in c.get(f"/cmdb-final/{rid}?vista=azure&az=todos", auth=AUTH).text


def test_azure_writes(setup):
    st, rid, fake, webapp = setup
    with session_scope() as s:
        az = {x["nome"]: x for x in s.get(FinalRun, rid).vistas["azure"]}
    with TestClient(webapp.app) as c:
        c.get(f"/cmdb-final/{rid}", auth=AUTH)
        token = c.cookies["cw_csrf"]
        # segredo novo -> lista de APIs, com o tipo e os atributos das APIs
        r = c.post(f"/cmdb-final/{rid}/azure", data={"csrf": token, "chave": az["Pagamentos API"]["chave"], "lista": "apis"}, auth=AUTH)
        assert "incluído na lista de APIs" in r.text
        m, p, body = fake.writes()[-1]
        ci_ = body["cis"][0]
        assert m == "POST" and ci_["type"] == "exemplo_api"
        assert ci_["properties"]["display_label"] == "Pagamentos API" and ci_["properties"]["secret_location"] == LOC
        assert ci_["properties"]["secret_expiration_date"] == "2027-06-15T00:00:00"
        assert ci_["properties"]["application_name"] == "Pagamentos"
        # certificado novo -> lista de certificados, com emissor por verificar e série x<n>
        c.post(f"/cmdb-final/{rid}/azure", data={"csrf": token, "chave": az["Portal SSO"]["chave"], "lista": "certificados"}, auth=AUTH)
        m, p, body = fake.writes()[-1]
        props = body["cis"][0]["properties"]
        assert body["cis"][0]["type"] == "digital_certificate" and props["common_name"] == "Portal SSO"
        assert props["issuer_name"] == "Por verificar" and props["serial_number"] == "x1"
        # data mais recente de uma API registada -> atualiza só a data, nesse registo
        c.post(f"/cmdb-final/{rid}/azure", data={"csrf": token, "chave": az["Radar"]["chave"], "lista": "apis"}, auth=AUTH)
        m, p, body = fake.writes()[-1]
        assert m == "PUT" and p.endswith("/dataModel/ci/a2") and body["properties"] == {"secret_expiration_date": "2028-03-01T00:00:00"}
        # repetir não escreve outra vez; igual não tem ação
        n = len(fake.writes())
        r = c.post(f"/cmdb-final/{rid}/azure", data={"csrf": token, "chave": az["Radar"]["chave"], "lista": "apis"}, auth=AUTH)
        assert "já foi aplicada" in r.text and len(fake.writes()) == n
        r = c.post(f"/cmdb-final/{rid}/azure", data={"csrf": token, "chave": az["CRM Testes"]["chave"], "lista": "apis"}, auth=AUTH)
        assert "nada para aplicar" in r.text
    with session_scope() as s:
        ws = list(s.scalars(select(UcmdbWrite).where(UcmdbWrite.parte == "azure")))
        assert sorted((w.cn, w.lista, w.acao, w.estado) for w in ws) == [
            ("Pagamentos API", "apis", "criar", "ok"), ("Portal SSO", "certificados", "criar", "ok"),
            ("Radar", "apis", "atualizar", "ok")]
        assert all(w.verificado for w in ws)
    # o histórico mostra as escritas do Azure
    with TestClient(webapp.app) as c:
        assert "Pagamentos API" in c.get("/jobs", auth=AUTH).text


class FakeThinTql(FakeWithApis):
    """O TQL das APIs só traz o display_label (como na UCMDB real): o resto vem por CI."""
    def handler(self, request):
        if request.url.path.endswith("/topology") and request.content == b"APIs_Exemplo":
            self.calls.append(("POST", request.url.path, None))
            return httpx.Response(200, json={"cis": [{"ucmdbId": k, "type": v["type"],
                                                      "properties": {"display_label": v["properties"]["display_label"]}}
                                                     for k, v in self.store.items() if v["type"] == "exemplo_api"]})
        return super().handler(request)


def test_azure_api_with_thin_tql(setup, monkeypatch):
    st, rid, fake, webapp = setup
    thin = FakeThinTql(list(CIS) + API_CIS)
    monkeypatch.setattr(webapp, "UCMDB_CLIENT", thin.client())
    with session_scope() as s:
        az = {x["nome"]: x for x in s.get(FinalRun, rid).vistas["azure"]}
    with TestClient(webapp.app) as c:
        c.get(f"/cmdb-final/{rid}", auth=AUTH)
        token = c.cookies["cw_csrf"]
        r = c.post(f"/cmdb-final/{rid}/azure", data={"csrf": token, "chave": az["Pagamentos API"]["chave"], "lista": "apis"}, auth=AUTH)
        assert "incluído na lista de APIs" in r.text
        props = thin.writes()[-1][2]["cis"][0]["properties"]
        assert props["secret_expiration_date"] == "2027-06-15T00:00:00" and props["secret_location"] == LOC


def test_azure_api_fields_unknown_lists_attributes(setup, monkeypatch):
    st, rid, fake, webapp = setup
    monkeypatch.setattr(webapp, "get_settings", lambda: replace(st, apis_field_expiry="nao_existe_attr"))
    with session_scope() as s:
        az = {x["nome"]: x for x in s.get(FinalRun, rid).vistas["azure"]}
    with TestClient(webapp.app) as c:
        c.get(f"/cmdb-final/{rid}", auth=AUTH)
        token = c.cookies["cw_csrf"]
        c.post(f"/cmdb-final/{rid}/azure", data={"csrf": token, "chave": az["Pagamentos API"]["chave"], "lista": "apis"}, auth=AUTH)
    with session_scope() as s:
        w = s.scalar(select(UcmdbWrite).where(UcmdbWrite.parte == "azure"))
        assert w.estado == "erro" and "fim da validade" in w.detalhe and "secret_expiration_date" in w.detalhe


class FakeHiddenDate(FakeThinTql):
    """Como na UCMDB real: nenhum CI devolve a data de fim (nem o TQL, nem o GET), mas o modelo de classes
    (GET /classModel/citypes/{tipo}) diz que o tipo tem um atributo de data "scml_fim"."""
    def handler(self, request):
        p = request.url.path
        if request.method == "GET" and p.endswith("/classModel/citypes/exemplo_api"):
            self.calls.append(("GET", p, None))
            return httpx.Response(200, json={"name": "exemplo_api", "attributes": [
                {"name": "display_label", "displayLabel": "Display Label", "type": "string"},
                {"name": "create_time", "displayLabel": "Create Time", "type": "date"},
                {"name": "last_modified_time", "displayLabel": "Last Modified Time", "type": "date"},
                {"name": "scml_fim", "displayLabel": "Data de fim de validade", "type": "date"}]})
        r = super().handler(request)
        if request.method == "GET" and "/dataModel/ci/a" in p and r.status_code == 200:
            data = json.loads(r.content)
            data["properties"].pop("secret_expiration_date", None)
            return httpx.Response(200, json=data)
        return r


def test_azure_api_expiry_from_class_model(setup, monkeypatch):
    st, rid, fake, webapp = setup
    hidden = FakeHiddenDate(list(CIS) + API_CIS)
    monkeypatch.setattr(webapp, "UCMDB_CLIENT", hidden.client())
    with session_scope() as s:
        az = {x["nome"]: x for x in s.get(FinalRun, rid).vistas["azure"]}
    with TestClient(webapp.app) as c:
        c.get(f"/cmdb-final/{rid}", auth=AUTH)
        token = c.cookies["cw_csrf"]
        r = c.post(f"/cmdb-final/{rid}/azure", data={"csrf": token, "chave": az["Pagamentos API"]["chave"], "lista": "apis"}, auth=AUTH)
        assert "incluído na lista de APIs" in r.text, r.text[:3000]
    props = hidden.writes()[-1][2]["cis"][0]["properties"]
    assert props["scml_fim"] == "2027-06-15T00:00:00" and "create_time" not in props


class FakeRequired(FakeWithApis):
    """UCMDB que exige name e SGSI para criar uma API (HTTP 400 "Not all required attributes are provided")."""
    required = ("name", "SGSI")
    model: list = []

    def __init__(self, cis):
        super().__init__(cis)
        for v in self.store.values():
            if v["type"] == "exemplo_api":
                v["properties"].update({"SGSI": "Sim", "name": v["properties"]["display_label"]})

    def handler(self, request):
        p, m = request.url.path, request.method
        if m == "GET" and p.endswith("/classModel/citypes/exemplo_api"):
            return httpx.Response(200, json={"name": "exemplo_api", "attributes": self.model})
        if m == "POST" and p.endswith("/dataModel"):
            ci = json.loads(request.content)["cis"][0]
            if ci["type"] == "exemplo_api" and any(not ci["properties"].get(a) for a in self.required):
                self.calls.append((m, p, json.loads(request.content)))
                return httpx.Response(400, json={"error": "The following error has occurred: Not all required attributes "
                                                          "are provided. Please consult logs for more details"})
        return super().handler(request)


def _include_api(rid, webapp):
    with session_scope() as s:
        az = {x["nome"]: x for x in s.get(FinalRun, rid).vistas["azure"]}
    with TestClient(webapp.app) as c:
        c.get(f"/cmdb-final/{rid}", auth=AUTH)
        token = c.cookies["cw_csrf"]
        c.post(f"/cmdb-final/{rid}/azure", data={"csrf": token, "chave": az["Pagamentos API"]["chave"], "lista": "apis"}, auth=AUTH)
    with session_scope() as s:
        return s.scalars(select(UcmdbWrite).where(UcmdbWrite.parte == "azure").order_by(UcmdbWrite.id.desc())).first()


def test_azure_api_required_attributes_retry(setup, monkeypatch):
    """O modelo de classes não diz quais são obrigatórios: envia sempre o name; se a UCMDB recusar, tenta de novo
    com os atributos que todas as APIs têm iguais (SGSI=Sim) e diz o que preencheu."""
    st, rid, fake, webapp = setup
    req = FakeRequired(list(CIS) + API_CIS)
    monkeypatch.setattr(webapp, "UCMDB_CLIENT", req.client())
    w = _include_api(rid, webapp)
    assert w.estado in ("ok", "aviso"), w.detalhe
    sent = [b["cis"][0]["properties"] for m, p, b in req.writes() if m == "POST"]
    assert sent[0]["name"] == "Pagamentos API" and "SGSI" not in sent[0]
    assert sent[-1]["SGSI"] == "Sim" and "SGSI=Sim" in w.detalhe


def test_azure_api_required_without_common_value(setup, monkeypatch):
    st, rid, fake, webapp = setup
    req = FakeRequired(list(CIS) + API_CIS)
    req.required = ("name", "scml_dono")
    req.model = [{"name": "scml_dono", "displayLabel": "Dono", "type": "string", "required": True},
                 {"name": "name", "displayLabel": "Name", "type": "string", "qualifiers": [{"name": "ID_ATTRIBUTE"}]}]
    monkeypatch.setattr(webapp, "UCMDB_CLIENT", req.client())
    w = _include_api(rid, webapp)
    assert w.estado == "erro" and "scml_dono (Dono)" in w.detalhe and "CERTWATCH_APIS_CREATE_DEFAULTS" in w.detalhe
    assert not [1 for m, p, b in req.writes() if m == "POST"]          # nem chegou a enviar
    monkeypatch.setattr(webapp, "get_settings", lambda: replace(st, apis_create_defaults={"scml_dono": "DSTI"}))
    w = _include_api(rid, webapp)
    assert w.estado in ("ok", "aviso"), w.detalhe
    assert [b for m, p, b in req.writes() if m == "POST"][-1]["cis"][0]["properties"]["scml_dono"] == "DSTI"


def test_api_attributes_page(setup, monkeypatch):
    st, rid, fake, webapp = setup
    req = FakeRequired(list(CIS) + API_CIS)
    req.model = [{"name": "scml_dono", "displayLabel": "Dono", "type": "string", "required": True},
                 {"name": "SGSI", "displayLabel": "SGSI", "type": "string"},
                 {"name": "secret_expiration_date", "displayLabel": "Data de expiração", "type": "date"},
                 {"name": "client_secret", "displayLabel": "Segredo", "type": "string"}]
    req.store["a1"]["properties"]["client_secret"] = "S3gr3do-Muito-Secreto-123456"
    monkeypatch.setattr(webapp, "UCMDB_CLIENT", req.client())
    with TestClient(webapp.app) as c:
        assert "Ver atributos das APIs" in c.get("/cmdb-final/permissoes", auth=AUTH).text
        page = c.get("/cmdb-final/permissoes/apis?ver=1", auth=AUTH).text
    assert "scml_dono" in page and "obrigatório sem valor" in page and "Sim (3)" in page
    assert "lido como fim da validade" in page and "S3gr3do" not in page

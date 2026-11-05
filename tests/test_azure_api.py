"""Azure pelo Microsoft Graph: o mesmo resultado da exportação, sem guardar o client secret nem o hint dos segredos."""
import json
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
from urllib.parse import parse_qs

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from certwatch import cmdb_final as cf
from certwatch.azure_rec import read_azure
from certwatch.db import session_scope
from certwatch.fontes import azure as az
from certwatch.models import AuditLog, FinalInput

AUTH = ("admin", "teste-admin-123")
NOW = datetime(2026, 11, 4, 10, 0, tzinfo=timezone.utc)
TODAY = date(2026, 11, 4)
SECRET = "segredo-do-atalaia~123"
GRAPH = "https://graph.microsoft.com"
CLIENT_ID = "11111111-2222-3333-4444-555555555555"
ORIG_FETCH = az.fetch


def pw(key, end, start="2026-01-01T10:00:00Z"):
    return {"keyId": key, "startDateTime": start, "endDateTime": end, "hint": "seg", "displayName": "x", "secretText": None}


def kc(key, end):
    return {"keyId": key, "startDateTime": "2026-01-01T10:00:00Z", "endDateTime": end, "type": "AsymmetricX509Cert",
            "usage": "Verify", "key": "MIIC-conteudo-do-certificado"}


APPS = [
    {"id": "o1", "appId": "app-crm", "displayName": "CRM Testes", "passwordCredentials": [pw("k3", "2027-01-24T14:59:29.1234567Z")], "keyCredentials": []},
    {"id": "o2", "appId": "app-radar", "displayName": "Radar", "passwordCredentials": [pw("k4", "2028-03-01T10:00:00Z")], "keyCredentials": []},
    {"id": "o3", "appId": "app-sso", "displayName": "Portal SSO", "passwordCredentials": [], "keyCredentials": [kc("k7", "2027-09-20T10:00:00Z")]},
    {"id": "o4", "appId": "app-velha", "displayName": "App_TST", "passwordCredentials": [pw("k1", "2025-10-20T14:59:29Z")], "keyCredentials": []},
    {"id": "o5", "appId": "app-vazia", "displayName": "Sem segredos", "passwordCredentials": [], "keyCredentials": []},
    {"id": "o6", "appId": CLIENT_ID, "displayName": "Atalaia Cert", "passwordCredentials": [pw("kA", (datetime.now(timezone.utc) + timedelta(days=16, hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))], "keyCredentials": []},
]
SPS = [{"appId": "app-crm", "displayName": "CRM"}, {"appId": "app-radar", "displayName": "Radar"},
       {"appId": "app-sso", "displayName": "Portal SSO"}]


class FakeGraph:
    """Entra ID + Graph simulados: token por client secret, páginas de 2, permissão obrigatória."""

    def __init__(self, secret=SECRET, apps=APPS, sps=SPS, allowed=True, throttle=0, evil_next=False):
        self.secret, self.apps, self.sps, self.allowed, self.throttle, self.evil = secret, apps, sps, allowed, throttle, evil_next
        self.calls = []

    def handler(self, request: httpx.Request):
        url = str(request.url)
        self.calls.append((request.method, url, dict(request.headers), request.content))
        if request.url.host == "login.microsoftonline.com":
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            assert request.url.path == "/tenant-x/oauth2/v2.0/token"
            assert form["grant_type"] == "client_credentials" and form["scope"] == GRAPH + "/.default"
            if form.get("client_secret") != self.secret:
                return httpx.Response(401, json={"error": "invalid_client", "error_codes": [7000215],
                                                 "error_description": "AADSTS7000215: Invalid client secret provided."})
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3599})
        assert request.headers.get("authorization") == "Bearer tok"
        if self.throttle:
            self.throttle -= 1
            return httpx.Response(429, headers={"Retry-After": "0"})
        if not self.allowed:
            return httpx.Response(403, json={"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}})
        data = {"/v1.0/applications": self.apps, "/v1.0/servicePrincipals": self.sps}.get(request.url.path)
        if data is None:
            return httpx.Response(404)
        q = dict(request.url.params)
        assert "$select" in q or "$skiptoken" in q
        page = int(q.get("$skiptoken", "0"))
        top = 1 if q.get("$top") == "1" else 2
        chunk = data[page * top:(page + 1) * top]
        body = {"value": json.loads(json.dumps(chunk))}
        if (page + 1) * top < len(data) and top > 1:
            host = "https://evil.example" if self.evil else GRAPH
            body["@odata.nextLink"] = f"{host}{request.url.path}?$skiptoken={page + 1}"
        return httpx.Response(200, json=body)

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self.handler))


@pytest.fixture()
def st(env, tmp_path):
    imp = tmp_path / "import"
    imp.mkdir()
    return replace(env, import_dir=imp, ucmdb_min_cis=1, azure_tenant_id="tenant-x", azure_client_id=CLIENT_ID,
                   azure_client_secret=SECRET, import_issuers={"CA1": "Corp CA01", "CA2": "Corp CA02"})


def test_fetch_like_the_export(st):
    fake = FakeGraph()
    res = az.fetch(st, fake.client(), NOW)
    assert res.apps == 6 and res.sem_credenciais == 1 and len(res.rows) == 5
    by = {r["KeyId"]: r for r in res.rows}
    assert by["k3"]["EnterpriseApplication"] == "CRM" and by["k3"]["AppRegistration"] == "CRM Testes"
    assert by["k3"]["EndDate"] == "24/01/2027 14:59:29" and by["k3"]["Status"] == "Valid"    # hora de Lisboa (inverno = UTC)
    assert by["k7"]["CredentialType"] == "Certificate" and by["k1"]["Status"] == "Expired"
    assert by["kA"]["EnterpriseApplication"] == "Atalaia Cert"                                # sem service principal
    assert [r["KeyId"] for r in res.proprio] == ["kA"]
    data = az.to_csv(res.rows)
    text = data.decode("utf-8-sig")
    assert text.splitlines()[0] == '"' + '";"'.join(az.COLUMNS) + '"'
    for leaked in ("seg", "MIIC", SECRET, "tok"):
        assert leaked not in text.replace("Segredos", "")
    rows, info = read_azure(data, "api.csv", TODAY)                         # o mesmo leitor da exportação
    assert info["validas"] == 5 and {r["key_id"] for r in rows} == {"k1", "k3", "k4", "k7", "kA"}
    # o segredo só foi para o endereço do token; o Graph só recebeu o token
    for m, url, headers, body in fake.calls:
        if "graph.microsoft.com" in url:
            assert SECRET.encode() not in body and m == "GET"
    assert sum(1 for c in fake.calls if "applications" in c[1]) == 3          # 6 aplicações em páginas de 2


def test_errors_are_explained(st):
    with pytest.raises(az.AzureError, match="AADSTS7000215.*«Value»"):
        az.fetch(st, FakeGraph(secret="outro").client(), NOW)
    with pytest.raises(az.AzureError, match="Application.Read.All"):
        az.fetch(st, FakeGraph(allowed=False).client(), NOW)
    with pytest.raises(az.AzureError, match="fora de"):
        az.fetch(st, FakeGraph(evil_next=True).client(), NOW)                  # o token não sai do Graph
    res = az.fetch(st, FakeGraph(throttle=2).client(), NOW)                    # 429 com Retry-After: tenta outra vez
    assert len(res.rows) == 5
    assert "CERTWATCH_AZURE_TENANT_ID" in az.configured(replace(st, azure_tenant_id=""))
    assert "secrets/azure_client_secret" in az.configured(replace(st, azure_client_secret=None))
    assert az.parse_graph_dt("2027-01-24T14:59:29.1234567Z") == datetime(2027, 1, 24, 14, 59, 29, 123456, tzinfo=timezone.utc)


EXPORT = "\n".join([
    '"EnterpriseApplication";"AppRegistration";"AppId";"CredentialType";"KeyId";"StartDate";"EndDate";"Status"',
    '"CRM";"CRM Testes";"app-crm";"Secret";"k3";"24/01/2025 10:00:00";"24/01/2027 14:59:29";"Valid"',
    '"Radar";"Radar";"app-radar";"Secret";"k4";"01/01/2026 10:00:00";"01/03/2027 10:00:00";"Valid"',
    '"Antiga";"Antiga";"x";"Secret";"k9";"01/01/2026 10:00:00";"01/03/2027 10:00:00";"Valid"',
]).encode("utf-8")


def test_compare_with_export(st):
    res = az.fetch(st, FakeGraph().client(), NOW)
    cmp = cf.azure_compare("azure.csv", EXPORT, az.to_csv(res.rows), TODAY)
    assert cmp["por_keyid"] and cmp["iguais"] == 1
    assert [d["key_id"] for d in cmp["diferentes"]] == ["k4"] and "01-03-2028" in cmp["diferentes"][0]["diferencas"][0]
    assert [x["key_id"] for x in cmp["so_ficheiro"]] == ["k9"]
    assert {x["key_id"] for x in cmp["so_api"]} == {"k1", "k7", "kA"}


def _gen(settings, monkeypatch, fake):
    import certwatch.fontes.azure as mod
    monkeypatch.setattr(mod, "fetch", lambda s, client=None, now=None: ORIG_FETCH(s, fake.client(), NOW))
    from tests.test_avi import _gen as avi_gen, FakeAvi
    return avi_gen(settings, monkeypatch, FakeAvi())


def test_reconcile_source_modes(st, monkeypatch):
    (st.import_dir / "azure.csv").write_bytes(EXPORT)
    fake = FakeGraph()
    run = _gen(replace(st, azure_source="ficheiro"), monkeypatch, fake)
    assert run.status == "pronto", run.error
    assert not fake.calls and run.inputs["AZURE"]["origem"] == "diretoria"
    run = _gen(replace(st, azure_source="auto"), monkeypatch, fake)
    assert run.status == "pronto" and run.inputs["AZURE"]["origem"] == "api", run.error
    assert any(x["nome"] == "Portal SSO" for x in run.vistas["azure"])
    assert (st.import_dir / "azure.csv").exists()
    with session_scope() as s:
        for up in s.scalars(select(FinalInput)):
            s.delete(up)
    run = _gen(replace(st, azure_source="auto"), monkeypatch, FakeGraph(secret="outro"))
    assert run.status == "pronto" and run.inputs["AZURE"]["origem"] == "diretoria"
    assert any("Azure pela API falhou" in p["erro"] and "foi usado o ficheiro" in p["erro"] for p in run.problems)
    run = _gen(replace(st, azure_source="api"), monkeypatch, FakeGraph(secret="outro"))
    assert run.status == "erro" and "Azure pela API" in run.error


def test_azure_page(st, monkeypatch):
    from certwatch.web import app as webapp
    monkeypatch.setattr(webapp, "get_settings", lambda: st)
    fake = FakeGraph()
    monkeypatch.setattr(webapp, "AZURE_CLIENT", None)
    import certwatch.fontes.azure as mod
    monkeypatch.setattr(mod, "fetch", lambda s, client=None, now=None: ORIG_FETCH(s, fake.client(), NOW))
    (st.import_dir / "azure.csv").write_bytes(EXPORT)
    with TestClient(webapp.app) as c:
        page = c.get("/cmdb-final/azure", auth=AUTH).text
        assert "Testar e comparar com o ficheiro" in page and SECRET not in page and "Application.Read.All" in page
        assert "Ler pela API do Azure" in c.get("/cmdb-final", auth=AUTH).text
        token = c.cookies["cw_csrf"]
        page = c.post("/cmdb-final/azure/testar", data={"csrf": token}, auth=AUTH).text
        assert "<b>5</b> segredos e certificados de <b>6</b> App Registrations" in page
        assert "Só na API (3)" in page and "segredo do Atalaia" in page and "16 dias" in page and SECRET not in page
        with session_scope() as s:
            assert not s.scalars(select(FinalInput)).first()                 # testar não muda a fonte
            a = s.scalar(select(AuditLog).where(AuditLog.action == "azure.testar"))
            assert a is not None and SECRET not in json.dumps(a.details if hasattr(a, "details") else str(a.__dict__), default=str)
        csv = c.get("/cmdb-final/azure/csv", auth=AUTH)
        assert csv.status_code == 200 and "Portal SSO" in csv.content.decode("utf-8-sig")
        r = c.post("/cmdb-final/azure/usar", data={"csrf": token}, auth=AUTH, follow_redirects=False)
        assert r.status_code == 303
        with session_scope() as s:
            up = s.scalars(select(FinalInput)).first()
            assert up.uploaded_by == cf.AZURE_API_ACTOR and up.name.startswith("azure-api-") and up.source == "AZURE"
            assert SECRET.encode() not in up.data
        monkeypatch.setattr(webapp, "AZURE_CLIENT", FakeGraph(secret="outro").client())
        diag = c.post("/cmdb-final/azure/diagnosticar", data={"csrf": token}, auth=AUTH).text
        assert "Diagnóstico da ligação" in diag and "falhou" in diag and "AADSTS7000215" in diag
        monkeypatch.setattr(webapp, "get_settings", lambda: replace(st, azure_client_secret=None))
        assert "secrets/azure_client_secret" in c.get("/cmdb-final/azure", auth=AUTH).text


def test_diagnose_steps(st):
    ok = az.diagnose(st, FakeGraph().client())
    assert [x["passo"] for x in ok] == ["Configuração", "Saída para a internet", "Token", "Ler as App Registrations",
                                       "Ler as Enterprise Applications"] and all(x["ok"] for x in ok)
    denied = az.diagnose(st, FakeGraph(allowed=False).client())
    assert denied[-1]["passo"] == "Ler as App Registrations" and not denied[-1]["ok"] and "Grant admin consent" in denied[-1]["fazer"]
    bad = az.diagnose(st, FakeGraph(secret="x").client())
    assert bad[-1]["passo"] == "Token" and not bad[-1]["ok"]
    assert az.diagnose(replace(st, azure_client_id=""))[0]["ok"] is False


def test_proxy_host_never_shows_credentials(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://utilizador:palavra@proxy.exemplo.pt:8080")
    assert az._proxy_host() == "proxy.exemplo.pt"

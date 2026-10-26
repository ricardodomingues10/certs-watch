"""AVI pela REST API: o mesmo resultado do script de exportação, sem guardar a chave privada nem credenciais."""
import copy
import json
from dataclasses import replace
from datetime import date

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from certwatch import cmdb_final as cf
from certwatch.collectors import avi
from certwatch.db import session_scope
from certwatch.models import AuditLog, FinalInput, FinalRun

TODAY = date(2026, 10, 26)
AUTH = ("admin", "teste-admin-123")
ORIG_FETCH = avi.fetch
KEY = "-----BEGIN PRIVATE KEY-----\nMIIEsegredo\n-----END PRIVATE KEY-----"


def item(name, cn, not_after, serial_dec, issuer, sans=(), not_before="2026-01-01 00:00:00"):
    return {"name": name, "uuid": f"sslkeyandcertificate-{name}", "type": "SSL_CERTIFICATE_TYPE_VIRTUALSERVICE",
            "key": KEY, "key_passphrase": "<sensitive>",
            "certificate": {"subject": {"common_name": cn}, "issuer": {"common_name": issuer},
                            "not_before": not_before, "not_after": not_after, "serial_number": serial_dec,
                            "subject_alt_names": list(sans), "certificate": "-----BEGIN CERTIFICATE-----x"}}


VS = [item("vs-portal", "portal.exemplo.pt", "2027-05-01 12:00:00", "255", "DigiCert Global G2", ["portal.exemplo.pt"]),
      item("vs-novo", "novo-avi.exemplo.pt", "2028-04-10 12:00:00", "4660", "DigiCert Global G2",
           ["novo-avi.exemplo.pt", "www.novo-avi.exemplo.pt"]),
      item("vs-api", "so-api.exemplo.pt", "2027-08-01 12:00:00", "17", "Corp CA01")]
CAS = [{"name": "Corp-Intermedia", "type": "SSL_CERTIFICATE_TYPE_CA", "key": KEY,
        "certificate": {"subject": {"common_name": "Corp Intermedia"}, "issuer": {"common_name": "Corp Root"},
                        "not_before": "2020-01-01 00:00:00", "not_after": "2026-12-01 00:00:00", "serial_number": "1"}}]


class FakeAvi:
    """Controlador AVI simulado: login com cookies, páginas de 2, cabeçalho X-Avi-Tenant obrigatório."""

    def __init__(self, vs=VS, cas=CAS, password="pw"):
        self.vs, self.cas, self.password = vs, cas, password
        self.calls = []

    def handler(self, request: httpx.Request):
        p, m = request.url.path, request.method
        self.calls.append((m, str(request.url), dict(request.headers)))
        if p == "/login":
            body = json.loads(request.content)
            if body.get("password") != self.password:
                return httpx.Response(401, json={"error": "Invalid credentials"})
            return httpx.Response(200, json={"user": {}},
                                  headers=[("set-cookie", "sessionid=s1; Path=/"), ("set-cookie", "csrftoken=c1; Path=/")])
        if p == "/logout":
            return httpx.Response(200)
        if "sessionid=s1" not in request.headers.get("cookie", ""):
            return httpx.Response(401)
        if request.headers.get("X-Avi-Tenant") != "admin":
            return httpx.Response(403)
        if p == "/api/sslkeyandcertificate":
            q = dict(request.url.params)
            data = self.cas if q.get("type") == "SSL_CERTIFICATE_TYPE_CA" else self.vs
            page, size = int(q.get("page", 1)), 2
            chunk = data[(page - 1) * size: page * size]
            nxt = f"https://avi.test{p}?page={page + 1}" if page * size < len(data) else None
            return httpx.Response(200, json={"count": len(data), "results": copy.deepcopy(chunk),
                                             **({"next": nxt} if nxt else {})})
        return httpx.Response(404)

    def client(self):
        return httpx.Client(base_url="https://avi.test", transport=httpx.MockTransport(self.handler))


@pytest.fixture()
def st(env, tmp_path):
    imp = tmp_path / "import"
    imp.mkdir()
    return replace(env, import_dir=imp, ucmdb_min_cis=1, import_issuers={"CA1": "Corp CA01", "CA2": "Corp CA02"},
                   avi_url="https://avi.test", avi_user="leitor", avi_password="pw")


def script_file(rows) -> bytes:
    """Como o Export-Csv -Encoding Unicode do script (UTF-16, tudo entre aspas)."""
    head = '"Nome","Subject_CommonName","Validity_NotBefore","Validity_NotAfter","SerialNumber","Issuer_CommonName","SubjectAlternativeName"'
    lines = [head] + [",".join(f'"{v}"' for v in r) for r in rows]
    return ("\r\n".join(lines) + "\r\n").encode("utf-16")


def test_fetch_like_the_script(st):
    fake = FakeAvi()
    res = avi.fetch(st, fake.client())
    assert [r["Nome"] for r in res.vs] == ["vs-portal", "vs-novo", "vs-api"] and len(res.ca) == 1
    portal = res.vs[0]
    assert portal["SerialNumber"] == "ff" and portal["Validity_NotAfter"] == "2027-05-01 12:00:00"
    assert res.vs[1]["SubjectAlternativeName"] == "novo-avi.exemplo.pt; www.novo-avi.exemplo.pt"
    assert res.vs[2]["SubjectAlternativeName"] == "[sem SAN]"
    # só leitura, pede só os campos precisos, tenant em todos os pedidos, sessão fechada no fim
    gets = [c for c in fake.calls if c[0] == "GET"]
    assert all("fields=name%2Ccertificate%2Ctype" in u and h.get("x-avi-tenant") == "admin" for _, u, h in gets)
    assert not [c for c in fake.calls if c[0] in ("PUT", "PATCH", "DELETE")]
    assert fake.calls[-1][0] == "POST" and fake.calls[-1][1].endswith("/logout") and fake.calls[-1][2].get("x-csrftoken") == "c1"
    # a chave privada nunca sai do coletor
    assert "PRIVATE KEY" not in json.dumps(res.vs + res.ca) and "PRIVATE KEY" not in avi.to_csv(res.vs).decode("utf-8-sig")
    # o CSV é lido pelo mesmo leitor do ficheiro
    items, info = cf.read_source("AVI", "avi-api.csv", avi.to_csv(res.vs), TODAY)
    assert info["validas"] == 3 and {i.cn for i in items} == {"portal.exemplo.pt", "novo-avi.exemplo.pt", "so-api.exemplo.pt"}


def test_errors_are_explained(st):
    with pytest.raises(avi.AviError, match="recusou as credenciais"):
        avi.fetch(st, FakeAvi(password="outra").client())
    with pytest.raises(avi.AviError, match="secrets/avi_user"):
        avi.fetch(replace(st, avi_user=""), FakeAvi().client())
    with pytest.raises(avi.AviError, match="permissão"):
        avi.fetch(replace(st, avi_tenant="outro"), FakeAvi().client())
    assert avi.serial_hex("4660") == "1234" and avi.serial_hex("AB:CD") == "abcd" and avi.serial_hex("") == ""


def test_compare_with_script_file(st):
    res = avi.fetch(st, FakeAvi().client())
    file = script_file([
        ("vs-portal", "portal.exemplo.pt", "2026-01-01 00:00:00", "2027-05-01 12:00:00", "ff", "DigiCert Global G2", "portal.exemplo.pt"),
        ("vs-novo", "novo-avi.exemplo.pt", "2026-01-01 00:00:00", "2027-04-10 12:00:00", "1234", "DigiCert Global G2", "x"),
        ("vs-antigo", "antigo.exemplo.pt", "2025-01-01 00:00:00", "2027-01-01 12:00:00", "99", "Corp CA01", "[sem SAN]")])
    cmp = cf.avi_compare("avi.csv", file, avi.to_csv(res.vs))
    assert cmp["iguais"] == 1 and [d["nome"] for d in cmp["diferentes"]] == ["vs-novo"]
    assert "fim: ficheiro 2027-04-10" in cmp["diferentes"][0]["diferencas"][0]
    assert [r["nome"] for r in cmp["so_ficheiro"]] == ["vs-antigo"] and [r["nome"] for r in cmp["so_api"]] == ["vs-api"]


def _gen(st, monkeypatch, fake):
    import certwatch.collectors.avi as mod
    monkeypatch.setattr(mod, "fetch", lambda settings, client=None, with_ca=True: ORIG_FETCH(settings, fake.client(), with_ca))
    from tests.test_cmdb_final import CA1, CIS, ca2_xlsx, live
    (st.import_dir / "ca1.csv").write_bytes(CA1)
    (st.import_dir / "ca2.xlsx").write_bytes(ca2_xlsx())
    (st.import_dir / "avi.csv").write_bytes(script_file([
        ("vs-portal", "portal.exemplo.pt", "2026-01-01 00:00:00", "2027-05-01 12:00:00", "ff", "DigiCert Global G2", "x")]))
    with session_scope() as s:
        rid = cf.start_run(s, "admin").id
    cf.generate(rid, st, fetch=lambda s2: (cf.build_cmdb_table(copy.deepcopy(CIS), s2), []),
                live_factory=lambda s, s2: live, today=TODAY)
    with session_scope() as s:
        run = s.get(FinalRun, rid)
        s.expunge(run)
        return run


def test_reconcile_source_modes(st, monkeypatch):
    # ficheiro (por omissão): a API nem é chamada
    fake = FakeAvi()
    run = _gen(replace(st, avi_source="ficheiro"), monkeypatch, fake)
    assert run.status == "pronto", run.error
    assert not fake.calls and run.inputs["AVI"]["origem"] == "diretoria"
    # auto: lê pela API (o ficheiro fica onde está)
    run = _gen(replace(st, avi_source="auto"), monkeypatch, fake)
    assert run.status == "pronto" and run.inputs["AVI"]["origem"] == "api", run.error
    assert any(c["cn"] == "so-api.exemplo.pt" for c in run.changes)
    assert (st.import_dir / "avi.csv").exists()
    # auto com a API em baixo: usa o ficheiro e diz porquê
    with session_scope() as s:
        for up in s.scalars(select(FinalInput)):
            s.delete(up)
    run = _gen(replace(st, avi_source="auto"), monkeypatch, FakeAvi(password="outra"))
    assert run.status == "pronto" and run.inputs["AVI"]["origem"] == "diretoria"
    assert any("AVI pela API falhou" in p["erro"] for p in run.problems)
    # api: se falhar, a reconciliação para
    run = _gen(replace(st, avi_source="api"), monkeypatch, FakeAvi(password="outra"))
    assert run.status == "erro" and "AVI pela API" in run.error


def test_avi_page(st, monkeypatch):
    from certwatch.web import app as webapp
    monkeypatch.setattr(webapp, "get_settings", lambda: st)
    fake = FakeAvi()
    monkeypatch.setattr(webapp, "AVI_CLIENT", None)
    import certwatch.collectors.avi as mod
    monkeypatch.setattr(mod, "fetch", lambda settings, client=None, with_ca=True: ORIG_FETCH(settings, fake.client(), with_ca))
    (st.import_dir / "avi.csv").write_bytes(script_file([
        ("vs-portal", "portal.exemplo.pt", "2026-01-01 00:00:00", "2027-05-01 12:00:00", "ff", "DigiCert Global G2", "x")]))
    with TestClient(webapp.app) as c:
        page = c.get("/cmdb-final/avi", auth=AUTH).text
        assert "Testar e comparar com o ficheiro" in page and "leitor" not in page and ">pw<" not in page
        assert "Ler pela API do AVI" in c.get("/cmdb-final", auth=AUTH).text
        token = c.cookies["cw_csrf"]
        page = c.post("/cmdb-final/avi/testar", data={"csrf": token}, auth=AUTH).text
        assert "<b>3</b> certificados" in page and "Só na API (2)" in page and "Corp Intermedia" in page
        with session_scope() as s:
            assert not s.scalars(select(FinalInput)).first()          # testar não muda a fonte
            assert s.scalar(select(AuditLog).where(AuditLog.action == "avi.testar")) is not None
        csv = c.get("/cmdb-final/avi/csv?tipo=vs", auth=AUTH)
        assert csv.status_code == 200 and b"PRIVATE" not in csv.content and "vs-novo" in csv.content.decode("utf-8-sig")
        r = c.post("/cmdb-final/avi/usar", data={"csrf": token}, auth=AUTH, follow_redirects=False)
        assert r.status_code == 303
        with session_scope() as s:
            up = s.scalars(select(FinalInput)).first()
            assert up.uploaded_by == cf.AVI_API_ACTOR and up.name.startswith("avi-api-")
            assert cf.current_inputs(s, st)["AVI"]["por"] == cf.AVI_API_ACTOR
        assert (st.import_dir / "avi.csv").exists()
        # sem credenciais: a página diz o que falta e não tenta
        monkeypatch.setattr(webapp, "get_settings", lambda: replace(st, avi_password=None))
        assert "secrets/avi_password" in c.get("/cmdb-final/avi", auth=AUTH).text

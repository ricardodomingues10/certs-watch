"""Escrever na UCMDB pela REST API: aplicar alterações de uma geração (uma ou todas) e editar um certificado."""
import copy
import json
from dataclasses import replace
from datetime import datetime, timezone

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from certwatch import cmdb_final as cf
from certwatch import ucmdb_write as uw
from certwatch.db import session_scope
from certwatch.models import AuditLog, CmdbRecord, FinalRun, UcmdbWrite
from tests.test_cmdb_final import AVI, CA1, CIS, TODAY, ca2_xlsx, live

AUTH = ("admin", "teste-admin-123")


class FakeUcmdb:
    """UCMDB em memória: guarda os CIs, aceita datas em ISO 8601 e devolve-as em milissegundos."""

    def __init__(self, cis):
        self.store = {c["ucmdbId"]: {"type": c["type"], "properties": copy.deepcopy(c["properties"])} for c in cis}
        self.calls = []
        self.n = 0

    accepts = ("local",)      # formatos de data que esta UCMDB aceita: "local" (sem fuso), "ms"

    def _bad_date(self, props):
        v = props.get("valid_to")
        if isinstance(v, str):
            if v.endswith("Z") or "local" not in self.accepts:
                return httpx.Response(500, json={"error": f'The following error has occurred: Invalid format: "{v}" is '
                                                          'malformed at "Z". Please consult logs for more details'})
        elif isinstance(v, int) and "ms" not in self.accepts:
            return httpx.Response(500, json={"error": "Invalid format: long"})
        return None

    def _norm(self, props):
        out = dict(props)
        for k, v in props.items():
            if k == "valid_to" and isinstance(v, str):
                d = datetime.fromisoformat(v).replace(tzinfo=cf.ZoneInfo("Europe/Lisbon"))
                out[k] = int(d.timestamp() * 1000)
        return out

    def handler(self, request):
        p, m = request.url.path, request.method
        body = json.loads(request.content) if request.content and m in ("POST", "PUT") and not p.endswith("/topology") else None
        self.calls.append((m, p, body))
        if p.endswith("/authenticate"):
            return httpx.Response(200, json={"token": "t"})
        if m == "GET" and "/dataModel/ci/" in p:
            cid = p.rsplit("/", 1)[1]
            if cid not in self.store:
                return httpx.Response(404, json={"error": "not found"})
            return httpx.Response(200, json={"ucmdbId": cid, **self.store[cid]})
        if m in ("PUT", "POST") and "/dataModel" in p:
            bad = self._bad_date(body["properties"] if m == "PUT" else body["cis"][0]["properties"])
            if bad is not None:
                return bad
        if m == "PUT":
            cid = p.rsplit("/", 1)[1]
            self.store[cid]["properties"].update(self._norm(body["properties"]))
            return httpx.Response(200, json={"addedCis": [], "updatedCis": [cid], "ignoredCis": [], "removedCis": []})
        if m == "POST" and p.endswith("/dataModel"):
            self.n += 1
            cid = f"novo{self.n}"
            ci = body["cis"][0]
            self.store[cid] = {"type": ci["type"], "properties": self._norm(ci["properties"])}
            return httpx.Response(200, json={"addedCis": [cid], "updatedCis": [], "ignoredCis": [], "removedCis": []})
        return httpx.Response(404)

    def client(self):
        return httpx.Client(base_url="https://cmdb.test/rest-api", transport=httpx.MockTransport(self.handler))

    def writes(self):
        return [c for c in self.calls if c[0] in ("PUT", "POST") and "/dataModel" in c[1]]


@pytest.fixture(autouse=True)
def _reset_date_format():
    uw._working_format.clear()
    yield
    uw._working_format.clear()


@pytest.fixture()
def setup(env, tmp_path, monkeypatch):
    imp = tmp_path / "import"
    imp.mkdir()
    st = replace(env, import_dir=imp, ucmdb_min_cis=1, final_ct=False,
                 import_issuers={"CA1": "Corp CA01", "CA2": "Corp CA02"},
                 ucmdb_url="https://cmdb.test", ucmdb_user="svc", ucmdb_password="pw", ucmdb_write=True)
    (imp / "ca1.csv").write_bytes(CA1)
    (imp / "ca2.xlsx").write_bytes(ca2_xlsx())
    (imp / "avi.csv").write_bytes(AVI)
    with session_scope() as s:
        rid = cf.start_run(s, "admin").id
    cf.generate(rid, st, fetch=lambda x: (cf.build_cmdb_table(copy.deepcopy(CIS), x), []),
                live_factory=lambda s, x: live, today=TODAY)
    fake = FakeUcmdb(CIS)
    from certwatch.web import app as webapp
    monkeypatch.setattr(webapp, "get_settings", lambda: st)
    monkeypatch.setattr(webapp, "UCMDB_CLIENT", fake.client())
    monkeypatch.setattr(webapp, "UCMDB_WRITE_SYNC", True)
    with session_scope() as s:
        changes = {c["cn"]: c for c in s.get(FinalRun, rid).changes}
    return st, rid, fake, changes, webapp


def test_apply_one_new_and_one_changed(setup):
    st, rid, fake, changes, webapp = setup
    with TestClient(webapp.app) as c:
        page = c.get(f"/cmdb-final/{rid}", auth=AUTH).text
        assert "Aplicar na UCMDB" in page and 'form="ucmdb-one"' in page
        token = c.cookies["cw_csrf"]
        # novo
        k = changes["novo-avi.exemplo.pt"]["chave"]
        r = c.post(f"/cmdb-final/{rid}/ucmdb", data={"csrf": token, "modo": "um", "chave": k}, auth=AUTH)
        assert r.status_code == 200 and "criado" in r.text
        (m, path, body), = fake.writes()
        assert m == "POST" and body["cis"][0]["type"] == "digital_certificate"
        props = body["cis"][0]["properties"]
        assert props["common_name"] == "novo-avi.exemplo.pt" and props["serial_number"] == "N4"
        assert props["issuer_name"] == "DigiCert Global G2" and props["valid_to"] == "2028-04-10T00:00:00"
        assert "global_id" not in props
        with session_scope() as s:
            w = s.scalar(select(UcmdbWrite).where(UcmdbWrite.chave == k))
            assert w.estado == "ok" and w.verificado is True and w.ucmdb_id == "novo1"
        stored = fake.store["novo1"]["properties"]["valid_to"]
        assert datetime.fromtimestamp(stored / 1000, tz=timezone.utc).astimezone(cf.ZoneInfo("Europe/Lisbon")).date().isoformat() == "2028-04-10"
        # alterado: só os campos que mudaram
        k2 = changes["renovado.exemplo.pt"]["chave"]
        c.post(f"/cmdb-final/{rid}/ucmdb", data={"csrf": token, "modo": "um", "chave": k2}, auth=AUTH)
        m, path, body = fake.writes()[-1]
        assert m == "PUT" and path.endswith("/dataModel/ci/u2")
        assert set(body["properties"]) <= {"valid_to", "serial_number", "description"} and "valid_to" in body["properties"]
        assert "Changed with n8n" in fake.store["u2"]["properties"]["description"]
        # repetir a mesma não escreve outra vez
        r = c.post(f"/cmdb-final/{rid}/ucmdb", data={"csrf": token, "modo": "um", "chave": k2}, auth=AUTH)
        assert "já foram aplicadas" in r.text and len(fake.writes()) == 2


def test_changed_meanwhile_is_not_written(setup):
    st, rid, fake, changes, webapp = setup
    fake.store["u2"]["properties"]["serial_number"] = "MUDOU-NA-UCMDB"
    with TestClient(webapp.app) as c:
        c.get(f"/cmdb-final/{rid}", auth=AUTH)
        token = c.cookies["cw_csrf"]
        k = changes["renovado.exemplo.pt"]["chave"]
        r = c.post(f"/cmdb-final/{rid}/ucmdb", data={"csrf": token, "modo": "um", "chave": k}, auth=AUTH)
        assert "Mudou na UCMDB depois da reconciliação" in r.text and not fake.writes()
        assert "Tentar de novo" in r.text


def test_apply_all_and_disabled(setup):
    st, rid, fake, changes, webapp = setup
    with TestClient(webapp.app) as c:
        c.get(f"/cmdb-final/{rid}", auth=AUTH)
        token = c.cookies["cw_csrf"]
        assert "Confirme" in c.post(f"/cmdb-final/{rid}/ucmdb", data={"csrf": token, "modo": "todas"}, auth=AUTH).text
        r = c.post(f"/cmdb-final/{rid}/ucmdb", data={"csrf": token, "modo": "todas", "confirmo": "1"}, auth=AUTH)
        assert r.status_code == 200
        with session_scope() as s:
            run = s.get(FinalRun, rid)
            incl = [x for x in run.changes if x.get("incluir", True)]
            ws = list(s.scalars(select(UcmdbWrite).where(UcmdbWrite.run_id == rid)))
            assert len(ws) == len(incl) and all(w.estado in ("ok", "aviso", "ignorado") for w in ws)
            assert {w.chave for w in ws} == {x["chave"] for x in incl}
            assert s.scalar(select(AuditLog).where(AuditLog.action == "ucmdb.escrever")) is not None
        assert "Todas as alterações incluídas já foram aplicadas" in r.text
        n = len(fake.writes())
        # desligado: não escreve
        webapp.get_settings = lambda: replace(st, ucmdb_write=False)
    from certwatch.web import app as webapp2
    with TestClient(webapp2.app) as c:
        c.get(f"/cmdb-final/{rid}", auth=AUTH)
        token = c.cookies["cw_csrf"]
        r = c.post(f"/cmdb-final/{rid}/ucmdb", data={"csrf": token, "modo": "todas", "confirmo": "1"}, auth=AUTH)
        assert "CERTWATCH_UCMDB_WRITE=true" in r.text and len(fake.writes()) == n


def test_edit_certificate(setup):
    st, rid, fake, changes, webapp = setup
    with session_scope() as s:
        s.add(CmdbRecord(ucmdb_id="u1", global_id="g1", common_name="igual.exemplo.pt", cn_norm="igual.exemplo.pt", kind="host"))
    with TestClient(webapp.app) as c:
        page = c.get("/ucmdb/certificado?q=igual", auth=AUTH).text
        assert "/ucmdb/certificado/u1" in page
        page = c.get("/ucmdb/certificado/u1", auth=AUTH).text
        assert 'type="date"' in page and 'value="2027-03-01"' in page and "issuer_name" in page
        token = c.cookies["cw_csrf"]
        idx = {col: i for i, col in enumerate(uw.EDIT_COLUMNS)}
        form = {"csrf": token, f"f_{idx['ValidTo']}": "2027-09-15", f"f_{idx['IssuerName']}": "Corp CA02",
                f"f_{idx['Issuer']}": "Corp CA01", "registar": "1", "acao": "rever"}
        r = c.post("/ucmdb/certificado/u1", data=form, auth=AUTH)
        assert "Vai mudar na UCMDB" in r.text and "Corp CA02" in r.text and not fake.writes()
        sig = r.text.split('name="assinatura" value="')[1].split('"')[0]
        # sem confirmar -> não grava
        r = c.post("/ucmdb/certificado/u1", data={**form, "acao": "gravar", "assinatura": sig}, auth=AUTH)
        assert "Confirme a gravação" in r.text and not fake.writes()
        # assinatura de outro estado -> não grava
        r = c.post("/ucmdb/certificado/u1", data={**form, "acao": "gravar", "assinatura": "x", "confirmo": "1"}, auth=AUTH)
        assert "Reveja de novo" in r.text and not fake.writes()
        r = c.post("/ucmdb/certificado/u1", data={**form, "acao": "gravar", "assinatura": sig, "confirmo": "1"}, auth=AUTH)
        assert "Gravado na UCMDB." in r.text
        (m, path, body), = fake.writes()
        assert m == "PUT" and path.endswith("/u1")
        assert set(body["properties"]) == {"valid_to", "issuer_name", "description"}
        assert "Data de expiracao alterado de 01/03/2027 para 15/09/2027" in body["properties"]["description"]
        assert "IssuerName alterado de Corp CA01 para Corp CA02" in body["properties"]["description"]
        assert fake.store["u1"]["properties"]["issuer_name"] == "Corp CA02"
    with session_scope() as s:
        w = s.scalar(select(UcmdbWrite).where(UcmdbWrite.run_id.is_(None)))
        assert w.estado == "ok" and w.verificado is True
        assert s.scalar(select(AuditLog).where(AuditLog.action == "ucmdb.editar")).details["campos"] == \
            ["Description", "IssuerName", "ValidTo"]


def test_date_format_fallback_and_history(setup):
    st, rid, fake, changes, webapp = setup
    fake.accepts = ("ms",)          # esta UCMDB só aceita milissegundos
    with TestClient(webapp.app) as c:
        c.get(f"/cmdb-final/{rid}", auth=AUTH)
        token = c.cookies["cw_csrf"]
        k = changes["renovado.exemplo.pt"]["chave"]
        c.post(f"/cmdb-final/{rid}/ucmdb", data={"csrf": token, "modo": "um", "chave": k}, auth=AUTH)
        tries = [b["properties"]["valid_to"] for m, p, b in fake.writes()]
        assert tries[0] == "2027-11-10T00:00:00" and isinstance(tries[-1], int)
        with session_scope() as s:
            w = s.scalar(select(UcmdbWrite).where(UcmdbWrite.chave == k))
            assert w.estado == "ok" and "milissegundos" in w.detalhe
        # a seguinte já começa pelo formato que funcionou
        n = len(fake.writes())
        k2 = changes["www.exemplo.pt"]["chave"]
        c.post(f"/cmdb-final/{rid}/ucmdb", data={"csrf": token, "modo": "um", "chave": k2}, auth=AUTH)
        assert len(fake.writes()) == n + 1 and isinstance(fake.writes()[-1][2]["properties"]["valid_to"], int)
        # nenhum formato aceite -> erro com os formatos tentados
        fake.accepts = ()
        k3 = changes["novo-avi.exemplo.pt"]["chave"]
        c.post(f"/cmdb-final/{rid}/ucmdb", data={"csrf": token, "modo": "um", "chave": k3}, auth=AUTH)
        with session_scope() as s:
            w = s.scalar(select(UcmdbWrite).where(UcmdbWrite.chave == k3))
            assert w.estado == "erro" and "Formatos de data tentados" in w.detalhe
        # histórico em Execuções e auditoria + exportação
        page = c.get("/jobs", auth=AUTH).text
        assert "Alterações na UCMDB" in page and "renovado.exemplo.pt" in page and "reconciliação #" in page
        assert "serial_number" in page and "<del>0A01</del>" in page
        csvt = c.get("/jobs/ucmdb.csv", auth=AUTH).content.decode("utf-8-sig")
        assert csvt.splitlines()[0].startswith("Quando;Quem;Origem") and "renovado.exemplo.pt" in csvt and "erro" in csvt
        # histórico de alterações na CMDB: filtros, por certificado e exportação filtrada
        page = c.get("/cmdb/historico", auth=AUTH).text
        assert "Histórico de alterações na CMDB" in page and "<b>3</b> registos" in page and "1 com erro" in page
        assert "renovado.exemplo.pt" in page and "novo-avi.exemplo.pt" in page
        page = c.get("/cmdb/historico?resultado=erro", auth=AUTH).text
        assert "novo-avi.exemplo.pt" in page and "renovado.exemplo.pt" not in page
        page = c.get("/cmdb/historico?q=RENOVADO", auth=AUTH).text
        assert "renovado.exemplo.pt" in page and "novo-avi.exemplo.pt" not in page
        with session_scope() as s:
            cid = s.scalar(select(UcmdbWrite).where(UcmdbWrite.chave == k)).ucmdb_id
        page = c.get(f"/cmdb/historico?ci={cid}", auth=AUTH).text
        assert "<b>1</b> registo com estes filtros" in page and "Abrir o certificado" in page
        assert "Nada com estes filtros" in c.get("/cmdb/historico?origem=edicao", auth=AUTH).text
        assert "<b>0</b>" in c.get("/cmdb/historico?de=2099-01-01", auth=AUTH).text
        assert c.get("/cmdb/historico?de=lixo&origem=xpto&n=-5", auth=AUTH).status_code == 200
        csvf = c.get("/cmdb/historico.csv?resultado=erro", auth=AUTH).content.decode("utf-8-sig")
        assert "novo-avi.exemplo.pt" in csvf and "renovado.exemplo.pt" not in csvf

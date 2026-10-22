"""Pedidos SMAX: imagens dos comentários, percurso de renovação, renovação na CMDB, fechar e reabrir."""
import base64
import copy
import json
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import select

from certwatch import cmdb_final as cf
from certwatch import renewal as rn
from certwatch.collectors import smax
from certwatch.db import session_scope, utcnow
from certwatch.jobs import ingest_cmdb
from certwatch.models import FinalRun, Renewal, SmaxFile, SmaxTicket
from certwatch.tickets import ingest_smax, store_comments
from tests.pki import pem
from tests.test_cmdb_final import CIS, live as no_live

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 40
AUTH = ("admin", "teste-admin-123")
OLD = datetime(2026, 11, 10, 12, tzinfo=timezone.utc)


def settings(env, **kw):
    return replace(env, smax_url="https://smax.test", smax_tenant="123", smax_user="svc", smax_password="pw",
                   smax_fields={"endpoint": "Ep_c", "expiry": "Exp_c", "env": "Amb_c", "type": "Tipo_c"}, **kw)


def ticket(tid="2001", endpoint="renovado.exemplo.pt", phase="Execute", expiry=OLD):
    opts = {"complexTypeProperties": [{"properties": {"Ep_c": endpoint, "Exp_c": int(expiry.timestamp() * 1000),
                                                      "Amb_c": ["NAME6_C"]}}]}
    return {"entity_type": "Change", "properties": {"Id": tid, "DisplayLabel": f"Renovar {endpoint}", "PhaseId": phase,
                                                    "UserOptions": json.dumps(opts),
                                                    "LastUpdateTime": int(utcnow().timestamp() * 1000)}}


class FakeSmax:
    """SMAX simulado: comentários com imagens, anexos, leitura de um pedido, comentários e bulk UPDATE."""

    def __init__(self, phase="Execute", update_ok=True, keep_phase=False):
        self.phase, self.update_ok, self.keep_phase = phase, update_ok, keep_phase
        self.calls, self.posted_comments, self.updates = [], [], []

    def handler(self, request: httpx.Request):
        p = request.url.path
        self.calls.append((request.method, p))
        if p == "/auth/authentication-endpoint/authenticate/login":
            return httpx.Response(200, text="tok" + "x" * 40)
        if p == "/rest/123/collaboration/comments/Change/2001" and request.method == "GET":
            body = ('<p>Renovado, segue print</p><img src="/rest/123/frs/image-store/img-1">'
                    f'<img src="data:image/png;base64,{base64.b64encode(PNG).decode()}">'
                    '<img src="https://outro.exemplo/x.png"><img src="/rest/123/ems/Person/1">')
            return httpx.Response(200, json=[
                {"Id": "c1", "CreateTime": int(utcnow().timestamp() * 1000), "Submitter": {"UserId": "77"},
                 "Body": body, "PrivacyType": "PUBLIC", "AttachmentIds": ["a9", "../x"]},
                {"Id": "c0", "IsSystem": True, "Body": "sistema"}])
        if p == "/rest/123/collaboration/comments/Change/2001" and request.method == "POST":
            self.posted_comments.append(json.loads(request.content))
            return httpx.Response(200, json={"Id": "c2"})
        if p == "/rest/123/frs/image-store/img-1":
            return httpx.Response(200, content=PNG, headers={"content-type": "image/png"})
        if p == "/rest/123/ces/attachment/a9":
            return httpx.Response(200, content=b"%PDF-1.4 relatorio",
                                  headers={"content-disposition": 'attachment; filename="relatorio renovacao.pdf"'})
        if p == "/rest/123/ems/Person/77":
            return httpx.Response(200, json={"entities": [{"properties": {"Name": "Rui Técnico"}}]})
        if p == "/rest/123/ems/Change/2001":
            return httpx.Response(200, json={"entities": [ticket(phase=self.phase)]})
        if p == "/rest/123/ems/bulk":
            body = json.loads(request.content)
            self.updates.append(body)
            assert body["operation"] == "UPDATE" and body["entities"][0]["properties"]["Id"] == "2001"
            if not self.update_ok:
                return httpx.Response(200, json={"entity_result_list": [{"completion_status": "FAILED",
                                                 "errorDetails": {"message": "Falta o campo CompletionCode"}}]})
            if not self.keep_phase:
                self.phase = body["entities"][0]["properties"].get("PhaseId", self.phase)
            return httpx.Response(200, json={"entity_result_list": [{"completion_status": "OK", "entity": {}}]})
        return httpx.Response(404)

    def client(self):
        return httpx.Client(base_url="https://smax.test", transport=httpx.MockTransport(self.handler))


def test_comment_images_and_attachments(env):
    s = settings(env)
    fake = FakeSmax()
    found, info = smax.fetch_comments(s, ["2001"], fake.client())
    assert len(found) == 1 and info["ficheiros_novos"] == 3 and info["ficheiros_com_erro"] == 2
    files = {f["ref"]: f for f in found[0]["files"]}
    assert files["/rest/123/frs/image-store/img-1"]["mime"] == "image/png"
    assert "fora do repositório" in files["https://outro.exemplo/x.png"]["error"]       # nunca pedido
    assert "fora do repositório" in files["/rest/123/ems/Person/1"]["error"]            # só ficheiros, não APIs
    assert files["anexo:a9"]["name"] == "relatorio renovacao.pdf" and files["anexo:a9"]["mime"] == "application/pdf"
    assert "anexo:../x" not in files
    assert not any(c[1] == "/rest/123/ems/Person/1" for c in fake.calls)
    with session_scope() as db:
        db.add(SmaxTicket(**smax.parse_entity(ticket(), s), fetched_at=utcnow()))
        store_comments(db, found, ["2001"])
    # segunda leitura: o que já está guardado não é descarregado de novo
    with session_scope() as db:
        known = {(f.comment_id, f.ref) for f in db.scalars(select(SmaxFile).where(SmaxFile.error == ""))}
    fake2 = FakeSmax()
    found2, info2 = smax.fetch_comments(s, ["2001"], fake2.client(), known_files=known)
    assert info2["ficheiros_novos"] == 0 and not any("image-store" in c[1] for c in fake2.calls)
    with session_scope() as db:
        store_comments(db, found2, ["2001"])
        assert db.query(SmaxFile).count() == 5

    from certwatch.web import app as webapp
    with TestClient(webapp.app) as c:
        page = c.get("/pedidos/smax/2001", auth=AUTH).text
        assert "Renovado, segue print" in page and "Rui Técnico" in page and "/pedidos/ficheiro/" in page
        assert "relatorio renovacao.pdf" in page and "Percurso da renovação" in page
        with session_scope() as db:
            img = db.scalar(select(SmaxFile).where(SmaxFile.mime == "image/png"))
            pdf = db.scalar(select(SmaxFile).where(SmaxFile.mime == "application/pdf"))
            ids = img.id, pdf.id
        r = c.get(f"/pedidos/ficheiro/{ids[0]}", auth=AUTH)
        assert r.content == PNG and r.headers["content-type"] == "image/png"
        assert "sandbox" in r.headers["content-security-policy"] and r.headers["x-content-type-options"] == "nosniff"
        r = c.get(f"/pedidos/ficheiro/{ids[1]}", auth=AUTH)
        assert r.headers["content-type"] == "application/octet-stream" and "attachment" in r.headers["content-disposition"]
        lst = c.get("/pedidos", auth=AUTH).text
        assert "/pedidos/smax/2001" in lst and "imagem(ns)/anexo(s)" in lst


def test_filters(env):
    s = settings(env)
    with session_scope() as db:
        ingest_smax(db, s, [smax.parse_entity(ticket("2001"), s), smax.parse_entity(ticket("2002", phase="Review"), s)])
        store_comments(db, [{"id": "k1", "ticket_id": "2001", "created_at": datetime(2026, 10, 20, 10, tzinfo=timezone.utc),
                             "author_id": "", "body": "visto", "privacy": "", "origin": "", "author": "", "files": []}], [])
    from certwatch.web import app as webapp
    with TestClient(webapp.app) as c:
        r = c.get("/pedidos", params={"vista": "todos", "fase": "Review"}, auth=AUTH).text
        assert "2002" in r and "/pedidos/smax/2001" not in r
        r = c.get("/pedidos", params={"vista": "todos", "desde": "2026-10-20", "ate": "2026-10-20"}, auth=AUTH).text
        assert "/pedidos/smax/2001" in r and "/pedidos/smax/2002" not in r
        r = c.get("/pedidos", params={"vista": "todos", "desde": "2026-10-21"}, auth=AUTH).text
        assert "/pedidos/smax/2001" not in r
        assert c.get("/pedidos", params={"desde": "ontem"}, auth=AUTH).status_code == 400
        r = c.get("/pedidos", params={"vista": "todos", "sem_comentario": "1"}, auth=AUTH).text
        assert "/pedidos/smax/2002" in r and "/pedidos/smax/2001" not in r


def _setup_pipeline(env, tmp_path):
    imp = tmp_path / "import"
    imp.mkdir()
    st = replace(settings(env), import_dir=imp, publish_dir=tmp_path, ucmdb_min_cis=1, final_sources=[], final_ct=False)
    with session_scope() as db:
        ingest_cmdb(db, st, [{"ucmdb_id": "u2", "global_id": "g2", "common_name": "renovado.exemplo.pt",
                              "valid_to": OLD.isoformat(), "issuer": "Corp CA01", "issuer_name": "Corp CA01"}])
        ingest_smax(db, st, [smax.parse_entity(ticket(), st)])
    return st


def test_pipeline_manual_renewal_to_cmdb(env, tmp_path):
    st = _setup_pipeline(env, tmp_path)
    with session_scope() as db:
        p = rn.pipeline(db.get(SmaxTicket, "2001"), st, rn.load_context(db))
    assert [x["done"] for x in p["steps"]] == [True, False, False, False, False] and p["current"] == "renovado"

    from certwatch.web import app as webapp
    webapp_get = webapp.get_settings
    webapp.get_settings = lambda: st
    try:
        with TestClient(webapp.app) as c:
            c.get("/pedidos/smax/2001", auth=AUTH)
            token = c.cookies["cw_csrf"]
            r = c.post("/pedidos/smax/2001/renovacao", data={"csrf": token, "modo": "manual", "validade": "2025-01-01"}, auth=AUTH)
            assert "tem de ser no futuro" in r.text
            r = c.post("/pedidos/smax/2001/renovacao", data={"csrf": token, "modo": "manual", "validade": "2027-11-10",
                                                             "serie": "0A02", "nota": "print no comentário"}, auth=AUTH)
            assert "Renovação registada" in r.text and "Nova validade 10-11-2027" in r.text
            # instalação confirmada à mão (sem servidor verificável)
            c.post("/pedidos/smax/2001/instalado", data={"csrf": token, "nota": "IIS interno, confirmado pelo Rui"}, auth=AUTH)
            # fechar sem a escrita ativa: recusado
            assert c.post("/pedidos/smax/2001/fase", data={"csrf": token, "acao": "fechar", "confirmo": "1"},
                          auth=AUTH).status_code == 409
    finally:
        webapp.get_settings = webapp_get

    with session_scope() as db:
        p = rn.pipeline(db.get(SmaxTicket, "2001"), st, rn.load_context(db))
        assert [x["done"] for x in p["steps"]] == [True, True, True, False, False] and p["current"] == "cmdb"
        run_id = cf.start_run(db, "admin").id
    # a renovação entra na geração dos ficheiros da CMDB, sem precisar de nenhum ficheiro de fonte
    cmdb = [dict(copy.deepcopy(CIS[1]))]
    cf.generate(run_id, st, fetch=lambda s2: (cf.build_cmdb_table(copy.deepcopy(cmdb), s2), []),
                live_factory=lambda s, s2: no_live, today=date(2026, 10, 22))
    with session_scope() as db:
        run = db.get(FinalRun, run_id)
        assert run.status == "pronto", run.error
        ch = run.changes[0]
        assert ch["cn"] == "renovado.exemplo.pt" and ch["fonte"] == "RENOVACAO" and ch["incluir"]
        assert "10-11-2027" in run.csv.decode() and '"0A02"' in run.csv.decode()
        p = rn.pipeline(db.get(SmaxTicket, "2001"), st, rn.load_context(db))
        assert p["steps"][3]["run"]["id"] == run_id and "por publicar" in p["steps"][3]["detail"]
        # depois de a UCMDB importar: a CMDB lida mostra a nova data
        ingest_cmdb(db, st, [{"ucmdb_id": "u2", "global_id": "g2", "common_name": "renovado.exemplo.pt",
                              "valid_to": "2027-11-10T12:00:00+00:00", "issuer": "Corp CA01", "issuer_name": "Corp CA01"}])
    with session_scope() as db:
        p = rn.pipeline(db.get(SmaxTicket, "2001"), st, rn.load_context(db))
        assert p["steps"][3]["done"] and p["current"] == "fechado"


def test_renewal_from_certificate_file(env, tmp_path, pki):
    st = _setup_pipeline(env, tmp_path)
    leaf, _ = pki.leaf("renovado.exemplo.pt", sans=["renovado.exemplo.pt"], days_valid=400)
    other, _ = pki.leaf("outro.exemplo.pt", sans=["outro.exemplo.pt"])
    from certwatch.web import app as webapp
    webapp_get = webapp.get_settings
    webapp.get_settings = lambda: st
    try:
        with TestClient(webapp.app) as c:
            c.get("/pedidos/smax/2001", auth=AUTH)
            token = c.cookies["cw_csrf"]
            r = c.post("/pedidos/smax/2001/renovacao", data={"csrf": token, "modo": "ficheiro"},
                       files={"ficheiro": ("x.txt", b"isto nao e um certificado")}, auth=AUTH)
            assert "não é um certificado X.509" in r.text
            r = c.post("/pedidos/smax/2001/renovacao", data={"csrf": token, "modo": "ficheiro"},
                       files={"ficheiro": ("o.pem", pem(other))}, auth=AUTH)
            assert "não para renovado.exemplo.pt" in r.text
            r = c.post("/pedidos/smax/2001/renovacao", data={"csrf": token, "modo": "ficheiro"},
                       files={"ficheiro": ("r.cer", leaf.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER))},
                       auth=AUTH)
            assert "Renovação registada" in r.text
    finally:
        webapp.get_settings = webapp_get
    with session_scope() as db:
        r = db.scalar(select(Renewal).where(Renewal.active.is_(True)))
        assert r.origin == "ficheiro" and r.issuer == "Exemplo Teste Issuing CA" and r.serial == format(leaf.serial_number, "X")
        run_id = cf.start_run(db, "admin").id
    cmdb = [dict(copy.deepcopy(CIS[1]))]
    cf.generate(run_id, st, fetch=lambda s2: (cf.build_cmdb_table(copy.deepcopy(cmdb), s2), []),
                live_factory=lambda s, s2: no_live, today=date(2026, 10, 22))
    with session_scope() as db:
        run = db.get(FinalRun, run_id)
        ch = run.changes[0]
        # os dados do próprio certificado também atualizam o emissor
        assert {f["campo"] for f in ch["campos"]} >= {"ValidTo", "SerialNumber", "Issuer", "IssuerName"}
        assert "Validado pelo ficheiro do certificado" in ch["descricao"]


def test_close_and_reopen(env):
    s = settings(env, smax_update_enabled=True)
    fake = FakeSmax()
    res = smax.change_phase(s, "2001", "fechar", "Renovado e CMDB atualizada.", fake.client())
    assert res["ok"] and res["fase_antes"] == "Execute" and res["fase_depois"] == "Close"
    assert fake.updates[0]["entities"][0]["properties"] == {"Id": "2001", "PhaseId": "Close"}
    # o comentário é escrito antes de fechar
    order = [c for c in fake.calls if c[0] == "POST" and c[1] != "/auth/authentication-endpoint/authenticate/login"]
    assert order[0][1].endswith("/comments/Change/2001") and order[1][1].endswith("/ems/bulk")
    assert fake.posted_comments[0]["Body"] == "<p>Renovado e CMDB atualizada.</p>"
    assert fake.posted_comments[0]["PrivacyType"] == "INTERNAL"
    # reabrir: o comentário vem depois
    res = smax.change_phase(s, "2001", "reabrir", "Reaberto: falta instalar.", fake.client())
    assert res["ok"] and res["fase_depois"] == "Execute"
    # campos obrigatórios em falta: motivo do SMAX
    res = smax.change_phase(replace(s, smax_close_fields={"PhaseId": "Close"}), "2001", "fechar", "", FakeSmax(update_ok=False).client())
    assert not res["ok"] and res["estado"] == "falhou" and "CompletionCode" in res["motivo"]
    # aceite mas a fase não mudou (regra do modelo de change)
    res = smax.change_phase(s, "2001", "fechar", "", FakeSmax(keep_phase=True).client())
    assert not res["ok"] and "a fase ficou Execute" in res["motivo"]


def test_close_route_updates_local_ticket(env, monkeypatch):
    st = settings(env, smax_update_enabled=True)
    with session_scope() as db:
        ingest_smax(db, st, [smax.parse_entity(ticket(), st)])
    from certwatch.web import app as webapp
    monkeypatch.setattr(webapp, "get_settings", lambda: st)
    fake = FakeSmax()
    real = smax.change_phase
    monkeypatch.setattr(smax, "change_phase", lambda st_, tid, acao, com="", c=None: real(st_, tid, acao, com, fake.client()))
    with TestClient(webapp.app) as c:
        c.get("/pedidos/smax/2001", auth=AUTH)
        token = c.cookies["cw_csrf"]
        assert c.post("/pedidos/smax/2001/fase", data={"csrf": token, "acao": "fechar"}, auth=AUTH).status_code == 400
        r = c.post("/pedidos/smax/2001/fase", data={"csrf": token, "acao": "fechar", "confirmo": "1",
                                                     "comentario": "Fechado."}, auth=AUTH)
        assert "Pedido fechado no SMAX: fase Close. Comentário registado." in r.text and "Reabrir no SMAX" in r.text
    with session_scope() as db:
        assert db.get(SmaxTicket, "2001").phase == "Close"

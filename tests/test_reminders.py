"""Próximos 90 dias: certificados e segredos por data, quem tem cada pedido, mudar no SMAX e no Atalaia, lembretes."""
import json
from dataclasses import replace
from datetime import timedelta
from urllib.parse import unquote

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from certwatch import reminders as rm
from certwatch.db import session_scope
from certwatch.models import AuditLog, CertOwner, Reminder, SmaxTicket, Team
from tests.test_dashboard import NOW, setup
from tests.test_report import FakeSMTP

AUTH = ("admin", "teste-admin-123")


class FakeSmax:
    """SMAX simulado: login, procura de grupos e pessoas, ler e atualizar um pedido, comentar."""

    def __init__(self):
        self.calls = []
        self.ticket = {"Id": "2001", "DisplayLabel": "Renovar comped.exemplo.pt", "PhaseId": "Execute", "UserOptions": "{}"}
        self.owner = {"OwnedByGroup": {"Name": "Sistemas"}, "OwnedByPerson": {"Name": "Ana"}}

    def handler(self, request: httpx.Request):
        p, m = request.url.path, request.method
        self.calls.append((m, p, dict(request.url.params), request.content))
        if p.endswith("/authenticate/login"):
            return httpx.Response(200, text="T" * 40)
        if p == "/rest/1/ems/PersonGroup":
            f = request.url.params["filter"]
            if "startswith" in f and "Redes" in f:
                return httpx.Response(200, json={"entities": [{"properties": {"Id": "g9", "Name": "Redes e Comunicações"}}]})
            return httpx.Response(200, json={"entities": []})
        if p == "/rest/1/ems/Person":
            f = request.url.params["filter"]
            people = [{"Id": "p1", "Name": "Ana", "Email": "ana@exemplo.pt"}, {"Id": "p7", "Name": "Rui Costa", "Email": "rui@exemplo.pt"}]
            hits = [x for x in people if x["Name"].lower().startswith(f.split("'")[1].lower())]
            return httpx.Response(200, json={"entities": [{"properties": x} for x in hits]})
        if p == "/rest/1/ems/Change/2001" and m == "GET":
            return httpx.Response(200, json={"entities": [{"properties": self.ticket, "related_properties": self.owner}]})
        if p == "/rest/1/ems/bulk":
            props = json.loads(request.content)["entities"][0]["properties"]
            if props.get("OwnedByGroup") == "g9":
                self.owner["OwnedByGroup"] = {"Name": "Redes e Comunicações"}
            if props.get("OwnedByPerson") == "p7":
                self.owner["OwnedByPerson"] = {"Name": "Rui Costa"}
            return httpx.Response(200, json={"entity_result_list": [{"completion_status": "OK"}]})
        if "/collaboration/comments/" in p:
            return httpx.Response(200, json={})
        return httpx.Response(404)

    def client(self):
        return httpx.Client(base_url="https://smax.test", transport=httpx.MockTransport(self.handler))


@pytest.fixture()
def st(env):
    s = setup(env)
    return replace(s, smax_user="svc", smax_password="pw", smax_update_enabled=True, smtp_host="smtp.exemplo.pt",
                   smtp_from="atalaia@exemplo.pt", smtp_security="none", report_allowed_domains=["exemplo.pt"])


def test_rows_sorted_and_checks(st):
    with session_scope() as s:
        s.add(Team(name="Redes", smax_group="Redes e Comunicações"))
    with session_scope() as s:
        tid = s.scalar(select(Team.id))
        from certwatch import owners as ow
        ow.set_owner(s, "comped.exemplo.pt", tid, "Rui Costa", "rui@exemplo.pt", "admin")
    with session_scope() as s:
        rows = rm.rows(s, st, 90)
    names = [r["nome"] for r in rows]
    assert names == ["semped.exemplo.pt", "Pagamentos API - 0123456789abcdef0123", "comped.exemplo.pt", "parado.exemplo.pt"]
    by = {r["nome"]: r for r in rows}
    assert by["semped.exemplo.pt"]["checks"] == ["sem_pedido"] and by["Pagamentos API - 0123456789abcdef0123"]["tipo"] == "api"
    assert set(by["comped.exemplo.pt"]["checks"]) == {"grupo_diferente", "pessoa_diferente"}
    assert by["comped.exemplo.pt"]["pedido"]["grupo"] == "Sistemas" and by["comped.exemplo.pt"]["pedido"]["responsavel"] == "Ana"
    assert by["parado.exemplo.pt"]["checks"] == ["sem_dono"]
    with session_scope() as s:
        assert "expirou.exemplo.pt" in [r["nome"] for r in rm.rows(s, st, 90, expired=True)]


def test_page_assign_both_and_reminders(st, monkeypatch):
    from certwatch.web import app as webapp
    fake = FakeSmax()
    monkeypatch.setattr(webapp, "get_settings", lambda: st)
    monkeypatch.setattr(webapp, "SMAX_CLIENT", fake.client())
    monkeypatch.setattr(webapp, "SMTP_FACTORY", FakeSMTP)
    with session_scope() as s:
        s.add(Team(name="Redes", smax_group="Redes e Comunicações", email="redes@exemplo.pt"))
    FakeSMTP.sent = []
    with TestClient(webapp.app) as c:
        page = c.get("/a-expirar", auth=AUTH).text
        assert "Próximos 90 dias" in page and "comped.exemplo.pt" in page and "Sistemas" in page and ">Ana<" in page
        assert page.index("semped.exemplo.pt") < page.index("comped.exemplo.pt")              # por data
        assert "Sem pedido aberto" in page and 'value="c:comped.exemplo.pt" checked' in page
        csv = c.get("/a-expirar/exportar", auth=AUTH).content.decode("utf-8-sig")
        assert csv.splitlines()[0].startswith("Expira;Dias;Nome") and "Sistemas" in csv
        token = c.cookies["cw_csrf"]
        # procurar e passar o pedido 2001 para Redes / Rui Costa, no SMAX e no Atalaia
        pg = c.get("/a-expirar/pedido/2001?g=Redes&p=Rui", auth=AUTH).text
        assert "Redes e Comunicações" in pg and "rui@exemplo.pt" in pg and "(equipa Redes)" in pg
        r = c.post("/a-expirar/pedido/2001", data={"csrf": token, "grupo": "g9|Redes e Comunicações",
                                                    "pessoa": "p7|Rui Costa|rui@exemplo.pt", "atalaia": "1", "confirmo": "1",
                                                    "comentario": "Reatribuído"}, auth=AUTH)
        assert "passado no SMAX para Redes e Comunicações · Rui Costa" in r.text and "equipa Redes" in r.text
        bulk = [json.loads(b) for m, p, q, b in fake.calls if p == "/rest/1/ems/bulk"]
        assert bulk[0]["entities"][0]["properties"] == {"Id": "2001", "OwnedByGroup": "g9", "OwnedByPerson": "p7"}
        with session_scope() as s:
            t = s.get(SmaxTicket, "2001")
            assert (t.owner_group, t.owner_person) == ("Redes e Comunicações", "Rui Costa")
            o = s.scalar(select(CertOwner).where(CertOwner.cn_norm == "comped.exemplo.pt"))
            assert o.person == "Rui Costa" and o.person_email == "rui@exemplo.pt" and o.team_id is not None
            assert s.scalar(select(AuditLog).where(AuditLog.action == "pedido.atribuir")) is not None
        # sem confirmação não faz nada
        assert "Confirme" in c.post("/a-expirar/pedido/2001", data={"csrf": token, "grupo": "g9|x"}, auth=AUTH).text
        # lembretes: pré-visualização com o email lido do SMAX, depois envio
        prev = c.post("/a-expirar/lembretes", data={"csrf": token, "k": ["c:comped.exemplo.pt", "c:parado.exemplo.pt"]}, auth=AUTH).text
        assert "Rui Costa" in prev and 'value="rui@exemplo.pt"' in prev and "Ana" in prev and 'value="ana@exemplo.pt"' in prev
        names = __import__("re").findall(r'name="pessoa_(\d+)" value="([^"]+)"', prev)
        assert len(names) == 2
        form = {"csrf": token, "k": ["c:comped.exemplo.pt", "c:parado.exemplo.pt"], "confirmo": "1",
                "assunto": "Lembrete | {n} a expirar", "intro": "Por favor reveja."}
        for i, n in names:
            form[f"pessoa_{i}"], form[f"enviar_{i}"] = n, "1"
            form[f"email_{i}"] = "rui@exemplo.pt" if n == "Rui Costa" else "ana@gmail.com"     # fora do domínio: falha
        r = c.post("/a-expirar/lembretes/enviar", data=form, auth=AUTH, follow_redirects=False)
        assert r.status_code == 303
        aviso = unquote(r.cookies.get("cw_aviso") or r.headers.get("set-cookie", ""))
        assert "1 lembrete(s) enviado(s)" in aviso and "Ana" in aviso
        msgs = [m for m in FakeSMTP.sent if not isinstance(m, tuple)]
        assert len(msgs) == 1 and msgs[0]["To"] == "rui@exemplo.pt" and msgs[0]["Subject"] == "Lembrete | 1 a expirar"
        body = msgs[0].get_body(("html",)).get_content()
        assert "comped.exemplo.pt" in body and "Por favor reveja." in body and "2001" in body
        with session_scope() as s:
            rs = {r.person: r for r in s.scalars(select(Reminder))}
        assert rs["Rui Costa"].ok and rs["Rui Costa"].tickets == ["2001"] and not rs["Ana"].ok
        assert "Lembrete" in c.get("/a-expirar", auth=AUTH).text            # a coluna do último lembrete


def test_assign_requires_update_enabled(st, monkeypatch):
    from certwatch.web import app as webapp
    monkeypatch.setattr(webapp, "get_settings", lambda: replace(st, smax_update_enabled=False))
    monkeypatch.setattr(webapp, "SMAX_CLIENT", FakeSmax().client())
    with TestClient(webapp.app) as c:
        c.get("/a-expirar", auth=AUTH)
        r = c.post("/a-expirar/pedido/2001", data={"csrf": c.cookies["cw_csrf"], "grupo": "g9|Redes", "confirmo": "1"}, auth=AUTH)
        assert "CERTWATCH_SMAX_UPDATE_ENABLED" in r.text
        # só no Atalaia continua a ser possível
        r = c.post("/a-expirar/pedido/2001", data={"csrf": c.cookies["cw_csrf"], "so_atalaia": "1", "pessoa_nome": "Rui Costa",
                                                    "pessoa_email": "rui@exemplo.pt", "confirmo": "1"}, auth=AUTH)
        assert "Dono no Atalaia atualizado" in r.text


def test_answer_link_proposals_and_approval(st, monkeypatch):
    import re
    from certwatch.models import ChangeProposal, ReminderLink
    from certwatch.web import app as webapp
    fake = FakeSmax()
    monkeypatch.setattr(webapp, "get_settings", lambda: st)
    monkeypatch.setattr(webapp, "SMAX_CLIENT", fake.client())
    monkeypatch.setattr(webapp, "SMTP_FACTORY", FakeSMTP)
    FakeSMTP.sent = []
    with TestClient(webapp.app) as c:
        c.get("/a-expirar", auth=AUTH)
        token = c.cookies["cw_csrf"]
        prev = c.post("/a-expirar/lembretes", data={"csrf": token, "k": ["c:comped.exemplo.pt", "c:parado.exemplo.pt"]}, auth=AUTH).text
        (i, name), = re.findall(r'name="pessoa_(\d+)" value="([^"]+)"', prev)
        c.post("/a-expirar/lembretes/enviar", data={"csrf": token, "k": ["c:comped.exemplo.pt", "c:parado.exemplo.pt"],
                                                     "confirmo": "1", f"pessoa_{i}": name, f"enviar_{i}": "1",
                                                     f"email_{i}": "ana@exemplo.pt"}, auth=AUTH)
        msg = [m for m in FakeSMTP.sent if not isinstance(m, tuple)][-1]
        body = msg.get_body(("html",)).get_content()
        link = re.search(r'href="(http[^"?]+/r/([^"?]+))"', body)
        assert link and "É meu" in body and "Passar para…" in body
        code = link.group(2)
        with session_scope() as s:
            ln = s.scalar(select(ReminderLink))
            assert ln.token_hash != code and code not in str(ln.__dict__) and ln.tickets == ["2001", "2002"]
        # a pessoa abre o link (sem login) e responde
        anon = TestClient(webapp.app)
        page = anon.get(f"/r/{code}?pedido=2001&acao=mudar")
        assert page.status_code == 200 and "Pedidos de renovação atribuídos a Ana" in page.text and "comped.exemplo.pt" in page.text
        assert page.headers["referrer-policy"] == "no-referrer"
        assert anon.get("/r/inventado").status_code == 404
        r = anon.post(f"/r/{code}", data={"csrf": anon.cookies["cw_csrf"], "acao_2001": "mudar", "grupo_2001": "Redes e Comunicações",
                                           "pessoa_2001": "Rui Costa", "email_2001": "rui@exemplo.pt", "nota_2001": "é da rede",
                                           "acao_2002": "confirma"})
        assert "2 respostas registadas" in r.text
        # responder outra vez substitui a resposta pendente
        anon.post(f"/r/{code}", data={"csrf": anon.cookies["cw_csrf"], "acao_2002": "confirma", "nota_2002": "em curso"})
        with session_scope() as s:
            props = {p.ticket_id: p for p in s.scalars(select(ChangeProposal))}
        assert len(props) == 2 and props["2002"].note == "em curso" and props["2001"].was_person == "Ana"
        # nada mudou no SMAX ainda
        assert not [p for m, p, q, b in fake.calls if p == "/rest/1/ems/bulk"]
        page = c.get("/a-expirar", auth=AUTH).text
        assert "Respostas por rever" in page and "Pede para passar a Redes e Comunicações" in page
        lst = c.get("/a-expirar/propostas", auth=AUTH).text
        assert "é da rede" in lst and "Aprovar e mudar" in lst
        # «é meu»: confirmar
        c.post(f"/a-expirar/propostas/{props['2002'].id}/aprovar", data={"csrf": token}, auth=AUTH)
        assert "Confirmado por Ana" in c.get("/a-expirar", auth=AUTH).text
        # «passar para»: abre a mudança já com a procura feita; guardar aprova a proposta
        r = c.post(f"/a-expirar/propostas/{props['2001'].id}/aprovar", data={"csrf": token}, auth=AUTH, follow_redirects=False)
        assert r.status_code == 303 and "/a-expirar/pedido/2001?" in r.headers["location"] and "proposta=" in r.headers["location"]
        pg = c.get(r.headers["location"], auth=AUTH).text
        assert "Resposta de Ana" in pg and "Redes e Comunicações" in pg and 'name="proposta"' in pg
        r = c.post("/a-expirar/pedido/2001", data={"csrf": token, "grupo": "g9|Redes e Comunicações", "pessoa": "p7|Rui Costa|rui@exemplo.pt",
                                                    "atalaia": "1", "confirmo": "1", "proposta": str(props["2001"].id)}, auth=AUTH)
        assert "Proposta de Ana aprovada" in r.text
        with session_scope() as s:
            assert {p.status for p in s.scalars(select(ChangeProposal))} == {"aplicada"}
        # o link deixa de valer quando expira
        with session_scope() as s:
            s.scalar(select(ReminderLink)).expires_at = NOW - timedelta(days=1)
        assert anon.get(f"/r/{code}").status_code == 404
    from certwatch.web.app import _RedactInvite
    import logging
    rec = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, '%s - "%s %s"', ("1.2.3.4", "GET", f"/r/{code}?pedido=1"), None)
    _RedactInvite().filter(rec)
    assert code not in rec.getMessage()

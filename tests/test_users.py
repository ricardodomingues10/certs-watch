"""Contas de utilizador: convites por email, palavras-passe (só hash), papéis e disposição do Painel por pessoa."""
import logging
import re
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from certwatch import config, users as us
from certwatch.db import session_scope
from certwatch.models import AuditLog, User, UserPref

AUTH = ("admin", "teste-admin-123")
PW = "uma frase bem comprida"


@pytest.fixture()
def web(env):
    from certwatch.web import app as webapp
    from certwatch.web import security
    security.forget_logins()
    security._FAILS.clear()
    webapp.invalidate_nav()
    with TestClient(webapp.app) as c:
        yield c


def csrf(c):
    return c.cookies.get("cw_csrf")


def invite(c, email, papel="operador", nome="Ana Silva"):
    c.get("/utilizadores", auth=AUTH)
    r = c.post("/utilizadores/convidar", data={"csrf": csrf(c), "email": email, "nome": nome, "papel": papel}, auth=AUTH)
    assert r.status_code == 200, r.text
    m = re.search(r'value="(http[^"]+/convite/([^"]+))"', r.text)
    assert m, "sem email configurado o link aparece na página"
    return m.group(2), r.text


def accept(c, token, pw=PW):
    page = c.get(f"/convite/{token}")
    assert page.status_code == 200
    return c.post(f"/convite/{token}", data={"csrf": csrf(c), "palavra": pw, "confirmar": pw})


def test_password_hash_and_rules(env):
    h = us.hash_password(PW)
    assert h.startswith("scrypt$") and PW not in h and h != us.hash_password(PW)       # sal diferente em cada hash
    assert us.verify_password(PW, h) and not us.verify_password(PW + "x", h) and not us.verify_password(PW, "lixo")
    assert us.password_problems("curta", "ana@exemplo.pt", env)
    assert us.password_problems("ana-e-mais-coisas-1", "ana@exemplo.pt", env)           # contém o nome de utilizador
    assert us.password_problems("aaaaaaaaaaaaaaaa", "x@exemplo.pt", env)                # pouca variedade
    assert not us.password_problems(PW, "ana@exemplo.pt", env)


def test_invite_accept_and_login(web):
    token, page = invite(web, " Ana.Silva@Exemplo.pt ")
    assert "O email não está configurado" in page and "ana.silva@exemplo.pt" in page and "Convite enviado" in page
    with session_scope() as s:
        u = s.scalar(select(User))
        assert u.email == "ana.silva@exemplo.pt" and u.status == "convidado" and u.password_hash == ""
        assert u.token_hash == us.token_hash(token) and token not in u.token_hash                 # só o hash do código
        assert not any(token in str(a.details) + a.target for a in s.scalars(select(AuditLog)))  # nem na auditoria
    assert web.get("/", auth=("ana.silva@exemplo.pt", PW)).status_code == 401                    # ainda sem palavra-passe
    bad = web.post(f"/convite/{token}", data={"csrf": csrf(web), "palavra": PW, "confirmar": PW + "!"})
    assert bad.status_code == 400 and "não são iguais" in bad.text
    ok = accept(web, token)
    assert ok.status_code == 200 and "Palavra-passe definida" in ok.text
    assert web.get(f"/convite/{token}").status_code == 404                                       # uma só vez
    r = web.get("/", auth=("Ana.Silva@exemplo.pt", PW))
    assert r.status_code == 200 and 'href="/conta"' in r.text and "ana.silva@exemplo.pt" in r.text
    assert 'href="/utilizadores"' not in r.text                                                  # menu só para administradores
    assert web.get("/utilizadores", auth=("ana.silva@exemplo.pt", PW)).status_code == 403
    with session_scope() as s:
        u = s.scalar(select(User))
        assert u.status == "ativo" and us.verify_password(PW, u.password_hash) and u.token_hash == ""


def test_invite_by_email(web, monkeypatch):
    from certwatch.web import app as webapp
    st = replace(config.get_settings(), smtp_host="smtp.exemplo.pt", smtp_from="atalaia@exemplo.pt",
                 public_url="https://atalaia.exemplo.pt", client_name="Santa Casa")
    monkeypatch.setattr(webapp, "get_settings", lambda: st)
    sent = []
    monkeypatch.setattr(webapp.rp, "send", lambda settings, msgs: sent.extend(msgs))
    web.get("/utilizadores", auth=AUTH)
    r = web.post("/utilizadores/convidar", data={"csrf": csrf(web), "email": "rui@exemplo.pt", "nome": "Rui", "papel": "leitura"},
                 auth=AUTH)
    assert r.status_code == 200 and "Convite enviado para rui@exemplo.pt" in r.text and "/convite/" not in r.text
    assert len(sent) == 1 and sent[0]["To"] == "rui@exemplo.pt" and "Convite para o Atalaia Cert" in sent[0]["Subject"]
    body = sent[0].get_body(("html",)).get_content()
    assert "https://atalaia.exemplo.pt/convite/" in body and "Só consulta" in body and "admin" in body


def test_roles_actions_and_guards(web):
    token, _ = invite(web, "chefe@exemplo.pt", papel="admin")
    accept(web, token)
    boss = ("chefe@exemplo.pt", PW)
    assert web.get("/utilizadores", auth=boss).status_code == 200
    t2, _ = invite(web, "leitor@exemplo.pt", papel="leitura")
    accept(web, t2)
    reader = ("leitor@exemplo.pt", PW)
    with session_scope() as s:
        ids = {u.email: u.id for u in s.scalars(select(User))}
    # só consulta: vê, mas não altera nada (exceto o tema, a sua palavra-passe e a disposição do Painel)
    assert web.get("/certificados", auth=reader).status_code == 200
    assert web.post("/jobs/pipeline", data={"csrf": csrf(web)}, auth=reader).status_code == 403
    assert web.post("/tema", data={"csrf": csrf(web), "tema": "relatorio", "next": "/"}, auth=reader,
                    follow_redirects=False).status_code == 303
    # um administrador não se altera a si próprio
    web.get("/utilizadores", auth=boss)
    r = web.post(f"/utilizadores/{ids['chefe@exemplo.pt']}/desativar", data={"csrf": csrf(web)}, auth=boss)
    assert r.status_code == 400 and "sua própria conta" in r.text
    # mudar o papel, desativar (deixa de entrar logo), ativar, novo link, apagar
    r = web.post(f"/utilizadores/{ids['leitor@exemplo.pt']}/papel", data={"csrf": csrf(web), "papel": "operador"}, auth=boss)
    assert r.status_code == 200 and "passou a operador" in r.text
    assert web.post("/jobs/pipeline", data={"csrf": csrf(web), "next": "/jobs"}, auth=reader,
                    follow_redirects=False).status_code == 303
    web.post(f"/utilizadores/{ids['leitor@exemplo.pt']}/desativar", data={"csrf": csrf(web)}, auth=boss)
    assert web.get("/", auth=reader).status_code == 401
    web.post(f"/utilizadores/{ids['leitor@exemplo.pt']}/ativar", data={"csrf": csrf(web)}, auth=boss)
    assert web.get("/", auth=reader).status_code == 200
    r = web.post(f"/utilizadores/{ids['leitor@exemplo.pt']}/link", data={"csrf": csrf(web)}, auth=boss)
    new = re.search(r"/convite/([^\"]+)\"", r.text).group(1)
    assert "palavra-passe nova" in r.text
    assert web.get(f"/convite/{new}").status_code == 200 and "Palavra-passe nova" in web.get(f"/convite/{new}").text
    assert accept(web, new, "outra frase bem comprida").status_code == 200
    assert web.get("/", auth=reader).status_code == 401 and web.get("/", auth=("leitor@exemplo.pt", "outra frase bem comprida")).status_code == 200
    web.post(f"/utilizadores/{ids['leitor@exemplo.pt']}/apagar", data={"csrf": csrf(web)}, auth=boss)
    with session_scope() as s:
        assert {u.email for u in s.scalars(select(User))} == {"chefe@exemplo.pt"}
        acts = [a.action for a in s.scalars(select(AuditLog).where(AuditLog.action.like("utilizador.%")))]
    assert {"utilizador.convidar", "utilizador.papel", "utilizador.desativar", "utilizador.ativar", "utilizador.link",
            "utilizador.apagar", "utilizador.palavra_passe"} <= set(acts)
    # convidar outra vez quem já tem conta não estraga a conta
    r = web.post("/utilizadores/convidar", data={"csrf": csrf(web), "email": "chefe@exemplo.pt", "papel": "leitura"}, auth=boss)
    assert r.status_code == 400 and "já tem conta" in r.text


def test_own_password_and_lockout(web):
    token, _ = invite(web, "ana@exemplo.pt")
    accept(web, token)
    me = ("ana@exemplo.pt", PW)
    assert "Mudar a palavra-passe" in web.get("/conta", auth=me).text
    r = web.post("/conta/palavra-passe", data={"csrf": csrf(web), "atual": "errada", "nova": "nova frase comprida", "confirmar": "nova frase comprida"}, auth=me)
    assert r.status_code == 400 and "atual não está certa" in r.text
    r = web.post("/conta/palavra-passe", data={"csrf": csrf(web), "atual": PW, "nova": "nova frase comprida", "confirmar": "nova frase comprida"}, auth=me)
    assert r.status_code == 200 and "Palavra-passe alterada" in r.text
    assert web.get("/", auth=me).status_code == 401                                             # 1.ª tentativa falhada
    for _ in range(9):
        assert web.get("/", auth=("ana@exemplo.pt", "errada")).status_code == 401
    assert web.get("/", auth=("ana@exemplo.pt", "nova frase comprida")).status_code == 429       # bloqueada 15 min
    assert web.get("/", auth=AUTH).status_code == 200                                            # os outros continuam


def test_invite_token_not_in_access_log(env):
    from certwatch.web.app import _RedactInvite
    rec = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, '%s - "%s %s HTTP/%s" %d',
                            ("1.2.3.4", "GET", "/convite/AbC-123_xyz", "1.1", 200), None)
    _RedactInvite().filter(rec)
    assert "AbC-123_xyz" not in rec.getMessage() and "/convite/***" in rec.getMessage()


def test_panel_layout_per_user(web):
    page = web.get("/", auth=AUTH).text
    order = re.findall(r'data-card="([a-z0-9]+)"', page)
    assert order[:3] == ["cobertura", "resumo", "mal"] and 'class="pn-cell w-4 h-0" data-card="cobertura"' in page
    assert "Organizar o painel" in page
    assert web.post("/painel/disposicao", json={"order": ["nis2"]}, auth=AUTH).status_code == 403   # sem CSRF
    r = web.post("/painel/disposicao", json={"order": ["nis2", "mal", "inventado"], "w": {"nis2": 6, "mal": 99}, "h": {"mal": 10}},
                 headers={"X-CSRF-Token": csrf(web)}, auth=AUTH)
    assert r.status_code == 200
    page = web.get("/", auth=AUTH).text
    order = re.findall(r'data-card="([a-z0-9]+)"', page)
    assert order[:2] == ["nis2", "mal"] and len(order) == 10                                   # os outros seguem-se
    assert 'class="pn-cell w-6 h-0" data-card="nis2"' in page and 'class="pn-cell w-4 h-10" data-card="mal"' in page
    with session_scope() as s:
        assert s.scalar(select(UserPref)).username == "admin"
    web.post("/painel/disposicao", json={"reset": True}, headers={"X-CSRF-Token": csrf(web)}, auth=AUTH)
    assert re.findall(r'data-card="([a-z0-9]+)"', web.get("/", auth=AUTH).text)[0] == "cobertura"

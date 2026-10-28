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


def login(c, email, pw, nxt="/"):
    c.get("/entrar")
    return c.post("/entrar", data={"csrf": csrf(c), "email": email, "palavra": pw, "next": nxt}, follow_redirects=False)


def test_login_page_session_and_logout(web):
    r = web.get("/certificados", headers={"Accept": "text/html"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/entrar?next=%2Fcertificados"
    page = web.get("/entrar?next=/certificados").text
    assert "Entrar" in page and 'href="/registar"' in page and 'href="/recuperar"' in page
    bad = login(web, "admin", "errada")
    assert bad.status_code == 401 and "Email ou palavra-passe errados" in bad.text and "cw_sessao" not in bad.cookies
    ok = login(web, "admin", "teste-admin-123", "/certificados")
    assert ok.status_code == 303 and ok.headers["location"] == "/certificados"
    token = ok.cookies["cw_sessao"]
    with session_scope() as s:
        from certwatch.models import LoginSession
        ls = s.scalar(select(LoginSession))
        assert ls.username == "admin" and ls.token_hash == us.token_hash(token) and token not in ls.token_hash
    page = web.get("/certificados")                                                    # o cookie basta, sem basic auth
    assert page.status_code == 200 and 'action="/sair"' in page.text
    assert login(web, "//evil.example", "x", "https://evil.example").status_code == 401
    web.post("/sair", data={"csrf": csrf(web)}, follow_redirects=False)
    web.cookies.set("cw_sessao", token)                                                 # o código antigo já não vale
    assert web.get("/certificados").status_code == 401


def test_signup_needs_admin_approval(web, monkeypatch):
    from certwatch.web import app as webapp
    st = replace(config.get_settings(), smtp_host="smtp.exemplo.pt", smtp_from="atalaia@exemplo.pt", signup_domains=("scml.pt",))
    monkeypatch.setattr(webapp, "get_settings", lambda: st)
    sent = []
    monkeypatch.setattr(webapp.rp, "send", lambda settings, msgs: sent.extend(msgs))
    # há um administrador com email para receber o aviso
    with session_scope() as s:
        boss = User(email="chefe@scml.pt", name="Chefe", role="admin", status="ativo")
        us.set_password(boss, PW)
        s.add(boss)
    web.get("/registar")
    form = {"csrf": csrf(web), "nome": "Marta Lopes", "email": "marta@gmail.com", "equipa": "Sistemas Centrais",
            "palavra": PW, "confirmar": PW}
    r = web.post("/registar", data=form)
    assert r.status_code == 400 and "só emails de @scml.pt" in r.text
    r = web.post("/registar", data={**form, "email": "Marta@SCML.pt"})
    assert r.status_code == 200 and "Pedido enviado" in r.text
    assert sent and sent[-1]["To"] == "chefe@scml.pt" and "marta@scml.pt" in sent[-1]["Subject"]
    with session_scope() as s:
        u = us.by_email(s, "marta@scml.pt")
        assert u.status == "pendente" and u.request_note == "Sistemas Centrais" and PW not in u.password_hash
    assert web.post("/registar", data={**form, "email": "marta@scml.pt"}).status_code == 400         # já há pedido
    wait = login(web, "marta@scml.pt", PW)
    assert wait.status_code == 403 and "à espera de aprovação" in wait.text
    assert web.get("/", auth=("marta@scml.pt", PW)).status_code == 401
    # o administrador vê o pedido e aprova-o com um papel
    page = web.get("/utilizadores", auth=AUTH).text
    assert "Pedidos de acesso" in page and "Sistemas Centrais" in page
    with session_scope() as s:
        uid = us.by_email(s, "marta@scml.pt").id
    assert web.post(f"/utilizadores/{uid}/aprovar", data={"csrf": csrf(web), "papel": ""}, auth=AUTH).status_code == 400
    r = web.post(f"/utilizadores/{uid}/aprovar", data={"csrf": csrf(web), "papel": "operador"}, auth=AUTH)
    assert r.status_code == 200 and "aprovado como operador" in r.text and "Foi avisado por email" in r.text
    assert sent[-1]["To"] == "marta@scml.pt" and "aprovado" in sent[-1]["Subject"]
    ok = login(web, "marta@scml.pt", PW)
    assert ok.status_code == 303
    with session_scope() as s:
        u = us.by_email(s, "marta@scml.pt")
        assert u.status == "ativo" and u.role == "operador" and u.approved_by == "admin"
    # recusar apaga o pedido
    web.post("/registar", data={**form, "email": "outro@scml.pt", "nome": "Outro"})
    with session_scope() as s:
        oid = us.by_email(s, "outro@scml.pt").id
    web.post(f"/utilizadores/{oid}/recusar", data={"csrf": csrf(web)}, auth=AUTH)
    with session_scope() as s:
        assert us.by_email(s, "outro@scml.pt") is None


def test_signup_can_be_turned_off(web, monkeypatch):
    from certwatch.web import app as webapp
    st = replace(config.get_settings(), signup=False)
    monkeypatch.setattr(webapp, "get_settings", lambda: st)
    assert 'href="/registar"' not in web.get("/entrar").text
    r = web.post("/registar", data={"csrf": csrf(web), "nome": "X", "email": "x@exemplo.pt", "palavra": PW, "confirmar": PW})
    assert r.status_code == 400 and "desligados" in r.text


def test_recover_and_test_email(web, monkeypatch):
    from certwatch.web import app as webapp
    token, _ = invite(web, "ana@exemplo.pt")
    accept(web, token)
    st = replace(config.get_settings(), smtp_host="smtp.exemplo.pt", smtp_from="atalaia@exemplo.pt")
    monkeypatch.setattr(webapp, "get_settings", lambda: st)
    sent = []
    monkeypatch.setattr(webapp.rp, "send", lambda settings, msgs: sent.extend(msgs))
    web.get("/recuperar")
    same = [web.post("/recuperar", data={"csrf": csrf(web), "email": e}).text for e in ("ana@exemplo.pt", "ninguem@exemplo.pt")]
    assert all("Se existir uma conta ativa" in t for t in same)                       # não revela quem tem conta
    assert len(sent) == 1 and sent[0]["To"] == "ana@exemplo.pt"
    link = re.search(r'href="(http[^"]+/convite/[^"]+)"', sent[0].get_body(("html",)).get_content()).group(1)
    assert "pedido, na página de entrada" in sent[0].get_body(("html",)).get_content()
    new = link.rsplit("/", 1)[1]
    assert accept(web, new, "outra frase bem comprida").status_code == 200
    assert login(web, "ana@exemplo.pt", "outra frase bem comprida").status_code == 303
    # teste de email: envia ou mostra o erro do servidor de email
    r = web.post("/utilizadores/testar-email", data={"csrf": csrf(web), "para": "admin@exemplo.pt"}, auth=AUTH)
    assert "Email de teste enviado para admin@exemplo.pt" in r.text and sent[-1]["To"] == "admin@exemplo.pt"

    def boom(settings, msgs):
        raise webapp.rp.ReportError("O servidor de email recusou ou não respondeu: SMTPRecipientsRefused")
    monkeypatch.setattr(webapp.rp, "send", boom)
    r = web.post("/utilizadores/testar-email", data={"csrf": csrf(web), "para": "admin@exemplo.pt"}, auth=AUTH)
    assert "não foi enviado" in r.text and "SMTPRecipientsRefused" in r.text


def test_disabling_closes_sessions(web):
    token, _ = invite(web, "rui@exemplo.pt")
    accept(web, token)
    ok = login(web, "rui@exemplo.pt", PW)
    sess = ok.cookies["cw_sessao"]
    assert web.get("/certificados").status_code == 200
    with session_scope() as s:
        uid = us.by_email(s, "rui@exemplo.pt").id
    web.post(f"/utilizadores/{uid}/desativar", data={"csrf": csrf(web)}, auth=AUTH)
    web.cookies.set("cw_sessao", sess)
    assert web.get("/certificados").status_code == 401

"""Verificação em dois passos (TOTP): ativar, entrar, códigos de recuperação, repor e obrigar."""
import base64
import re
import time
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from certwatch import config, mfa
from certwatch.db import session_scope
from certwatch.models import AuditLog, LoginSession, User
from tests.test_users import AUTH, PW, accept, csrf, invite, login


@pytest.fixture()
def web(env):
    from certwatch.web import app as webapp
    from certwatch.web import security
    security.forget_logins()
    security._MEMORY.clear()
    webapp.invalidate_nav()
    with TestClient(webapp.app) as c:
        yield c


def secret_of(email):
    with session_scope() as s:
        u = s.scalar(select(User).where(User.email == email))
        return mfa.unseal(config.get_settings(), u.totp_secret)


def now_code(email, offset=0):
    return mfa.code_at(secret_of(email), int(time.time() // mfa.STEP) + offset)


def enable(web, email="ana@exemplo.pt"):
    """Convida, entra e ativa os dois passos; devolve os códigos de recuperação."""
    token, _ = invite(web, email)
    accept(web, token)
    assert login(web, email, PW).status_code == 303
    r = web.post("/conta/dois-passos/iniciar", data={"csrf": csrf(web), "atual": PW})
    assert r.status_code == 200 and "Confirmar e ativar" in r.text
    key = re.search(r'mfa-key">([A-Z2-7 ]+)<', r.text).group(1).replace(" ", "")
    assert key == secret_of(email) and 'src="data:image/svg+xml' in r.text
    r = web.post("/conta/dois-passos/ativar", data={"csrf": csrf(web), "codigo": now_code(email)})
    assert r.status_code == 200 and "Guarde estes códigos de recuperação" in r.text
    codes = re.findall(r"<li>([a-z0-9]{5}-[a-z0-9]{5})</li>", r.text)
    assert len(codes) == 10
    return codes


def test_rfc6238_vector_and_single_use():
    s = base64.b32encode(b"12345678901234567890").decode()
    assert mfa.code_at(s, 59 // 30) == "287082"                      # RFC 6238, T=59, SHA-1 (6 últimos dígitos)
    assert mfa.verify(s, "287 082", 0, now=59) == 1
    assert mfa.verify(s, "287082", 1, now=59) is None                 # o mesmo código não serve duas vezes
    assert mfa.verify(s, "287082", 0, now=59 + 30) == 1               # um intervalo de tolerância
    assert mfa.verify(s, "287082", 0, now=59 + 90) is None
    assert mfa.verify(s, "abcdef", 0, now=59) is None and mfa.verify("", "287082", 0, now=59) is None
    codes, hashes = mfa.new_recovery_codes()
    assert len(set(codes)) == 10 and codes[0] not in "".join(hashes)
    left = mfa.use_recovery(hashes, codes[3].upper())
    assert left is not None and len(left) == 9 and mfa.use_recovery(left, codes[3]) is None
    assert mfa.uri(s, "ana@exemplo.pt").startswith("otpauth://totp/Atalaia%20Cert:ana%40exemplo.pt?secret=" + s)


def test_enable_then_login_needs_the_code(web):
    codes = enable(web)
    with session_scope() as s:
        u = s.scalar(select(User).where(User.email == "ana@exemplo.pt"))
        assert u.totp_on and secret_of("ana@exemplo.pt") not in u.totp_secret          # a chave fica cifrada
        assert all(c not in str(u.totp_codes) for c in codes)                          # dos códigos, só o sha256
    web.post("/sair", data={"csrf": csrf(web)})
    # a palavra-passe certa já não chega: nem pela página, nem por basic authentication
    r = login(web, "ana@exemplo.pt", PW, "/certificados")
    assert r.status_code == 303 and r.headers["location"].startswith("/entrar/codigo?next=")
    assert "cw_sessao" not in r.headers.get("set-cookie", "")
    assert web.get("/certificados", headers={"Accept": "text/html"}, follow_redirects=False).headers["location"].startswith("/entrar")
    r = web.get("/", auth=("ana@exemplo.pt", PW))
    assert r.status_code == 401 and "dois passos" in r.text
    assert "Código de verificação" in web.get("/entrar/codigo").text
    r = web.post("/entrar/codigo", data={"csrf": csrf(web), "codigo": "000000", "next": "/certificados"})
    assert r.status_code == 401 and "Código errado" in r.text
    # o código do passo de ativação já foi gasto; o seguinte serve, uma vez
    code = now_code("ana@exemplo.pt", 1)
    r = web.post("/entrar/codigo", data={"csrf": csrf(web), "codigo": code, "next": "/certificados"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/certificados"
    assert web.get("/conta").status_code == 200
    with session_scope() as s:
        assert [x.stage for x in s.scalars(select(LoginSession))] == [""]             # a entrada pendente foi apagada
        a = s.scalars(select(AuditLog).where(AuditLog.action == "sessao.entrar").order_by(AuditLog.id.desc())).first()
        assert a.details == {"segundo_passo": "totp"}
    web.post("/sair", data={"csrf": csrf(web)})
    login(web, "ana@exemplo.pt", PW)
    r = web.post("/entrar/codigo", data={"csrf": csrf(web), "codigo": code}, follow_redirects=False)
    assert r.status_code == 401                                                        # repetido: recusado


def test_recovery_code_works_once_and_wrong_codes_lock(web):
    codes = enable(web)
    web.post("/sair", data={"csrf": csrf(web)})
    login(web, "ana@exemplo.pt", PW)
    r = web.post("/entrar/codigo", data={"csrf": csrf(web), "codigo": codes[0]}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/conta?recuperacao=1")
    assert "ficam 9" in web.get("/conta?recuperacao=1").text
    web.post("/sair", data={"csrf": csrf(web)})
    login(web, "ana@exemplo.pt", PW)
    assert web.post("/entrar/codigo", data={"csrf": csrf(web), "codigo": codes[0]}).status_code == 401
    for _ in range(9):
        assert web.post("/entrar/codigo", data={"csrf": csrf(web), "codigo": "123456"}).status_code == 401
    r = web.post("/entrar/codigo", data={"csrf": csrf(web), "codigo": codes[1]})
    assert r.status_code == 429 and "Demasiados códigos errados" in r.text
    # sem o cookie da entrada pendente não há segundo passo
    web.cookies.delete("cw_2passo")
    assert web.get("/entrar/codigo", follow_redirects=False).headers["location"] == "/entrar"


def test_start_and_disable_need_the_password_and_admin_can_reset(web):
    token, _ = invite(web, "ana@exemplo.pt")
    accept(web, token)
    login(web, "ana@exemplo.pt", PW)
    r = web.post("/conta/dois-passos/iniciar", data={"csrf": csrf(web), "atual": "errada"})
    assert r.status_code == 400 and "palavra-passe não está certa" in r.text
    web.post("/conta/dois-passos/iniciar", data={"csrf": csrf(web), "atual": PW})
    r = web.post("/conta/dois-passos/ativar", data={"csrf": csrf(web), "codigo": "000000"})
    assert r.status_code == 400 and "Confirmar e ativar" in r.text                    # mostra a mesma chave outra vez
    with session_scope() as s:
        assert not s.scalar(select(User).where(User.email == "ana@exemplo.pt")).totp_on
    web.post("/conta/dois-passos/ativar", data={"csrf": csrf(web), "codigo": now_code("ana@exemplo.pt")})
    r = web.post("/conta/dois-passos/desligar", data={"csrf": csrf(web), "atual": PW, "codigo": "000000"})
    assert r.status_code == 400 and "código não está certo" in r.text
    # o administrador repõe (telemóvel perdido): as sessões fecham e a pessoa volta a entrar só com a palavra-passe
    page = web.get("/utilizadores", auth=AUTH).text
    assert "Repor os dois passos" in page and "dois passos" in page
    with session_scope() as s:
        uid = s.scalar(select(User.id).where(User.email == "ana@exemplo.pt"))
    r = web.post(f"/utilizadores/{uid}/dois-passos", data={"csrf": csrf(web)}, auth=AUTH)
    assert "foi reposta" in r.text
    with session_scope() as s:
        u = s.get(User, uid)
        assert not u.totp_on and u.totp_secret == "" and u.totp_codes is None
        assert s.scalar(select(LoginSession).where(LoginSession.username == "ana@exemplo.pt")) is None
        assert s.scalars(select(AuditLog).where(AuditLog.action == "utilizador.dois_passos")).all()[-1].details == {"passo": "repor"}
    web.cookies.delete("cw_sessao")
    r = login(web, "ana@exemplo.pt", PW)
    assert r.status_code == 303 and r.headers["location"] == "/"
    # desligar pela própria pessoa: palavra-passe e código
    web.post("/conta/dois-passos/iniciar", data={"csrf": csrf(web), "atual": PW})
    web.post("/conta/dois-passos/ativar", data={"csrf": csrf(web), "codigo": now_code("ana@exemplo.pt")})
    r = web.post("/conta/dois-passos/desligar", data={"csrf": csrf(web), "atual": PW, "codigo": now_code("ana@exemplo.pt", 1)})
    assert r.status_code == 200 and "desligada" in r.text


def test_required_sends_people_to_enable_it_first(web, monkeypatch):
    from certwatch.web import app as webapp
    from certwatch.web import security
    token, _ = invite(web, "ana@exemplo.pt")
    accept(web, token)
    st = replace(config.get_settings(), mfa_required=True)
    monkeypatch.setattr(webapp, "get_settings", lambda: st)
    monkeypatch.setattr(security, "get_settings", lambda: st)
    assert web.get("/", auth=("ana@exemplo.pt", PW)).status_code == 401                # basic: nunca, sendo obrigatória
    assert web.get("/", auth=AUTH).status_code == 200                                  # a conta de recurso continua
    login(web, "ana@exemplo.pt", PW)
    r = web.get("/certificados", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/conta?dois-passos=1")
    assert "Nesta instalação é obrigatória" in web.get("/conta").text
    r = web.post("/jobs/pipeline", data={"csrf": csrf(web)}, headers={"Accept": "text/html"}, follow_redirects=False)
    assert r.status_code in (303, 403)                                                 # nada corre antes de ativar
    web.post("/conta/dois-passos/iniciar", data={"csrf": csrf(web), "atual": PW})
    web.post("/conta/dois-passos/ativar", data={"csrf": csrf(web), "codigo": now_code("ana@exemplo.pt")})
    security.forget_logins()
    assert web.get("/certificados").status_code == 200
    r = web.post("/conta/dois-passos/desligar", data={"csrf": csrf(web), "atual": PW, "codigo": now_code("ana@exemplo.pt", 1)})
    assert r.status_code == 400 and "obrigatória" in r.text

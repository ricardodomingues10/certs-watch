"""Autenticação, proteção CSRF e cabeçalhos de segurança."""
from __future__ import annotations

import hashlib
import secrets
import time
from datetime import timedelta
from urllib.parse import quote

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from ..config import get_settings

_basic = HTTPBasic(realm="Atalaia Cert", auto_error=False)   # basic authentication fica para scripts (curl -u)
CSRF_COOKIE = "cw_csrf"
SESSION_COOKIE = "cw_sessao"


# Verificações bem-sucedidas guardadas 60 s (o scrypt demora ~50 ms; o navegador manda as credenciais em cada pedido).
# Alterar, desativar ou apagar um utilizador limpa a cache, por isso as mudanças valem logo.
_OK_CACHE: dict[str, tuple[float, str, str]] = {}
_SESSION_CACHE: dict[str, tuple[float, str, str, bool]] = {}
FAIL_LIMIT, FAIL_WINDOW = 10, 900          # 10 tentativas falhadas em 15 min bloqueiam esse utilizador nesse endereço
READONLY_POST = {"/tema", "/painel/disposicao", "/conta/palavra-passe", "/conta/calendario", "/sair",
                 "/conta/dois-passos/iniciar", "/conta/dois-passos/ativar", "/conta/dois-passos/desligar"}
# com CERTWATCH_MFA_REQUIRED, quem ainda não ativou os dois passos só chega a estas páginas
MFA_SETUP_PATHS = ("/conta", "/sair", "/tema", "/marca/", "/estado/")


class PermissionDenied(Exception):
    """A pessoa entrou, mas o papel dela não deixa fazer isto. A aplicação mostra um aviso na página onde estava
    (em vez de abrir uma página de erro)."""

    def __init__(self, user: str, role: str, action: str):
        super().__init__(action)
        self.user, self.role, self.action = user, role, action


# o que cada endereço faz, para o aviso dizer que ação foi recusada
ACTIONS = [("/jobs", "executar trabalhos"), ("/pedidos", "criar ou alterar pedidos no SMAX"),
           ("/cmdb-final", "atualizar a CMDB"), ("/ucmdb", "escrever na UCMDB"), ("/cmdb", "alterar a CMDB"),
           ("/findings", "decidir sobre alertas"), ("/endpoints", "alterar servidores"),
           ("/descoberta", "triar certificados encontrados na internet"), ("/relatorio", "preparar ou enviar relatórios"),
           ("/utilizadores", "gerir os utilizadores"), ("/certificados", "alterar certificados"), ("/apis", "alterar APIs")]


def action_of(path: str) -> str:
    return next((label for prefix, label in ACTIONS if path == prefix or path.startswith(prefix + "/")), "fazer esta alteração")


def forget_logins() -> None:
    _OK_CACHE.clear()
    _SESSION_CACHE.clear()


def _deny(request: Request, msg: str = "Credenciais inválidas"):
    """Sem sessão: uma página aberta no navegador vai para a página de entrada; o resto recebe 401."""
    if request.method == "GET" and "text/html" in request.headers.get("accept", ""):
        nxt = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        raise HTTPException(status.HTTP_303_SEE_OTHER, "Entre primeiro", headers={"Location": "/entrar?next=" + quote(nxt, safe="")})
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, msg)


def client_ip(request: Request) -> str:
    """De onde vem o pedido. O X-Forwarded-For só conta quando quem liga é um proxy de confiança
    (CERTWATCH_TRUSTED_PROXIES); nesse caso vale o endereço mais à direita que não é um desses proxies. Sem proxies
    de confiança o cabeçalho é ignorado: quem liga diretamente podia escrever lá um endereço diferente em cada
    tentativa e nunca chegar ao limite."""
    import ipaddress
    peer = request.client.host if request.client else ""
    nets = get_settings().trusted_proxies
    if not nets or not peer:
        return peer

    def trusted(ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in ipaddress.ip_network(n) for n in nets)

    if not trusted(peer):
        return peer
    for hop in reversed([h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]):
        try:
            ipaddress.ip_address(hop)
        except ValueError:
            return peer                      # cabeçalho estragado: não se confia em nada do que lá está
        if not trusted(hop):
            return hop
    return peer


# Tentativas falhadas: ficam na base de dados (valem depois de um reinício e para todos os processos) e são apagadas
# quando saem da janela. Se a base não responder, conta-se em memória, com um teto, para o limite nunca desaparecer.
ACCOUNT_LIMIT = 50                         # tentativas falhadas na mesma conta, venham de onde vierem
_MEMORY: dict[str, list[float]] = {}
_MEMORY_MAX = 5000
_last_prune = float("-inf")            # time.monotonic() pode começar perto de zero


def _kh(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()


def _memory_count(kh: str) -> int:
    now = time.monotonic()
    return len([t for t in _MEMORY.get(kh, []) if now - t < FAIL_WINDOW])


def too_many(key: str, limit: int = FAIL_LIMIT) -> bool:
    from sqlalchemy import func, select
    from ..db import session_scope, utcnow
    from ..models import LoginFailure
    kh = _kh(key)
    try:
        with session_scope() as db:
            n = db.scalar(select(func.count(LoginFailure.id)).where(
                LoginFailure.key_hash == kh, LoginFailure.at >= utcnow() - timedelta(seconds=FAIL_WINDOW))) or 0
    except Exception:
        n = 0
    return max(n, _memory_count(kh)) >= limit


def note_failure(key: str) -> None:
    global _last_prune
    from sqlalchemy import delete
    from ..db import session_scope, utcnow
    from ..models import LoginFailure
    kh = _kh(key)
    try:
        with session_scope() as db:
            db.add(LoginFailure(key_hash=kh))
            if time.monotonic() - _last_prune > 300:            # limpeza: no máximo de 5 em 5 minutos
                _last_prune = time.monotonic()
                db.execute(delete(LoginFailure).where(LoginFailure.at < utcnow() - timedelta(seconds=FAIL_WINDOW)))
    except Exception:
        now = time.monotonic()
        if len(_MEMORY) >= _MEMORY_MAX:
            _MEMORY.clear()
        _MEMORY[kh] = [t for t in _MEMORY.get(kh, []) if now - t < FAIL_WINDOW] + [now]


def clear_failures(key: str) -> None:
    from sqlalchemy import delete
    from ..db import session_scope
    from ..models import LoginFailure
    kh = _kh(key)
    _MEMORY.pop(kh, None)
    try:
        with session_scope() as db:
            db.execute(delete(LoginFailure).where(LoginFailure.key_hash == kh))
    except Exception:
        pass


def _login_keys(username: str, ip: str) -> tuple[str, str]:
    name = username.strip().lower()
    return f"{name}|{ip}", f"conta|{name}"


def login_blocked(username: str, ip: str) -> bool:
    """Dois limites em 15 minutos: 10 tentativas falhadas desta conta a partir deste endereço, e 50 nesta conta a
    partir de qualquer endereço (para quem muda de endereço a cada tentativa)."""
    pair, account = _login_keys(username, ip)
    return too_many(pair) or too_many(account, ACCOUNT_LIMIT)


def login_failed(username: str, ip: str) -> None:
    pair, account = _login_keys(username, ip)
    note_failure(pair)
    note_failure(account)


def login_ok(username: str, ip: str) -> None:
    """Entrou: esquece as falhas deste endereço. As da conta ficam até saírem da janela, para uma entrada legítima
    não dar mais tentativas a quem está a adivinhar a partir de outro lado."""
    clear_failures(_login_keys(username, ip)[0])


def check_login(username: str, password: str) -> tuple[str, str] | None:
    return _check(username, password)


def _session_user(token: str) -> tuple[str, str, bool] | None:
    """(papel, utilizador, tem dois passos) da sessão do cookie, se ainda vale (fecha ao fim de
    CERTWATCH_SESSION_HOURS sem uso). Uma sessão à espera do código (stage) ainda não é uma sessão."""
    from ..db import as_utc, session_scope, utcnow
    from ..models import LoginSession, User
    from ..users import token_hash
    from sqlalchemy import select
    key = token_hash(token)
    hit = _SESSION_CACHE.get(key)
    if hit and time.monotonic() - hit[0] < 30:
        return hit[1], hit[2], hit[3]
    s = get_settings()
    mfa = True
    with session_scope() as db:
        ls = db.scalar(select(LoginSession).where(LoginSession.token_hash == key))
        if ls is None or ls.stage:
            return None
        now = utcnow()
        if as_utc(ls.expires_at) < now or now - as_utc(ls.last_seen) > timedelta(hours=s.session_hours):
            db.delete(ls)
            return None
        if ls.username == s.admin_user:
            if not s.admin_password:
                return None
            role = "admin"
        else:
            u = db.scalar(select(User).where(User.email == ls.username))
            if u is None or u.status != "ativo":
                db.delete(ls)
                return None
            role, mfa = u.role, bool(u.totp_on)
            if u.last_seen is None or now - as_utc(u.last_seen) > timedelta(minutes=5):
                u.last_seen = now
        if now - as_utc(ls.last_seen) > timedelta(minutes=5):
            ls.last_seen = now
        name = ls.username
    if len(_SESSION_CACHE) > 500:
        _SESSION_CACHE.clear()
    _SESSION_CACHE[key] = (time.monotonic(), role, name, mfa)
    return role, name, mfa


def has_second_factor(username: str) -> bool:
    from ..db import session_scope
    from ..users import by_email
    try:
        with session_scope() as db:
            u = by_email(db, username)
            return bool(u is not None and u.totp_on)
    except Exception:
        return True                          # na dúvida, não se entra só com a palavra-passe


def _check(username: str, password: str) -> tuple[str, str] | None:
    """(papel, nome) se as credenciais são válidas: a conta de recurso do servidor ou um utilizador ativo."""
    s = get_settings()
    if s.admin_password and secrets.compare_digest(username.encode(), s.admin_user.encode()) \
            and secrets.compare_digest(password.encode(), s.admin_password.encode()):
        return "admin", s.admin_user
    from ..db import session_scope, utcnow, as_utc
    from ..users import by_email, verify_password
    key = hashlib.sha256(f"{username.lower()}\0{password}".encode()).hexdigest()
    hit = _OK_CACHE.get(key)
    if hit and time.monotonic() - hit[0] < 60:
        return hit[1], hit[2]
    with session_scope() as db:
        u = by_email(db, username)
        if u is None or u.status != "ativo" or not u.password_hash or not verify_password(password, u.password_hash):
            return None
        now = utcnow()
        if u.last_seen is None or now - as_utc(u.last_seen) > timedelta(minutes=5):
            u.last_seen = now
        role, name = u.role, u.email
    if len(_OK_CACHE) > 500:
        _OK_CACHE.clear()
    _OK_CACHE[key] = (time.monotonic(), role, name)
    return role, name


def current_user(request: Request, credentials: HTTPBasicCredentials | None = Depends(_basic)) -> str:
    found, via = None, ""
    if credentials is not None:
        ip = client_ip(request)
        if login_blocked(credentials.username, ip):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Demasiadas tentativas falhadas. Tente daqui a 15 minutos.")
        found = _check(credentials.username, credentials.password)
        if found is None:
            if not get_settings().admin_password and not _any_user():
                raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Palavra-passe de administração não configurada")
            login_failed(credentials.username, ip)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credenciais inválidas")
        settings = get_settings()
        if found[1] != settings.admin_user and (settings.mfa_required or has_second_factor(found[1])):
            # a basic authentication só leva a palavra-passe: não pode ser o atalho à volta do segundo passo
            raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                "Esta conta tem verificação em dois passos: entre pela página de entrada.")
        via, mfa = "basic", True
    else:
        token = request.cookies.get(SESSION_COOKIE)
        hit = _session_user(token) if token and len(token) < 100 else None
        via = "sessao"
        if hit is None:
            _deny(request)
        found, mfa = hit[:2], hit[2]
    role, name = found
    request.state.user, request.state.role, request.state.via = name, role, via
    if not mfa and get_settings().mfa_required and not request.url.path.startswith(MFA_SETUP_PATHS):
        # obrigatório e ainda por ativar: a pessoa só chega à sua conta, onde o ativa
        if request.method == "GET":
            raise HTTPException(status.HTTP_303_SEE_OTHER, "Ative a verificação em dois passos",
                                headers={"Location": "/conta?dois-passos=1#dois-passos"})
        raise PermissionDenied(name, role, "usar a aplicação antes de ativar a verificação em dois passos")
    if role == "leitura" and request.method not in ("GET", "HEAD", "OPTIONS") and request.url.path not in READONLY_POST:
        raise PermissionDenied(name, role, action_of(request.url.path))
    return name


def require_admin(request: Request, user: str = Depends(current_user)) -> str:
    if getattr(request.state, "role", "") != "admin":
        raise PermissionDenied(user, getattr(request.state, "role", ""), "gerir os utilizadores")
    return user


def _any_user() -> bool:
    from sqlalchemy import select
    from ..db import session_scope
    from ..models import User
    try:
        with session_scope() as db:
            return db.scalar(select(User.id).where(User.status == "ativo").limit(1)) is not None
    except Exception:
        return False


def check_csrf(request: Request, token: str | None) -> None:
    cookie = request.cookies.get(CSRF_COOKIE)
    if not cookie or not token or not secrets.compare_digest(cookie, token):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Token CSRF inválido")


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
                               "frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",          # só a própria aplicação vê de que página se veio (para voltar lá com um aviso)
    "Cache-Control": "no-store",
}
SVG_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox"


def host_of(header: str) -> str:
    """O nome no cabeçalho Host, sem a porta (aceita [::1]:8088)."""
    h = (header or "").strip().lower()
    if h.startswith("["):
        return h[1:].split("]", 1)[0]
    return h.rsplit(":", 1)[0].rstrip(".") if ":" in h else h.rstrip(".")


def host_allowed(header: str) -> bool:
    return host_of(header) in get_settings().allowed_hosts


async def security_middleware(request: Request, call_next):
    if not host_allowed(request.headers.get("host", "")):
        # Um Host que não é o da aplicação nunca chega às páginas: os links dos emails (recuperar a palavra-passe,
        # convite, lembrete) são feitos com o endereço do pedido e não podem apontar para o servidor de outra pessoa.
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(
            "Endereço não reconhecido. Para chegar ao Atalaia Cert por este nome, defina CERTWATCH_PUBLIC_URL "
            "(ou CERTWATCH_ALLOWED_HOSTS) no .env do servidor.", status_code=400)
    token = request.cookies.get(CSRF_COOKIE) or secrets.token_urlsafe(32)
    request.state.csrf = token
    response = await call_next(request)
    if request.cookies.get(CSRF_COOKIE) != token:
        response.set_cookie(CSRF_COOKIE, token, httponly=True, samesite="strict",
                            secure=get_settings().cookie_secure, path="/")
    if request.url.path.startswith("/static/") and request.url.path.endswith(".svg"):
        # os SVG da aplicação (o logótipo) trazem a animação em <style> e a fotografia em data:; nunca correm scripts
        response.headers["Content-Security-Policy"] = SVG_CSP
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    return response

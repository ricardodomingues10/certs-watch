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
_SESSION_CACHE: dict[str, tuple[float, str, str]] = {}
_FAILS: dict[str, list[float]] = {}
FAIL_LIMIT, FAIL_WINDOW = 10, 900          # 10 tentativas falhadas em 15 min bloqueiam esse utilizador nesse endereço
READONLY_POST = {"/tema", "/painel/disposicao", "/conta/palavra-passe", "/sair"}


def forget_logins() -> None:
    _OK_CACHE.clear()
    _SESSION_CACHE.clear()


def _deny(request: Request, msg: str = "Credenciais inválidas"):
    """Sem sessão: uma página aberta no navegador vai para a página de entrada; o resto recebe 401."""
    if request.method == "GET" and "text/html" in request.headers.get("accept", ""):
        nxt = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        raise HTTPException(status.HTTP_303_SEE_OTHER, "Entre primeiro", headers={"Location": "/entrar?next=" + quote(nxt, safe="")})
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, msg)


def too_many(key: str) -> bool:
    now = time.monotonic()
    return len([t for t in _FAILS.get(key, []) if now - t < FAIL_WINDOW]) >= FAIL_LIMIT


def note_failure(key: str) -> None:
    now = time.monotonic()
    _FAILS[key] = [t for t in _FAILS.get(key, []) if now - t < FAIL_WINDOW] + [now]


def clear_failures(key: str) -> None:
    _FAILS.pop(key, None)


def check_login(username: str, password: str) -> tuple[str, str] | None:
    return _check(username, password)


def _session_user(token: str) -> tuple[str, str] | None:
    """(papel, utilizador) da sessão do cookie, se ainda vale (fecha ao fim de CERTWATCH_SESSION_HOURS sem uso)."""
    from ..db import as_utc, session_scope, utcnow
    from ..models import LoginSession, User
    from ..users import token_hash
    from sqlalchemy import select
    key = token_hash(token)
    hit = _SESSION_CACHE.get(key)
    if hit and time.monotonic() - hit[0] < 30:
        return hit[1], hit[2]
    s = get_settings()
    with session_scope() as db:
        ls = db.scalar(select(LoginSession).where(LoginSession.token_hash == key))
        if ls is None:
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
            role = u.role
            if u.last_seen is None or now - as_utc(u.last_seen) > timedelta(minutes=5):
                u.last_seen = now
        if now - as_utc(ls.last_seen) > timedelta(minutes=5):
            ls.last_seen = now
        name = ls.username
    if len(_SESSION_CACHE) > 500:
        _SESSION_CACHE.clear()
    _SESSION_CACHE[key] = (time.monotonic(), role, name)
    return role, name


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
        who = f"{credentials.username.lower()}|{request.client.host if request.client else ''}"
        if too_many(who):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Demasiadas tentativas falhadas. Tente daqui a 15 minutos.")
        found = _check(credentials.username, credentials.password)
        if found is None:
            if not get_settings().admin_password and not _any_user():
                raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Palavra-passe de administração não configurada")
            note_failure(who)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credenciais inválidas")
        clear_failures(who)
        via = "basic"
    else:
        token = request.cookies.get(SESSION_COOKIE)
        found = _session_user(token) if token and len(token) < 100 else None
        via = "sessao"
        if found is None:
            _deny(request)
    role, name = found
    request.state.user, request.state.role, request.state.via = name, role, via
    if role == "leitura" and request.method not in ("GET", "HEAD", "OPTIONS") and request.url.path not in READONLY_POST:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "A sua conta é só de consulta: não pode alterar nada.")
    return name


def require_admin(request: Request, user: str = Depends(current_user)) -> str:
    if getattr(request.state, "role", "") != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Só um administrador pode gerir os utilizadores.")
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
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
SVG_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox"


async def security_middleware(request: Request, call_next):
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

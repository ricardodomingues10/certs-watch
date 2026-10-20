"""Autenticação, proteção CSRF e cabeçalhos de segurança."""
from __future__ import annotations

import secrets

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from ..config import get_settings

_basic = HTTPBasic(realm="certwatch")
CSRF_COOKIE = "cw_csrf"


def current_user(credentials: HTTPBasicCredentials = Depends(_basic)) -> str:
    s = get_settings()
    if not s.admin_password:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Palavra-passe de administração não configurada")
    ok_user = secrets.compare_digest(credentials.username.encode(), s.admin_user.encode())
    ok_pass = secrets.compare_digest(credentials.password.encode(), s.admin_password.encode())
    if not (ok_user and ok_pass):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credenciais inválidas",
                            headers={"WWW-Authenticate": 'Basic realm="certwatch"'})
    return credentials.username


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


async def security_middleware(request: Request, call_next):
    token = request.cookies.get(CSRF_COOKIE) or secrets.token_urlsafe(32)
    request.state.csrf = token
    response = await call_next(request)
    if request.cookies.get(CSRF_COOKIE) != token:
        response.set_cookie(CSRF_COOKIE, token, httponly=True, samesite="strict",
                            secure=get_settings().cookie_secure, path="/")
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    return response

"""Contas de utilizador: quem pode entrar, com que papel, e os convites por email.

- Cada pessoa entra com o seu email e a sua palavra-passe (basic authentication do navegador).
- A palavra-passe nunca é guardada nem registada: só o hash scrypt (sal aleatório, parâmetros no próprio hash).
- O convite é um link com um código aleatório de 256 bits, válido CERTWATCH_INVITE_HOURS horas (72) e de uma só
  utilização; na base de dados fica só o sha256 do código. O mesmo mecanismo serve para definir uma palavra-passe nova.
- A conta "admin" definida no servidor (secrets/admin_password) continua a funcionar como conta de recurso.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import re
import secrets
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import Settings
from .db import as_utc, utcnow
from .models import User

ROLES = {"admin": "Administrador", "operador": "Operador", "leitura": "Só consulta"}
ROLE_HELP = {
    "admin": "Tudo, incluindo gerir os utilizadores e convidar pessoas.",
    "operador": "Tudo menos gerir utilizadores: criar pedidos, atualizar a CMDB, executar, decidir alertas.",
    "leitura": "Vê todas as páginas, mas não altera nada.",
}
STATUS = {"convidado": "Convite enviado", "ativo": "Ativo", "desativado": "Desativado"}
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")

_N, _R, _P = 2 ** 14, 8, 1          # scrypt: ~16 MB e ~50 ms por verificação


class UserError(ValueError):
    """Pedido inválido (mensagem para mostrar a quem fez o pedido)."""


def norm_email(email: str) -> str:
    return (email or "").strip().lower()


def valid_email(email: str) -> bool:
    return len(email) <= 254 and bool(EMAIL_RE.match(email))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    b64 = lambda b: base64.b64encode(b).decode("ascii")  # noqa: E731
    return f"scrypt${_N}${_R}${_P}${b64(salt)}${b64(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        kind, n, r, p, salt, dk = stored.split("$")
        if kind != "scrypt":
            return False
        want = base64.b64decode(dk)
        got = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                             dklen=len(want))
        return hmac.compare_digest(got, want)
    except (ValueError, TypeError):
        return False


def password_problems(password: str, email: str, settings: Settings) -> list[str]:
    p = []
    if len(password) < settings.password_min:
        p.append(f"tem de ter pelo menos {settings.password_min} caracteres")
    if password.strip() != password:
        p.append("não pode começar nem acabar com espaços")
    if email and email.split("@")[0].lower() in password.lower():
        p.append("não pode conter o seu nome de utilizador")
    if len(set(password)) < 5:
        p.append("tem de ter mais variedade de caracteres")
    return p


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii", "ignore")).hexdigest()


def issue_token(user: User, kind: str, settings: Settings, now: datetime | None = None) -> str:
    """Gera um link novo (convite ou nova palavra-passe); invalida o anterior. Devolve o código, que só vai no email."""
    token = secrets.token_urlsafe(32)
    user.token_hash = token_hash(token)
    user.token_kind = kind
    user.token_expires = (now or utcnow()) + timedelta(hours=settings.invite_hours)
    return token


def user_for_token(session: Session, token: str, now: datetime | None = None) -> User | None:
    if not token or len(token) > 100:
        return None
    u = session.scalar(select(User).where(User.token_hash == token_hash(token)))
    if u is None or u.status == "desativado" or not u.token_expires or as_utc(u.token_expires) < (now or utcnow()):
        return None
    return u


def set_password(user: User, password: str) -> None:
    user.password_hash = hash_password(password)
    user.password_set_at = utcnow()
    user.token_hash, user.token_kind, user.token_expires = "", "", None
    if user.status == "convidado":
        user.status = "ativo"


def by_email(session: Session, email: str) -> User | None:
    return session.scalar(select(User).where(User.email == norm_email(email)))


def active_admins(session: Session) -> int:
    return session.scalar(select(func.count()).select_from(User).where(User.role == "admin", User.status == "ativo")) or 0


def invite(session: Session, settings: Settings, email: str, name: str, role: str, by: str) -> tuple[User, str]:
    email = norm_email(email)
    if not valid_email(email):
        raise UserError("O email não é válido.")
    if role not in ROLES:
        raise UserError("Papel desconhecido.")
    if email == norm_email(settings.admin_user):
        raise UserError("Esse nome está reservado para a conta de recurso do servidor.")
    u = by_email(session, email)
    if u is not None and u.status != "convidado":
        raise UserError(f"{email} já tem conta ({STATUS[u.status].lower()}). Para lhe dar uma palavra-passe nova use «Enviar link».")
    if u is None:
        u = User(email=email)
        session.add(u)
    u.name, u.role, u.invited_by, u.invited_at, u.status = name.strip()[:128], role, by, utcnow(), "convidado"
    token = issue_token(u, "convite", settings)
    session.flush()
    return u, token


def base_url(settings: Settings, fallback: str) -> str:
    return (settings.public_url or fallback).rstrip("/")


def link_for(settings: Settings, fallback_base: str, token: str) -> str:
    return f"{base_url(settings, fallback_base)}/convite/{token}"


def email_message(settings: Settings, user: User, link: str, by: str, client: str, base: str):
    """O email do convite (ou do link para uma palavra-passe nova)."""
    from .report import build_message
    e = html.escape
    who = e(user.name or user.email)
    app = "Atalaia Cert" + (f" da {e(client)}" if client else "")
    if user.token_kind == "convite":
        subject = f"Convite para o Atalaia Cert{f' ({client})' if client else ''}"
        intro = (f"<p>Olá {who},</p><p>{e(by)} convidou-o para o {app}, a aplicação que acompanha os certificados e "
                 f"os segredos de APIs da organização. O seu papel é <b>{e(ROLES[user.role])}</b>: {e(ROLE_HELP[user.role])}</p>")
    else:
        subject = "Definir a palavra-passe do Atalaia Cert"
        intro = f"<p>Olá {who},</p><p>{e(by)} pediu um link para definir uma palavra-passe nova no {app}.</p>"
    body = (intro +
            f"<p>Para entrar, defina a sua palavra-passe neste link, válido durante {settings.invite_hours} horas e só uma vez:</p>"
            f"<p><a href=\"{e(link)}\">{e(link)}</a></p>"
            f"<p>Depois entre em <a href=\"{e(base)}\">{e(base)}</a> com o seu email (<b>{e(user.email)}</b>) e essa palavra-passe.</p>"
            "<p>Se não esperava este email, ignore-o: sem definir a palavra-passe ninguém entra com esta conta.</p>")
    return build_message(settings, [user.email], subject, body, None)

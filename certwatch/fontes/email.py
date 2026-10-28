"""Fonte: servidor de email (SMTP), só para enviar.

Como: SMTP com STARTTLS (por omissão), SSL direto ou sem cifra, conforme CERTWATCH_SMTP_SECURITY; o certificado do
servidor é verificado contra o mesmo trust store das outras ligações. Autenticação só se CERTWATCH_SMTP_USER estiver
definido (palavra-passe no segredo smtp_password). Usado pelo relatório por email, pelos convites e pelos links de
palavra-passe. Nunca recebe email.
"""
from __future__ import annotations

import html
import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from ..config import Settings

FONTE = {
    "id": "email", "nome": "Servidor de email (SMTP)", "tipo": "SMTP", "estado": "em uso",
    "para": "Enviar o relatório por email, os convites, os avisos de pedidos de acesso e os links de palavra-passe.",
    "config": ["CERTWATCH_SMTP_HOST", "CERTWATCH_SMTP_PORT", "CERTWATCH_SMTP_SECURITY", "CERTWATCH_SMTP_FROM",
               "CERTWATCH_SMTP_USER", "secrets/smtp_password"],
    "chamadas": [
        {"metodo": "SMTP", "endereco": "EHLO, STARTTLS, AUTH LOGIN (se houver utilizador)", "para": "abrir a sessão cifrada", "acesso": "envio", "estado": "em uso", "onde": "send"},
        {"metodo": "SMTP", "endereco": "MAIL FROM / RCPT TO / DATA", "para": "enviar cada mensagem (HTML e texto)", "acesso": "envio", "estado": "em uso", "onde": "send"},
    ],
}


class EmailError(RuntimeError):
    """O email não pôde ser preparado ou enviado (mensagem para mostrar a quem pediu)."""


def configured(settings: Settings) -> bool:
    return not smtp_problems(settings)


def smtp_problems(settings: Settings) -> list[str]:
    p = []
    if not settings.smtp_host:
        p.append("CERTWATCH_SMTP_HOST não definido")
    if not settings.smtp_from:
        p.append("CERTWATCH_SMTP_FROM não definido")
    if settings.smtp_security not in ("starttls", "ssl", "none"):
        p.append("CERTWATCH_SMTP_SECURITY tem de ser starttls, ssl ou none")
    if settings.smtp_user and not settings.smtp_password:
        p.append("CERTWATCH_SMTP_USER definido mas falta o segredo smtp_password")
    return p


def build_message(settings: Settings, to: list[str], subject: str, html_body: str,
                  attachment: tuple[str, bytes] | list[tuple[str, bytes]] | None) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = settings.smtp_from
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=settings.smtp_from.rsplit("@", 1)[-1] if "@" in settings.smtp_from else None)
    text = re.sub(r"<(br|/p|/tr|/div)\s*/?>", "\n", html_body)
    text = html.unescape(re.sub(r"<[^>]+>", " ", text))
    msg.set_content(re.sub(r"[ \t]+", " ", re.sub(r"\n\s*\n+", "\n\n", text)).strip())
    msg.add_alternative(html_body, subtype="html")
    for name, data in ([attachment] if isinstance(attachment, tuple) else (attachment or [])):
        msg.add_attachment(data, maintype="application",
                           subtype="vnd.openxmlformats-officedocument.spreadsheetml.sheet", filename=name)
    return msg


def send(settings: Settings, messages: list[EmailMessage], smtp_factory=None) -> None:
    problems = smtp_problems(settings)
    if problems:
        raise EmailError("Email não configurado: " + "; ".join(problems) + ".")
    from ..trust import build_bundle
    ctx = ssl.create_default_context(cafile=build_bundle(settings))
    try:
        if smtp_factory is not None:
            server = smtp_factory(settings)
        elif settings.smtp_security == "ssl":
            server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=30, context=ctx)
        else:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30)
        with server:
            if settings.smtp_security == "starttls" and smtp_factory is None:
                server.starttls(context=ctx)
            if settings.smtp_user:
                server.login(settings.smtp_user, settings.smtp_password or "")
            for m in messages:
                server.send_message(m)
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        detail = str(exc).replace(settings.smtp_password or "\0", "***")
        raise EmailError(f"O servidor de email recusou ou não respondeu: {type(exc).__name__}: {detail}"[:500]) from exc


def estado(settings: Settings) -> tuple[bool, str]:
    p = smtp_problems(settings)
    return (not p), ("; ".join(p) if p else f"{settings.smtp_host}:{settings.smtp_port} ({settings.smtp_security}), de {settings.smtp_from}")

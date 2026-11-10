"""Verificação em dois passos (TOTP, RFC 6238): a palavra-passe e um código de 6 dígitos de uma aplicação
(Microsoft Authenticator, Google Authenticator, Aegis, …).

- A chave de cada pessoa fica cifrada na base de dados (a mesma cifra das credenciais dos conectores).
- Um código só serve uma vez: guarda-se o último intervalo de 30 s aceite e recusa-se esse e os anteriores.
- Dez códigos de recuperação, mostrados uma vez; na base fica só o sha256 de cada um, e cada um serve uma vez.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

from .config import Settings

STEP, DIGITS, WINDOW = 30, 6, 1          # aceita o intervalo atual e um para cada lado (relógios desacertados)
RECOVERY_CODES = 10


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def code_at(secret: str, step: int) -> str:
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return str((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 10 ** DIGITS).zfill(DIGITS)


def clean(code: str) -> str:
    return "".join(ch for ch in (code or "") if ch.isalnum()).lower()


def verify(secret: str, code: str, last_step: int = 0, now: float | None = None) -> int | None:
    """O intervalo a que o código pertence, se está certo e ainda não foi usado; senão None."""
    code = clean(code)
    if len(code) != DIGITS or not code.isdigit() or not secret:
        return None
    current = int((time.time() if now is None else now) // STEP)
    found = None
    for step in range(current - WINDOW, current + WINDOW + 1):
        if hmac.compare_digest(code_at(secret, step), code) and step > last_step:
            found = step                 # sem sair mais cedo: o tempo de resposta não diz qual acertou
    return found


def uri(secret: str, account: str, issuer: str = "Atalaia Cert") -> str:
    return (f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP}")


def qr_data_uri(text: str) -> str:
    """O código QR como imagem SVG num data: (a CSP da aplicação aceita img-src data:). Sem a biblioteca, fica vazio
    e a página mostra só a chave para escrever à mão."""
    try:
        import segno
    except ImportError:
        return ""
    return segno.make(text, error="m").svg_data_uri(scale=5, border=2, dark="#000", light="#fff")


def grouped(secret: str) -> str:
    return " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))


# ------------------------------------------------------------------ guardar a chave
def seal(settings: Settings, secret: str) -> str:
    from .conectores import encrypt
    return encrypt(settings, {"totp": secret})


def unseal(settings: Settings, sealed: str) -> str:
    from .conectores import decrypt
    return str(decrypt(settings, sealed).get("totp") or "")


# ------------------------------------------------------------------ códigos de recuperação
def _h(code: str) -> str:
    return hashlib.sha256(clean(code).encode()).hexdigest()


def new_recovery_codes() -> tuple[list[str], list[str]]:
    """(os códigos, para mostrar uma vez; os sha256, para guardar)"""
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"          # sem 0/o, 1/i/l
    codes = ["-".join("".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(2)) for _ in range(RECOVERY_CODES)]
    return codes, [_h(c) for c in codes]


def use_recovery(hashes: list[str] | None, code: str) -> list[str] | None:
    """A lista sem o código usado, se ele existia; senão None."""
    if len(clean(code)) != 10:
        return None
    h, left, hit = _h(code), [], False
    for x in hashes or []:
        if not hit and hmac.compare_digest(x, h):
            hit = True
        else:
            left.append(x)
    return left if hit else None


# ------------------------------------------------------------------ sobre o utilizador
def start(settings: Settings, user) -> str:
    """Gera uma chave nova (ainda não ativa) e devolve-a para mostrar."""
    secret = new_secret()
    user.totp_secret, user.totp_on, user.totp_step, user.totp_codes = seal(settings, secret), False, 0, None
    return secret


def activate(settings: Settings, user, code: str) -> list[str] | None:
    """Confirma o primeiro código e liga a verificação. Devolve os códigos de recuperação, ou None se o código falhou."""
    step = verify(unseal(settings, user.totp_secret), code, user.totp_step or 0)
    if step is None:
        return None
    codes, hashes = new_recovery_codes()
    user.totp_on, user.totp_step, user.totp_codes = True, step, hashes
    return codes


def check(settings: Settings, user, code: str) -> str:
    """"totp" ou "recuperacao" se o código serve (e fica gasto); "" se não."""
    if not user.totp_on:
        return ""
    step = verify(unseal(settings, user.totp_secret), code, user.totp_step or 0)
    if step is not None:
        user.totp_step = step
        return "totp"
    left = use_recovery(user.totp_codes, code)
    if left is not None:
        user.totp_codes = left
        return "recuperacao"
    return ""


def reset(user) -> None:
    user.totp_secret, user.totp_on, user.totp_step, user.totp_codes = "", False, 0, None

"""Cifra do que a aplicação guarda na base de dados e não pode ficar legível: as credenciais dos conectores e as
chaves da verificação em dois passos.

A chave vem de um segredo próprio, `secrets/data_key` (ou CERTWATCH_DATA_KEY), passada por scrypt. Os textos cifrados
com ela começam por "v2:". Antes havia uma chave tirada do endereço da base de dados (um sha256 simples, que mudava
quando se mudava a palavra-passe da base): esses textos, sem prefixo, continuam a abrir e são cifrados de novo com a
chave própria no arranque seguinte.

Trocar a chave: pôr a antiga em `secrets/data_key_old`, a nova em `secrets/data_key` e reiniciar. No arranque tudo é
cifrado de novo com a nova; depois apaga-se a antiga.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from .config import Settings

log = logging.getLogger(__name__)
PREFIX = "v2:"
MIN_KEY = 32                          # caracteres: `openssl rand -base64 32` dá 44
_SALT = b"atalaia-cert:dados:v2"


@lru_cache(maxsize=4)
def _derived(secret: str) -> Fernet:
    dk = hashlib.scrypt(secret.encode("utf-8"), salt=_SALT, n=2 ** 15, r=8, p=1, dklen=32, maxmem=128 * 1024 * 1024)
    return Fernet(base64.urlsafe_b64encode(dk))


def _legacy(settings: Settings) -> Fernet:
    seed = ("atalaia-conectores:" + settings.database_url).encode()
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(seed).digest()))


def problems(settings: Settings) -> list[str]:
    out = []
    for name, value in (("data_key", settings.data_key), ("data_key_old", settings.data_key_old)):
        if value and len(value) < MIN_KEY:
            out.append(f"O segredo {name} é curto demais ({len(value)} caracteres; mínimo {MIN_KEY}). "
                       "Gere um com: openssl rand -base64 32")
    return out


def own_key(settings: Settings) -> bool:
    return bool(settings.data_key) and not problems(settings)


def encrypt(settings: Settings, data: dict) -> str:
    if not data:
        return ""
    raw = json.dumps(data).encode()
    if own_key(settings):
        return PREFIX + _derived(settings.data_key).encrypt(raw).decode()
    return _legacy(settings).encrypt(raw).decode()


def decrypt(settings: Settings, token: str) -> dict:
    if not token:
        return {}
    try:
        if token.startswith(PREFIX):
            body = token[len(PREFIX):].encode()
            for key in (settings.data_key, settings.data_key_old):
                if key and len(key) >= MIN_KEY:
                    try:
                        return json.loads(_derived(key).decrypt(body))
                    except InvalidToken:
                        continue
            return {}
        return json.loads(_legacy(settings).decrypt(token.encode()))
    except (InvalidToken, ValueError):
        return {}


def current(settings: Settings, token: str) -> bool:
    """O texto já está cifrado com a chave em vigor?"""
    if not token:
        return True
    if not own_key(settings):
        return not token.startswith(PREFIX)
    if not token.startswith(PREFIX):
        return False
    try:
        _derived(settings.data_key).decrypt(token[len(PREFIX):].encode())
        return True
    except InvalidToken:
        return False


def rekey_all(settings: Settings) -> dict:
    """No arranque: o que está cifrado com a chave antiga (a derivada da base de dados, ou data_key_old) passa para
    a chave em vigor. O que não abre com nenhuma fica como está e é contado, para se saber."""
    from sqlalchemy import select
    from .db import session_scope
    from .models import ConnectorConfig, User
    done = {"cifrados_de_novo": 0, "ilegiveis": 0}
    if not own_key(settings):
        return done
    with session_scope() as s:
        rows = [(r, "secrets_enc") for r in s.scalars(select(ConnectorConfig).where(ConnectorConfig.secrets_enc != ""))]
        rows += [(u, "totp_secret") for u in s.scalars(select(User).where(User.totp_secret != ""))]
        for row, attr in rows:
            token = getattr(row, attr)
            if current(settings, token):
                continue
            data = decrypt(settings, token)
            if not data:
                done["ilegiveis"] += 1
                continue
            setattr(row, attr, encrypt(settings, data))
            done["cifrados_de_novo"] += 1
    if done["cifrados_de_novo"] or done["ilegiveis"]:
        log.info("Chave de cifra: %s valores cifrados de novo, %s ilegíveis", done["cifrados_de_novo"], done["ilegiveis"])
    return done


def status(settings: Settings) -> dict:
    """Para a página Fontes e ligações (só o estado, nunca a chave)."""
    from sqlalchemy import select
    from .db import session_scope
    from .models import ConnectorConfig, User
    with session_scope() as s:
        tokens = list(s.scalars(select(ConnectorConfig.secrets_enc).where(ConnectorConfig.secrets_enc != "")))
        tokens += list(s.scalars(select(User.totp_secret).where(User.totp_secret != "")))
    return {"propria": own_key(settings), "problemas": problems(settings), "antiga": bool(settings.data_key_old),
            "valores": len(tokens), "por_migrar": sum(1 for t in tokens if not current(settings, t)),
            "ilegiveis": sum(1 for t in tokens if not decrypt(settings, t))}

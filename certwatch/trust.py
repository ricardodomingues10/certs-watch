"""Trust store: CAs públicas do sistema + raízes internas colocadas em trust_dir."""
from __future__ import annotations

import hashlib
import socket
import ssl
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from .config import Settings

_BUNDLE_CACHE: dict[str, str] = {}


def local_trust_files(settings: Settings) -> list[Path]:
    if not settings.trust_dir.is_dir():
        return []
    return sorted(p for p in settings.trust_dir.iterdir() if p.suffix.lower() in {".pem", ".crt", ".cer"} and p.is_file())


def build_bundle(settings: Settings) -> str:
    """Escreve um bundle combinado e devolve o caminho (em cache por processo)."""
    key = f"{settings.system_ca_bundle}|{settings.trust_dir}"
    if key in _BUNDLE_CACHE and Path(_BUNDLE_CACHE[key]).is_file():
        return _BUNDLE_CACHE[key]
    parts: list[str] = []
    if settings.system_ca_bundle.is_file():
        parts.append(settings.system_ca_bundle.read_text(encoding="utf-8", errors="ignore"))
    for f in local_trust_files(settings):
        data = f.read_bytes()
        if b"-----BEGIN CERTIFICATE-----" in data:
            parts.append(data.decode("ascii", errors="ignore"))
        else:  # DER
            cert = x509.load_der_x509_certificate(data)
            parts.append(cert.public_bytes(Encoding.PEM).decode("ascii"))
    fd = tempfile.NamedTemporaryFile("w", prefix="certwatch-trust-", suffix=".pem", delete=False)
    with fd:
        fd.write("\n".join(parts))
    _BUNDLE_CACHE[key] = fd.name
    return fd.name


def ssl_context_for_api(settings: Settings) -> ssl.SSLContext | bool:
    if not settings.ucmdb_verify_tls:
        return False
    return ssl.create_default_context(cafile=build_bundle(settings))


def fetch_presented_chain(host: str, port: int, timeout: float = 10.0) -> list[bytes]:
    """Obtém a chain apresentada pelo servidor SEM a validar (bootstrap de confiança)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            return list(ss.get_unverified_chain() or [])


def describe(der: bytes) -> dict:
    c = x509.load_der_x509_certificate(der)
    return {
        "subject": c.subject.rfc4514_string(),
        "issuer": c.issuer.rfc4514_string(),
        "not_after": c.not_valid_after_utc.isoformat(),
        "self_signed": c.issuer == c.subject,
        "sha256": hashlib.sha256(der).hexdigest(),
        "pem": c.public_bytes(Encoding.PEM).decode("ascii"),
    }

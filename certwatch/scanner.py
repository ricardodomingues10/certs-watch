"""Scanner TLS.

Para cada alvo:
  1) handshake com verificação da chain contra o trust store (sem verificação de
     hostname — essa é feita à parte, para não mascarar erros de chain);
  2) se a verificação falhar ou o handshake não for possível, novo handshake
     permissivo apenas para recolher a chain apresentada.

Nunca passa dados por uma shell: só sockets.
"""
from __future__ import annotations

import hashlib
import socket
import ssl
import time
import warnings
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID


@dataclass
class ScanOutcome:
    host: str
    port: int
    status: str = "ok"  # ok | dns_error | unreachable | tls_error
    error: str = ""
    tls_version: str = ""
    cipher: str = ""
    verify_ok: bool | None = None
    verify_code: int | None = None
    verify_message: str = ""
    chain_der: list[bytes] = field(default_factory=list)
    duration_ms: float = 0.0


def _context(cafile: str | None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Aceitar protocolos/cifras antigos para conseguir observar servidores legados;
    # o protocolo negociado é depois avaliado como finding.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except (ValueError, ssl.SSLError):
            pass
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    ctx.check_hostname = False
    if cafile:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=cafile)
    else:
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _handshake(host: str, port: int, ctx: ssl.SSLContext, timeout: float):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            chain = list(ss.get_unverified_chain() or [])
            cipher = ss.cipher()
            return chain, ss.version() or "", (cipher[0] if cipher else "")


def scan_endpoint(host: str, port: int, cafile: str, timeout: float = 8.0) -> ScanOutcome:
    out = ScanOutcome(host=host, port=port)
    t0 = time.monotonic()
    try:
        try:
            out.chain_der, out.tls_version, out.cipher = _handshake(host, port, _context(cafile), timeout)
            out.verify_ok = True
        except ssl.SSLCertVerificationError as exc:
            out.verify_ok = False
            out.verify_code = exc.verify_code
            out.verify_message = exc.verify_message or str(exc)
        except ssl.SSLError as exc:
            # Handshake falhou por outro motivo (protocolo, cifra...). Tentar só recolher a chain.
            out.error = f"handshake verificado falhou: {exc.reason or exc}"

        if not out.chain_der:
            try:
                out.chain_der, out.tls_version, out.cipher = _handshake(host, port, _context(None), timeout)
            except ssl.SSLError as exc:
                out.status = "tls_error"
                out.error = f"{out.error}; handshake permissivo falhou: {exc.reason or exc}".strip("; ")
    except socket.gaierror as exc:
        out.status = "dns_error"
        out.error = f"DNS: {exc}"
    except (TimeoutError, socket.timeout):
        out.status = "unreachable"
        out.error = "timeout"
    except OSError as exc:
        out.status = "unreachable"
        out.error = str(exc)
    out.duration_ms = round((time.monotonic() - t0) * 1000, 1)
    if out.status == "ok" and not out.chain_der:
        out.status = "tls_error"
        out.error = out.error or "servidor não apresentou certificado"
    return out


def _cn(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else ""


def summarize(der: bytes) -> dict:
    """Extrai os campos técnicos de um certificado DER."""
    c = x509.load_der_x509_certificate(der)
    try:
        san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns = [str(v) for v in san.get_values_for_type(x509.DNSName)]
        ips = [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        dns, ips = [], []
    try:
        h = c.signature_hash_algorithm
        sig = h.name if h else getattr(c.signature_algorithm_oid, "_name", c.signature_algorithm_oid.dotted_string)
    except UnsupportedAlgorithm:
        sig = c.signature_algorithm_oid.dotted_string

    pk = c.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", pk.key_size
    elif isinstance(pk, ec.EllipticCurvePublicKey):
        key_type, key_bits = "EC", pk.curve.key_size
    elif isinstance(pk, ed25519.Ed25519PublicKey):
        key_type, key_bits = "Ed25519", 256
    elif isinstance(pk, ed448.Ed448PublicKey):
        key_type, key_bits = "Ed448", 456
    elif isinstance(pk, dsa.DSAPublicKey):
        key_type, key_bits = "DSA", pk.key_size
    else:
        key_type, key_bits = "?", None

    try:
        is_ca = c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False

    spki = pk.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return {
        "sha256": c.fingerprint(hashes.SHA256()).hex(),
        "subject_cn": _cn(c.subject),
        "subject_dn": c.subject.rfc4514_string(),
        "issuer_cn": _cn(c.issuer),
        "issuer_dn": c.issuer.rfc4514_string(),
        "serial_hex": format(c.serial_number, "X"),
        "not_before": c.not_valid_before_utc,
        "not_after": c.not_valid_after_utc,
        "sans_dns": dns,
        "sans_ip": ips,
        "sig_hash": (sig or "").lower(),
        "key_type": key_type,
        "key_bits": key_bits,
        "spki_sha256": hashlib.sha256(spki).hexdigest(),
        "is_ca": bool(is_ca),
        "self_issued": c.issuer == c.subject,
        "pem": c.public_bytes(Encoding.PEM).decode("ascii"),
    }

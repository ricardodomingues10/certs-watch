"""PKI de teste e servidor TLS local para exercitar o scanner com casos reais."""
from __future__ import annotations

import socket
import ssl
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

NOW = datetime.now(timezone.utc)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Exemplo Teste"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_cert(cn, issuer_cert=None, issuer_key=None, *, ca=False, sans=None, ip_sans=None, days_valid=200,
              not_before=None, key=None, hash_alg=None, key_size=2048):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    nb = not_before or (NOW - timedelta(days=1))
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_cert.subject if issuer_cert else _name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(nb + timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                          encipher_only=False, decipher_only=False), critical=True)
    else:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    if sans or ip_sans:
        import ipaddress
        names = [x509.DNSName(s) for s in (sans or [])] + [x509.IPAddress(ipaddress.ip_address(i)) for i in (ip_sans or [])]
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    if issuer_cert is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    cert = builder.sign(issuer_key or key, hash_alg or hashes.SHA256())
    return cert, key


def pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


class PKI:
    def __init__(self):
        self.root, self.root_key = make_cert("Exemplo Teste Root CA", ca=True, days_valid=3650)
        self.inter, self.inter_key = make_cert("Exemplo Teste Issuing CA", self.root, self.root_key, ca=True, days_valid=1825)

    def leaf(self, cn="localhost", sans=("localhost",), **kw):
        return make_cert(cn, self.inter, self.inter_key, sans=list(sans) if sans else None, **kw)


class TLSServer:
    """Servidor TLS mínimo em 127.0.0.1 que apresenta a chain indicada."""

    def __init__(self, chain_certs, key, *, max_version=None, min_version=None):
        self._dir = tempfile.TemporaryDirectory()
        d = Path(self._dir.name)
        (d / "chain.pem").write_bytes(b"".join(pem(c) for c in chain_certs))
        (d / "key.pem").write_bytes(key_pem(key))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        if min_version:
            ctx.minimum_version = min_version
        if max_version:
            ctx.maximum_version = max_version
        ctx.load_cert_chain(d / "chain.pem", d / "key.pem")
        self.ctx = ctx
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                break
            try:
                conn.settimeout(3)
                with self.ctx.wrap_socket(conn, server_side=True) as ss:
                    try:
                        ss.recv(1)
                    except (ssl.SSLError, OSError):
                        pass
            except (ssl.SSLError, OSError):
                pass

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self.sock.close()
        self._t.join(timeout=2)
        self._dir.cleanup()


def make_weak_leaf(pki, cn, key_size=1024):
    """Folha assinada com SHA-1 e chave RSA pequena (a biblioteca cryptography já recusa SHA-1,
    por isso usa-se o openssl CLI). Devolve (cert, key)."""
    import subprocess
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        (d / "ca.pem").write_bytes(pem(pki.inter))
        (d / "ca.key").write_bytes(key_pem(pki.inter_key))
        (d / "ext.cnf").write_text(f"subjectAltName=DNS:{cn}\nbasicConstraints=critical,CA:FALSE\n")
        run = lambda *a: subprocess.run(a, check=True, capture_output=True, cwd=d)
        run("openssl", "genrsa", "-out", "leaf.key", str(key_size))
        run("openssl", "req", "-new", "-key", "leaf.key", "-subj", f"/O=Exemplo Teste/CN={cn}", "-out", "leaf.csr")
        run("openssl", "x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
            "-days", "200", "-sha1", "-extfile", "ext.cnf", "-out", "leaf.pem")
        cert = x509.load_pem_x509_certificate((d / "leaf.pem").read_bytes())
        key = serialization.load_pem_private_key((d / "leaf.key").read_bytes(), password=None)
    return cert, key

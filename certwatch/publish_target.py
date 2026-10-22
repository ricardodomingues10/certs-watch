"""Destino da publicação dos ficheiros da CMDB: pasta montada no servidor do certwatch ("local") ou pasta noutro
servidor, por SFTP ("sftp"), quando a pasta de rede só está montada nesse servidor.

SFTP, com segurança:
- a autenticação é por chave SSH (recomendado) ou por password, guardadas no segredo Docker `publish_ssh`
  (/run/secrets/publish_ssh), ou pela password escrita na página no momento de publicar, usada só para essa ligação
  e nunca guardada nem registada;
- antes de autenticar, a impressão digital da chave do servidor (SHA256) é comparada com
  CERTWATCH_PUBLISH_SSH_HOSTKEY: se não coincidir, a ligação é cortada sem enviar credenciais;
- os ficheiros são escritos com um nome temporário, renomeados e lidos de volta para confirmar o conteúdo.
"""
from __future__ import annotations

import base64
import hashlib
import io
import os
import socket
import stat as statmod
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from .config import Settings

MAX_READ = 50 * 1024 * 1024


class TargetError(RuntimeError):
    pass


@dataclass
class FileInfo:
    size: int
    mtime: datetime


def _secret_kind(secret: str | None) -> str:
    s = (secret or "").strip()
    if not s:
        return ""
    return "chave" if s.startswith("-----BEGIN") else "password"


def describe(settings: Settings) -> dict:
    """Configuração do destino, sem ligar a lado nenhum."""
    if settings.publish_mode != "sftp":
        return {"modo": "local", "destino": str(settings.publish_dir), "pede_password": False, "problemas": []}
    problems = []
    if not settings.publish_ssh_host:
        problems.append("CERTWATCH_PUBLISH_SSH_HOST não definido")
    if not settings.publish_ssh_user:
        problems.append("CERTWATCH_PUBLISH_SSH_USER não definido")
    if not settings.publish_ssh_path.startswith("/"):
        problems.append("CERTWATCH_PUBLISH_SSH_PATH tem de ser um caminho absoluto no outro servidor")
    if not settings.publish_ssh_hostkeys:
        problems.append("CERTWATCH_PUBLISH_SSH_HOSTKEY não definido (impressão digital do servidor SSH)")
    kind = _secret_kind(settings.publish_ssh_secret)
    return {"modo": "sftp", "destino": f"{settings.publish_ssh_user}@{settings.publish_ssh_host}:{settings.publish_ssh_path}",
            "porta": settings.publish_ssh_port, "autenticacao": kind or "password pedida ao publicar",
            "pede_password": not kind, "problemas": problems}


def fingerprint(key) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def server_fingerprint(settings: Settings, timeout: float = 10.0) -> dict:
    """Liga-se ao servidor SSH só para ler a chave do servidor (sem autenticar)."""
    import paramiko
    sock = socket.create_connection((settings.publish_ssh_host, settings.publish_ssh_port), timeout=timeout)
    t = paramiko.Transport(sock)
    try:
        t.start_client(timeout=timeout)
        key = t.get_remote_server_key()
        return {"tipo": key.get_name(), "impressao": fingerprint(key)}
    finally:
        t.close()


def _load_key(text: str, passphrase: str | None):
    import paramiko
    errors = []
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(text), password=passphrase or None)
        except paramiko.PasswordRequiredException:
            raise TargetError("A chave SSH está protegida por frase-passe: defina o segredo publish_ssh_passphrase "
                              "ou use uma chave sem frase-passe só para esta publicação.")
        except (paramiko.SSHException, ValueError) as exc:
            errors.append(str(exc))
    raise TargetError("O segredo publish_ssh não contém uma chave privada SSH válida (Ed25519, ECDSA ou RSA).")


class LocalTarget:
    def __init__(self, settings: Settings):
        self.dir = settings.publish_dir
        self.label = str(self.dir)

    def __enter__(self):
        if not self.dir.is_dir():
            raise TargetError(f"A pasta de rede não está disponível ({self.dir}).")
        return self

    def __exit__(self, *exc):
        return False

    def info(self, name: str) -> FileInfo | None:
        try:
            st = (self.dir / name).stat()
        except FileNotFoundError:
            return None
        return FileInfo(st.st_size, datetime.fromtimestamp(st.st_mtime, tz=timezone.utc))

    def read(self, name: str) -> bytes:
        return (self.dir / name).read_bytes()

    def write(self, name: str, data: bytes) -> None:
        dest = self.dir / name
        tmp = dest.with_name(f".{name}.certwatch-{uuid.uuid4().hex[:8]}.tmp")
        try:
            with open(tmp, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            try:
                os.replace(tmp, dest)
            except OSError:
                # Algumas partilhas SMB não substituem por rename: escreve diretamente
                with open(dest, "wb") as fh:
                    fh.write(data)
                    fh.flush()
                    os.fsync(fh.fileno())
        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass

    def remove(self, name: str) -> None:
        (self.dir / name).unlink()


class SftpTarget:
    def __init__(self, settings: Settings, password: str | None = None, transport_factory=None):
        self.settings = settings
        self._password = password
        self._factory = transport_factory
        self.t = None
        self.sftp = None
        self.dir = PurePosixPath(settings.publish_ssh_path)
        self.label = describe(settings)["destino"]

    def __enter__(self):
        import paramiko
        st = self.settings
        problems = describe(st)["problemas"]
        if problems:
            raise TargetError("Destino SFTP incompleto: " + "; ".join(problems) + ".")
        secret = (st.publish_ssh_secret or "").strip()
        kind = _secret_kind(secret)
        if not kind and not self._password:
            raise TargetError("Indique a password da conta SSH para publicar.")
        try:
            if self._factory is not None:
                self.t = self._factory(st)
            else:
                sock = socket.create_connection((st.publish_ssh_host, st.publish_ssh_port), timeout=15)
                self.t = paramiko.Transport(sock)
                self.t.start_client(timeout=15)
            fp = fingerprint(self.t.get_remote_server_key())
            if fp not in st.publish_ssh_hostkeys:
                raise TargetError(f"A impressão digital do servidor SSH ({fp}) não é a configurada em "
                                  "CERTWATCH_PUBLISH_SSH_HOSTKEY. Ligação cortada sem enviar credenciais.")
            if kind == "chave":
                self.t.auth_publickey(st.publish_ssh_user, _load_key(secret, st.publish_ssh_passphrase))
            else:
                self.t.auth_password(st.publish_ssh_user, secret if kind == "password" else self._password)
            self._password = None
            if not self.t.is_authenticated():
                raise TargetError("Autenticação SSH recusada.")
            self.sftp = paramiko.SFTPClient.from_transport(self.t)
            try:
                if not statmod.S_ISDIR(self.sftp.stat(str(self.dir)).st_mode):
                    raise TargetError(f"{self.dir} não é uma pasta no outro servidor.")
            except FileNotFoundError:
                raise TargetError(f"A pasta {self.dir} não existe no outro servidor (a pasta de rede está montada?).")
        except paramiko.AuthenticationException:
            self.close()
            raise TargetError("Autenticação SSH recusada: utilizador, chave ou password errados.") from None
        except (paramiko.SSHException, OSError) as exc:
            self.close()
            raise TargetError(f"Ligação SSH falhou: {type(exc).__name__}: {exc}"[:400]) from None
        except TargetError:
            self.close()
            raise
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def close(self) -> None:
        self._password = None
        for x in (self.sftp, self.t):
            try:
                if x is not None:
                    x.close()
            except Exception:
                pass
        self.sftp = self.t = None

    def _p(self, name: str) -> str:
        return str(self.dir / name)

    def info(self, name: str) -> FileInfo | None:
        try:
            a = self.sftp.stat(self._p(name))
        except FileNotFoundError:
            return None
        return FileInfo(a.st_size or 0, datetime.fromtimestamp(a.st_mtime or 0, tz=timezone.utc))

    def read(self, name: str) -> bytes:
        with self.sftp.open(self._p(name), "rb") as fh:
            data = fh.read(MAX_READ + 1)
        if len(data) > MAX_READ:
            raise TargetError("Ficheiro demasiado grande")
        return data

    def write(self, name: str, data: bytes) -> None:
        tmp = self._p(f".{name}.certwatch-{uuid.uuid4().hex[:8]}.tmp")
        dest = self._p(name)
        try:
            with self.sftp.open(tmp, "wb") as fh:
                fh.set_pipelined(True)
                fh.write(data)
            try:
                self.sftp.posix_rename(tmp, dest)
            except (IOError, OSError):
                # Sem rename com substituição (ex.: pasta CIFS): escreve diretamente
                with self.sftp.open(dest, "wb") as fh:
                    fh.write(data)
        finally:
            try:
                self.sftp.remove(tmp)
            except (IOError, OSError):
                pass

    def remove(self, name: str) -> None:
        self.sftp.remove(self._p(name))


def open_target(settings: Settings, password: str | None = None, transport_factory=None):
    if settings.publish_mode == "sftp":
        return SftpTarget(settings, password, transport_factory)
    return LocalTarget(settings)


def test(settings: Settings, password: str | None = None, transport_factory=None) -> tuple[bool, str]:
    """Liga-se ao destino, escreve, lê e apaga um ficheiro temporário."""
    name = f".certwatch-teste-{uuid.uuid4().hex[:8]}.tmp"
    try:
        with open_target(settings, password, transport_factory) as t:
            try:
                t.write(name, b"certwatch")
                ok = t.read(name) == b"certwatch"
            finally:
                try:
                    t.remove(name)
                except Exception:
                    pass
        return ok, ("Ligação, escrita, leitura e remoção funcionam." if ok else "O ficheiro escrito não foi lido corretamente.")
    except TargetError as exc:
        return False, str(exc)
    except OSError as exc:
        return False, f"Não foi possível escrever na pasta: {exc}"


__all__ = ["TargetError", "describe", "open_target", "server_fingerprint", "test", "fingerprint", "Path"]

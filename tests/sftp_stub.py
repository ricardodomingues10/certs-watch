"""Servidor SFTP mínimo (paramiko) sobre uma pasta temporária, para testar a publicação por SFTP a sério."""
import os
import socket
import threading

import paramiko
from paramiko import SFTPAttributes, SFTPHandle, SFTPServer, SFTPServerInterface, SFTP_OK, SFTP_NO_SUCH_FILE, SFTP_FAILURE


class _Handle(SFTPHandle):
    def stat(self):
        return SFTPAttributes.from_stat(os.fstat(self.readfile.fileno() if hasattr(self, "readfile") else self.writefile.fileno()))


class _FS(SFTPServerInterface):
    root = "/"

    def _real(self, path):
        return os.path.join(self.root, os.path.normpath("/" + path).lstrip("/"))

    def stat(self, path):
        try:
            return SFTPAttributes.from_stat(os.stat(self._real(path)))
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)

    lstat = stat

    def list_folder(self, path):
        p = self._real(path)
        out = []
        for n in os.listdir(p):
            a = SFTPAttributes.from_stat(os.stat(os.path.join(p, n)))
            a.filename = n
            out.append(a)
        return out

    def open(self, path, flags, attr):
        p = self._real(path)
        try:
            fd = os.open(p, flags, 0o644)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        mode = "wb" if flags & os.O_WRONLY else ("r+b" if flags & os.O_RDWR else "rb")
        f = os.fdopen(fd, mode)
        h = _Handle(flags)
        h.filename = p
        h.readfile = f
        h.writefile = f
        return h

    def remove(self, path):
        try:
            os.remove(self._real(path))
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        return SFTP_OK

    def rename(self, old, new):
        if os.path.exists(self._real(new)):
            return SFTP_FAILURE
        os.rename(self._real(old), self._real(new))
        return SFTP_OK

    def posix_rename(self, old, new):
        if getattr(self, "no_posix_rename", False):
            return SFTP_FAILURE
        try:
            os.replace(self._real(old), self._real(new))
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        return SFTP_OK


class _Auth(paramiko.ServerInterface):
    def __init__(self, user, password, pubkey):
        self.user, self.password, self.pubkey = user, password, pubkey

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_password(self, username, password):
        ok = self.password is not None and username == self.user and password == self.password
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        ok = self.pubkey is not None and username == self.user and key.asbytes() == self.pubkey.asbytes()
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED


class SftpStub:
    """Servidor numa porta local. host_key: chave do servidor; aceita password e/ou chave pública."""

    def __init__(self, root, user="svc", password=None, pubkey=None, no_posix_rename=False):
        self.root, self.user, self.password, self.pubkey = str(root), user, password, pubkey
        self.host_key = paramiko.Ed25519Key.generate() if hasattr(paramiko.Ed25519Key, "generate") else paramiko.RSAKey.generate(2048)
        self.no_posix_rename = no_posix_rename
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.passwords_seen = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(self.host_key)
            stub = self

            class FS(_FS):
                root = stub.root
                no_posix_rename = stub.no_posix_rename
            t.set_subsystem_handler("sftp", SFTPServer, FS)
            auth = _Auth(self.user, self.password, self.pubkey)
            orig = auth.check_auth_password

            def spy(u, p):
                stub.passwords_seen.append(p)
                return orig(u, p)
            auth.check_auth_password = spy
            try:
                t.start_server(server=auth)
            except Exception:
                pass

    def close(self):
        self.sock.close()

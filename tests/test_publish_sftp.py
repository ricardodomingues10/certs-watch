"""Publicação da CMDB final por SFTP noutro servidor (onde a pasta de rede está montada)."""
import io
import json
from dataclasses import replace

import paramiko
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from certwatch import cmdb_final as cf
from certwatch import publish_target as pt
from certwatch.db import session_scope
from certwatch.models import AuditLog, FinalPublishFile, FinalRun
from tests.sftp_stub import SftpStub
from tests.test_cmdb_final import AVI, CA1, TODAY, _fetch, ca2_xlsx, live

AUTH = ("admin", "teste-admin-123")
PW = "S3gred0!pw"


@pytest.fixture()
def remote(tmp_path):
    root = tmp_path / "remoto"
    (root / "mnt" / "usc").mkdir(parents=True)
    return root


def sftp_settings(env, tmp_path, stub, secret=None, **kw):
    imp = tmp_path / "import"
    imp.mkdir(exist_ok=True)
    return replace(env, import_dir=imp, ucmdb_min_cis=1, import_issuers={"CA1": "Corp CA01", "CA2": "Corp CA02"},
                   final_ct=False, publish_mode="sftp", publish_ssh_host="127.0.0.1", publish_ssh_port=stub.port,
                   publish_ssh_user="svc", publish_ssh_path="/mnt/usc",
                   publish_ssh_hostkeys=[pt.fingerprint(stub.host_key)], publish_ssh_secret=secret, **kw)


def ready_run(st):
    (st.import_dir / "ca1.csv").write_bytes(CA1)
    (st.import_dir / "ca2.xlsx").write_bytes(ca2_xlsx())
    (st.import_dir / "avi.csv").write_bytes(AVI)
    with session_scope() as s:
        rid = cf.start_run(s, "admin").id
    cf.generate(rid, st, fetch=_fetch, live_factory=lambda s, x: live, today=TODAY)
    return rid


def test_password_secret_and_typed_password(env, tmp_path, remote):
    stub = SftpStub(remote, password=PW)
    st = sftp_settings(env, tmp_path, stub, secret=PW)
    assert cf.folder_status(st)["modo"] == "sftp" and not cf.folder_status(st)["pede_password"]
    ok, msg = cf.test_write(st)
    assert ok, msg
    (remote / "mnt" / "usc" / "certs_update.csv").write_bytes(b"anterior")
    rid = ready_run(st)
    with session_scope() as s:
        run = s.get(FinalRun, rid)
        pub = cf.publish(s, st, run, ["xlsx", "csv", "csv_sem"], "admin")
        assert pub.ok, pub.result
        assert pub.folder == f"svc@127.0.0.1:/mnt/usc"
        assert (remote / "mnt" / "usc" / "certs_update.csv").read_bytes() == run.csv
        assert (remote / "mnt" / "usc" / "CMDB_Final.xlsx").read_bytes() == run.xlsx
        prev = s.scalar(select(FinalPublishFile).where(FinalPublishFile.name == "certs_update.csv"))
        assert prev.previous == b"anterior"
    assert not [p for p in (remote / "mnt" / "usc").iterdir() if p.name.startswith(".")]     # sem temporários
    # o ficheiro na pasta pode ser lido para a comparação
    assert cf.read_published(st, "CMDB_Final.xlsx")[:2] == b"PK"

    # sem segredo: a password é pedida e só serve para esta ligação
    st2 = replace(st, publish_ssh_secret=None)
    assert cf.folder_status(st2)["pede_password"]
    assert "Indique a password" in cf.test_write(st2)[1]
    assert not cf.test_write(st2, "errada")[0]
    assert cf.test_write(st2, PW)[0]
    stub.close()


def test_host_key_mismatch_sends_no_credentials(env, tmp_path, remote):
    stub = SftpStub(remote, password=PW)
    st = sftp_settings(env, tmp_path, stub, secret=PW)
    st = replace(st, publish_ssh_hostkeys=["SHA256:outraChaveQueNaoEDesteServidor"])
    ok, msg = cf.test_write(st)
    assert not ok and "não é a configurada" in msg and "sem enviar credenciais" in msg
    assert stub.passwords_seen == []
    assert pt.server_fingerprint(st)["impressao"] == pt.fingerprint(stub.host_key)
    stub.close()


def test_key_auth_and_no_posix_rename(env, tmp_path, remote):
    key = paramiko.RSAKey.generate(2048)
    buf = io.StringIO()
    key.write_private_key(buf)
    stub = SftpStub(remote, pubkey=key, no_posix_rename=True)
    st = sftp_settings(env, tmp_path, stub, secret=buf.getvalue())
    assert cf.folder_status(st)["autenticacao"] == "chave"
    (remote / "mnt" / "usc" / "certs_update.csv").write_bytes(b"anterior")
    rid = ready_run(st)
    with session_scope() as s:
        run = s.get(FinalRun, rid)
        pub = cf.publish(s, st, run, ["csv"], "admin")
        assert pub.ok, pub.result
        assert (remote / "mnt" / "usc" / "certs_update.csv").read_bytes() == run.csv
    # chave errada
    other = paramiko.RSAKey.generate(2048)
    b2 = io.StringIO()
    other.write_private_key(b2)
    ok, msg = cf.test_write(replace(st, publish_ssh_secret=b2.getvalue()))
    assert not ok and "Autenticação SSH recusada" in msg
    assert "não contém uma chave" in cf.test_write(replace(st, publish_ssh_secret="-----BEGIN lixo-----"))[1]
    stub.close()


def test_web_typed_password_never_stored(env, tmp_path, remote, monkeypatch):
    stub = SftpStub(remote, password=PW)
    st = sftp_settings(env, tmp_path, stub, secret=None)
    rid = ready_run(st)
    from certwatch.web import app as webapp
    monkeypatch.setattr(webapp, "get_settings", lambda: st)
    with TestClient(webapp.app) as c:
        page = c.get("/cmdb-final", auth=AUTH).text
        assert "svc@127.0.0.1:/mnt/usc" in page and 'type="password" name="ssh_password"' in page
        token = c.cookies["cw_csrf"]
        r = c.post("/cmdb-final/testar-pasta", data={"csrf": token, "ssh_password": PW}, auth=AUTH)
        assert "Ligação, escrita, leitura e remoção funcionam" in r.text
        r = c.post("/cmdb-final/impressao-digital", data={"csrf": token}, auth=AUTH)
        assert pt.fingerprint(stub.host_key) in r.text
        run_page = c.get(f"/cmdb-final/{rid}", auth=AUTH).text
        assert 'name="ssh_password"' in run_page
        r = c.post(f"/cmdb-final/{rid}/publicar", data={"csrf": token, "ficheiro": ["xlsx", "csv", "csv_sem"],
                                                        "confirmo": "1", "ssh_password": PW}, auth=AUTH)
        assert r.status_code == 200 and "falhou" not in r.text
    assert (remote / "mnt" / "usc" / "certs_update_sem_cabecalho.csv").exists()
    with session_scope() as s:
        dump = json.dumps([[a.action, a.target, a.details] for a in s.scalars(select(AuditLog))], ensure_ascii=False, default=str)
        assert PW not in dump and "cmdb_final.publicar" in dump
        for f in s.scalars(select(FinalPublishFile)):
            assert PW not in (f.error or "")
    stub.close()

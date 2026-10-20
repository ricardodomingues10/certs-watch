import os

import pytest

from certwatch import config, db, trust
from tests.pki import PKI, pem


@pytest.fixture(scope="session")
def pki():
    return PKI()


@pytest.fixture()
def env(tmp_path, monkeypatch, pki):
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    (trust_dir / "raiz-interna.pem").write_bytes(pem(pki.root))
    # Por omissão SQLite; com CERTWATCH_TEST_DATABASE_URL corre contra PostgreSQL real
    pg_url = os.environ.get("CERTWATCH_TEST_DATABASE_URL")
    monkeypatch.setenv("CERTWATCH_DATABASE_URL", pg_url or f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("CERTWATCH_TRUST_DIR", str(trust_dir))
    monkeypatch.setenv("CERTWATCH_SYSTEM_CA_BUNDLE", str(tmp_path / "nao-existe.pem"))
    monkeypatch.setenv("CERTWATCH_ADMIN_PASSWORD", "teste-admin-123")
    monkeypatch.setenv("CERTWATCH_UCMDB_URL", "https://cmdb.exemplo.local:8443")
    monkeypatch.setenv("CERTWATCH_UCMDB_TQL", "Certificados_Exemplo")
    monkeypatch.setenv("CERTWATCH_UCMDB_USER", "u")
    monkeypatch.setenv("CERTWATCH_UCMDB_PASSWORD", "p")
    monkeypatch.setenv("CERTWATCH_UCMDB_MIN_CIS", "3")
    monkeypatch.setenv("CERTWATCH_SCAN_ALLOWED_PORTS", "443")
    for f in (config.get_settings, db.get_engine, db.get_sessionmaker):
        f.cache_clear()
    trust._BUNDLE_CACHE.clear()
    if pg_url:
        from certwatch import models  # noqa: F401
        db.Base.metadata.drop_all(db.get_engine())
    db.init_db()
    yield config.get_settings()
    db.get_engine().dispose()
    for f in (config.get_settings, db.get_engine, db.get_sessionmaker):
        f.cache_clear()

"""GET /api/status: estado no contrato soc-status/1 para o Portal SOC."""

from fastapi.testclient import TestClient

from certwatch import config
from certwatch.db import session_scope, utcnow
from certwatch.models import Finding, JobRun
from certwatch.web import app as webapp
from certwatch.web.app import app


def _with_token(monkeypatch, value="tok-portal-123"):
    monkeypatch.setenv("CERTWATCH_STATUS_TOKEN", value)
    config.get_settings.cache_clear()
    webapp._STATUS_CACHE.clear()


def test_desligado_sem_token(env):
    with TestClient(app) as c:
        r = c.get("/api/status")
        assert r.status_code == 404 and "status_token" in r.json()["error"]


def test_token_errado(env, monkeypatch):
    _with_token(monkeypatch)
    with TestClient(app) as c:
        assert c.get("/api/status").status_code == 401
        assert c.get("/api/status", headers={"Authorization": "Bearer errado"}).status_code == 401
        # o login normal (basic auth) não serve: é um token próprio, só de leitura do estado
        assert c.get("/api/status", auth=("admin", "teste-admin-123")).status_code == 401


def test_contrato(env, monkeypatch):
    _with_token(monkeypatch)
    now = utcnow()
    with session_scope() as s:
        s.add(JobRun(job="ingest_cmdb", status="ok", requested_by="teste", started_at=now, finished_at=now,
                     summary={"ingest_cmdb": {"recebidos": 3}}))
        s.add(Finding(id="f1", type="EXPIRADO", severity="critica", subject="x:443", cn_norm="x.exemplo.pt",
                      details={}, status="aberto"))
    with TestClient(app) as c:
        d = c.get("/api/status", headers={"Authorization": "Bearer tok-portal-123"}).json()
    assert d["schema"] == "soc-status/1" and d["service"] == "atalaia-cert"
    assert d["status"] == "warn"  # há um alerta crítico
    assert "1 alertas críticos" in d["message"]
    fresh = {f["id"]: f for f in d["freshness"]}
    assert fresh["atalaia_cmdb"]["status"] == "ok" and fresh["atalaia_cmdb"]["updated_at"]
    assert fresh["atalaia_cmdb"]["max_age_hours"] == 48
    assert fresh["atalaia_smax"]["status"] == "off"  # SMAX não configurado
    assert fresh["atalaia_ct"]["status"] == "off"
    assert any(c["id"] == "alertas" and c["status"] == "warn" for c in d["checks"])
    assert d["jobs"][0]["id"] == "pipeline" and d["jobs"][0]["next_run"]

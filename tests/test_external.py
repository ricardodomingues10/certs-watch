"""Renovação automática (Let's Encrypt) e avaliação externa SSL Labs."""
from dataclasses import replace
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select

from certwatch.classify import is_auto_renew
from certwatch.fontes import ssllabs
from certwatch.db import session_scope, utcnow
from certwatch.evaluator import evaluate, expiry_severity
from certwatch.external import external_targets, run_ssllabs
from certwatch.insights import build_inventory
from certwatch.jobs import ingest_cmdb
from certwatch.models import Finding, SslLabsResult

NOW = utcnow()


@pytest.mark.parametrize("issuer,expected", [
    ("Let's Encrypt", True), ("C=US, O=Let's Encrypt, CN=R10", True), ("R11", True), ("E6", True),
    ("CN=R3,O=Let's Encrypt,C=US", True), ("YR1", True), ("letsencrypt", True), ("ISRG Root X1", True),
    ("DigiCert Global G2 TLS RSA SHA256 2020 CA1", False), ("Exemplo Issuing CA01", False),
    ("Sectigo RSA Domain Validation Secure Server CA", False), ("GEANT OV RSA CA 4", False), ("", False),
])
def test_auto_renew_detection(env, issuer, expected):
    assert is_auto_renew(env, issuer) is expected


def test_auto_renew_alerting(env):
    assert expiry_severity(60, 0.6, env, auto_renew=True) is None      # normal: renova a 30 dias
    assert expiry_severity(25, 0.27, env, auto_renew=True) is None
    assert expiry_severity(15, 0.16, env, auto_renew=True) == "alta"     # a renovação falhou
    assert expiry_severity(60, 0.6, env) == "baixa"                      # manual: aviso a 90 dias
    off = replace(env, auto_renew_alert_days=0)
    assert expiry_severity(60, 0.6, off, auto_renew=True) == "baixa"


def _cmdb(env, rows):
    with session_scope() as s:
        ingest_cmdb(s, replace(env, ucmdb_min_cis=1), [
            {"ucmdb_id": str(i), "global_id": str(i), "common_name": cn, "valid_to": (NOW + timedelta(days=d)).isoformat(),
             "issuer": iss, "issuer_name": iname} for i, (cn, d, iss, iname) in enumerate(rows)])


def test_inventory_column_filter_and_export(env):
    _cmdb(env, [("le.exemplo.pt", 50, "", "R10"),                         # só no IssuerName
                ("le2.exemplo.pt", 10, "Let's Encrypt", ""),              # renovação falhou
                ("manual.exemplo.pt", 50, "DigiCert Global G2", "")])
    with session_scope() as s:
        rows = {r["cn"]: r for r in build_inventory(s, env, utcnow())}
        evaluate(s, env)
        sev = {f.cn_norm: f.severity for f in s.scalars(select(Finding).where(Finding.type == "EXPIRACAO"))}
    assert rows["le.exemplo.pt"]["renovacao"] == "auto" and rows["le.exemplo.pt"]["renovacao_fonte"] == "CMDB"
    assert rows["manual.exemplo.pt"]["renovacao"] == "manual"
    assert "le.exemplo.pt" not in sev and sev["le2.exemplo.pt"] == "alta" and sev["manual.exemplo.pt"] == "baixa"

    from fastapi.testclient import TestClient
    from certwatch.web.app import app
    auth = ("admin", "teste-admin-123")
    with TestClient(app) as c:
        page = c.get("/certificados", params={"renovacao": "auto"}, auth=auth).text
        assert "le.exemplo.pt" in page and "manual.exemplo.pt" not in page and "Renovação automática" in page
        csv_text = c.get("/certificados/exportar", params={"renovacao": "auto"}, auth=auth).content.decode("utf-8")
        assert "Renovação automática" in csv_text.splitlines()[0]
        assert "le2.exemplo.pt" in csv_text and "manual.exemplo.pt" not in csv_text
        assert "Automática" in c.get("/certificados/detalhe", params={"cn": "le.exemplo.pt"}, auth=auth).text


def _ssllabs_transport(grades: dict, calls: list):
    state: dict = {}

    def handler(request: httpx.Request):
        assert request.headers["email"] == "seguranca@exemplo.pt"
        assert request.url.path == "/api/v4/analyze"
        host = request.url.params["host"]
        assert request.url.params.get("publish") == "off" and "startNew" not in request.url.params
        calls.append((host, dict(request.url.params)))
        n = state[host] = state.get(host, 0) + 1
        if n == 1:
            return httpx.Response(200, json={"host": host, "status": "DNS", "statusMessage": "Resolving domain names"},
                                  headers={"X-Max-Assessments": "7", "X-Current-Assessments": "1"})
        if n == 2:
            return httpx.Response(200, json={"host": host, "status": "IN_PROGRESS", "endpoints": [
                {"ipAddress": "203.0.113.10", "statusMessage": "In progress", "progress": 40}]})
        return httpx.Response(200, json={"host": host, "status": "READY", "testTime": 1760961600000, "endpoints": [
            {"ipAddress": "203.0.113.10", "statusMessage": "Ready", "grade": grades[host], "gradeTrustIgnored": grades[host],
             "hasWarnings": False},
            {"ipAddress": "2001:db8::10", "statusMessage": "Ready", "grade": "A", "gradeTrustIgnored": "A", "hasWarnings": True}]})
    return httpx.Client(base_url=ssllabs.API, transport=httpx.MockTransport(handler))


def test_ssllabs_assess_and_findings(env):
    s = replace(env, ssllabs_email="seguranca@exemplo.pt")
    _cmdb(s, [("www.exemplo.pt", 200, "DigiCert", ""), ("portal.exemplo.pt", 200, "DigiCert", ""),
              ("intranet.exemplo.local", 200, "Exemplo Issuing CA01", ""), ("*.exemplo.pt", 200, "DigiCert", "")])
    assert external_targets(s) == ["portal.exemplo.pt", "www.exemplo.pt"]   # sem internos nem wildcards

    calls, sleeps = [], []
    out = run_ssllabs(s, _ssllabs_transport({"www.exemplo.pt": "A+", "portal.exemplo.pt": "B"}, calls),
                      sleep=sleeps.append, clock=lambda: 0.0)
    assert out["avaliados"] == 2 and out["notas"] == {"portal.exemplo.pt": "B", "www.exemplo.pt": "A"}  # pior IP
    assert calls[0][1]["fromCache"] == "on" and calls[0][1]["maxAge"] == "24"
    assert "fromCache" not in calls[1][1]                                      # sondagem sem repetir pedidos novos
    assert 5 in sleeps and 10 in sleeps                                        # 5 s até IN_PROGRESS, depois 10 s

    with session_scope() as db:
        evaluate(db, s)
        f = db.scalar(select(Finding).where(Finding.type == "SSLLABS_NOTA"))
        assert f.cn_norm == "portal.exemplo.pt" and f.severity == "media"
        assert db.scalar(select(SslLabsResult).where(SslLabsResult.host == "www.exemplo.pt")).grade == "A"
    assert external_targets(s) == []                                         # avaliados há menos de 7 dias

    from fastapi.testclient import TestClient
    from certwatch.web.app import app
    from certwatch import config
    auth = ("admin", "teste-admin-123")
    with TestClient(app) as c:
        page = c.get("/testes", auth=auth).text
        assert "Avaliação externa (SSL Labs)" in page and "portal.exemplo.pt" in page
        det = c.get("/certificados/detalhe", params={"cn": "portal.exemplo.pt"}, auth=auth).text
        assert "ssllabs.com/ssltest/analyze.html?d=portal.exemplo.pt" in det


def test_ssllabs_not_registered_and_overload(env):
    s = replace(env, ssllabs_email="seguranca@exemplo.pt")
    _cmdb(s, [("www.exemplo.pt", 200, "DigiCert", "")])
    c441 = httpx.Client(base_url=ssllabs.API, transport=httpx.MockTransport(lambda r: httpx.Response(441)))
    out = run_ssllabs(s, c441, sleep=lambda _: None)
    assert "não registado" in out["erro"]
    c529 = httpx.Client(base_url=ssllabs.API, transport=httpx.MockTransport(lambda r: httpx.Response(529)))
    out = run_ssllabs(s, c529, sleep=lambda _: None)
    assert "sobrecarregado" in out["aviso"] and out["avaliados"] == 0
    assert run_ssllabs(env) == {"aviso": "CERTWATCH_SSLLABS_EMAIL não definido"}

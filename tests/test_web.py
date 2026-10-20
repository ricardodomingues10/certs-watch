from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from certwatch.db import session_scope, utcnow
from certwatch.models import AuditLog, Endpoint, Finding, JobRun
from certwatch.web.app import app

AUTH = ("admin", "teste-admin-123")


def test_auth_headers_and_pages(env):
    with TestClient(app) as c:
        assert c.get("/").status_code == 401
        assert c.get("/", auth=("admin", "errada")).status_code == 401
        assert c.get("/healthz").status_code == 200
        for path in ("/", "/certificados", "/findings", "/endpoints", "/jobs", "/api/inventario", "/api/findings"):
            r = c.get(path, auth=AUTH)
            assert r.status_code == 200, path
        r = c.get("/", auth=AUTH)
        assert r.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
        assert "cw_csrf" in c.cookies


def test_csrf_and_actions(env):
    with session_scope() as s:
        s.add(Finding(id="f1", type="ISSUER_DIVERGENTE", severity="media", subject="x:443",
                      cn_norm="x.exemplo.pt", details={}, status="aberto"))
    with TestClient(app) as c:
        c.get("/findings", auth=AUTH)
        token = c.cookies["cw_csrf"]
        until = (utcnow() + timedelta(days=30)).strftime("%Y-%m-%d")

        # sem token CSRF → recusado
        r = c.post("/findings/f1/aceitar", data={"reason": "risco aceite pelo dono", "until": until}, auth=AUTH)
        assert r.status_code == 403
        # justificação curta → recusado
        r = c.post("/findings/f1/aceitar", data={"reason": "ok", "until": until, "csrf": token}, auth=AUTH)
        assert r.status_code == 400
        # redirect externo é ignorado
        r = c.post("/findings/f1/aceitar", data={"reason": "risco aceite pelo dono do serviço", "until": until,
                                                "csrf": token, "next": "//evil.example"}, auth=AUTH,
                   follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/findings"

        r = c.post("/endpoints", data={"host": "a;b", "port": "443", "csrf": token}, auth=AUTH)
        assert r.status_code == 400
        r = c.post("/endpoints", data={"host": "portal.exemplo.pt", "port": "22", "csrf": token}, auth=AUTH)
        assert r.status_code == 400
        r = c.post("/endpoints", data={"host": "portal.exemplo.pt", "port": "443", "expected_cn": "*.exemplo.pt",
                                       "csrf": token}, auth=AUTH, follow_redirects=False)
        assert r.status_code == 303
        r = c.post("/jobs/pipeline", data={"csrf": token}, auth=AUTH, follow_redirects=False)
        assert r.status_code == 303

    with session_scope() as s:
        f = s.get(Finding, "f1")
        assert f.status == "aceite" and f.accepted_by == "admin"
        ep = s.scalar(select(Endpoint).where(Endpoint.host == "portal.exemplo.pt"))
        assert ep.expected_cn_norm == "*.exemplo.pt" and ep.source == "manual"
        assert s.scalar(select(JobRun).where(JobRun.status == "pending")).job == "pipeline"
        actions = {a.action for a in s.scalars(select(AuditLog))}
        assert {"finding.aceitar", "endpoint.adicionar", "job.pedir"} <= actions

from dataclasses import replace
from datetime import timedelta

import httpx
import pytest

from certwatch.collectors.ct import fetch_all
from certwatch.db import session_scope, utcnow
from certwatch.discovery import DiscoveryError, classify_ct, ingest_ct
from certwatch.jobs import ingest_cmdb
from certwatch.models import Certificate

NOW = utcnow().replace(microsecond=0)
NB = (NOW - timedelta(days=20)).replace(hour=0, minute=0, second=0)
NA = NB + timedelta(days=90)
ISO_NB, ISO_NA = NB.strftime("%Y-%m-%dT%H:%M:%S"), NA.strftime("%Y-%m-%dT%H:%M:%S")
PORTAL_NA = (NOW + timedelta(days=150)).replace(hour=12, minute=0, second=0)


def transport(fail=()):
    calls = {"certspotter": 0}

    def handler(request: httpx.Request):
        host = request.url.host
        if host in fail:
            return httpx.Response(503)
        if host == "crt.sh":
            assert request.url.params["q"] == "%.exemplo.pt" and request.url.params["output"] == "json"
            return httpx.Response(200, json=[
                {"id": 1, "issuer_name": "C=US, O=Let's Encrypt, CN=R10", "common_name": "app.exemplo.pt",
                 "name_value": "app.exemplo.pt\nwww.app.exemplo.pt", "serial_number": "0abc12",
                 "not_before": ISO_NB, "not_after": ISO_NA},
                {"id": 2, "issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
                 "common_name": "portal.exemplo.pt", "name_value": "portal.exemplo.pt", "serial_number": "77",
                 "not_before": ISO_NB, "not_after": PORTAL_NA.strftime("%Y-%m-%dT%H:%M:%S")},
                {"id": 3, "issuer_name": "C=US, O=Let's Encrypt, CN=E6", "common_name": "vpn.exemplo.pt",
                 "name_value": "vpn.exemplo.pt", "serial_number": "99", "not_before": ISO_NB, "not_after": ISO_NA},
                {"id": 4, "issuer_name": "CN=X", "common_name": "intruso.outro.pt", "name_value": "intruso.outro.pt",
                 "serial_number": "1", "not_before": ISO_NB, "not_after": ISO_NA},
            ])
        if host == "api.certspotter.com":
            calls["certspotter"] += 1
            if request.url.params.get("after"):
                return httpx.Response(200, json=[])
            return httpx.Response(200, json=[{
                "id": "cs1", "dns_names": ["app.exemplo.pt", "www.app.exemplo.pt"],
                "issuer": {"name": "CN=R10,O=Let's Encrypt,C=US", "friendly_name": "Let's Encrypt"},
                "not_before": ISO_NB + "Z", "not_after": ISO_NA + "Z", "revoked": False}])
        if host == "api.ctlogs.dev":
            assert request.url.path == "/v1/subdomains/exemplo.pt"
            return httpx.Response(200, json={"rows": [
                {"id": "c1", "match": "app.exemplo.pt", "serial_hex": "0ABC12", "issuer": "CN=R10, O=Let's Encrypt, C=US",
                 "not_before": ISO_NB + "Z", "not_after": ISO_NA + "Z"}], "has_next": False})
        return httpx.Response(404)
    return httpx.MockTransport(handler), calls


def _settings(env):
    return replace(env, ct_domains=["exemplo.pt"])


def test_fetch_merge_and_classify(env):
    s = _settings(env)
    tr, calls = transport()
    records, report = fetch_all(s, httpx.Client(transport=tr))
    assert report == {"exemplo.pt/crtsh": 3, "exemplo.pt/certspotter": 1, "exemplo.pt/ctlogs": 1}
    assert calls["certspotter"] == 2   # paginação até resposta vazia

    with session_scope() as db:
        ingest_cmdb(db, replace(s, ucmdb_min_cis=1), [
            {"ucmdb_id": "p", "global_id": "p", "common_name": "portal.exemplo.pt", "valid_to": PORTAL_NA.isoformat(),
             "issuer": "DigiCert Global G2 TLS RSA SHA256 2020 CA1", "issuer_name": ""},
            {"ucmdb_id": "v", "global_id": "v", "common_name": "vpn.exemplo.pt",
             "valid_to": (NOW + timedelta(days=400)).isoformat(), "issuer": "Outra CA", "issuer_name": ""},
        ])
        summary = ingest_ct(db, s, records, report)
    assert summary["novos"] == 3   # app (3 fontes fundidas), portal, vpn; intruso.outro.pt descartado

    with session_scope() as db:
        db.add(Certificate(sha256="a" * 64, subject_cn="app.exemplo.pt", issuer_cn="R10", serial_hex="ABC12",
                           not_after=NA, is_ca=False))
    with session_scope() as db:
        rows = {r["ct"].primary_name: r for r in classify_ct(db, s)}
    app = rows["app.exemplo.pt"]
    assert app["state"] == "desconhecido" and app["live"] is True
    assert app["ct"].sources == ["certspotter", "crtsh", "ctlogs"]
    assert app["ct"].names == ["app.exemplo.pt", "www.app.exemplo.pt"]
    assert rows["portal.exemplo.pt"]["state"] == "na_cmdb"
    assert rows["vpn.exemplo.pt"]["state"] == "nome_conhecido"

    # Nova execução não duplica
    with session_scope() as db:
        assert ingest_ct(db, s, records, report)["novos"] == 0


def test_partial_and_total_failure(env):
    s = _settings(env)
    tr, _ = transport(fail={"crt.sh"})
    records, report = fetch_all(s, httpx.Client(transport=tr))
    assert report["exemplo.pt/crtsh"].startswith("erro") and report["exemplo.pt/ctlogs"] == 1
    tr, _ = transport(fail={"crt.sh", "api.certspotter.com", "api.ctlogs.dev"})
    records, report = fetch_all(s, httpx.Client(transport=tr))
    with session_scope() as db, pytest.raises(DiscoveryError):
        ingest_ct(db, s, records, report)


def test_discovery_pages_triage_and_export(env, monkeypatch):
    from fastapi.testclient import TestClient
    from certwatch import config
    from certwatch.web.app import app
    monkeypatch.setenv("CERTWATCH_CT_DOMAINS", "exemplo.pt")
    config.get_settings.cache_clear()
    s = config.get_settings()
    tr, _ = transport()
    records, report = fetch_all(s, httpx.Client(transport=tr))
    with session_scope() as db:
        ingest_ct(db, s, records, report)
    auth = ("admin", "teste-admin-123")
    with TestClient(app) as c:
        page = c.get("/descoberta", auth=auth).text
        assert "app.exemplo.pt" in page and "Por triar" in page
        assert '<span class="badge warm">3</span>' in page          # contador na navegação
        token = c.cookies["cw_csrf"]
        with session_scope() as db:
            from certwatch.models import CtCert
            cid = db.query(CtCert).filter(CtCert.primary_name == "app.exemplo.pt").one().id
            injected = db.query(CtCert).filter(CtCert.primary_name == "vpn.exemplo.pt").one()
            injected.issuer_cn = "=HYPERLINK(1)"
            vid = injected.id
        r = c.post(f"/descoberta/{cid}/triagem", data={"decisao": "ignorar", "nota": "", "csrf": token}, auth=auth)
        assert r.status_code == 400                                   # ignorar exige motivo
        r = c.post(f"/descoberta/{cid}/triagem", data={"decisao": "adicionar", "csrf": token, "next": "/descoberta"},
                   auth=auth, follow_redirects=False)
        assert r.status_code == 303
        c.post(f"/descoberta/{vid}/triagem", data={"decisao": "adicionar", "csrf": token}, auth=auth)
        csv_text = c.get("/descoberta/exportar", params={"triagem": "adicionar"}, auth=auth).content.decode("utf-8")
        assert csv_text.startswith("\ufeffNomes;") and "app.exemplo.pt, www.app.exemplo.pt" in csv_text
        assert "'=HYPERLINK(1)" in csv_text                           # sem injeção de fórmulas
        assert "app.exemplo.pt" in c.get("/descoberta", params={"triagem": "adicionar"}, auth=auth).text
        assert c.get("/pesquisa", params={"q": "www.app"}, auth=auth).status_code == 200

"""Teste de ponta a ponta: CMDB → scan real a servidores TLS locais → findings → ciclo de vida."""
from contextlib import ExitStack
from datetime import timedelta

from sqlalchemy import select

from certwatch.db import session_scope, utcnow
from certwatch.evaluator import evaluate
from certwatch.jobs import _store_outcome, ingest_cmdb
from certwatch.models import Endpoint, Finding
from certwatch.scanner import scan_endpoint
from certwatch.trust import build_bundle
from tests.pki import NOW, TLSServer, make_weak_leaf

ISSUING = "Exemplo Teste Issuing CA"


def rec(uid, cn, valid_to, issuer=ISSUING):
    return {"ucmdb_id": uid, "global_id": uid, "common_name": cn,
            "valid_to": valid_to.isoformat() if valid_to else None, "issuer": issuer, "issuer_name": ""}


def _findings(s):
    out = {}
    for f in s.scalars(select(Finding)):
        out.setdefault(f.cn_norm, {})[f.type] = f
    return out


def test_end_to_end(env, pki):
    ip = ["127.0.0.1"]
    ok_leaf, ok_key = pki.leaf("app-ok.exemplo.pt", sans=["app-ok.exemplo.pt"], ip_sans=ip)
    renov_leaf, renov_key = pki.leaf("app-renov.exemplo.pt", sans=["app-renov.exemplo.pt"], ip_sans=ip)
    chain_leaf, chain_key = pki.leaf("app-chain.exemplo.pt", sans=["app-chain.exemplo.pt"], ip_sans=ip)
    exp_leaf, exp_key = pki.leaf("app-exp.exemplo.pt", sans=["app-exp.exemplo.pt"], ip_sans=ip,
                                 not_before=NOW - timedelta(days=85), days_valid=90)
    iss_leaf, iss_key = pki.leaf("app-issuer.exemplo.pt", sans=["app-issuer.exemplo.pt"], ip_sans=ip)
    weak_leaf, weak_key = make_weak_leaf(pki, "app-weak.exemplo.pt")  # SHA-1, RSA 1024, sem SAN IP

    records = [
        rec("1", "app-ok.exemplo.pt", ok_leaf.not_valid_after_utc),
        rec("2", "app-renov.exemplo.pt", renov_leaf.not_valid_after_utc + timedelta(days=60)),
        rec("3", "app-chain.exemplo.pt", chain_leaf.not_valid_after_utc),
        rec("4", "app-exp.exemplo.pt", exp_leaf.not_valid_after_utc),
        rec("5", "app-issuer.exemplo.pt", iss_leaf.not_valid_after_utc, issuer="DigiCert Global G2 TLS RSA SHA256 2020 CA1"),
        rec("6", "app-weak.exemplo.pt", weak_leaf.not_valid_after_utc),
        rec("7", "*.exemplo.pt", NOW + timedelta(days=15), issuer="DigiCert Global G2 TLS RSA SHA256 2020 CA1"),
        rec("8", "old.exemplo.pt", NOW - timedelta(days=400)),
        rec("9", "late.exemplo.pt", NOW + timedelta(days=200)),
    ]
    with session_scope() as s:
        ingest_cmdb(s, env, records)

    servers = {
        "app-ok.exemplo.pt": ([ok_leaf, pki.inter], ok_key),
        "app-renov.exemplo.pt": ([renov_leaf, pki.inter], renov_key),
        "app-chain.exemplo.pt": ([chain_leaf], chain_key),              # sem intermédio
        "app-exp.exemplo.pt": ([exp_leaf, pki.inter], exp_key),
        "app-issuer.exemplo.pt": ([iss_leaf, pki.inter], iss_key),
        "app-weak.exemplo.pt": ([weak_leaf, pki.inter], weak_key),      # sem SAN IP → mismatch
    }
    cafile = build_bundle(env)
    with ExitStack() as stack:
        running = {cn: stack.enter_context(TLSServer(chain, key)) for cn, (chain, key) in servers.items()}
        with session_scope() as s:
            # Endpoints derivados da CMDB (porta 443) não são alcançáveis no teste: desativar
            for e in s.scalars(select(Endpoint)):
                e.enabled = False
            for cn, srv in running.items():
                ep = Endpoint(host="127.0.0.1", port=srv.port, expected_cn_norm=cn, source="manual")
                s.add(ep)
                s.flush()
                _store_outcome(s, ep, scan_endpoint("127.0.0.1", srv.port, cafile, 5))

    with session_scope() as s:
        summary = evaluate(s, env)
        f = _findings(s)

    assert "app-ok.exemplo.pt" not in f, f.get("app-ok.exemplo.pt")
    assert set(f["app-renov.exemplo.pt"]) == {"RENOVACAO_NAO_INSTALADA"}
    assert set(f["app-chain.exemplo.pt"]) == {"CHAIN_INVALIDA"}
    assert f["app-chain.exemplo.pt"]["CHAIN_INVALIDA"].details["codigo"] in (20, 21)
    assert f["app-exp.exemplo.pt"]["EXPIRACAO"].severity == "critica"
    assert f["app-exp.exemplo.pt"]["EXPIRACAO"].details["fonte"] == "live"
    assert set(f["app-issuer.exemplo.pt"]) == {"ISSUER_DIVERGENTE"}
    assert {"CRIPTO_FRACA", "HOSTNAME_MISMATCH"} <= set(f["app-weak.exemplo.pt"])
    assert f["app-weak.exemplo.pt"]["CRIPTO_FRACA"].severity == "alta"
    assert {"WILDCARD_SEM_ENDPOINT", "EXPIRACAO"} == set(f["*.exemplo.pt"])
    assert f["*.exemplo.pt"]["EXPIRACAO"].severity == "alta" and f["*.exemplo.pt"]["EXPIRACAO"].details["fonte"] == "cmdb"
    assert set(f["old.exemplo.pt"]) == {"CMDB_REGISTO_EXPIRADO"}
    assert "late.exemplo.pt" not in f
    assert summary["novos"] == summary["ativos"]

    # Aceitar um risco: mantém-se aceite enquanto válido
    fid = f["app-issuer.exemplo.pt"]["ISSUER_DIVERGENTE"].id
    with session_scope() as s:
        x = s.get(Finding, fid)
        x.status, x.accepted_until = "aceite", utcnow() + timedelta(days=30)
    with session_scope() as s:
        evaluate(s, env)
        assert s.get(Finding, fid).status == "aceite"
    # Aceitação expirada → volta a aberto
    with session_scope() as s:
        s.get(Finding, fid).accepted_until = utcnow() - timedelta(days=1)
    with session_scope() as s:
        r = evaluate(s, env)
        assert s.get(Finding, fid).status == "aberto" and r["reabertos"] == 1

    # CMDB corrigida → finding resolvido automaticamente (ids estáveis, sem duplicados)
    records[1] = rec("2", "app-renov.exemplo.pt", renov_leaf.not_valid_after_utc)
    with session_scope() as s:
        ingest_cmdb(s, env, records)
    with session_scope() as s:
        r = evaluate(s, env)
        f2 = _findings(s)
    assert f2["app-renov.exemplo.pt"]["RENOVACAO_NAO_INSTALADA"].status == "resolvido"
    assert r["resolvidos"] == 1 and r["novos"] == 0


    # As páginas renderizam com dados reais
    from fastapi.testclient import TestClient
    from certwatch.web.app import app
    from certwatch.jobs import enqueue, execute_job_run
    jid = enqueue("evaluate", "teste")
    execute_job_run(jid, env)
    auth = ("admin", "teste-admin-123")
    with TestClient(app) as c:
        assert "app-exp.exemplo.pt" in c.get("/", auth=auth).text
        inv = c.get("/certificados", auth=auth).text
        assert "app-renov.exemplo.pt" in inv and "late.exemplo.pt" in inv
        det = c.get("/certificados/detalhe", params={"cn": "app-chain.exemplo.pt"}, auth=auth).text
        assert "Cadeia de certificação inválida" in det and "Exemplo Teste Issuing CA" in det
        assert c.get("/certificados/detalhe", params={"cn": "*.exemplo.pt"}, auth=auth).status_code == 200
        assert "resolvido" in c.get("/findings", params={"status": "todos"}, auth=auth).text
        assert "127.0.0.1" in c.get("/endpoints", auth=auth).text
        jobs = c.get("/jobs", auth=auth).text
        assert "evaluate" in jobs and "teste" in jobs
        assert len(c.get("/api/findings", auth=auth).json()) >= 8
        assert c.get("/certificados", params={"dias": "7"}, auth=auth).status_code == 200

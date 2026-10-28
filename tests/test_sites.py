"""Sites e certificados: wildcard partilhado, registos da CMDB por site, nomes da internet, pedidos e comentários."""
import json
from dataclasses import replace
from datetime import timedelta

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import select

from certwatch import config
from certwatch import ticket_create as tc
from certwatch.db import session_scope, utcnow
from certwatch.insights import build_inventory
from certwatch.jobs import ingest_cmdb, sync_ct_endpoints
from certwatch.models import Certificate, CtCert, Endpoint, Finding, ScanResult, SmaxComment
from tests.test_ticket_create import ENV, AUTH, FakeSmax

NOW = utcnow().replace(microsecond=0)
WILD_EXP = NOW + timedelta(days=40)


def _serve(db, host, cert_sha, port=443, source="cmdb", expected=None):
    ep = db.scalar(select(Endpoint).where(Endpoint.host == host, Endpoint.port == port))
    if ep is None:   # a ingestão da CMDB já cria os servidores dos nomes que conhece
        ep = Endpoint(host=host, port=port, expected_cn_norm=expected or host, source=source)
        db.add(ep)
        db.flush()
    sr = ScanResult(endpoint_id=ep.id, status="ok", tls_version="TLSv1.3", verify_ok=True, leaf_sha256=cert_sha)
    db.add(sr)
    db.flush()
    ep.last_scan_id = sr.id
    return ep


def _setup(env):
    with session_scope() as db:
        ingest_cmdb(db, replace(env, ucmdb_min_cis=1), [
            {"ucmdb_id": "w", "global_id": "w", "common_name": "*.exemplo.pt", "valid_to": WILD_EXP.isoformat(),
             "issuer": "DigiCert", "issuer_name": ""},
            # registo "por site" do wildcard (mesma data) e registo desatualizado (outra data)
            {"ucmdb_id": "a", "global_id": "a", "common_name": "adfs.exemplo.pt", "valid_to": WILD_EXP.isoformat(),
             "issuer": "DigiCert", "issuer_name": ""},
            {"ucmdb_id": "p", "global_id": "p", "common_name": "portal.exemplo.pt",
             "valid_to": (NOW - timedelta(days=200)).isoformat(), "issuer": "DigiCert", "issuer_name": ""},
            {"ucmdb_id": "o", "global_id": "o", "common_name": "own.exemplo.pt",
             "valid_to": (NOW + timedelta(days=60)).isoformat(), "issuer": "DigiCert", "issuer_name": ""},
        ])
    with session_scope() as db:
        db.add(Certificate(sha256="w" * 64, subject_cn="*.exemplo.pt", issuer_cn="DigiCert", serial_hex="AA",
                           not_before=NOW - timedelta(days=300), not_after=WILD_EXP, sans_dns=["*.exemplo.pt", "exemplo.pt"]))
        db.add(Certificate(sha256="o" * 64, subject_cn="own.exemplo.pt", issuer_cn="DigiCert", serial_hex="BB",
                           not_before=NOW - timedelta(days=30), not_after=NOW + timedelta(days=60), sans_dns=["own.exemplo.pt"]))
        for h in ("adfs.exemplo.pt", "portal.exemplo.pt", "mail.exemplo.pt"):
            _serve(db, h, "w" * 64, source="ct" if h == "mail.exemplo.pt" else "cmdb")
        _serve(db, "own.exemplo.pt", "o" * 64)


def test_inventory_map_and_cmdb_site_records(env):
    _setup(env)
    with session_scope() as db:
        inv = {r["cn"]: r for r in build_inventory(db, env, utcnow())}
    adfs, portal, wild, own = inv["adfs.exemplo.pt"], inv["portal.exemplo.pt"], inv["*.exemplo.pt"], inv["own.exemplo.pt"]
    assert adfs["servido_por"]["cn"] == "*.exemplo.pt" and adfs["servido_por"]["wildcard"]
    assert adfs["servido_por"]["cmdb"] == "por_site"          # mesma data: registo por site do wildcard
    assert portal["servido_por"]["cmdb"] == "diferente"       # registo com outra data
    assert inv["mail.exemplo.pt"]["servido_por"]["cmdb"] == "sem_registo"
    assert {s["host"] for s in wild["instalado_em"]} == {"adfs.exemplo.pt", "portal.exemplo.pt", "mail.exemplo.pt"}
    assert {s["host"] for s in adfs["servido_por"]["sites"]} == {"portal.exemplo.pt", "mail.exemplo.pt"}
    assert own["servido_por"] is None

    from certwatch.evaluator import evaluate
    with session_scope() as db:
        evaluate(db, env)
        cmdb_exp = [f for f in db.scalars(select(Finding)) if f.type == "EXPIRACAO" and (f.details or {}).get("fonte") == "cmdb"]
    assert not any(f.cn_norm == "*.exemplo.pt" for f in cmdb_exp)   # o wildcard é confirmado pelos sites

    from certwatch.web.app import app
    with TestClient(app) as c:
        det = c.get("/certificados/detalhe", params={"cn": "adfs.exemplo.pt"}, auth=AUTH).text
        assert "Este site usa o certificado" in det and "*.exemplo.pt" in det and "registo por site" in det
        assert "outra data" in c.get("/certificados/detalhe", params={"cn": "portal.exemplo.pt"}, auth=AUTH).text
        wdet = c.get("/certificados/detalhe", params={"cn": "*.exemplo.pt"}, auth=AUTH).text
        assert "Onde está instalado" in wdet and "mail.exemplo.pt" in wdet
        lst = c.get("/certificados", params={"servido": "outro"}, auth=AUTH).text
        assert "adfs.exemplo.pt" in lst and "own.exemplo.pt" not in lst and "servido por" in lst
        assert "instalado em <b>3</b> sites" in c.get("/certificados", params={"servido": "partilhado"}, auth=AUTH).text


def test_ct_names_become_endpoints_without_noise(env):
    s = replace(env, ct_domains=["exemplo.pt"], unreachable_after=2)
    with session_scope() as db:
        db.add(CtCert(key_serial="1", key_time="t", domain="exemplo.pt", names=["novo.exemplo.pt", "*.exemplo.pt", "x.outro.pt"],
                      primary_name="novo.exemplo.pt", issuer_cn="R10", issuer_dn="", serial_hex="1",
                      not_before=NOW - timedelta(days=5), not_after=NOW + timedelta(days=80), sources=["crtsh"],
                      source_ids={}, triage="por_triar"))
        db.add(CtCert(key_serial="2", key_time="t2", domain="exemplo.pt", names=["velho.exemplo.pt"], primary_name="velho.exemplo.pt",
                      issuer_cn="R10", issuer_dn="", serial_hex="2", not_before=NOW - timedelta(days=200),
                      not_after=NOW - timedelta(days=100), sources=["crtsh"], source_ids={}, triage="por_triar"))
    with session_scope() as db:
        out = sync_ct_endpoints(db, s)
        assert out["novos"] == 1
        ep = db.scalar(select(Endpoint).where(Endpoint.host == "novo.exemplo.pt"))
        assert ep.source == "ct" and ep.port == 443
        assert sync_ct_endpoints(db, s)["novos"] == 0
    # Sem resposta: não entra no inventário, não dá alerta, e é desligado após N falhas
    from certwatch.jobs import run_scan
    from certwatch import jobs
    from certwatch.fontes.servidores import ScanOutcome
    import certwatch.jobs as J
    orig = J.scan_endpoint
    J.scan_endpoint = lambda host, port, cafile, timeout: ScanOutcome(host, port, status="dns_error", error="não resolve")
    try:
        for _ in range(2):
            with session_scope() as db:
                run_scan(db, s)
    finally:
        J.scan_endpoint = orig
    with session_scope() as db:
        ep = db.scalar(select(Endpoint).where(Endpoint.host == "novo.exemplo.pt"))
        assert not ep.enabled and "Desligado automaticamente" in ep.note
        assert "novo.exemplo.pt" not in {r["cn"] for r in build_inventory(db, s, utcnow())}
        from certwatch.evaluator import evaluate
        evaluate(db, s)
        assert not db.scalars(select(Finding).where(Finding.type == "INALCANCAVEL")).all()


def test_ticket_targets_served_certificate_once(env, monkeypatch):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    config.get_settings.cache_clear()
    _setup(env)
    s = config.get_settings()
    with session_scope() as db:
        b = tc.create_batch(db, ["adfs.exemplo.pt", "portal.exemplo.pt", "own.exemplo.pt"], "admin", s)
        db.flush()
        ds = {d.cn: d for d in tc.drafts_of(db, b.id)}
    assert set(ds) == {"*.exemplo.pt", "own.exemplo.pt"}                   # dois sites do wildcard = um pedido
    w = ds["*.exemplo.pt"]
    assert w.via == ["adfs.exemplo.pt", "portal.exemplo.pt"] and w.expiry_source == "servidor"
    assert set(w.sites) == {"adfs.exemplo.pt", "portal.exemplo.pt", "mail.exemplo.pt"}
    assert any("Selecionado através de adfs.exemplo.pt" in x for x in w.warnings)
    w.ambiente, w.tipo, w.app_id, w.responsavel, w.localizacao = "PRD", "Externo", "9", "Equipa", "DMZ"
    p = tc.build_payload(w, s)["entities"][0]["properties"]
    opts = json.loads(p["UserOptions"])["complexTypeProperties"][0]["properties"]
    assert opts["EndpointCert_c"] == "*.exemplo.pt"
    assert "Instalado em: adfs.exemplo.pt, mail.exemplo.pt, portal.exemplo.pt" in p["Description"]


def test_smax_page_overdue_comments_and_api_tickets(env, monkeypatch):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    config.get_settings.cache_clear()
    s = config.get_settings()
    fake = FakeSmax()
    fake.add("7001", "*.exemplo.pt", NOW - timedelta(days=3), phase="Execute")         # aberto, certificado já expirou
    fake.add("7002", "own.exemplo.pt", NOW + timedelta(days=60), phase="Execute")
    fake.add("7003", "CRM Testes", NOW + timedelta(days=20), phase="Execute")          # pedido de uma API
    fake.add("7004", "antigo.exemplo.pt", NOW - timedelta(days=400), phase="Close")
    fake.add("7005", "semrenov.exemplo.pt", NOW - timedelta(days=3), phase="Execute")    # expirou e não há certificado novo
    comments = {"7001": [{"Id": "c1", "IsSystem": False, "Body": "<p>Aguardamos o <b>CSR</b> da equipa</p>",
                          "PrivacyType": "PUBLIC", "Submitter": {"UserId": "55"}, "CommentFrom": "Agent",
                          "CreateTime": int((NOW - timedelta(days=1)).timestamp() * 1000)},
                         {"Id": "c0", "IsSystem": True, "Body": "Fase alterada", "CreateTime": 1}]}
    base = fake.handler

    def handler(request):
        if "/collaboration/comments/Change/" in request.url.path:
            return httpx.Response(200, json=comments.get(request.url.path.rsplit("/", 1)[1], []))
        if "/ems/Person/55" in request.url.path:
            return httpx.Response(200, json={"entities": [{"properties": {"Name": "Ana Técnica"}}]})
        return base(request)
    fake.handler = handler
    from certwatch.fontes import smax
    monkeypatch.setattr(smax, "client", fake.client)
    _setup(env)
    with session_scope() as db:
        from certwatch.fontes.ucmdb import parse_apis
        from certwatch.jobs import ingest_apis
        recs, fields = parse_apis([{"ucmdbId": "x", "properties": {"display_label": "CRM Testes", "secret_expiration_date":
                                    (NOW + timedelta(days=20)).strftime("%d-%m-%Y %H:%M:%S")}}], s)
        ingest_apis(db, s, recs, fields)
    from certwatch.tickets import ingest_smax
    with session_scope() as db:
        out = ingest_smax(db, s)
        assert out["comentarios"]["comentarios"] == 1
        c = db.scalar(select(SmaxComment))
        assert c.author == "Ana Técnica" and c.body == "Aguardamos o CSR da equipa"

    from certwatch.web.app import app
    with TestClient(app) as cl:
        page = cl.get("/pedidos", auth=AUTH).text
        assert "7001" in page and "Aguardamos o CSR da equipa" in page and "Ana Técnica" in page
        assert "/pedidos/smax/7001#comentarios" in page
        assert "https://smax.test/saw/Change/7001/discussions?TENANTID=123" in cl.get("/pedidos/smax/7001", auth=AUTH).text
        late = cl.get("/pedidos", params={"vista": "atrasados"}, auth=AUTH).text
        assert "7005" in late and "7002" not in late and "expirou há 3 d" in late
        # 7001: o pedido era para o wildcard que expirou, mas o wildcard atual expira depois: renovado, pedido por fechar
        assert "7001" not in late
        done = cl.get("/pedidos", params={"vista": "ja_renovado"}, auth=AUTH).text
        assert "7001" in done and "já renovado: fechar" in done and "7005" not in done and "7002" not in done
        com = cl.get("/pedidos", params={"vista": "comentarios"}, auth=AUTH).text
        assert "7001" in com and "7002" not in com
        assert "7004" in cl.get("/pedidos", params={"vista": "fechados"}, auth=AUTH).text
        assert "/apis?q=CRM%20Testes" in page                                       # pedido ligado à API
        apis = cl.get("/apis", auth=AUTH).text
        assert "7003" in apis and "Pedido SMAX" in apis
        assert "pedidos abertos com certificado já expirado" in cl.get("/", auth=AUTH).text
        det = cl.get("/certificados/detalhe", params={"cn": "adfs.exemplo.pt"}, auth=AUTH).text
        assert "7001" in det and "Aguardamos o CSR" in det                           # pedido do wildcard, visto no site
        assert "Lotes criados aqui" in page and cl.get("/pedidos/lotes", auth=AUTH).status_code == 200

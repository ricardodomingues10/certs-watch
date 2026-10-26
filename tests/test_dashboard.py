"""Painel orientado à ação: expiram sem pedido, movimento nos pedidos, pedidos parados e indicadores NIS2."""
from dataclasses import replace
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from certwatch import config
from certwatch import dashboard as dash
from certwatch.db import session_scope, utcnow
from certwatch.evaluator import load_snapshot
from certwatch.insights import build_inventory
from certwatch.jobs import ingest_cmdb
from certwatch.models import ApiRecord, SmaxComment, SmaxEvent
from certwatch.tickets import ingest_smax

NOW = utcnow().replace(microsecond=0)
AUTH = ("admin", "teste-admin-123")


def tk(tid, endpoint, expiry, phase, updated_days_ago=1, created_days_ago=None):
    return {"id": tid, "display_label": f"Renovar {endpoint}", "endpoint": endpoint, "environment": "PRD",
            "cert_expiry": expiry, "cert_type": "Externo", "phase": phase, "priority": "", "owner_group": "Sistemas",
            "owner_person": "Ana", "last_update": NOW - timedelta(days=updated_days_ago), "scheduled_end": None,
            "service_component": "",
            "created": NOW - timedelta(days=created_days_ago) if created_days_ago is not None else None}


def setup(env):
    s = replace(env, smax_url="https://smax.test", smax_tenant="1", ucmdb_min_cis=1)
    certs = [("semped.exemplo.pt", NOW + timedelta(days=5)),      # expira em 5 dias, sem pedido
             ("comped.exemplo.pt", NOW + timedelta(days=12)),     # tem pedido em curso
             ("parado.exemplo.pt", NOW + timedelta(days=15)),     # pedido em curso mas parado
             ("expirou.exemplo.pt", NOW - timedelta(days=3)),     # expirou há 3 dias, sem pedido
             ("longe.exemplo.pt", NOW + timedelta(days=200))]     # fora do prazo
    with session_scope() as db:
        ingest_cmdb(db, s, [{"ucmdb_id": str(i), "global_id": str(i), "common_name": cn, "valid_to": d.isoformat(),
                             "issuer": "DigiCert", "issuer_name": ""} for i, (cn, d) in enumerate(certs)])
        db.add(ApiRecord(ucmdb_id="a1", name="Pagamentos API - 0123456789abcdef0123", host="", scheme="", url="",
                         expiry=NOW + timedelta(days=8), application="Pagamentos", location="AzureAD", active=True))
        # 1.ª leitura do SMAX: sem histórico, nada conta como mudança
        out = ingest_smax(db, s, [tk("2001", "comped.exemplo.pt", NOW + timedelta(days=12), "Plan", created_days_ago=40),
                                  tk("2002", "parado.exemplo.pt", NOW + timedelta(days=15), "Execute",
                                     updated_days_ago=14, created_days_ago=30)])
        assert out["mudancas"] == 0
    with session_scope() as db:
        # 2.ª leitura: 2001 muda de fase, 2003 é novo
        out = ingest_smax(db, s, [tk("2001", "comped.exemplo.pt", NOW + timedelta(days=12), "Execute", updated_days_ago=0,
                                     created_days_ago=40),
                                  tk("2002", "parado.exemplo.pt", NOW + timedelta(days=15), "Execute",
                                     updated_days_ago=14, created_days_ago=30),
                                  tk("2003", "outro.exemplo.pt", NOW + timedelta(days=60), "Plan", updated_days_ago=0,
                                     created_days_ago=0)])
        assert out["mudancas"] == 2
        db.add(SmaxComment(id="c1", ticket_id="2001", created_at=NOW - timedelta(hours=2), author="Rui",
                           body="CSR enviado à CA"))
    return s


def test_dashboard_lists(env):
    s = setup(env)
    with session_scope() as db:
        ev = {e.ticket_id: e for e in db.scalars(select(SmaxEvent))}
        assert ev["2001"].kind == "fase" and (ev["2001"].de, ev["2001"].para) == ("Plan", "Execute")
        assert ev["2003"].kind == "novo"
        snap = load_snapshot(db)
        inv = build_inventory(db, s, NOW, snap)
        items = dash.expiring_without_ticket(inv, snap, db, s, NOW)
        names = [x["nome"] for x in items]
        assert names == ["expirou.exemplo.pt", "semped.exemplo.pt", "Pagamentos API"]     # por dias, sem os que têm pedido
        api = items[-1]
        assert api["tipo"] == "API" and api["criar"] is None and api["emissor"] == "Pagamentos"
        act = dash.ticket_activity(db, s, NOW, 24)
        kinds = {(a["pedido"], a["tipo"]) for a in act}
        assert {("2001", "fase"), ("2001", "comentario"), ("2003", "novo")} <= kinds
        stale = dash.stale_tickets(db, s, NOW)
        assert [t["pedido"] for t in stale] == ["2002"] and stale[0]["parado"] == 14 and stale[0]["urgente"]
        nis = dash.nis2(inv, snap, db, s, NOW, [])
        assert nis["cobertura"]["total"] == 4 and nis["cobertura"]["com_pedido"] == 2       # 2 certificados + 1 API + 1 sem
        assert nis["antecedencia"] is not None and nis["n_pedidos"] == 3


def test_dashboard_page_and_evidence(env, monkeypatch):
    setup(env)
    for k, v in {"CERTWATCH_SMAX_URL": "https://smax.test", "CERTWATCH_SMAX_TENANT": "1",
                 "CERTWATCH_SMAX_USER": "svc", "CERTWATCH_SMAX_PASSWORD": "x"}.items():
        monkeypatch.setenv(k, v)
    config.get_settings.cache_clear()
    from certwatch.web.app import app
    with TestClient(app) as c:
        page = c.get("/", auth=AUTH).text
        assert "Expiram sem pedido" in page and "semped.exemplo.pt" in page and "comped.exemplo.pt" not in page.split("Movimento nos pedidos")[0]
        assert "mudou de fase" in page and "CSR enviado à CA" in page and "pedido novo" in page
        assert "Pedidos parados" in page and "2002" in page and "14 dias" in page
        assert "Conformidade e evidência" in page and "Gestão de ativos" in page
        assert 'name="cn" value="semped.exemplo.pt"' not in page or "Criar pedidos para os selecionados" in page
        week = c.get("/?janela=168", auth=AUTH).text
        assert "7 dias" in week
        csv = c.get("/painel/evidencia.csv", auth=AUTH)
        text = csv.content.decode("utf-8-sig")
        assert csv.status_code == 200 and text.splitlines()[0].startswith("Tipo;Nome;Expira")
        assert "semped.exemplo.pt" in text and "Pagamentos API" in text


def test_navigation_and_theme(env):
    from certwatch.web.app import app, nav_tree
    tree = {g["key"]: g for g in nav_tree("/cmdb-final/avi", {})}
    assert tree["sistema"]["on"] and not tree["cmdb"]["on"]                       # o prefixo mais longo ganha
    assert [i["label"] for i in tree["sistema"]["items"] if i["on"]] == ["AVI pela API"]
    assert nav_tree("/cert/abc", {})[1]["on"] and nav_tree("/", {})[0]["on"]
    with TestClient(app) as c:
        page = c.get("/certificados", auth=AUTH).text
        assert 'data-palette="consola"' in page and 'aria-current="page"><span>Certificados</span>' in page
        token = c.cookies["cw_csrf"]
        r = c.post("/tema", data={"csrf": token, "tema": "relatorio", "next": "/certificados"}, auth=AUTH, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/certificados"
        assert 'data-palette="relatorio"' in c.get("/certificados", auth=AUTH).text
        assert c.post("/tema", data={"csrf": token, "tema": "neon"}, auth=AUTH).status_code == 400
        assert c.post("/tema", data={"csrf": "x", "tema": "consola"}, auth=AUTH).status_code == 403



def test_client_branding(env, tmp_path, monkeypatch):
    from dataclasses import replace
    from certwatch.web import app as webapp
    brand = tmp_path / "branding"
    brand.mkdir()
    st = replace(config.get_settings(), branding_dir=brand, client_name="Santa Casa da Misericórdia de Lisboa")
    monkeypatch.setattr(webapp, "get_settings", lambda: st)
    with TestClient(webapp.app) as c:
        page = c.get("/", auth=AUTH).text
        assert "Santa Casa da Misericórdia de Lisboa" in page and "/marca/logo" not in page     # sem logo: só o nome
        assert c.get("/marca/logo", auth=AUTH).status_code == 404
        (brand / "logo.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>')
        page = c.get("/", auth=AUTH).text
        assert 'src="/marca/logo"' in page
        r = c.get("/marca/logo", auth=AUTH)
        assert r.status_code == 200 and r.headers["content-type"].startswith("image/svg+xml")
        assert "sandbox" in r.headers["content-security-policy"]                                # o SVG não corre scripts
        assert c.get("/marca/logo").status_code == 401                                          # só com sessão


def test_atalaia_brand_and_logo(env, monkeypatch):
    """O nome visível é Atalaia Cert. O logótipo (a vigia com o foco) é SVG inline animado por style.css: não depende
    de <style> dentro do SVG nem de imagens externas, por isso mexe-se com a CSP da página."""
    from dataclasses import replace
    from certwatch.web import app as webapp
    from certwatch.web.security import SVG_CSP
    with TestClient(webapp.app) as c:
        page = c.get("/certificados", auth=AUTH).text
        assert " · Atalaia Cert" in page and 'href="/static/atalaia-icone.svg"' in page
        assert page.count('<svg class="atalaia atl-anim-sempre') == 2                       # coluna e barra do telemóvel
        assert 'id="atl-feixe-r"' in page and 'id="atl-feixe-m"' in page                   # ids únicos por logótipo
        head = page.split("<main>")[0]
        assert "<style" not in head and "<script>" not in head and 'class="atl-lt"' in head
        css = c.get("/static/style.css").text
        assert "@keyframes atl-foco" in css and ".atalaia.atl-anim-parado" in css
        icon = c.get("/static/atalaia-icone.svg")
        assert icon.status_code == 200 and icon.headers["content-security-policy"] == SVG_CSP and "<script" not in icon.text
        assert c.get("/certificados").headers["www-authenticate"] == 'Basic realm="Atalaia Cert"'
        st = replace(config.get_settings(), logo_animation="auto")
        monkeypatch.setattr(webapp, "get_settings", lambda: st)
        assert 'class="atalaia atl-anim-auto' in c.get("/certificados", auth=AUTH).text


def test_busy_state_drives_the_page_beam(env):
    """Enquanto há trabalho em curso (execuções na fila ou a correr, recentes), a página diz o quê e o foco varre a
    página; /estado/ocupado diz quando acabou. Trabalho parado há mais de 2 h não conta (ex.: worker desligado)."""
    from certwatch.models import JobRun
    from certwatch.web import app as webapp
    with TestClient(webapp.app) as c:
        page = c.get("/", auth=AUTH).text
        assert "data-ocupado" not in page
        assert c.get("/estado/ocupado", auth=AUTH).json() == {"ocupado": []}
        assert c.get("/estado/ocupado").status_code == 401
        with session_scope() as s:
            s.add(JobRun(job="scan", requested_by="admin", status="running"))
            s.add(JobRun(job="ingest_cmdb", requested_by="admin", status="pending",
                         requested_at=utcnow() - timedelta(hours=5)))                     # esquecido: não conta
        page = c.get("/", auth=AUTH).text
        assert 'data-ocupado="1"' in page and "Verificar servidores (a correr)" in page
        assert c.get("/estado/ocupado", auth=AUTH).json() == {"ocupado": ["Verificar servidores (a correr)"]}
        js = c.get("/static/app.js").text
        assert "/estado/ocupado" in js and "foco-pagina" in js

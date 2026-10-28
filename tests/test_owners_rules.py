"""Fontes e chamadas, donos por certificado, regras de pedidos (sem execução automática), calendário .ics e 47 dias."""
import logging
import re
from datetime import date, datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from certwatch import calendar_ics, owners as ow, prep47
from certwatch.db import session_scope
from certwatch.insights import build_inventory
from certwatch.models import CertOwner, Team, TicketRule, UserPref
from tests.test_dashboard import NOW, setup

AUTH = ("admin", "teste-admin-123")


@pytest.fixture()
def web(env):
    from certwatch.web import app as webapp
    from certwatch.web import security
    security.forget_logins()
    security._FAILS.clear()
    webapp.invalidate_nav()
    with TestClient(webapp.app) as c:
        yield c


def csrf(c):
    return c.cookies.get("cw_csrf")


def test_sources_registry_and_page(env, web):
    from certwatch.fontes import ORDER, all_sources
    fontes = all_sources(env)
    ids = [f["id"] for f in fontes]
    assert ids == list(ORDER)
    for f in fontes:
        assert {"id", "nome", "tipo", "estado", "para", "chamadas", "ligada", "detalhe", "modulo"} <= set(f)
        for c in f["chamadas"]:
            assert c["acesso"] in ("leitura", "escrita", "envio") and c["estado"] and c["metodo"] and c["endereco"] and c["onde"]
    assert {"ucmdb", "smax", "avi", "ct", "ssllabs", "servidores", "email", "ca", "azure", "teams", "dns", "acme"} <= set(ids)
    assert any(c["estado"] == "planeado" for f in fontes if f["id"] == "teams" for c in f["chamadas"])
    page = web.get("/fontes", auth=AUTH)
    assert page.status_code == 200 and "Fontes e chamadas" in page.text and "UCMDB" in page.text and "Teams" in page.text
    assert "planead" in page.text


def test_teams_webhooks_are_secret_file_only(env, tmp_path, monkeypatch):
    from certwatch.fontes import teams
    f = tmp_path / "teams_webhooks"
    f.write_text('{"sistemas": "https://exemplo.webhook.office.com/abc", "mau": "http://inseguro"}')
    monkeypatch.setattr(teams, "SECRET", f)
    hooks = teams.webhooks()
    assert "sistemas" in hooks and "mau" not in hooks
    assert teams.estado(env) == (True, "1 equipa(s) com endereço")
    card = teams.card("Expira em 7 dias", "a.exemplo.pt", "https://atalaia/x")
    assert card["type"] == "message" and "a.exemplo.pt" in str(card) and "webhook" not in str(card)
    with pytest.raises(ValueError):
        teams.post_card("outra", "t", "x")


def test_owner_assign_filter_bulk_and_smax_suggestion(env, web):
    setup(env)
    with session_scope() as s:
        s.add(Team(name="Sistemas", email="sistemas@exemplo.pt", smax_group="Sistemas"))
        s.add(Team(name="Redes"))
    with session_scope() as s:
        t = {x.name: x.id for x in s.scalars(select(Team))}
        inv = {r["cn"]: r for r in build_inventory(s, env, NOW)}
    # o pedido do SMAX (grupo Sistemas) sugere a equipa sem a atribuir
    assert inv["comped.exemplo.pt"]["dono"]["origem"] == "smax" and inv["comped.exemplo.pt"]["dono"]["equipa_id"] == t["Sistemas"]
    assert inv["semped.exemplo.pt"]["dono"] is None
    web.get("/certificados", auth=AUTH)
    r = web.post("/certificados/dono", data={"csrf": csrf(web), "cn": "semped.exemplo.pt", "equipa": str(t["Redes"]),
                                             "pessoa": "Rui Costa", "email": "Rui@Exemplo.pt"}, auth=AUTH, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].endswith("#dono")
    with session_scope() as s:
        o = s.scalar(select(CertOwner).where(CertOwner.cn_norm == "semped.exemplo.pt"))
        assert o.team_id == t["Redes"] and o.person == "Rui Costa" and o.person_email == "rui@exemplo.pt" and o.updated_by == "admin"
    detail = web.get("/certificados/detalhe?cn=semped.exemplo.pt", auth=AUTH).text
    assert 'id="dono"' in detail and "Rui Costa" in detail
    lst = web.get(f"/certificados?dono={t['Redes']}", auth=AUTH).text
    assert "semped.exemplo.pt" in lst and "longe.exemplo.pt" not in lst
    sem = web.get("/certificados?dono=sem", auth=AUTH).text
    assert "longe.exemplo.pt" in sem and "semped.exemplo.pt" not in sem
    csv = web.get("/certificados/exportar", auth=AUTH).content.decode("utf-8-sig")
    assert "Equipa dona" in csv.splitlines()[0] and "Redes" in csv
    # atribuição em bloco: primeiro a prévia, só aplica ao confirmar
    data = {"csrf": csrf(web), "padrao": "*.exemplo.pt", "equipa": str(t["Sistemas"]), "so_sem": "1"}
    prev = web.post("/donos/atribuir", data=data, auth=AUTH)
    assert prev.status_code == 200 and "longe.exemplo.pt" in prev.text
    with session_scope() as s:
        assert s.scalar(select(CertOwner).where(CertOwner.cn_norm == "longe.exemplo.pt")) is None
    done = web.post("/donos/atribuir", data={**data, "acao": "aplicar"}, auth=AUTH)
    assert "atribuído(s) à equipa Sistemas" in done.text
    with session_scope() as s:
        owners = {o.cn_norm: o.team_id for o in s.scalars(select(CertOwner))}
    assert owners["longe.exemplo.pt"] == t["Sistemas"] and owners["semped.exemplo.pt"] == t["Redes"]    # só os sem dono
    page = web.get("/donos", auth=AUTH)
    assert page.status_code == 200 and "Sistemas" in page.text and "Redes" in page.text
    # tirar o dono
    web.post("/certificados/dono", data={"csrf": csrf(web), "cn": "semped.exemplo.pt", "equipa": ""}, auth=AUTH)
    with session_scope() as s:
        assert s.scalar(select(CertOwner).where(CertOwner.cn_norm == "semped.exemplo.pt")) is None


def test_match_pattern():
    assert ow.match_pattern("a.exemplo.local", "*.exemplo.local")
    assert not ow.match_pattern("exemplo.local.mau.pt", "*.exemplo.local")


def test_rules_created_off_and_never_open_tickets(env, web, monkeypatch):
    setup(env)
    from certwatch import ticket_create as tc
    calls = []
    monkeypatch.setattr(tc, "create_batch", lambda *a, **k: calls.append(a))
    web.get("/pedidos/regras", auth=AUTH)
    r = web.post("/pedidos/regras", data={"csrf": csrf(web), "modelo": "0"}, auth=AUTH)
    assert r.status_code == 200
    r = web.post("/pedidos/regras", data={"csrf": csrf(web), "nome": "Tudo a 10 dias", "dias": "10", "tipo": "todos",
                                          "ambito": "todos", "renovacao": "todos", "grupo": "Sistemas"}, auth=AUTH)
    assert r.status_code == 200
    with session_scope() as s:
        regras = {x.name: x for x in s.scalars(select(TicketRule))}
    assert set(regras) == {"Externos de renovação manual a 30 dias", "Tudo a 10 dias"}
    assert not any(x.enabled for x in regras.values())                                   # criadas desligadas
    painel = web.get("/", auth=AUTH).text
    assert "Pedidos que as regras ativas abririam" not in painel
    rid = regras["Tudo a 10 dias"].id
    page = web.post(f"/pedidos/regras/{rid}/ativar", data={"csrf": csrf(web)}, auth=AUTH).text
    assert "Nada é aberto sem confirmação" in page
    card = page.split(f'id="ru-{rid}"')[1].split("</section>")[0]
    # expira em 5 dias, expirou há 3 e a API a 8 dias: os sem pedido dentro dos 10 dias
    assert "Hoje abriria 3 pedidos" in card and "semped.exemplo.pt" in card and "expirou.exemplo.pt" in card
    assert "Pagamentos API" in card and "longe.exemplo.pt" not in card and "comped.exemplo.pt" not in card
    painel = web.get("/", auth=AUTH).text
    assert "Pedidos que as regras ativas abririam" in painel
    assert calls == []                                                                     # nada criado no SMAX
    web.post(f"/pedidos/regras/{rid}/desativar", data={"csrf": csrf(web)}, auth=AUTH)
    web.post(f"/pedidos/regras/{rid}/apagar", data={"csrf": csrf(web)}, auth=AUTH)
    with session_scope() as s:
        assert [x.name for x in s.scalars(select(TicketRule))] == ["Externos de renovação manual a 30 dias"]


def test_rule_matching_filters(env):
    setup(env)
    from certwatch import dashboard as dash, rules as rl
    from certwatch.evaluator import load_snapshot
    with session_scope() as s:
        snap = load_snapshot(s)
        inv = build_inventory(s, env, NOW, snap)
        items = dash.expiring_without_ticket(inv, snap, s, env, NOW)
    by_cn = {r["cn"]: r for r in inv}
    api_only = TicketRule(name="a", days=30, kind="api", scope="todos", renewal="todos")
    assert [m["nome"] for m in rl.matches(api_only, items, by_cn)] == ["Pagamentos API"]
    short = TicketRule(name="b", days=4, kind="certificado", scope="todos", renewal="todos")
    assert [m["nome"] for m in rl.matches(short, items, by_cn)] == ["expirou.exemplo.pt"]
    issuer = TicketRule(name="c", days=30, kind="certificado", scope="todos", renewal="todos", issuer_contains="outraca")
    assert rl.matches(issuer, items, by_cn) == []


def test_ics_build_escaping_and_folding(env):
    setup(env)
    with session_scope() as s:
        from certwatch.evaluator import load_snapshot
        snap = load_snapshot(s)
        inv = build_inventory(s, env, NOW, snap)
        body = calendar_ics.build(inv, snap.apis, NOW, "https://atalaia.exemplo.pt/")
    assert body.startswith("BEGIN:VCALENDAR\r\n") and body.endswith("END:VCALENDAR\r\n")
    assert "\n" not in body.replace("\r\n", "")
    assert all(len(line.encode()) <= 75 for line in body.split("\r\n"))
    unfolded = body.replace("\r\n ", "")
    assert unfolded.count("BEGIN:VEVENT") == 6           # os 5 certificados (até 400 dias) + a API
    assert "SUMMARY:Expira: semped.exemplo.pt" in unfolded and "Expira o segredo: Pagamentos API" in unfolded
    assert "TRIGGER:-P30D" in unfolded and "TRIGGER:-P7D" in unfolded
    assert "URL:https://atalaia.exemplo.pt/certificados/detalhe?cn=semped.exemplo.pt" in unfolded
    assert calendar_ics._esc("a,b;c\\d\ne") == "a\\,b\\;c\\\\d\\ne"
    uids = re.findall(r"UID:(\S+)", unfolded)
    assert len(uids) == len(set(uids))
    again = calendar_ics.build(inv, snap.apis, NOW + timedelta(hours=1), "https://atalaia.exemplo.pt")
    assert re.findall(r"UID:(\S+)", again.replace("\r\n ", "")) == uids      # UID estável


def test_ics_download_and_token_feed(env, web, caplog):
    setup(env)
    with session_scope() as s:
        s.add(Team(name="Redes"))
    with session_scope() as s:
        tid = s.scalar(select(Team.id))
    r = web.get("/calendario.ics", auth=AUTH)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/calendar")
    assert "attachment" in r.headers["content-disposition"] and "semped.exemplo.pt" in r.text
    empty = web.get(f"/calendario.ics?equipa={tid}", auth=AUTH).text            # equipa sem certificados
    assert "BEGIN:VEVENT" not in empty and "Redes" in empty
    anon = TestClient(web.app)
    assert anon.get("/calendario.ics", follow_redirects=False).status_code in (303, 401)
    assert anon.get("/calendario/inventado.ics").status_code == 404
    web.get("/conta", auth=AUTH)
    page = web.post("/conta/calendario", data={"csrf": csrf(web), "acao": "gerar"}, auth=AUTH).text
    m = re.search(r'value="(https?://[^"]+/calendario/([^"/]+)\.ics)"', page)
    assert m, "o link aparece uma vez"
    token = m.group(2)
    with session_scope() as s:
        pref = s.scalar(select(UserPref).where(UserPref.key == "calendario"))
        assert token not in str(pref.value) and pref.value["hash"]                   # só o hash fica guardado
    caplog.set_level(logging.INFO)
    feed = anon.get(f"/calendario/{token}.ics")
    assert feed.status_code == 200 and "semped.exemplo.pt" in feed.text
    assert token not in web.get("/conta", auth=AUTH).text                           # não volta a aparecer
    from certwatch.web.app import _RedactInvite
    rec = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, '%s - "%s %s HTTP/1.1" %d', ("1.2.3.4", "GET", f"/calendario/{token}.ics", 200), None)
    _RedactInvite().filter(rec)
    assert token not in rec.getMessage()
    web.post("/conta/calendario", data={"csrf": csrf(web), "acao": "apagar"}, auth=AUTH)
    assert anon.get(f"/calendario/{token}.ics").status_code == 404


def test_prep47_analysis(env):
    setup(env)
    with session_scope() as s:
        inv = build_inventory(s, env, NOW)
    a = prep47.analyse(inv, env, date(2026, 10, 28), 2)
    assert a["atual"]["dias"] == 200 and a["proxima"]["dias"] == 100
    assert a["dias_ate"] == (date(2027, 3, 15) - date(2026, 10, 28)).days
    assert [p["passada"] for p in a["phases"]] == [True, False, False, False] and a["phases"][1]["atual"]
    assert a["classes"]["manual"] == 5 and a["n_manual"] == 5                       # DigiCert, renovação manual
    assert a["renov_total"] == {200: round(5 * 1.8), 100: round(5 * 3.6), 47: round(5 * 7.8)}
    assert a["horas_2029"] == round(5 * 7.8 * 2) and a["sem_dono"] == 3          # 2 têm a sugestão do grupo do pedido no SMAX
    assert [t["equipa"] for t in a["equipas"]] == ["Sem dono"] or a["equipas"][0]["n"] >= 1
    assert prep47.phase_for(date(2029, 3, 15)) == 3 and prep47.phase_for(date(2026, 3, 14)) == 0
    internal = prep47.classify({"live_issuer": "", "issuers": [], "renovacao": "manual"}, set())
    assert internal == "desconhecida"


def test_prep47_page(env, web):
    setup(env)
    page = web.get("/preparar-47-dias?horas=3", auth=AUTH)
    assert page.status_code == 200
    t = page.text
    assert "Preparar os 47 dias" in t and "estamos aqui" in t and "47 dias" in t and "O que fazer" in t
    assert 'value="3.0"' in t or 'value="3"' in t
    assert "semped.exemplo.pt" in t and "Cada certificado público tem dono" in t
    assert web.get("/preparar-47-dias?horas=lixo", auth=AUTH).status_code == 200

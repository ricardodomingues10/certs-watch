"""Sites públicos: todos os IPs, dentro e fora, comparados com a CMDB e com o pedido. E os domínios por RDAP."""
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.hazmat.primitives.serialization import Encoding
from fastapi.testclient import TestClient
from sqlalchemy import select

from certwatch import domains as dm
from certwatch import sites as st
from certwatch.db import session_scope
from certwatch.fontes import dns, rdap
from certwatch.fontes.servidores import ScanOutcome
from certwatch.models import DomainChange, SiteCheck

AUTH = ("admin", "teste-admin-123")
NOW = datetime.now(timezone.utc).replace(microsecond=0)


@pytest.fixture(scope="module")
def certs(pki):
    new, _ = pki.leaf("portal.exemplo.pt", sans=["portal.exemplo.pt"], days_valid=300)
    old, _ = pki.leaf("portal.exemplo.pt", sans=["portal.exemplo.pt"], days_valid=40)
    dead, _ = pki.leaf("portal.exemplo.pt", sans=["portal.exemplo.pt"], days_valid=10,
                       not_before=NOW - timedelta(days=20))
    other, _ = pki.leaf("outro.exemplo.pt", sans=["outro.exemplo.pt"], days_valid=300)
    return {k: v.public_bytes(Encoding.DER) for k, v in {"new": new, "old": old, "dead": dead, "other": other}.items()}


def fake_scan(by_ip):
    def scan(host, port, cafile, timeout=8.0, connect_to=""):
        out = ScanOutcome(host=host, port=port)
        v = by_ip.get(connect_to)
        if v is None:
            out.status, out.error = "unreachable", "timeout"
        elif v == "noipv6":
            out.status, out.error = "unreachable", "[Errno 101] Network is unreachable"
        else:
            out.chain_der, out.verify_ok = [v], True
        return out
    return scan


def probe(settings, inside, outside, by_ip, name="portal.exemplo.pt"):
    return st.probe(name, settings, "", lambda n: inside, lambda n: outside, fake_scan(by_ip))


def row(cmdb_days=None, tickets=(), in_cmdb=True):
    return {"cn": "portal.exemplo.pt", "common_name": "portal.exemplo.pt", "in_cmdb": in_cmdb,
            "cmdb_valid_to": NOW + timedelta(days=cmdb_days) if cmdb_days is not None else None,
            "smax": {"main": tickets[0] if tickets else None, "open": list(tickets)}, "dono": {"equipa": "Sistemas"}}


def ev(settings, p, r):
    return st.evaluate("portal.exemplo.pt", p, r, NOW, settings.timezone)


R = dns.Resolution


def test_all_good_and_cmdb_states(env, certs):
    p = probe(env, R(ips=["10.0.0.5"]), R(ips=["193.1.1.5"]), {"10.0.0.5": certs["new"], "193.1.1.5": certs["new"]})
    assert [n["vistas"] for n in p["nodes"]] == [["dentro"], ["fora"]]
    res = ev(env, p, row(cmdb_days=299))
    assert res["estado"] == "ok" and res["flags"] == [] and res["servido"]["nome_ok"] and res["dono"] == "Sistemas"
    # o servidor já tem um mais recente do que a CMDB
    assert ev(env, p, row(cmdb_days=39))["estado"] == "cmdb_desatualizada"
    # a CMDB já tem o renovado, o servidor ainda serve o antigo
    p_old = probe(env, R(ips=["10.0.0.5"]), R(ips=["193.1.1.5"]), {"10.0.0.5": certs["old"], "193.1.1.5": certs["old"]})
    assert ev(env, p_old, row(cmdb_days=299))["estado"] == "renovado_nao_instalado"
    assert ev(env, p, row(in_cmdb=False))["estado"] == "sem_cmdb"


def test_inside_outside_and_forgotten_node(env, certs):
    # a internet vê outro certificado
    p = probe(env, R(ips=["10.0.0.5"]), R(ips=["193.1.1.5"]), {"10.0.0.5": certs["new"], "193.1.1.5": certs["old"]})
    res = ev(env, p, row(cmdb_days=299))
    assert res["estado"] == "fora_diferente" and "renovado_nao_instalado" in res["flags"]
    # dois nós públicos, um esquecido com o antigo
    p = probe(env, R(ips=["10.0.0.5"]), R(ips=["193.1.1.5", "193.1.1.6"]),
              {"10.0.0.5": certs["new"], "193.1.1.5": certs["new"], "193.1.1.6": certs["old"]})
    res = ev(env, p, row(cmdb_days=299))
    assert res["estado"] == "nos_diferentes" and "renovado_nao_instalado" in res["flags"]
    # o mesmo IP dentro e fora: testado uma só vez
    p = probe(env, R(ips=["193.1.1.5"]), R(ips=["193.1.1.5"]), {"193.1.1.5": certs["new"]})
    assert len(p["nodes"]) == 1 and p["nodes"][0]["vistas"] == ["dentro", "fora"]


def test_tickets_expired_unreachable_and_notes(env, certs):
    p = probe(env, R(ips=["10.0.0.5"]), R(ips=["193.1.1.5"]), {"10.0.0.5": certs["new"], "193.1.1.5": certs["new"]})
    t = {"id": "5001", "url": "https://smax/5001", "fase": "Execute", "aberto": True, "expira": NOW + timedelta(days=39)}
    res = ev(env, p, row(cmdb_days=299, tickets=[t]))
    assert res["estado"] == "pedido_desatualizado" and res["pedidos_desatualizados"] == ["5001"]
    dead = probe(env, R(ips=["10.0.0.5"]), R(ips=["193.1.1.5"]), {"10.0.0.5": certs["dead"], "193.1.1.5": certs["dead"]})
    assert ev(env, dead, row(cmdb_days=-10))["estado"] == "expirado"
    none = probe(env, R(ips=["10.0.0.5"]), R(ips=["193.1.1.5"]), {})
    assert ev(env, none, row(cmdb_days=299))["estado"] == "sem_resposta"
    # IP público inacessível daqui (sem hairpin): fica a visão de dentro, com uma nota
    hair = probe(env, R(ips=["10.0.0.5"]), R(ips=["193.1.1.5"]), {"10.0.0.5": certs["new"]})
    res = ev(env, hair, row(cmdb_days=299))
    assert res["estado"] == "ok" and "fora_indisponivel" in res["notas"]
    # sem IPv6 neste servidor: não conta como falha
    v6 = probe(env, R(ips=["10.0.0.5"]), R(ips=["193.1.1.5", "2001:db8::5"]),
               {"10.0.0.5": certs["new"], "193.1.1.5": certs["new"], "2001:db8::5": "noipv6"})
    res = ev(env, v6, row(cmdb_days=299))
    assert res["estado"] == "ok" and "sem_ipv6" in res["notas"]
    # não existe no DNS público
    only_in = probe(env, R(ips=["10.0.0.5"]), R(inexistente=True, erro="não existe no DNS público"), {"10.0.0.5": certs["new"]})
    assert ev(env, only_in, row(cmdb_days=299))["estado"] == "so_interno"
    # nome que o certificado não cobre
    wrong = probe(env, R(ips=["10.0.0.5"]), R(ips=["193.1.1.5"]), {"10.0.0.5": certs["other"], "193.1.1.5": certs["other"]})
    assert ev(env, wrong, row(in_cmdb=False))["servido"]["nome_ok"] is False


def test_cdn_samples_and_limits(env, certs):
    many = [f"193.1.1.{i}" for i in range(1, 20)]
    p = probe(env, R(ips=[]), R(ips=many, cnames=["portal.exemplo.pt.cdn.cloudflare.net"]),
              {ip: (certs["new"] if i % 2 else certs["old"]) for i, ip in enumerate(many)})
    assert p["cdn"] and len(p["nodes"]) == 2
    res = ev(env, p, row(cmdb_days=299))
    assert "nos_diferentes" not in res["flags"] and "cdn" in res["notas"]
    p = probe(env, R(ips=[]), R(ips=many), {ip: certs["new"] for ip in many})
    assert len(p["nodes"]) == env.sites_max_ips


def test_public_dns_over_https():
    calls = []

    def handler(request):
        calls.append(str(request.url))
        if "cloudflare" in request.url.host:
            return httpx.Response(500)
        t = request.url.params["type"]
        ans = [{"type": 5, "data": "portal.exemplo.pt.edgekey.net."}]
        ans += [{"type": 1, "data": "193.1.1.5"}] if t == "A" else [{"type": 28, "data": "2001:db8::5"}]
        return httpx.Response(200, json={"Status": 0, "Answer": ans})
    c = httpx.Client(transport=httpx.MockTransport(handler))
    r = dns.resolve_public("portal.exemplo.pt", ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"], c)
    assert r.ips == ["193.1.1.5", "2001:db8::5"] and r.resolvedor == "dns.google" and r.cdn == "edgekey.net"
    nx = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"Status": 3})))
    r = dns.resolve_public("nao-existe.exemplo.pt", ["https://dns.google/resolve"], nx)
    assert r.inexistente and "não existe" in r.erro


def test_run_stores_and_page(env, certs, monkeypatch):
    from tests.test_dashboard import setup
    setup(env)
    by_ip = {"10.0.0.5": certs["new"]}
    with session_scope() as s:
        out = st.run(s, env, now=NOW, resolve_internal=lambda n: R(ips=["10.0.0.5"]) if n == "semped.exemplo.pt" else R(erro="x"),
                     resolve_public=lambda n: R(inexistente=True, erro="não existe no DNS público"), scan=fake_scan(by_ip))
    assert out["sites"] == 5 and out["sem_resposta"] == 4
    with session_scope() as s:
        names = {c.name: c.data["flags"] for c in s.scalars(select(SiteCheck))}
    assert names["semped.exemplo.pt"] == ["cmdb_desatualizada", "so_interno"]
    from certwatch.web import app as webapp
    webapp.invalidate_nav()
    with TestClient(webapp.app) as c:
        page = c.get("/sites-publicos", auth=AUTH)
        assert page.status_code == 200 and "semped.exemplo.pt" in page.text and "Sem resposta" in page.text
        assert "Com problemas" in page.text
        csv = c.get("/sites-publicos/exportar", auth=AUTH).content.decode("utf-8-sig")
        assert csv.splitlines()[0].startswith("Site;Estado") and "10.0.0.5" in csv
        assert "Sites públicos com problemas" in c.get("/", auth=AUTH).text


RDAP_PT = {
    "objectClassName": "domain", "ldhName": "exemplo.pt",
    "events": [{"eventAction": "registration", "eventDate": "2001-05-01T00:00:00Z"},
               {"eventAction": "expiration", "eventDate": (NOW + timedelta(days=40)).isoformat()},
               {"eventAction": "last changed", "eventDate": "2026-01-01T00:00:00Z"}],
    "status": ["active", "client transfer prohibited"],
    "nameservers": [{"ldhName": "NS1.EXEMPLO.PT"}, {"ldhName": "ns2.exemplo.pt."}],
    "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Dono"]]]},
                 {"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Registrar Exemplo, Lda"]]]}],
    "secureDNS": {"delegationSigned": True},
}


def rdap_client(doc):
    def handler(request):
        if request.url.host == "data.iana.org":
            return httpx.Response(200, json={"services": [[["pt"], ["https://rdap.dns.pt/"]], [["com", "net"], ["https://rdap.verisign.com/com/v1/"]]]})
        if request.url.path == "/domain/exemplo.pt":
            return httpx.Response(200, json=doc)
        return httpx.Response(404)
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_rdap_parse_and_changes(env):
    from dataclasses import replace
    s2 = replace(env, domains=["exemplo.pt", "outro.pt"])
    info = rdap.parse(RDAP_PT)
    assert info["registrar"] == "Registrar Exemplo, Lda" and info["nameservers"] == ["ns1.exemplo.pt", "ns2.exemplo.pt"]
    assert "client transfer prohibited" in info["status"] and info["dnssec"]
    assert rdap.server_for("www.exemplo.com.pt", {"pt": "a/", "com.pt": "b/"}) == "b/"
    with session_scope() as s:
        out = dm.run(s, s2, rdap_client(RDAP_PT))
    assert out == {"dominios": 2, "lidos": 1, "erros": 1, "alteracoes": 0}
    hijack = {**RDAP_PT, "nameservers": [{"ldhName": "ns.atacante.example"}], "status": ["active"]}
    with session_scope() as s:
        out = dm.run(s, s2, rdap_client(hijack))
    assert out["alteracoes"] == 2
    with session_scope() as s:
        ov = dm.overview(s, s2)
        assert {c.field for c in s.scalars(select(DomainChange))} == {"nameservers", "status"}
    row = next(r for r in ov["rows"] if r["domain"] == "exemplo.pt")
    assert row["alerta"] and not row["bloqueado"] and ov["alertas"] >= 3


def test_sites_email(env, certs):
    from certwatch import report as rp
    from tests.test_dashboard import setup
    setup(env)
    by_ip = {"10.0.0.5": certs["new"], "193.1.1.5": certs["new"], "193.1.1.6": certs["old"]}
    with session_scope() as s:
        st.run(s, env, now=NOW, resolve_internal=lambda n: R(ips=["10.0.0.5"]),
               resolve_public=lambda n: R(ips=["193.1.1.5", "193.1.1.6"]) if n == "semped.exemplo.pt" else R(ips=["193.1.1.5"]),
               scan=fake_scan(by_ip))
    with session_scope() as s:
        sel = rp.select_rows([], 0, 90, sites=rp.sites_data(s, env))
    now = NOW
    html = rp.email_html("sites", sel, 0, 90, 20, "Equipa", now)
    assert "Sites que precisam de ação" in html and "semped.exemplo.pt" in html and "Nós diferentes" in html
    assert "a CMDB ainda não reflete" in html                           # longe/comped: o servidor tem um mais recente
    subj = rp.subject_for("sites", sel, 0, 90, 20)
    assert subj.startswith("Sites públicos | 1 a precisar de ação")
    xlsx = rp.sites_excel(sel)
    from io import BytesIO
    from openpyxl import load_workbook
    wb = load_workbook(BytesIO(xlsx))
    assert wb.sheetnames == ["Sites", "Nos"] and wb["Sites"].max_row == 6
    from certwatch.web import app as webapp
    with TestClient(webapp.app) as c:
        c.get("/relatorio", auth=AUTH)
        r = c.post("/relatorio", data={"csrf": c.cookies["cw_csrf"], "desde": 0, "ate": 90, "alerta": 20, "ct_dias": 30},
                   auth=AUTH, follow_redirects=False)
        rid = r.headers["location"].rsplit("/", 1)[1]
        page = c.get(f"/relatorio/{rid}", auth=AUTH).text
        assert "Sites públicos e domínios" in page and 'value="sites"' in page
        prev = c.get(f"/relatorio/{rid}/previsao/sites", auth=AUTH).text
        assert "semped.exemplo.pt" in prev
        x = c.get(f"/relatorio/{rid}/excel?parte=sites", auth=AUTH)
        assert x.status_code == 200 and 'Sites_Publicos.xlsx' in x.headers["content-disposition"]

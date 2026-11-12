"""Revogação, CAA, HSTS e chaves reutilizadas, do princípio ao fim e sem rede:
servidor visto → postura.run (com respostas simuladas) → testes da página → alertas.
A primeira parte é a tabela de decisão dos testes (pura); a segunda corre tudo sobre a base de dados."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select

from certwatch import postura
from certwatch.checks import AVISO, FALHA, NA, NT, OK, evaluate_endpoint, registered_domain
from certwatch.db import session_scope, utcnow
from certwatch.evaluator import evaluate, load_snapshot
from certwatch.fontes.servidores import ScanOutcome
from certwatch.insights import check_matrix
from certwatch.jobs import _store_outcome
from certwatch.models import Certificate, Endpoint, Finding, PostureResult
from cryptography.hazmat.primitives import serialization
from tests.pki import PKI, make_crl, ocsp_response

NOW = datetime.now(timezone.utc)
YEAR = 31536000
NEW = ("cadeia.revogacao", "cripto.chave_unica", "protecao.caa", "protecao.hsts")


# ------------------------------------------------------------------ parte 1: tabela de decisão (sem base de dados)
def leaf_obj(**kw):
    base = dict(sha256="a" * 64, subject_cn="site.exemplo.pt", subject_dn="CN=site.exemplo.pt", issuer_cn="R11",
                issuer_dn="CN=R11,O=Let's Encrypt,C=US", serial_hex="0A", not_before=NOW - timedelta(days=10),
                not_after=NOW + timedelta(days=200), sans_dns=["site.exemplo.pt"], sans_ip=[], sig_hash="sha256",
                key_type="RSA", key_bits=2048, spki_sha256="b" * 64, self_issued=False)
    return SimpleNamespace(**(base | kw))


def run_checks(env, posture, leaf=None, port=443):
    ep = SimpleNamespace(id=1, host="site.exemplo.pt", port=port, expected_cn_norm="site.exemplo.pt", source="manual",
                         consecutive_failures=0)
    sr = SimpleNamespace(status="ok", error="", tls_version="TLSv1.3", cipher="X", resolved_ip="203.0.113.5", verify_ok=True,
                         verify_code=None, verify_message="", chain=[{"subject_cn": "site.exemplo.pt"}])
    return evaluate_endpoint(ep, sr, leaf or leaf_obj(), {}, env, NOW, posture)


def P(**kw):
    """Um servidor web externo, com tudo ligado e nada ainda verificado; cada teste muda só o que lhe interessa."""
    base = dict(ran=True, revogacao=None, caa=None, hsts=None, chave={}, revogacao_on=True, caa_on=True, hsts_on=True,
                web=True, externo=True, ca_interna=False, wildcard=False, caa_ids={"letsencrypt.org"})
    return base | kw


def R(status, **kw):
    return {"status": status, "em": NOW, **kw}


def types(ev):
    return sorted(t for t, _, _ in ev.findings)


@pytest.mark.parametrize("result,status,finding,sev", [
    (R("bom", metodo="ocsp"), OK, None, None),
    (R("revogado", metodo="crl", revogado_em="2026-11-01T00:00:00+00:00", motivo="chave comprometida"), FALHA, "REVOGADO", "critica"),
    (R("erro", detalhe="OCSP ocsp.ca.test: sem resposta a tempo"), AVISO, "REVOGACAO_NAO_VERIFICADA", "baixa"),
    (R("desconhecido", metodo="ocsp"), AVISO, "REVOGACAO_NAO_VERIFICADA", "baixa"),
    (R("sem_info", detalhe="o certificado não indica onde confirmar a revogação por http"), NA, None, None),
    (R("nao_confiavel"), NA, None, None),
    (R("expirado"), NA, None, None),
    (None, NT, None, None),
])
def test_revocation_decisions(env, result, status, finding, sev):
    ev = run_checks(env, P(revogacao=result))
    res = ev.results["cadeia.revogacao"]
    assert res.status == status, res.detail
    got = [(t, s) for t, s, _ in ev.findings if t.startswith("REVOGA")]
    assert got == ([(finding, sev)] if finding else [])
    if status == FALHA:
        assert "01-11-2026" in res.detail and "chave comprometida" in res.detail and "CRL" in res.detail


def test_revocation_never_ok_without_proof(env):
    """O que não se verificou não passa: sem execução, desligado, autoassinado ou resultado em falta, nunca "passou"."""
    assert run_checks(env, None).results["cadeia.revogacao"].status == NT
    assert run_checks(env, P(ran=False)).results["cadeia.revogacao"].detail == "ainda não verificado"
    assert run_checks(env, P(revogacao_on=False, revogacao=R("bom"))).results["cadeia.revogacao"].status == NA
    assert run_checks(env, P(revogacao=R("bom")), leaf_obj(self_issued=True)).results["cadeia.revogacao"].status == NA
    for p in (None, P(), P(ran=False)):
        ev = run_checks(env, p)
        assert not any(ev.results[c].status == OK for c in ("cadeia.revogacao", "protecao.caa", "protecao.hsts"))
        assert not [f for f in ev.findings if f[0] in ("REVOGADO", "CAA_VIOLADA", "HSTS_EM_FALTA", "REVOGACAO_NAO_VERIFICADA")]


@pytest.mark.parametrize("caa,over,status,finding", [
    (R("com_registos", zona="exemplo.pt", registos=[[0, "issue", "letsencrypt.org"]]), {}, OK, None),
    (R("com_registos", zona="exemplo.pt", registos=[[0, "issue", "digicert.com"]]), {}, FALHA, "CAA_VIOLADA"),
    (R("com_registos", zona="exemplo.pt", registos=[[0, "issue", ";"]]), {}, FALHA, "CAA_VIOLADA"),
    (R("sem_registos", zona=""), {}, AVISO, "zona:CAA_AUSENTE"),
    (R("com_registos", zona="exemplo.pt", registos=[[0, "iodef", "mailto:x@exemplo.pt"]]), {}, AVISO, "zona:CAA_AUSENTE"),
    (R("com_registos", zona="exemplo.pt", registos=[[0, "issue", "letsencrypt.org"], [0, "issuewild", "digicert.com"]]), {"wildcard": True}, FALHA, "CAA_VIOLADA"),
    (R("com_registos", zona="exemplo.pt", registos=[[0, "issue", "digicert.com"]]), {"ca_interna": True}, NA, None),
    (R("com_registos", zona="exemplo.pt", registos=[[0, "issue", "digicert.com"]]), {"caa_ids": set()}, NA, None),
    (R("com_registos", zona="exemplo.pt", registos=[[0, "issue", "digicert.com"]]), {"externo": False}, NA, None),
    (R("erro", erro="DNS público indisponível"), {}, AVISO, None),
    (None, {}, NT, None),
    (R("sem_registos"), {"caa_on": False}, NA, None),
])
def test_caa_decisions(env, caa, over, status, finding):
    ev = run_checks(env, P(caa=caa, **over))
    assert ev.results["protecao.caa"].status == status, ev.results["protecao.caa"].detail
    got = [t for t, _, _ in ev.findings if t.startswith("CAA")] + ["zona:" + z[0] for z in ev.zone_findings]
    assert got == ([finding] if finding else [])
    if finding == "zona:CAA_AUSENTE":
        assert ev.zone_findings[0][2:4] == ("exemplo.pt", "caa:exemplo.pt")              # um alerta por domínio


@pytest.mark.parametrize("hsts,over,status,finding,sev", [
    (R("presente", max_age=YEAR, include_subdomains=True), {}, OK, None, None),
    (R("presente", max_age=15552000), {}, OK, None, None),                               # exatamente o mínimo
    (R("presente", max_age=15551999), {}, AVISO, "HSTS_EM_FALTA", "baixa"),              # um segundo abaixo
    (R("presente", max_age=0), {}, AVISO, "HSTS_EM_FALTA", "baixa"),
    (R("ausente"), {}, AVISO, "HSTS_EM_FALTA", "baixa"),
    (R("ausente"), {"externo": False}, AVISO, "HSTS_EM_FALTA", "info"),                  # interno: regista, sem incomodar
    (R("invalido", erro="falta o max-age", cabecalho="includeSubDomains"), {}, AVISO, "HSTS_EM_FALTA", "baixa"),
    (R("nao_http"), {}, NA, None, None),
    (R("erro", erro="ConnectTimeout"), {}, AVISO, None, None),
    (R("ausente"), {"web": False}, NA, None, None),
    (R("ausente"), {"hsts_on": False}, NA, None, None),
    (None, {}, NT, None, None),
])
def test_hsts_decisions(env, hsts, over, status, finding, sev):
    ev = run_checks(env, P(hsts=hsts, **over))
    assert ev.results["protecao.hsts"].status == status, ev.results["protecao.hsts"].detail
    assert [(t, s) for t, s, _ in ev.findings if t.startswith("HSTS")] == ([(finding, sev)] if finding else [])


def test_key_reuse_decisions(env):
    assert run_checks(env, P(chave={})).results["cripto.chave_unica"].status == OK
    shared = {"partilhada": [{"cn": "outro.exemplo.pt", "onde": ["outro.exemplo.pt:443"], "sha256": "c" * 64}], "anterior": None}
    ev = run_checks(env, P(chave=shared))
    assert ev.results["cripto.chave_unica"].status == AVISO and "outro.exemplo.pt" in ev.results["cripto.chave_unica"].detail
    assert ("CHAVE_PARTILHADA", "media") in [(t, s) for t, s, _ in ev.findings]
    prev = {"partilhada": [], "anterior": {"sha256": "d" * 64, "de": "2025-01-01", "ate": "2026-01-01"}}
    ev = run_checks(env, P(chave=prev))
    assert ev.results["cripto.chave_unica"].status == AVISO and ("CHAVE_REUTILIZADA", "baixa") in [(t, s) for t, s, _ in ev.findings]
    assert registered_domain("a.b.exemplo.pt") == "exemplo.pt"


# ------------------------------------------------------------------ parte 2: do servidor ao alerta, sobre a base de dados
OCSP = "http://ocsp.ca.test/"
CRL = "http://crl.ca.test/ca.crl"


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def serve(s, host, chain, *, port=443, verify_ok=True, ip="93.184.216.34"):
    """Guarda um servidor como se tivesse acabado de ser visto a servir esta cadeia."""
    ep = Endpoint(host=host, port=port, expected_cn_norm=host, source="manual")
    s.add(ep)
    s.flush()
    out = ScanOutcome(host=host, port=port, status="ok", tls_version="TLSv1.3", cipher="X", resolved_ip=ip,
                      verify_ok=verify_ok, chain_der=[der(c) for c in chain])
    _store_outcome(s, ep, out)
    return ep.id


class Net:
    """A "internet" do teste: respostas de OCSP/CRL, do DNS (CAA) e dos sites (HSTS), e o registo do que foi pedido."""

    def __init__(self):
        self.http, self.caa, self.hsts, self.calls = {}, {}, {}, []

    def clients(self):
        def rev(req):
            self.calls.append((req.method, str(req.url)))
            hit = self.http.get(str(req.url))
            if isinstance(hit, Exception):
                raise hit
            return httpx.Response(200, content=hit) if hit is not None else httpx.Response(404)

        def dns(req):
            name = req.url.params["name"].rstrip(".")
            self.calls.append(("CAA", name))
            if name in self.caa.get("__fail__", ()):
                return httpx.Response(200, json={"Status": 2})
            recs = self.caa.get(name)
            if recs is None:
                return httpx.Response(200, json={"Status": 3})
            return httpx.Response(200, json={"Status": 0, "Answer": [{"type": 257, "data": d} for d in recs]})

        def web(req):
            self.calls.append(("GET", str(req.url)))
            hit = self.hsts.get(req.url.host)
            if isinstance(hit, Exception):
                raise hit
            return httpx.Response(200, headers={"Strict-Transport-Security": hit} if hit else {})
        mk = lambda h: httpx.Client(transport=httpx.MockTransport(h))  # noqa: E731
        return {"revogacao": mk(rev), "caa": mk(dns), "hsts": mk(web)}


def row(matrix, host):
    return next(r for r in matrix if r.ep.host == host)


def findings(s):
    return {(f.type, f.subject): f for f in s.scalars(select(Finding).where(Finding.status == "aberto"))}


def test_from_server_to_alert(env):
    env = replace(env, internal_suffixes=[], internal_issuer_patterns=["interna"], caa_issuers=(("exemplo teste", ("ca.exemplo.test",)),))
    pki, net = PKI(), Net()
    good, _ = pki.leaf("bom.exemplo.pt", sans=("bom.exemplo.pt",), ocsp_url=OCSP)
    bad, _ = pki.leaf("revogado.exemplo.pt", sans=("revogado.exemplo.pt",), crl_url=CRL)
    nochain, _ = pki.leaf("semcadeia.exemplo.pt", sans=("semcadeia.exemplo.pt",), ocsp_url="http://nunca.test/")
    ldaps, _ = pki.leaf("ldap.exemplo.pt", sans=("ldap.exemplo.pt",))
    net.http = {OCSP: ocsp_response(good, pki.inter, pki.inter_key), CRL: make_crl(pki.inter, pki.inter_key, [bad])}
    net.caa = {"exemplo.pt": ['0 issue "ca.exemplo.test"']}
    net.hsts = {"bom.exemplo.pt": "max-age=63072000; includeSubDomains", "revogado.exemplo.pt": None}
    with session_scope() as s:
        serve(s, "bom.exemplo.pt", [good, pki.inter])
        serve(s, "bom2.exemplo.pt", [good, pki.inter])                                  # o mesmo certificado noutro servidor
        serve(s, "revogado.exemplo.pt", [bad, pki.inter])
        serve(s, "semcadeia.exemplo.pt", [nochain, pki.inter], verify_ok=False)         # cadeia que não mereceu confiança
        serve(s, "ldap.exemplo.pt", [ldaps, pki.inter], port=636)
    with session_scope() as s:
        m = check_matrix(s, env, utcnow())
        assert all(row(m, "bom.exemplo.pt").results[c].status == NT for c in NEW if c != "cripto.chave_unica")
    with session_scope() as s:
        summary = postura.run(s, env, clients=net.clients())
    assert summary["revogacao"] == {"bom": 1, "revogado": 1, "nao_confiavel": 1, "sem_info": 1}
    assert summary["caa"] == {"com_registos": 5} and summary["hsts"] == {"presente": 1, "ausente": 3}
    # uma pergunta por certificado, e nenhuma para a cadeia sem confiança (o endereço vinha de um certificado qualquer)
    assert [c for c in net.calls if c[0] == "POST"] == [("POST", OCSP)]
    assert not any("nunca.test" in c[1] for c in net.calls)
    assert not any("ldap.exemplo.pt" in c[1] for c in net.calls if c[0] == "GET")       # 636 não é um site web
    assert [c for c in net.calls if c == ("CAA", "exemplo.pt")] == [("CAA", "exemplo.pt")]   # o domínio pergunta-se uma vez

    with session_scope() as s:
        m = check_matrix(s, env, utcnow())
        g = row(m, "bom.exemplo.pt").results
        assert [g[c].status for c in NEW] == [OK, OK, OK, OK], {c: g[c].detail for c in NEW}
        assert "OCSP" in g["cadeia.revogacao"].detail and "730 dias" in g["protecao.hsts"].detail
        assert row(m, "bom2.exemplo.pt").results["cadeia.revogacao"].status == OK         # herdou a resposta do mesmo certificado
        b = row(m, "revogado.exemplo.pt")
        assert b.results["cadeia.revogacao"].status == FALHA and b.worst == FALHA and b.results["protecao.hsts"].status == AVISO
        assert row(m, "semcadeia.exemplo.pt").results["cadeia.revogacao"].status == NA
        assert row(m, "ldap.exemplo.pt").results["protecao.hsts"].status == NA
        evaluate(s, env)
        f = findings(s)
        rev = f[("REVOGADO", "revogado.exemplo.pt:443")]
        assert rev.severity == "critica" and rev.details["motivo"] == "chave comprometida" and rev.details["metodo"] == "crl"
        assert ("HSTS_EM_FALTA", "revogado.exemplo.pt:443") in f and ("HSTS_EM_FALTA", "bom.exemplo.pt:443") not in f
        assert not [k for k in f if k[0] in ("CAA_AUSENTE", "CAA_VIOLADA", "CHAVE_PARTILHADA", "REVOGACAO_NAO_VERIFICADA")]

    # o certificado revogado é trocado: o alerta fecha-se sozinho na execução seguinte
    fresh, _ = pki.leaf("revogado.exemplo.pt", sans=("revogado.exemplo.pt",), crl_url=CRL)
    net.hsts["revogado.exemplo.pt"] = "max-age=31536000"
    with session_scope() as s:
        ep = s.scalar(select(Endpoint).where(Endpoint.host == "revogado.exemplo.pt"))
        _store_outcome(s, ep, ScanOutcome(host=ep.host, port=443, status="ok", tls_version="TLSv1.3", verify_ok=True,
                                          resolved_ip="93.184.216.34", chain_der=[der(fresh), der(pki.inter)]))
    with session_scope() as s:
        postura.run(s, env, clients=net.clients())
        evaluate(s, env)
        assert not [k for k in findings(s) if k[0] == "REVOGADO" or k == ("HSTS_EM_FALTA", "revogado.exemplo.pt:443")]
        assert s.scalar(select(Finding).where(Finding.type == "REVOGADO")).status == "resolvido"


def test_one_caa_alert_per_domain_and_violation_per_server(env):
    env = replace(env, internal_suffixes=[], revocation=False, hsts=False, caa_issuers=(("exemplo teste", ("ca.exemplo.test",)),))
    pki, net = PKI(), Net()
    net.caa = {"outra.pt": ['0 issue "letsencrypt.org"'], "__fail__": ("falha.pt",)}
    with session_scope() as s:
        for h in ("a.semcaa.pt", "b.semcaa.pt", "c.d.semcaa.pt", "www.outra.pt", "x.falha.pt"):
            leaf, _ = pki.leaf(h, sans=(h,))
            serve(s, h, [leaf, pki.inter])
        internal, _ = pki.leaf("intranet.casa.local", sans=("intranet.casa.local",))
        serve(s, "intranet.casa.local", [internal, pki.inter], ip="10.0.0.5")
    with session_scope() as s:
        assert postura.run(s, env, clients=net.clients()) == {"caa": {"sem_registos": 3, "com_registos": 1, "erro": 1}}
        assert not any(c == ("CAA", "intranet.casa.local") for c in net.calls)           # nomes internos não vão ao DNS público
        evaluate(s, env)
        f = findings(s)
        missing = f[("CAA_AUSENTE", "semcaa.pt")]
        assert missing.severity == "baixa" and missing.details["n_nomes"] == 3 and missing.details["nomes"] == ["a.semcaa.pt", "b.semcaa.pt", "c.d.semcaa.pt"]
        assert len([k for k in f if k[0] == "CAA_AUSENTE"]) == 1
        viol = f[("CAA_VIOLADA", "www.outra.pt:443")]
        assert viol.severity == "media" and viol.details["dominio"] == "outra.pt"
        m = check_matrix(s, env, utcnow())
        assert row(m, "x.falha.pt").results["protecao.caa"].status == AVISO              # DNS em baixo: atenção, sem alerta
        assert not [k for k in f if "falha.pt" in k[1] and k[0].startswith("CAA")]
        assert row(m, "intranet.casa.local").results["protecao.caa"].status == NA


def test_key_reuse_from_what_was_seen(env):
    env = replace(env, revocation=False, hsts=False, caa=False)
    pki = PKI()
    a, key = pki.leaf("loja.exemplo.pt", sans=("loja.exemplo.pt", "www.loja.exemplo.pt"))
    b, _ = pki.leaf("api.outro.pt", sans=("api.outro.pt",), key=key)                    # outro serviço, mesma chave
    old, key2 = pki.leaf("portal.exemplo.pt", sans=("portal.exemplo.pt",), not_before=NOW - timedelta(days=400), days_valid=390)
    renewed, _ = pki.leaf("portal.exemplo.pt", sans=("portal.exemplo.pt",), key=key2)   # renovado sem chave nova
    clean_old, _ = pki.leaf("limpo.exemplo.pt", sans=("limpo.exemplo.pt",), not_before=NOW - timedelta(days=400), days_valid=390)
    clean_new, _ = pki.leaf("limpo.exemplo.pt", sans=("limpo.exemplo.pt",))             # renovado com chave nova
    wild, key3 = pki.leaf("*.grupo.pt", sans=("*.grupo.pt",), not_before=NOW - timedelta(days=30))
    member, _ = pki.leaf("x.grupo.pt", sans=("x.grupo.pt",), key=key3)
    with session_scope() as s:
        for h in ("loja.exemplo.pt", "www.loja.exemplo.pt"):
            serve(s, h, [a, pki.inter])                                                  # o mesmo certificado em dois servidores
        serve(s, "api.outro.pt", [b, pki.inter])
        ep = serve(s, "portal.exemplo.pt", [old, pki.inter])
        _store_outcome(s, s.get(Endpoint, ep), ScanOutcome(host="portal.exemplo.pt", port=443, status="ok", verify_ok=True,
                                                           chain_der=[der(renewed), der(pki.inter)]))
        ep = serve(s, "limpo.exemplo.pt", [clean_old, pki.inter])
        _store_outcome(s, s.get(Endpoint, ep), ScanOutcome(host="limpo.exemplo.pt", port=443, status="ok", verify_ok=True,
                                                           chain_der=[der(clean_new), der(pki.inter)]))
        serve(s, "y.grupo.pt", [wild, pki.inter])
        serve(s, "x.grupo.pt", [member, pki.inter])
    with session_scope() as s:
        m = check_matrix(s, env, utcnow())
        d = {r.ep.host: r.results["cripto.chave_unica"] for r in m}
        assert d["loja.exemplo.pt"].status == AVISO and "api.outro.pt" in d["loja.exemplo.pt"].detail
        assert d["www.loja.exemplo.pt"].status == AVISO and d["api.outro.pt"].status == AVISO
        assert "loja.exemplo.pt" in d["api.outro.pt"].detail
        assert d["portal.exemplo.pt"].status == AVISO and "certificado anterior" in d["portal.exemplo.pt"].detail
        assert d["limpo.exemplo.pt"].status == OK
        # wildcard e um nome que ele cobre são o mesmo serviço: conta como renovação com a mesma chave, não como partilha
        assert d["x.grupo.pt"].status == AVISO and "anterior" in d["x.grupo.pt"].detail and d["y.grupo.pt"].status == OK
        evaluate(s, env)
        f = findings(s)
        assert f[("CHAVE_PARTILHADA", "api.outro.pt:443")].severity == "media"
        assert f[("CHAVE_PARTILHADA", "loja.exemplo.pt:443")].details["outros"][0]["cn"] == "api.outro.pt"
        assert f[("CHAVE_REUTILIZADA", "portal.exemplo.pt:443")].severity == "baixa"
        assert ("CHAVE_REUTILIZADA", "limpo.exemplo.pt:443") not in f
        # a chave nunca fica escrita num alerta: só a impressão digital da chave pública
        assert all(len(x.details.get("chave_sha256", "")) == 64 for k, x in f.items() if k[0].startswith("CHAVE"))


def test_old_results_stop_counting_and_gone_servers_are_cleaned(env):
    env = replace(env, internal_suffixes=[], caa=False, hsts=False)
    pki, net = PKI(), Net()
    leaf, _ = pki.leaf("bom.exemplo.pt", sans=("bom.exemplo.pt",), ocsp_url=OCSP)
    net.http = {OCSP: ocsp_response(leaf, pki.inter, pki.inter_key)}
    with session_scope() as s:
        serve(s, "bom.exemplo.pt", [leaf, pki.inter])
        s.add(PostureResult(kind="hsts", key="99999", status="ausente", data={}, checked_at=utcnow() - timedelta(days=90)))
    with session_scope() as s:
        postura.run(s, env, clients=net.clients())
        assert s.get(PostureResult, ("hsts", "99999")) is None                           # servidor que já não existe
        assert row(check_matrix(s, env, utcnow()), "bom.exemplo.pt").results["cadeia.revogacao"].status == OK
        # oito dias depois, sem nova verificação (CA em baixo, tarefa parada): deixa de dizer "passou"
        later = utcnow() + timedelta(days=8)
        res = row(check_matrix(s, env, later), "bom.exemplo.pt").results["cadeia.revogacao"]
        assert res.status == NT and res.detail == "sem resultado recente"


def test_everything_off_does_nothing(env):
    env = replace(env, revocation=False, caa=False, hsts=False)
    pki, net = PKI(), Net()
    leaf, _ = pki.leaf("bom.exemplo.pt", sans=("bom.exemplo.pt",), ocsp_url=OCSP)
    with session_scope() as s:
        serve(s, "bom.exemplo.pt", [leaf, pki.inter])
    with session_scope() as s:
        assert postura.run(s, env, clients=net.clients()) == {} and net.calls == []
        r = row(check_matrix(s, env, utcnow()), "bom.exemplo.pt").results
        assert [r[c].status for c in ("cadeia.revogacao", "protecao.caa", "protecao.hsts")] == [NA, NA, NA]


def test_issuer_found_by_key_identifier_when_server_sends_only_the_leaf(env):
    env = replace(env, caa=False, hsts=False)
    pki, net = PKI(), Net()
    known, _ = pki.leaf("outro.exemplo.pt", sans=("outro.exemplo.pt",))
    alone, _ = pki.leaf("so.exemplo.pt", sans=("so.exemplo.pt",), ocsp_url=OCSP)
    net.http = {OCSP: ocsp_response(alone, pki.inter, pki.inter_key)}
    with session_scope() as s:
        serve(s, "outro.exemplo.pt", [known, pki.inter])                                 # o intermédio já foi visto aqui
        serve(s, "so.exemplo.pt", [alone])                                               # este servidor só envia a folha
    with session_scope() as s:
        postura.run(s, env, clients=net.clients())
        assert s.get(PostureResult, ("revogacao", s.scalar(select(Certificate.sha256).where(Certificate.subject_cn == "so.exemplo.pt")))).status == "bom"


# ------------------------------------------------------------------ parte 3: a página, para quem não é da área
def test_page_says_it_in_plain_words(env, monkeypatch):
    import re
    from fastapi.testclient import TestClient
    from certwatch import checks
    from certwatch.web import app as webapp
    st = replace(env, internal_suffixes=[], caa_issuers=(("exemplo teste", ("ca.exemplo.test",)),))
    monkeypatch.setattr(webapp, "get_settings", lambda: st)
    pki, net = PKI(), Net()
    good, _ = pki.leaf("bom.exemplo.pt", sans=("bom.exemplo.pt",), ocsp_url=OCSP)
    bad, _ = pki.leaf("revogado.exemplo.pt", sans=("revogado.exemplo.pt",), crl_url=CRL)
    net.http = {OCSP: ocsp_response(good, pki.inter, pki.inter_key), CRL: make_crl(pki.inter, pki.inter_key, [bad])}
    net.caa = {"exemplo.pt": ['0 issue "ca.exemplo.test"']}
    net.hsts = {"bom.exemplo.pt": "max-age=63072000"}
    # cada teste tem as cinco coisas que a página mostra, e nenhuma explicação "porque importa" usa siglas por explicar
    assert set(checks.WHY) == {c.id for c in checks.CHECKS} and len(checks.CHECKS) == 17
    for c in checks.CHECKS:
        assert c.title and c.question.endswith("?") and c.how and c.meaning and c.fix and len(c.why) < 140
        assert not re.search(r"\\b(OCSP|CRL|CAA|HSTS|SAN|SNI|TLS|CA)\\b", c.why), c.id
    assert [l[0] for l in checks.LAYERS] == list(dict.fromkeys(c.layer for c in checks.CHECKS))    # a ordem das etapas é a dos testes
    with TestClient(webapp.app) as web:
        auth = ("admin", "teste-admin-123")
        empty = web.get("/testes", auth=auth).text
        assert "Ainda não há servidores verificados" in empty
        with session_scope() as s:
            serve(s, "bom.exemplo.pt", [good, pki.inter])
            serve(s, "revogado.exemplo.pt", [bad, pki.inter])
        with session_scope() as s:
            postura.run(s, st, clients=net.clients())
        page = web.get("/testes", auth=auth).text
        # resumo em palavras, com texto (não só cor) em cada estado
        for text in ("Como estão os servidores", "O que precisa de ação", "pela ordem em que correm", "Todos os testes passaram.",
                     "Há um problema que afeta a segurança ou o acesso.", "Não foi revogado", "parece válido, mas já não devia ser aceite"):
            assert text in page, text
        assert re.search(r'tx-t-falha"[^>]*><b>1</b>', page) and re.search(r'tx-t-aviso"[^>]*><b>1</b>', page)  # o outro não está na CMDB
        assert page.count('<span aria-hidden="true">✕</span> Falhou') >= 2 and "<caption" in page and 'style="' not in page
        assert "revogado pela CA" in page and "chave comprometida" in page and "o site não envia o cabeçalho" in page
        assert page.index("Não foi revogado") < page.index("Site obriga a usar HTTPS")               # o mais grave primeiro
        assert 'class="matrix"' not in page                                                          # a grelha fica na vista técnica
        one = web.get("/testes?teste=cadeia.revogacao", auth=auth).text
        for text in ("Porque importa", "Como é verificado", "Resultado agora", "Como corrigir", "O que se viu", "Voltar a todos os testes",
                     "revogado.exemplo.pt", "lista de revogados (CRL)"):
            assert text in one, text
        assert "bom.exemplo.pt</a>" not in one                                                       # só quem falha ou pede atenção
        assert "bom.exemplo.pt" in web.get("/testes?teste=cadeia.revogacao&estado=ok", auth=auth).text
        tec = web.get("/testes?vista=tecnica", auth=auth).text
        assert 'class="matrix"' in tec and tec.count('class="rot"') == 17 and "Voltar à vista simples" in tec
        cat = web.get("/testes/como-funciona", auth=auth).text
        assert cat.count("Porque importa:") == 17 and "Strict-Transport-Security: max-age=31536000" in cat
        det = web.get("/certificados/detalhe?cn=revogado.exemplo.pt", auth=auth).text
        assert "Não foi revogado" in det and "revogado pela CA" in det
        # a execução aparece em Execuções e nas automatizações, e as fontes novas em Fontes e ligações
        assert "Revogação, CAA e HSTS" in web.get("/jobs", auth=auth).text
        assert "Revogação, CAA e HSTS" in web.get("/automacoes/nova?acao=ler", auth=auth).text
        fontes = web.get("/fontes", auth=auth).text
        assert "Revogação (OCSP e CRL das CAs)" in fontes and "Cabeçalhos dos sites (HSTS)" in fontes


def test_job_runs_posture_and_reevaluates(env, monkeypatch):
    from certwatch import jobs
    called = []
    monkeypatch.setattr(postura, "run", lambda s, st, **kw: called.append(1) or {"revogacao": {"bom": 1}})
    out = jobs._run("postura", env)
    assert called == [1] and out["postura"] == {"revogacao": {"bom": 1}} and "evaluate" in out
    assert "postura" in jobs.JOBS

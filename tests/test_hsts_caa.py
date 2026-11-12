"""HSTS e CAA: os analisadores (puros) e as leituras, com respostas simuladas."""
import httpx
import pytest

from certwatch.fontes import dns as fd
from certwatch.fontes import hsts as fh

YEAR = 31536000


# ------------------------------------------------------------------ HSTS: cabeçalho → o que quer dizer
@pytest.mark.parametrize("header,max_age,sub,preload,valid", [
    ("max-age=31536000", YEAR, False, False, True),
    ("max-age=31536000; includeSubDomains; preload", YEAR, True, True, True),
    ("MAX-AGE=600 ; INCLUDESUBDOMAINS", 600, True, False, True),
    ('max-age="31536000"', YEAR, False, False, True),
    ("includeSubDomains; max-age=0", 0, True, False, True),
    ("max-age=31536000; foo=bar; baz", YEAR, False, False, True),            # diretivas desconhecidas ignoram-se
    ("includeSubDomains", None, True, False, False),                           # sem max-age não vale
    ("max-age=abc", None, False, False, False),
    ("max-age=-1", None, False, False, False),
    ("max-age=1; max-age=2", None, False, False, False),                       # repetida: o browser ignora tudo
    ("", None, False, False, False),
])
def test_hsts_parse(header, max_age, sub, preload, valid):
    h = fh.parse(header)
    assert (h.max_age, h.include_subdomains, h.preload, h.valido) == (max_age, sub, preload, valid)


def hsts_client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)


def test_hsts_fetch_states():
    ok = fh.fetch("site.test", 443, hsts_client(lambda r: httpx.Response(200, headers={"Strict-Transport-Security": "max-age=63072000; includeSubDomains"})))
    assert ok.status == "presente" and ok.hsts.max_age == 63072000 and ok.http_status == 200
    # também conta numa resposta de redirecionamento, e não se segue o redirecionamento
    calls = []
    def redirect(r):
        calls.append(str(r.url))
        return httpx.Response(301, headers={"Location": "https://outro.test/", "Strict-Transport-Security": "max-age=600"})
    red = fh.fetch("site.test", 8443, hsts_client(redirect))
    assert red.status == "presente" and red.http_status == 301 and calls == ["https://site.test:8443/"]
    assert fh.fetch("site.test", 443, hsts_client(lambda r: httpx.Response(200))).status == "ausente"
    bad = fh.fetch("site.test", 443, hsts_client(lambda r: httpx.Response(200, headers={"Strict-Transport-Security": "includeSubDomains"})))
    assert bad.status == "invalido" and bad.cabecalho == "includeSubDomains"

    def not_http(r):
        raise httpx.RemoteProtocolError("Server disconnected without sending a response.")
    assert fh.fetch("ldaps.test", 443, hsts_client(not_http)).status == "nao_http"

    def down(r):
        raise httpx.ConnectTimeout("t")
    assert fh.fetch("site.test", 443, hsts_client(down)).status == "erro"


def test_hsts_two_headers_use_the_first():
    r = fh.fetch("site.test", 443, hsts_client(lambda q: httpx.Response(200, headers=[("Strict-Transport-Security", "max-age=100"),
                                                                                         ("Strict-Transport-Security", "max-age=999999")])))
    assert r.hsts.max_age == 100


# ------------------------------------------------------------------ CAA: leitura (subir na árvore) e avaliação
def doh(zone_records: dict, calls=None, fail=()):
    """zone_records: {nome: [linhas "0 issue \\"ca.test\\""]}. Nomes ausentes respondem NXDOMAIN (3)."""
    def handler(req):
        name = req.url.params["name"].rstrip(".").lower()
        assert req.url.params["type"] == "CAA"
        if calls is not None:
            calls.append(name)
        if name in fail:
            return httpx.Response(200, json={"Status": 2})
        recs = zone_records.get(name)
        if recs is None:
            return httpx.Response(200, json={"Status": 3})
        return httpx.Response(200, json={"Status": 0, "Answer": [{"name": name, "type": 257, "data": d} for d in recs]})
    return httpx.Client(transport=httpx.MockTransport(handler))


URLS = ["https://doh.test/dns-query"]


def test_caa_climbs_to_the_parent_and_stops_at_the_first_answer():
    calls = []
    c = doh({"exemplo.pt": ['0 issue "letsencrypt.org"', '0 iodef "mailto:seg@exemplo.pt"'], "pt": ['0 issue "nao-deve-chegar-aqui"']}, calls)
    r = fd.caa_lookup("www.loja.exemplo.pt", URLS, c)
    assert r.zona == "exemplo.pt" and r.erro == "" and (0, "issue", "letsencrypt.org") in r.registos and len(r.registos) == 2
    assert calls == ["www.loja.exemplo.pt", "loja.exemplo.pt", "exemplo.pt"]            # nunca pergunta pelo "pt"
    r = fd.caa_lookup("*.exemplo.pt", URLS, doh({"exemplo.pt": ['0 issue ";"']}))
    assert r.zona == "exemplo.pt" and r.registos == [(0, "issue", ";")]


def test_caa_none_and_errors_are_different_things():
    calls = []
    assert fd.caa_lookup("a.b.exemplo.pt", URLS, doh({}, calls)).registos == []
    assert calls == ["a.b.exemplo.pt", "b.exemplo.pt", "exemplo.pt"]                    # pára no domínio: o "pt" não é nosso
    none = fd.caa_lookup("a.exemplo.pt", URLS, doh({}))
    assert none.zona == "" and none.registos == [] and none.erro == ""                  # não há: é um facto
    err = fd.caa_lookup("a.exemplo.pt", URLS, doh({}, fail=("exemplo.pt",)))
    assert err.erro and err.registos == []                                              # não se sabe: é uma falha
    assert fd.caa_lookup("a.exemplo.pt", [], None).erro


def test_caa_answer_formats():
    # formato genérico (RFC 3597) que alguns resolvedores devolvem: \# <len> <hex>
    raw = b"\x00\x05issue" + b"digicert.com"
    hexed = "\\# %d %s" % (len(raw), raw.hex())
    r = fd.caa_lookup("exemplo.pt", URLS, doh({"exemplo.pt": [hexed, '128 issuewild "sectigo.com; account=1"', "0 issue letsencrypt.org"]}))
    assert r.registos == [(0, "issue", "digicert.com"), (128, "issuewild", "sectigo.com; account=1"), (0, "issue", "letsencrypt.org")]
    # um CNAME na resposta não é um registo CAA
    c = httpx.Client(transport=httpx.MockTransport(lambda q: httpx.Response(200, json={"Status": 0, "Answer": [
        {"name": "exemplo.pt", "type": 5, "data": "cdn.test."}]}) if q.url.params["name"] == "exemplo.pt" else httpx.Response(200, json={"Status": 3})))
    assert fd.caa_lookup("exemplo.pt", URLS, c).registos == []


LE, DIGI = {"letsencrypt.org"}, {"digicert.com", "geotrust.com"}


@pytest.mark.parametrize("records,issuer,wildcard,verdict", [
    ([(0, "issue", "letsencrypt.org")], LE, False, "autorizada"),
    ([(0, "issue", "letsencrypt.org")], DIGI, False, "nao_autorizada"),
    ([(0, "issue", "LetsEncrypt.org ; validationmethods=dns-01")], LE, False, "autorizada"),     # parâmetros ignoram-se
    ([(0, "issue", "digicert.com"), (0, "issue", "letsencrypt.org")], LE, False, "autorizada"),
    ([(0, "issue", ";")], LE, False, "nao_autorizada"),                                          # ninguém pode emitir
    ([(0, "iodef", "mailto:x@exemplo.pt")], LE, False, "sem_restricao"),                         # CAA sem issue não restringe
    ([(0, "issue", "letsencrypt.org"), (0, "issuewild", "digicert.com")], LE, True, "nao_autorizada"),   # wildcard: manda o issuewild
    ([(0, "issue", "letsencrypt.org"), (0, "issuewild", "digicert.com")], DIGI, True, "autorizada"),
    ([(0, "issue", "letsencrypt.org"), (0, "issuewild", "digicert.com")], LE, False, "autorizada"),      # não-wildcard: manda o issue
    ([(0, "issue", "letsencrypt.org")], LE, True, "autorizada"),                                  # sem issuewild, o issue vale para wildcards
    ([(0, "issuewild", "digicert.com")], LE, False, "sem_restricao"),                             # issuewild não restringe nomes normais
    ([(0, "issue", "letsencrypt.org"), (128, "futuro", "x")], LE, False, "nao_autorizada"),      # crítico desconhecido: não emitir
    ([(0, "issue", "letsencrypt.org")], set(), False, "ca_desconhecida"),
    ([(0, "issue", ";")], set(), False, "nao_autorizada"),                                        # proibido a todas, conhecidas ou não                         # não sabemos o identificador desta CA
])
def test_caa_evaluate(records, issuer, wildcard, verdict):
    assert fd.caa_evaluate(records, issuer, wildcard)[0] == verdict


def test_caa_identifiers_of_known_cas():
    from certwatch.postura import caa_ids
    assert "letsencrypt.org" in caa_ids("CN=R11,O=Let's Encrypt,C=US", ())
    assert "digicert.com" in caa_ids("CN=GeoTrust TLS RSA CA G1,OU=www.digicert.com,O=DigiCert Inc,C=US", ())
    assert "sectigo.com" in caa_ids("CN=Sectigo RSA Domain Validation Secure Server CA,O=Sectigo Limited", ())
    assert "pki.goog" in caa_ids("CN=WR2,O=Google Trust Services,C=US", ())
    assert caa_ids("CN=CA Interna da Casa,O=Exemplo", ()) == set()
    assert caa_ids("CN=CA Interna da Casa,O=Exemplo", (("ca interna da casa", ("pki.exemplo.pt",)),)) == {"pki.exemplo.pt"}

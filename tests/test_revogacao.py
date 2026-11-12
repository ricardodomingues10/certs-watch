"""Revogação (OCSP e CRL): tabela de decisão completa, sem rede. Cada teste é uma linha da tabela:
situação → estado esperado. As respostas são fabricadas com a PKI de teste e servidas por um transporte simulado."""
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from certwatch.fontes import revogacao as rv
from tests.pki import PKI, make_cert, make_crl, ocsp_error, ocsp_response, pem

OCSP = "http://ocsp.exemplo.test/"
CRL = "http://crl.exemplo.test/issuing.crl"
NOW = datetime.now(timezone.utc)


@pytest.fixture(scope="module")
def pki():
    return PKI()


def client(routes, calls=None):
    """routes: {url: bytes | (status, bytes) | Exception}. Tudo o resto dá 404."""
    def handler(req):
        if calls is not None:
            calls.append((req.method, str(req.url)))
        hit = routes.get(str(req.url))
        if isinstance(hit, Exception):
            raise hit
        if hit is None:
            return httpx.Response(404)
        if isinstance(hit, tuple):
            return httpx.Response(hit[0], content=hit[1], headers=hit[2] if len(hit) > 2 else None)
        return httpx.Response(200, content=hit)
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)   # mesmo um cliente que os seguisse


def check(cert, issuer, routes, calls=None, **kw):
    return rv.check(pem(cert).decode(), pem(issuer).decode(), client(routes, calls), now=NOW, **kw)


# ------------------------------------------------------------------ OCSP
def test_ocsp_good(pki):
    cert, _ = pki.leaf(ocsp_url=OCSP)
    r = check(cert, pki.inter, {OCSP: ocsp_response(cert, pki.inter, pki.inter_key)})
    assert (r.status, r.metodo) == ("bom", "ocsp") and r.url == OCSP and r.valido_ate


def test_ocsp_revoked_gives_date_and_reason(pki):
    from cryptography import x509
    cert, _ = pki.leaf(ocsp_url=OCSP)
    when = NOW - timedelta(days=4)
    r = check(cert, pki.inter, {OCSP: ocsp_response(cert, pki.inter, pki.inter_key, status="revoked", revoked_at=when,
                                                    reason=x509.ReasonFlags.key_compromise)})
    assert (r.status, r.metodo) == ("revogado", "ocsp")
    assert r.revogado_em[:10] == when.date().isoformat() and r.motivo == "chave comprometida"


def test_ocsp_delegated_responder_signed_by_the_issuer_is_accepted(pki):
    from cryptography.x509.oid import ExtendedKeyUsageOID
    cert, _ = pki.leaf(ocsp_url=OCSP)
    resp_cert, resp_key = make_cert("OCSP Responder", pki.inter, pki.inter_key, eku=ExtendedKeyUsageOID.OCSP_SIGNING)
    r = check(cert, pki.inter, {OCSP: ocsp_response(cert, pki.inter, resp_key, signer_cert=resp_cert)})
    assert r.status == "bom"


@pytest.mark.parametrize("case", ["estranho", "sem_eku", "outro_emissor", "assinatura_do_proprio"])
def test_ocsp_signed_by_someone_else_is_refused(pki, case):
    """Uma resposta "bom" só vale se vier do emissor ou de um respondedor que o emissor autorizou para isso."""
    from cryptography.x509.oid import ExtendedKeyUsageOID
    cert, leaf_key = pki.leaf(ocsp_url=OCSP)
    other = PKI()
    if case == "estranho":                 # chave qualquer, com um certificado que ela própria assinou
        c, k = make_cert("Qualquer")
        body = ocsp_response(cert, pki.inter, k, signer_cert=c)
    elif case == "sem_eku":                # emitido pelo emissor, mas não é um respondedor OCSP
        c, k = make_cert("Servidor Web", pki.inter, pki.inter_key)
        body = ocsp_response(cert, pki.inter, k, signer_cert=c)
    elif case == "outro_emissor":          # respondedor legítimo… de outra CA
        c, k = make_cert("OCSP de Outra CA", other.inter, other.inter_key, eku=ExtendedKeyUsageOID.OCSP_SIGNING)
        body = ocsp_response(cert, pki.inter, k, signer_cert=c)
    else:                                  # o próprio servidor a dizer que está bom
        body = ocsp_response(cert, pki.inter, leaf_key, signer_cert=cert)
    r = check(cert, pki.inter, {OCSP: body})
    assert r.status == "erro" and "assinatura" in r.detalhe


@pytest.mark.parametrize("this_update,next_update,why", [
    (NOW - timedelta(days=10), NOW - timedelta(days=3), "fora do prazo"),      # resposta antiga reaproveitada
    (NOW + timedelta(days=2), NOW + timedelta(days=5), "futuro"),              # data no futuro
])
def test_ocsp_outside_its_validity_is_refused(pki, this_update, next_update, why):
    cert, _ = pki.leaf(ocsp_url=OCSP)
    r = check(cert, pki.inter, {OCSP: ocsp_response(cert, pki.inter, pki.inter_key, this_update=this_update, next_update=next_update)})
    assert r.status == "erro" and why in r.detalhe


def test_ocsp_about_another_certificate_is_refused(pki):
    cert, _ = pki.leaf(ocsp_url=OCSP)
    another, _ = pki.leaf("outro.exemplo.test", sans=("outro.exemplo.test",))
    r = check(cert, pki.inter, {OCSP: ocsp_response(cert, pki.inter, pki.inter_key, about=another)})
    assert r.status == "erro" and "outro certificado" in r.detalhe


def test_ocsp_unknown_without_crl_stays_unknown(pki):
    cert, _ = pki.leaf(ocsp_url=OCSP)
    r = check(cert, pki.inter, {OCSP: ocsp_response(cert, pki.inter, pki.inter_key, status="unknown")})
    assert r.status == "desconhecido"


def test_ocsp_unknown_still_asks_the_crl(pki):
    """"Não conheço" não é "está bom": se a CA tem lista de revogados, é ela que decide."""
    cert, _ = pki.leaf(ocsp_url=OCSP, crl_url=CRL)
    unknown = ocsp_response(cert, pki.inter, pki.inter_key, status="unknown")
    r = check(cert, pki.inter, {OCSP: unknown, CRL: make_crl(pki.inter, pki.inter_key, [cert])})
    assert (r.status, r.metodo) == ("revogado", "crl")
    r = check(cert, pki.inter, {OCSP: unknown, CRL: make_crl(pki.inter, pki.inter_key, [])})
    assert (r.status, r.metodo) == ("bom", "crl")
    r = check(cert, pki.inter, {OCSP: unknown, CRL: httpx.ConnectError("x")})
    assert r.status == "desconhecido"


# ------------------------------------------------------------------ CRL
@pytest.mark.parametrize("as_pem", [False, True])
def test_crl_revoked_when_there_is_no_ocsp(pki, as_pem):
    cert, _ = pki.leaf(crl_url=CRL)
    r = check(cert, pki.inter, {CRL: make_crl(pki.inter, pki.inter_key, [cert], as_pem=as_pem)})
    assert (r.status, r.metodo) == ("revogado", "crl") and r.motivo == "chave comprometida" and r.revogado_em


def test_crl_good_and_downloaded_once_per_run(pki):
    a, _ = pki.leaf(crl_url=CRL)
    b, _ = pki.leaf("b.exemplo.test", sans=("b.exemplo.test",), crl_url=CRL)
    revoked, _ = pki.leaf("c.exemplo.test", sans=("c.exemplo.test",), crl_url=CRL)
    calls, cache = [], {}
    routes = {CRL: make_crl(pki.inter, pki.inter_key, [revoked])}
    assert check(a, pki.inter, routes, calls, cache=cache).status == "bom"
    assert check(b, pki.inter, routes, calls, cache=cache).status == "bom"
    assert check(revoked, pki.inter, routes, calls, cache=cache).status == "revogado"
    assert calls == [("GET", CRL)]                                              # três certificados, um download


def test_ocsp_down_falls_back_to_crl(pki):
    cert, _ = pki.leaf(ocsp_url=OCSP, crl_url=CRL)
    for broken in (httpx.ConnectError("sem rota"), (500, b"erro"), ocsp_error("try_later"), b"isto nao e ocsp"):
        r = check(cert, pki.inter, {OCSP: broken, CRL: make_crl(pki.inter, pki.inter_key, [cert])})
        assert (r.status, r.metodo) == ("revogado", "crl"), broken


def test_ocsp_good_does_not_download_the_crl(pki):
    cert, _ = pki.leaf(ocsp_url=OCSP, crl_url=CRL)
    calls = []
    check(cert, pki.inter, {OCSP: ocsp_response(cert, pki.inter, pki.inter_key), CRL: b""}, calls)
    assert calls == [("POST", OCSP)]


@pytest.mark.parametrize("case,why", [("outra_ca", "assinatura"), ("vencida", "fora do prazo"), ("lixo", "não é uma CRL"),
                                     ("grande", "grande demais")])
def test_crl_that_cannot_be_trusted_is_refused(pki, case, why):
    cert, _ = pki.leaf(crl_url=CRL)
    other = PKI()
    body = {"outra_ca": lambda: make_crl(pki.inter, other.inter_key, []),             # nome certo, assinatura de outra chave
            "vencida": lambda: make_crl(pki.inter, pki.inter_key, [], this_update=NOW - timedelta(days=30), next_update=NOW - timedelta(days=20)),
            "lixo": lambda: b"<html>pagina de erro</html>",
            "grande": lambda: make_crl(pki.inter, pki.inter_key, list(range(1000, 1400)))}[case]()
    r = check(cert, pki.inter, {CRL: body}, max_crl_bytes=4096 if case == "grande" else 20_000_000)
    assert r.status == "erro" and why in r.detalhe


def test_second_crl_address_is_tried_when_the_first_fails(pki):
    alt = "http://crl2.exemplo.test/issuing.crl"
    cert, _ = pki.leaf(crl_url=[CRL, alt])
    r = check(cert, pki.inter, {CRL: httpx.ReadTimeout("lento"), alt: make_crl(pki.inter, pki.inter_key, [])})
    assert (r.status, r.metodo, r.url) == ("bom", "crl", alt)


# ------------------------------------------------------------------ sem informação, sem emissor, endereços perigosos
def test_certificate_without_ocsp_or_crl(pki):
    cert, _ = pki.leaf()
    r = check(cert, pki.inter, {})
    assert r.status == "sem_info" and r.metodo == ""


def test_everything_down_is_an_error_never_good(pki):
    cert, _ = pki.leaf(ocsp_url=OCSP, crl_url=CRL)
    r = check(cert, pki.inter, {OCSP: httpx.ConnectTimeout("t"), CRL: httpx.ConnectError("x")})
    assert r.status == "erro" and "OCSP" in r.detalhe and "CRL" in r.detalhe


def test_wrong_issuer_given(pki):
    cert, _ = pki.leaf(ocsp_url=OCSP)
    r = rv.check(pem(cert).decode(), pem(pki.root).decode(), client({}), now=NOW)
    assert r.status == "erro" and "emissor" in r.detalhe
    assert rv.check(pem(cert).decode(), "", client({}), now=NOW).status == "erro"


@pytest.mark.parametrize("url", ["ldap://dc.interno/CN=CA", "file:///etc/passwd", "ftp://x/y.crl", "http://user:pw@crl.test/a.crl",
                                 "http:///sem-host.crl", "gopher://x"])
def test_only_plain_http_addresses_are_ever_contacted(pki, url):
    cert, _ = pki.leaf(crl_url=url)
    calls = []
    r = check(cert, pki.inter, {}, calls)
    assert calls == [] and r.status == "sem_info" and "http" in r.detalhe      # só havia endereços que não se usam


def test_redirects_are_not_followed(pki):
    cert, _ = pki.leaf(crl_url=CRL)
    calls = []
    r = check(cert, pki.inter, {CRL: (302, b"", {"Location": "http://169.254.169.254/latest/meta-data/"})}, calls)
    assert r.status == "erro" and calls == [("GET", CRL)]
    cert, _ = pki.leaf(ocsp_url=OCSP)
    calls = []
    check(cert, pki.inter, {OCSP: (307, b"", {"Location": "http://10.0.0.1/admin"})}, calls)
    assert calls == [("POST", OCSP)]


def test_reason_labels_are_portuguese():
    assert rv.REASONS["keyCompromise"] == "chave comprometida" and rv.REASONS["superseded"] == "substituído por outro"

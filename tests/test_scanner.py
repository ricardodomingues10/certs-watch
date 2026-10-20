import socket
from datetime import timedelta

from certwatch.scanner import scan_endpoint, summarize
from certwatch.trust import build_bundle
from tests.pki import NOW, TLSServer, make_cert, make_weak_leaf


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_valid_chain(env, pki):
    leaf, key = pki.leaf()
    with TLSServer([leaf, pki.inter], key) as srv:
        out = scan_endpoint("127.0.0.1", srv.port, build_bundle(env), 5)
    assert out.status == "ok" and out.verify_ok is True
    assert len(out.chain_der) == 2
    s = summarize(out.chain_der[0])
    assert s["issuer_cn"] == "Exemplo Teste Issuing CA" and s["key_type"] == "RSA" and s["sig_hash"] == "sha256"


def test_missing_intermediate(env, pki):
    leaf, key = pki.leaf()
    with TLSServer([leaf], key) as srv:
        out = scan_endpoint("127.0.0.1", srv.port, build_bundle(env), 5)
    assert out.status == "ok" and out.verify_ok is False
    assert out.verify_code in (20, 21)  # unable to get local issuer / verify leaf signature
    assert len(out.chain_der) == 1      # a chain é recolhida no 2.º handshake


def test_self_signed(env):
    cert, key = make_cert("selfsigned.exemplo.local", sans=["selfsigned.exemplo.local"])
    with TLSServer([cert], key) as srv:
        out = scan_endpoint("127.0.0.1", srv.port, build_bundle(env), 5)
    assert out.verify_ok is False and out.verify_code == 18
    assert summarize(out.chain_der[0])["self_issued"] is True


def test_expired_leaf(env, pki):
    leaf, key = pki.leaf(not_before=NOW - timedelta(days=100), days_valid=30)
    with TLSServer([leaf, pki.inter], key) as srv:
        out = scan_endpoint("127.0.0.1", srv.port, build_bundle(env), 5)
    assert out.verify_ok is False and out.verify_code == 10


def test_unknown_root(env):
    other_root, other_key = make_cert("Outra Root", ca=True)
    leaf, key = make_cert("x.exemplo.pt", other_root, other_key, sans=["x.exemplo.pt"])
    with TLSServer([leaf, other_root], key) as srv:
        out = scan_endpoint("127.0.0.1", srv.port, build_bundle(env), 5)
    assert out.verify_ok is False and out.verify_code == 19  # self-signed certificate in chain


def test_sha1_and_small_key(env, pki):
    leaf, key = make_weak_leaf(pki, "weak.exemplo.pt")
    with TLSServer([leaf, pki.inter], key) as srv:
        out = scan_endpoint("127.0.0.1", srv.port, build_bundle(env), 5)
    s = summarize(out.chain_der[0])
    assert s["sig_hash"] == "sha1" and s["key_bits"] == 1024


def test_unreachable(env):
    out = scan_endpoint("127.0.0.1", _free_port(), build_bundle(env), 2)
    assert out.status == "unreachable" and not out.chain_der


def test_dns_error(env):
    out = scan_endpoint("nao-existe.invalid", 443, build_bundle(env), 2)
    assert out.status in ("dns_error", "unreachable")

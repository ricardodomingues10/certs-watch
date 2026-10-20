from certwatch.classify import cert_type, is_private_ip, scope_of


def test_cert_type():
    assert cert_type("portal.exemplo.pt", "host") == "hostname"
    assert cert_type("portal.exemplo.pt", "host", is_api=True) == "api"
    assert cert_type("*.exemplo.pt", "wildcard") == "wildcard"
    assert cert_type("10.0.0.5", "ip") == "ip"
    assert cert_type("exemplo issuing ca01", "other", common_name="Exemplo Issuing CA01") == "ca"
    assert cert_type("exemplo root ca", "other", issuer_norm="exemplo root ca", common_name="Exemplo Root CA") == "ca"
    assert cert_type("joao.silva", "other", common_name="joao.silva") == "outro"


def test_private_ip():
    assert is_private_ip("10.1.2.3") and is_private_ip("192.168.0.1") and is_private_ip("127.0.0.1")
    assert not is_private_ip("8.8.8.8") and not is_private_ip("lixo")


def test_scope(env):
    s = env  # sufixos internos por omissão: .local, .lan, .internal, .intranet, .corp
    assert scope_of("app.exemplo.local", "host", s) == "interno"
    assert scope_of("*.exemplo.local", "wildcard", s) == "interno"
    assert scope_of("10.20.1.15", "ip", s) == "interno"
    assert scope_of("8.8.8.8", "ip", s) == "externo"
    assert scope_of("portal.exemplo.pt", "host", s, resolved_ip="10.0.0.8") == "interno"   # resolve para IP privado
    assert scope_of("portal.exemplo.pt", "host", s, resolved_ip="1.1.1.1") == "externo"
    assert scope_of("app.exemplo.pt", "host", s, issuer_norm="exemplo internal ca01") == "interno"
    assert scope_of("www.exemplo.pt", "host", s) == "externo"
    assert scope_of("exemplo root ca", "other", s) == "desconhecido"

from certwatch.normalize import classify, hostname_matches, norm_host, norm_issuer, norm_serial, parse_iso


def test_norm_host():
    assert norm_host(" HTTPS://Portal.exemplo.pt:8443/x ") == "portal.exemplo.pt"
    assert norm_host("www.exemplo.pt.") == "www.exemplo.pt"
    assert norm_host("*.exemplo.pt") == "*.exemplo.pt"
    assert norm_host("Misericórdia.pt") == "misericórdia.pt".encode("idna").decode()


def test_classify():
    assert classify("portal.exemplo.pt") == "host"
    assert classify("*.exemplo.pt") == "wildcard"
    assert classify("10.1.2.3") == "ip"
    assert classify("Exemplo Root CA".lower()) == "other"
    assert classify("srvapp01") == "other"           # nome curto não é alvo
    assert classify("a;rm -rf /.exemplo.pt") == "other"  # injeção rejeitada
    assert classify("") == "other"


def test_norm_issuer():
    assert norm_issuer("CN=Exemplo Issuing CA01, DC=exemplo, DC=local") == "exemplo issuing ca01"
    assert norm_issuer("  DigiCert   Global G2 TLS RSA SHA256 2020 CA1 ") == "digicert global g2 tls rsa sha256 2020 ca1"


def test_norm_serial():
    assert norm_serial("0a:1B:ff") == "A1BFF"
    assert norm_serial("00 00") == "0"
    assert norm_serial("") == ""


def test_parse_iso():
    assert parse_iso("2037-12-12T14:50:30.000Z").isoformat() == "2037-12-12T14:50:30+00:00"
    assert parse_iso("lixo") is None


def test_hostname_matches():
    assert hostname_matches("portal.exemplo.pt", ["portal.exemplo.pt"])
    assert hostname_matches("portal.exemplo.pt", ["*.exemplo.pt"])
    assert not hostname_matches("a.b.exemplo.pt", ["*.exemplo.pt"])   # wildcard só cobre um rótulo
    assert not hostname_matches("exemplo.pt", ["*.exemplo.pt"])
    assert not hostname_matches("evil-exemplo.pt", ["*.exemplo.pt"])
    assert hostname_matches("10.0.0.1", [], ["10.0.0.1"])
    assert not hostname_matches("10.0.0.1", ["10.0.0.1"], [])    # IP só por SAN IP

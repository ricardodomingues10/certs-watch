from dataclasses import replace
from datetime import datetime, timedelta, timezone

from openpyxl import Workbook

from certwatch import cmdb_final as cf
from certwatch.db import utcnow
from certwatch.reconcile import map_columns, norm_header, parse_date
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Europe/Lisbon")
NOW = utcnow()


def d(days):  # data local "DD/MM/AAAA HH:MM" a N dias
    return (NOW + timedelta(days=days)).astimezone(TZ).strftime("%d/%m/%Y %H:%M")


def test_headers_and_dates():
    assert norm_header("[Digital Certificate] : LocalizaÃ§Ã£o") == "localizacao"
    assert norm_header("Issued Common Name:") == "issuedcommonname"
    cols = map_columns(["Nome", "Subject_CommonName", "Validity_NotAfter", "SerialNumber", "Issuer_CommonName"])
    assert cols["cn"] == 1 and cols["valid_to"] == 2 and cols["issuer"] == 4
    assert parse_date("10/04/2028", TZ).date().isoformat() == "2028-04-09"   # meia-noite Lisboa = 23:00 UTC do dia anterior
    assert parse_date("10/04/2028 12:00", TZ).astimezone(TZ).day == 10       # nunca troca dia/mês
    assert parse_date("13/25/2028", TZ) is None
    assert parse_date("11/27/2026 3:52 PM", TZ).astimezone(TZ).strftime("%d-%m %H:%M") == "27-11 15:52"
    assert parse_date("2027-01-10T10:00:00.000Z", TZ).isoformat() == "2027-01-10T10:00:00+00:00"
    assert parse_date(46000, TZ).year == 2025                                 # serial Excel
    assert parse_date("20280410", TZ) is not None


def test_reading_real_exports(env, tmp_path):
    """Os ficheiros reais: certutil em UTF-16 com BOM, Excel do AVI e CSV Windows-1252 com acentos estragados."""
    today = NOW.astimezone(TZ).date()
    ca1 = "\n".join([
        '"Req ID:","Requester Name:","Issued Common Name:","Certificate Expiration Date:","Serial Number:","Request Disposition:"',
        f'"10","DOM\\\\a","novo.exemplo.local","{d(200)}","1a2b","20 -- Issued"',
        f'"11","DOM\\\\b","igual.exemplo.local","{d(100)}","3c4d","20 -- Issued"',
        f'"13","DOM\\\\d","revogado.exemplo.local","{d(50)}","7a8b","21 -- Revoked"',
        '"14","DOM\\\\e","malformado.exemplo.local","31/31/2026","9c9d","20 -- Issued"',
    ])
    items, info = cf.read_source("CA1", "CA1_export.csv", b"\xff\xfe" + ca1.encode("utf-16-le"), today)
    by = {x.cn: x for x in items}
    assert by["novo.exemplo.local"].keep and by["novo.exemplo.local"].serial == "1a2b"
    assert not by["revogado.exemplo.local"].keep and by["revogado.exemplo.local"].drop == "NAO_EMITIDO"
    assert not by["malformado.exemplo.local"].keep and by["malformado.exemplo.local"].drop.startswith("DATA_")
    assert info["validas"] == 2

    wb = Workbook()
    ws = wb.active
    ws.append(["Nome", "Subject_CommonName", "Validity_NotAfter", "SerialNumber", "Issuer_CommonName", "SubjectAlternativeName"])
    ws.append(["lb-cert", "lb.exemplo.pt", (NOW + timedelta(days=100)).strftime("%Y-%m-%dT%H:%M:%S"), "AA", "DigiCert", "lb.exemplo.pt"])
    ws.append(["outro", "app.exemplo.pt", datetime.now() + timedelta(days=30), "BB", "Let's Encrypt R10", ""])
    import io
    buf = io.BytesIO()
    wb.save(buf)
    items, info = cf.read_source("AVI", "avi_certs.xlsx", buf.getvalue(), today)
    assert [x.cn for x in items if x.keep] == ["lb.exemplo.pt", "app.exemplo.pt"] and items[0].issuer == "DigiCert"

    ca2 = "Issued Common Name:;Certificate Expiration Date:;LocalizaÃ§Ã£o\n" + f"ca2.exemplo.local;{d(90)};Lisboa\n"
    items, info = cf.read_source("CA2", "ca2.csv", ca2.encode("cp1252"), today)
    assert items[0].cn == "ca2.exemplo.local" and items[0].keep


def test_old_reconcile_page_redirects_and_directory_panel(env, tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from certwatch import config
    from certwatch.web.app import app
    imp = tmp_path / "imp"
    imp.mkdir()
    (imp / "avi_x.csv").write_text("Subject_CommonName;Validity_NotAfter;Issuer_CommonName\n"
                                   f"novo.exemplo.pt;{(NOW + timedelta(days=40)).date().isoformat()};DigiCert\n")
    monkeypatch.setenv("CERTWATCH_IMPORT_DIR", str(imp))
    config.get_settings.cache_clear()
    auth = ("admin", "teste-admin-123")
    with TestClient(app) as c:
        r = c.get("/reconciliacao", auth=auth, follow_redirects=False)
        assert r.status_code == 301 and r.headers["location"] == "/cmdb-final"
        page = c.get("/cmdb-final", auth=auth).text
        assert "avi_x.csv" in page and "fonte AVI" in page and "Comparar todas as fontes" in page


def test_old_env_still_reads_azure_and_directory_panel(env, tmp_path, monkeypatch):
    """Um .env da 0.3 com CERTWATCH_IMPORT_SOURCES sem AZURE continua a reconhecer azure*;
    a página mostra o que acontece a cada ficheiro da diretoria."""
    from fastapi.testclient import TestClient
    from certwatch import config
    from certwatch.web.app import app
    imp = tmp_path / "imp"
    imp.mkdir()
    (imp / "azure.csv").write_text('"AppRegistration";"CredentialType";"KeyId";"EndDate"\n"App X";"Secret";"k";"20/10/2030 10:00:00"\n')
    (imp / "notas.docx").write_bytes(b"x")
    (imp / "exportacao.csv").write_text("a;b\n1;2\n")
    monkeypatch.setenv("CERTWATCH_IMPORT_DIR", str(imp))
    monkeypatch.setenv("CERTWATCH_IMPORT_SOURCES", "CA1=ca1;CA2=ca2;AVI=avi")
    config.get_settings.cache_clear()
    assert config.get_settings().import_sources["AZURE"] == "azure"
    with TestClient(app) as c:
        page = c.get("/cmdb-final", auth=("admin", "teste-admin-123")).text
    assert "azure.csv" in page and "fonte AZURE" in page
    assert "extensão .docx não suportada" in page and "não começa por nenhum prefixo conhecido" in page

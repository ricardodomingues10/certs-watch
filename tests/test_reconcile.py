from dataclasses import replace
from datetime import datetime, timedelta, timezone

from openpyxl import Workbook

from certwatch.db import session_scope, utcnow
from certwatch.jobs import ingest_cmdb
from certwatch.models import ImportFile
from certwatch.reconcile import ingest_imports, map_columns, norm_header, parse_date, reconcile
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


def test_import_and_reconcile(env, tmp_path):
    imp = tmp_path / "import"
    imp.mkdir()
    s = replace(env, import_dir=imp, import_issuers={"CA1": "Exemplo Issuing CA01"}, ucmdb_min_cis=1)

    with session_scope() as db:
        ingest_cmdb(db, s, [
            {"ucmdb_id": "1", "global_id": "1", "common_name": "igual.exemplo.local",
             "valid_to": (NOW + timedelta(days=100)).isoformat(), "issuer": "Exemplo Issuing CA01", "issuer_name": ""},
            {"ucmdb_id": "2", "global_id": "2", "common_name": "renovado.exemplo.local",
             "valid_to": (NOW + timedelta(days=10)).isoformat(), "issuer": "Exemplo Issuing CA01", "issuer_name": ""},
            {"ucmdb_id": "3", "global_id": "3", "common_name": "lb.exemplo.pt",
             "valid_to": (NOW + timedelta(days=300)).isoformat(), "issuer": "DigiCert", "issuer_name": ""},
            {"ucmdb_id": "4", "global_id": "4", "common_name": "sumiu.exemplo.local",
             "valid_to": (NOW + timedelta(days=60)).isoformat(), "issuer": "Exemplo Issuing CA01", "issuer_name": ""},
        ])

    # CA1: certutil em UTF-16 com BOM, separado por vírgulas, datas portuguesas
    ca1 = "\n".join([
        '"Req ID:","Requester Name:","Issued Common Name:","Certificate Expiration Date:","Serial Number:","Request Disposition:"',
        f'"10","DOM\\\\a","novo.exemplo.local","{d(200)}","1a2b","20 -- Issued"',
        f'"11","DOM\\\\b","igual.exemplo.local","{d(100)}","3c4d","20 -- Issued"',
        f'"12","DOM\\\\c","renovado.exemplo.local","{d(375)}","5e6f","20 -- Issued"',
        f'"13","DOM\\\\d","revogado.exemplo.local","{d(50)}","7a8b","21 -- Revoked"',
        '"14","DOM\\\\e","malformado.exemplo.local","31/31/2026","9c9d","20 -- Issued"',
    ])
    (imp / "CA1_export.csv").write_bytes(b"\xff\xfe" + ca1.encode("utf-16-le"))

    # AVI: Excel com data em texto ISO e em célula de data
    wb = Workbook()
    ws = wb.active
    ws.append(["Nome", "Subject_CommonName", "Validity_NotAfter", "SerialNumber", "Issuer_CommonName", "SubjectAlternativeName"])
    ws.append(["lb-cert", "lb.exemplo.pt", (NOW + timedelta(days=100)).strftime("%Y-%m-%dT%H:%M:%S"), "AA", "DigiCert", "lb.exemplo.pt"])
    ws.append(["outro", "app.exemplo.pt", datetime.now() + timedelta(days=30), "BB", "Let's Encrypt R10", ""])
    wb.save(imp / "avi_certs.xlsx")

    # CA2: Windows-1252, ponto e vírgula, cabeçalho com acentos estragados
    ca2 = "Issued Common Name:;Certificate Expiration Date:;LocalizaÃ§Ã£o\n" + f"ca2.exemplo.local;{d(90)};Lisboa\n"
    (imp / "ca2.csv").write_bytes(ca2.encode("cp1252"))
    (imp / "notas.csv").write_text("x;y\n1;2\n")

    with session_scope() as db:
        out = ingest_imports(db, s)
    assert out["CA1"]["estado"] == "importado" and out["CA1"]["registos"] == 3
    assert out["AVI"]["registos"] == 2 and out["CA2"]["registos"] == 1
    assert out["ignorados"] == ["notas.csv"]

    with session_scope() as db:
        f = db.query(ImportFile).filter_by(source="CA1", is_current=True).one()
        assert any("Linha 6" in p for p in f.problems)
        assert any("não emitido" in p for p in f.problems)
        res = reconcile(db, s)
    by = {(r["source"], r["cn_norm"]): r for r in res["rows"]}
    assert by[("CA1", "novo.exemplo.local")]["state"] == "novo"
    assert by[("CA1", "igual.exemplo.local")]["state"] == "igual"
    assert by[("CA1", "renovado.exemplo.local")]["state"] == "data_posterior"
    assert by[("AVI", "lb.exemplo.pt")]["state"] == "data_anterior"
    assert by[("AVI", "app.exemplo.pt")]["state"] == "novo"
    assert by[("CA2", "ca2.exemplo.local")]["state"] == "novo"
    assert by[("CA1", "sumiu.exemplo.local")]["state"] == "so_na_cmdb"
    assert res["counts"]["novo"] == 3

    # Os mesmos ficheiros não são reimportados
    with session_scope() as db:
        assert ingest_imports(db, s)["CA1"]["estado"] == "sem alterações"


def test_reconcile_pages(env, tmp_path, monkeypatch):
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
        c.get("/reconciliacao", auth=auth)
        token = c.cookies["cw_csrf"]
        from certwatch.jobs import run_now
        assert run_now("ingest_imports", "teste", config.get_settings()).status == "ok"
        from certwatch.web.app import invalidate_nav
        invalidate_nav()
        page = c.get("/reconciliacao", auth=auth).text
        assert "novo.exemplo.pt" in page and "Novo: não existe na CMDB" in page
        csv_text = c.get("/reconciliacao/exportar", auth=auth).content.decode("utf-8")
        assert "novo.exemplo.pt" in csv_text and "AVI" in csv_text
        assert c.post("/jobs/ingest_imports", data={"csrf": token, "next": "/reconciliacao"}, auth=auth,
                      follow_redirects=False).headers["location"] == "/reconciliacao"
        dash = c.get("/", auth=auth).text
        assert "Configuração" in dash and "Ficheiros de reconciliação" in dash and "AVI: avi_x.csv" in dash


def test_azure_credentials_against_api_list(env, tmp_path):
    from certwatch.collectors.ucmdb import parse_apis
    from certwatch.jobs import ingest_apis
    imp = tmp_path / "import"
    imp.mkdir()
    s = replace(env, import_dir=imp)
    loc = "AzureAD - App Registration - Client Secret"
    cis = [
        {"ucmdbId": "a1", "properties": {"display_label": "CRM Testes", "application_name": "CRM",
                                         "secret_expiration_date": "24-01-2027 13:00:00", "secret_location": loc}},
        {"ucmdbId": "a2", "properties": {"display_label": "Radar - 0123456789abcdef0123", "application_name": "Radar",
                                         "secret_expiration_date": d(100)[:10].replace("/", "-") + " 13:00:00",
                                         "secret_location": loc}},
        {"ucmdbId": "a3", "properties": {"display_label": "Removida do Azure", "application_name": "Z",
                                         "secret_expiration_date": d(200)[:10].replace("/", "-") + " 13:00:00",
                                         "secret_location": loc}},
    ]
    records, fields = parse_apis(cis, s)
    with session_scope() as db:
        ingest_apis(db, s, records, fields)

    csv_text = "\n".join([
        '"EnterpriseApplication";"AppRegistration";"AppId";"CredentialType";"KeyId";"StartDate";"EndDate";"DaysRemaining";"Status"',
        '"App_TST";"App_TST";"x";"Secret";"k1";"20/10/2024 14:59:29";"20/10/2025 14:59:29";"0";"Expired"',
        '"Automacao Exemplo";"Novo App";"x";"Certificate";"k2";"21/06/2026 23:00:00";"21/06/2036 23:00:00";"3532";"Valid"',
        '"CRM";"CRM Testes";"x";"Secret";"k3";"24/01/2025 10:00:00";"24/01/2027 14:59:29";"460";"Valid"',
        f'"Radar";"Radar";"x";"Secret";"k4";"01/01/2026 10:00:00";"{d(400)}";"400";"Valid"',
    ])
    (imp / "azure.csv").write_text(csv_text, encoding="utf-8")
    with session_scope() as db:
        out = ingest_imports(db, s)
        assert out["AZURE"]["registos"] == 4
        res = reconcile(db, s)
    by = {(r["source"], r["cn"]): r for r in res["rows"]}
    assert by[("AZURE", "App_TST")]["state"] == "expirado"
    assert by[("AZURE", "Novo App")]["state"] == "novo" and by[("AZURE", "Novo App")]["issuer"] == "Certificate"
    assert by[("AZURE", "CRM Testes")]["state"] == "igual"                 # mesma data, horas diferentes
    assert by[("AZURE", "Radar")]["state"] == "data_posterior"            # segredo novo não registado
    assert by[("AZURE", "Removida do Azure")]["state"] == "so_na_cmdb"
    assert all(r["azure"] for r in res["rows"])

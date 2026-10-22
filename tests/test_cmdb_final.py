"""CMDB final: lógica do workflow n8n de reconciliação, ficheiros gerados, publicação e comparação."""
from dataclasses import replace
from datetime import date, datetime, timezone
from io import BytesIO

import pytest
from openpyxl import Workbook, load_workbook
from sqlalchemy import select
from zoneinfo import ZoneInfo

from certwatch import cmdb_final as cf
from certwatch.db import session_scope
from certwatch.models import CmdbRecord, FinalInput, FinalPublishFile, FinalRun

TZ = ZoneInfo("Europe/Lisbon")
TODAY = date(2026, 10, 21)
P = "[Digital Certificate] : "


def ms(d: date, hour: int = 12) -> int:
    return int(datetime(d.year, d.month, d.day, hour, tzinfo=TZ).timestamp() * 1000)


def ci(uid, cn, valid_to, issuer="Corp CA01", serial="AA01", **extra):
    props = {"display_label": cn or extra.pop("display_label", ""), "name": extra.pop("name", cn), "common_name": cn,
             "valid_to": ms(valid_to) if valid_to else None, "issuer": issuer, "issuer_name": issuer,
             "serial_number": serial, "certificate_type": "SSL", "localizacao": "IIS", "aplicacao": "Portal",
             "responsabilidade_instalacao": "DSTI", "created_by": "admin", "description": "", **extra}
    return {"ucmdbId": f"u{uid}", "globalId": f"g{uid}", "type": "digital_certificate", "properties": props}


CIS = [
    ci(1, "igual.exemplo.pt", date(2027, 3, 1)),
    ci(2, "renovado.exemplo.pt", date(2026, 11, 10), serial="0A01"),
    ci(3, "www.exemplo.pt", date(2027, 6, 1), issuer="Antiga CA"),          # regressão -> servidor
    ci(4, "*.exemplo.pt", date(2027, 6, 1)),                                # regressão wildcard -> mantém
    ci(5, "mudo.exemplo.pt", date(2027, 6, 1)),                             # regressão sem resposta -> mantém
    ci(6, "", date(2026, 11, 1), name="antigo.exemplo.pt"),                 # sem CommonName, encontrado pelo Name
    ci(7, "duplo.exemplo.pt", date(2026, 1, 5), serial="D1"),
    ci(8, "duplo.exemplo.pt", date(2026, 11, 20), serial="D2"),
]


def ca_csv(rows):
    head = '"Req ID:","Requester Name:","Issued Common Name:","Certificate Expiration Date:","Serial Number:","Request Disposition:"'
    return ("\n".join([head] + [",".join(f'"{x}"' for x in r) for r in rows]) + "\n").encode("utf-8")


CA1 = ca_csv([
    ("10", "DOM\\a", "igual.exemplo.pt", "01/03/2027 10:00", "AA01", "20 -- Issued"),
    ("11", "DOM\\a", "renovado.exemplo.pt", "10/11/2027 09:00", "0a:02", "20 -- Issued"),
    ("12", "DOM\\a", "www.exemplo.pt", "01/02/2027", "BB", "20 -- Issued"),
    ("13", "DOM\\a", "*.exemplo.pt", "01/02/2027", "CC", "20 -- Issued"),
    ("14", "DOM\\a", "mudo.exemplo.pt", "01/02/2027", "DD", "20 -- Issued"),
    ("15", "DOM\\a", "antigo.exemplo.pt", "05/12/2027", "EE", "20 -- Issued"),
    ("16", "DOM\\a", "duplo.exemplo.pt", "20/12/2027", "D3", "20 -- Issued"),
    ("17", "DOM\\a", "novo-ca1.exemplo.pt", "01/01/2028", "N1", "20 -- Issued"),
    ("18", "DOM\\a", "revogado.exemplo.pt", "01/01/2028", "R1", "21 -- Revoked"),
    ("19", "DOM\\a", "expirado.exemplo.pt", "01/01/2025", "E1", "20 -- Issued"),
    ("20", "DOM\\a", "semdata.exemplo.pt", "", "S1", "20 -- Issued"),
    ("21", "DOM\\a", "SERVIDOR01", "01/01/2028", "S2", "20 -- Issued"),
    ("22", "DOM\\a", "partido.exemplo.pt", "31/31/2027", "S3", "20 -- Issued"),
])


def ca2_xlsx():
    wb = Workbook()
    ws = wb.active
    ws.append(["Req ID:", "Issued Common Name:", "Certificate Expiration Date:", "Serial Number:", "Request Disposition:"])
    ws.append([30, "novo-ca2.exemplo.pt", datetime(2028, 2, 2, 8, 0), "N2", "20 -- Issued"])
    ws.append([31, "serial-excel.exemplo.pt", 46818.75, "N3", "20 -- Issued"])   # 2028-03-06, a hora é ignorada
    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()


AVI = (
    "Nome,Subject_CommonName,Validity_NotAfter,SerialNumber,Issuer_CommonName,SubjectAlternativeName\n"
    "vs-novo,novo-avi.exemplo.pt,2028-04-10 12:00:00,N4,DigiCert Global G2,novo-avi.exemplo.pt\n"
    "vs-ca1,novo-ca1.exemplo.pt,2028-01-01T00:00:00Z,N1,Corp CA01,\n"
    "vs-sem-cn,,2028-05-05,N5,DigiCert Global G2,\n"
).encode("utf-8")


@pytest.fixture()
def settings(env, tmp_path):
    imp = tmp_path / "import"
    imp.mkdir()
    pub = tmp_path / "publicar"
    pub.mkdir()
    return replace(env, import_dir=imp, publish_dir=pub, ucmdb_min_cis=1,
                   import_issuers={"CA1": "Corp CA01", "CA2": "Corp CA02"})


def live(host):
    if host == "www.exemplo.pt":
        return {"status": "OK", "not_after": datetime(2027, 9, 30, 23, 0, tzinfo=timezone.utc),
                "serial": "FF01", "issuer_cn": "Nova CA", "origem": "teste"}
    return {"status": "ERROR", "detail": "timeout", "origem": "teste"}


def build(settings, cis=CIS):
    import copy
    table = cf.build_cmdb_table(copy.deepcopy(cis), settings)
    sources = {
        "CA1": cf.read_source("CA1", "ca1.csv", CA1, TODAY)[0],
        "CA2": cf.read_source("CA2", "ca2.xlsx", ca2_xlsx(), TODAY)[0],
        "AVI": cf.read_source("AVI", "avi.csv", AVI, TODAY)[0],
    }
    return cf.reconcile_final(table, sources, settings, live, TODAY)


def by_cn(res, cn):
    H = res.table.h
    return [(i, r) for i, r in enumerate(res.table.rows) if r[H("CommonName")] == cn]


def test_parse_day_never_swaps():
    assert cf.parse_day("10/04/2028").day == date(2028, 4, 10)
    assert cf.parse_day("10-04-2028 00:00:00").day == date(2028, 4, 10)
    assert cf.parse_day("13/25/2028").status == "INVALIDO"
    assert cf.parse_day("20280410").day == date(2028, 4, 10)
    assert cf.parse_day(46818.75).day == date(2028, 3, 6)
    assert cf.parse_day("2028-04-10T23:30:00Z").day == date(2028, 4, 10)
    assert cf.parse_day("").status == "VAZIO"
    assert cf.parse_day("amanhã").status == "NAO_RECONHECIDO"
    assert cf.parse_day("01/01/1990").status == "ANO_SUSPEITO"


def test_columns_from_api(settings):
    t = cf.build_cmdb_table([dict(c) for c in CIS], settings)
    assert t.headers[:3] == [P + "Display Label", P + "ValidTo", P + "Aplicação"]
    assert P + "Localização" in t.headers and P + "Responsabilidade de instalação" in t.headers
    assert not any("created" in h.lower() for h in t.headers)            # Created By fica de fora
    r = t.rows[0]
    assert r[P + "ValidTo"] == "01-03-2027 12:00:00"                      # epoch ms -> hora de Lisboa
    assert r[P + "Global Id"] == "g1" and r[P + "Aplicação"] == "Portal"
    assert "Subject Alternative Names" in t.diag["colunas_vazias"]


def test_column_overrides_file(settings):
    (settings.import_dir / "cmdb-colunas.csv").write_text(
        "atributo;coluna\naplicacao;\nresponsabilidade_instalacao;Responsabilidade de instalação\nx_custom;Campo X\n",
        encoding="utf-8")
    cis = [ci(1, "a.exemplo.pt", date(2027, 1, 1), x_custom="v")]
    t = cf.build_cmdb_table(cis, settings)
    assert t.rows[0][P + "Campo X"] == "v"
    assert t.rows[0][P + "Aplicação"] == ""                               # excluída no ficheiro
    assert t.headers[0] == P + "Responsabilidade de instalação"            # ordem do ficheiro


def test_reconcile_like_workflow(settings):
    res = build(settings)
    H = res.table.h
    # igual: nada muda
    (i, r), = by_cn(res, "igual.exemplo.pt")
    assert i not in res.mods
    # renovado: data e série novas, Description auditável
    (i, r), = by_cn(res, "renovado.exemplo.pt")
    assert r[H("ValidTo")] == "10-11-2027 00:00:00" and r[H("SerialNumber")] == "0a:02"
    assert r[H("Description")] == ("Changed with n8n - Data de expiracao alterado de 10/11/2026 para 10/11/2027; "
                                   "SerialNumber alterado de 0A01 para 0a:02")
    # regressão validada no servidor: o servidor manda (data, série, emissor)
    (i, r), = by_cn(res, "www.exemplo.pt")
    assert r[H("ValidTo")] == "30-09-2027 00:00:00" and r[H("SerialNumber")] == "FF01"
    assert r[H("Issuer")] == r[H("IssuerName")] == "Nova CA"
    assert r[H("Description")].startswith("Changed with n8n - Validado via TLS; Data de expiracao alterado de 01/06/2027 para 30/09/2027")
    # wildcard e servidor sem resposta: a CMDB fica como estava
    for cn in ("*.exemplo.pt", "mudo.exemplo.pt"):
        (i, r), = by_cn(res, cn)
        assert i not in res.mods and r[H("ValidTo")] == "01-06-2027 12:00:00"
    decisions = {x["cn"]: x["decisao"] for x in res.live}
    assert decisions == {"www.exemplo.pt": "ATUALIZAR_COM_SERVIDOR", "*.exemplo.pt": "MANTER_CMDB_WILDCARD",
                         "mudo.exemplo.pt": "MANTER_CMDB_SEM_RESPOSTA"}
    # sem CommonName na CMDB: encontrado pelo Name, o CommonName é preenchido na MESMA linha
    (i, r), = by_cn(res, "antigo.exemplo.pt")
    assert res.table.ids[i] == "u6" and "CommonName preenchido com antigo.exemplo.pt" in r[H("Description")]
    # duas linhas com o mesmo nome: muda a de data mais próxima
    rows = dict(by_cn(res, "duplo.exemplo.pt"))
    changed = [i for i in rows if i in res.mods]
    assert len(changed) == 1 and res.table.ids[changed[0]] == "u8"
    # novos: CA1/CA2 com o emissor configurado, AVI com o Issuer_CommonName; CA1 e AVI com o mesmo certificado = 1 linha
    new = {res.table.rows[i][H("CommonName")]: res.table.rows[i] for i in res.new_rows}
    assert set(new) == {"novo-ca1.exemplo.pt", "novo-ca2.exemplo.pt", "serial-excel.exemplo.pt", "novo-avi.exemplo.pt"}
    assert new["novo-ca1.exemplo.pt"][H("IssuerName")] == "Corp CA01"
    assert new["novo-ca2.exemplo.pt"][H("Issuer")] == "Corp CA02"
    assert new["serial-excel.exemplo.pt"][H("ValidTo")] == "06-03-2028 00:00:00"
    a = new["novo-avi.exemplo.pt"]
    assert (a[H("IssuerName")], a[H("Global Id")], a[H("Localização")], a[H("Certificate Status")],
            a[H("Certificate Type")], a[H("Description")]) == (
        "DigiCert Global G2", "x", "AVI", "Ativo", "SSL", "Changed with n8n - novo certificado")
    assert a[H("Subject Alternative Names")] == "novo-avi.exemplo.pt"
    # relatório de erros
    errs = {(p["fonte"], p["cn"]): p["erro"] for p in res.problems}
    assert errs[("CA1", "revogado.exemplo.pt")].startswith("Pedido não emitido")
    assert errs[("CA1", "expirado.exemplo.pt")] == "Certificado já expirado"
    assert errs[("CA1", "semdata.exemplo.pt")] == "Data de expiração vazia"
    assert errs[("CA1", "SERVIDOR01")].startswith("Nome sem domínio")
    assert errs[("CA1", "partido.exemplo.pt")].startswith("Data inválida")
    assert errs[("AVI", "vs-sem-cn")].startswith("Nome sem domínio")     # sem CN usa o Nome, como no workflow
    s = res.summary
    assert (s["novos"], s["alterados"], s["regressoes"], s["regressoes_atualizadas"]) == (4, 4, 3, 1)


def test_outputs_and_validation(settings):
    res = build(settings)
    delta = cf._delta_rows(res)
    assert len(delta) == 8 and not cf.validate_delta(delta)
    csv = cf.build_csv(delta, True)
    text = csv.decode("utf-8")
    assert not csv.startswith(b"\xef\xbb\xbf") and text.endswith("\r\n") and text.count("\r\n") == 9
    assert text.split("\r\n")[0].startswith('"Display Label"|"ValidTo"|"Aplicação"|')
    assert text.split("\r\n")[0].count("|") == 25
    sem = cf.build_csv(delta, False).decode("utf-8")
    assert sem.count("\r\n") == 8 and '"' not in sem and sem.split("\r\n")[0].count("|") == 25
    # aspas, pipes e quebras de linha dentro dos valores
    row = dict(delta[0], Description='a "b" | c\nd')
    assert '"a ""b""  /  c d"' in cf.build_csv([row], True).decode()     # | -> " / ", como no workflow
    assert "|a b  /  c d|" in cf.build_csv([row], False).decode()
    # novo sem número de série -> CSV recusados
    bad = [dict(delta[0], **{"Global Id": "x", "SerialNumber": ""})]
    assert "sem Issuer, IssuerName ou SerialNumber" in cf.validate_delta(bad)[0]
    dup = [dict(delta[0]), dict(delta[0])]
    assert "Chave primária repetida" in cf.validate_delta(dup)[0]
    # Excel: sem linhas extra, cores por estado, texto nunca vira fórmula
    res.table.rows[0][res.table.h("Description")] = "=1+1"
    x = cf.build_xlsx(res)
    ws = load_workbook(BytesIO(x)).worksheets[0]
    assert ws.title == "CMDB" and ws.max_row == len(res.table.rows) + 1 and ws["A1"].value == P + "Display Label"
    back = {r["cn"]: r for r in cf.read_final_xlsx(x)}
    assert back["novo-avi.exemplo.pt"]["cor"] == "novo" and back["renovado.exemplo.pt"]["cor"] == "alterado"
    assert back["igual.exemplo.pt"]["cor"] is None
    desc_col = res.table.headers.index(res.table.h("Description")) + 1
    assert ws.cell(row=2, column=desc_col).data_type == "s"


def test_expired_row_is_red(settings):
    cis = [ci(1, "velho.exemplo.pt", date(2026, 1, 1))]
    t = cf.build_cmdb_table(cis, settings)
    res = cf.reconcile_final(t, {"CA1": [], "CA2": [], "AVI": []}, settings, live, TODAY)
    assert res.expired_rows == {0}
    assert cf.read_final_xlsx(cf.build_xlsx(res))[0]["cor"] == "expirado"


def test_empty_cmdb_stops(settings):
    t = cf.build_cmdb_table([], settings)
    with pytest.raises(cf.FinalError):
        cf.reconcile_final(t, {}, settings, live, TODAY)


def test_generate_publish_and_compare(settings, monkeypatch):
    (settings.import_dir / "ca1_export.csv").write_bytes(CA1)
    (settings.import_dir / "avi_export.csv").write_bytes(AVI)
    with session_scope() as s:
        s.add(FinalInput(source="CA2", name="ca2.xlsx", sha256="x", size=1, data=ca2_xlsx(), uploaded_by="admin"))
        inputs = cf.current_inputs(s, settings)
        assert {k: v["origem"] for k, v in inputs.items()} == {"CA1": "diretoria", "AVI": "diretoria", "CA2": "carregado"}
        run_id = cf.start_run(s, "admin").id
        with pytest.raises(cf.FinalError):
            cf.start_run(s, "admin")                       # só uma geração de cada vez

    def fetch(_settings):
        import copy
        cis = copy.deepcopy(CIS)
        table = cf.build_cmdb_table(cis, _settings)
        recs = [{"ucmdb_id": c["ucmdbId"], "global_id": c["globalId"], "common_name": c["properties"]["common_name"],
                 "valid_to": datetime.fromtimestamp(c["properties"]["valid_to"] / 1000, tz=timezone.utc).isoformat(),
                 "issuer": c["properties"]["issuer"], "issuer_name": c["properties"]["issuer_name"]} for c in cis]
        return table, recs

    cf.generate(run_id, settings, fetch=fetch, live_factory=lambda s, st: live, today=TODAY)
    with session_scope() as s:
        run = s.get(FinalRun, run_id)
        assert run.status == "pronto", run.error
        assert run.summary["novos"] == 4 and run.csv and run.csv_sem and run.xlsx
        assert run.inputs["CA2"]["origem"] == "carregado"
        assert s.scalar(select(CmdbRecord).where(CmdbRecord.common_name == "renovado.exemplo.pt")) is not None

        # publicação: escreve os três ficheiros e guarda o que lá estava
        (settings.publish_dir / "certs_update.csv").write_bytes(b"anterior")
        pub = cf.publish(s, settings, run, ["xlsx", "csv", "csv_sem"], "admin")
        assert pub.ok, pub.result
        assert (settings.publish_dir / "certs_update.csv").read_bytes() == run.csv
        assert (settings.publish_dir / "CMDB_Final.xlsx").read_bytes() == run.xlsx
        prev = s.scalar(select(FinalPublishFile).where(FinalPublishFile.name == "certs_update.csv"))
        assert prev.previous == b"anterior"
        assert not [p for p in settings.publish_dir.iterdir() if p.name.startswith(".")]   # sem temporários
        assert cf.test_write(settings)[0]

        # comparação: o ficheiro final contra a CMDB atual (que ainda não recebeu as alterações)
        recs = list(s.scalars(select(CmdbRecord).where(CmdbRecord.active.is_(True))))
        rows, counts = cf.compare_with_cmdb(cf.read_final_xlsx(run.xlsx), recs, TZ)
        st = {r["cn"]: r for r in rows}
        assert st["igual.exemplo.pt"]["estado"] == "igual"
        assert st["renovado.exemplo.pt"]["dif"] == ["data"]
        assert set(st["www.exemplo.pt"]["dif"]) == {"data", "issuer", "issuer_name"}
        assert st["novo-avi.exemplo.pt"]["estado"] == "nao_existe"
        assert counts["nao_existe"] == 5 and counts["data"] == 3     # renovado, www e duplo
        assert "motivo" in st["antigo.exemplo.pt"] and "motivo" not in st["novo-avi.exemplo.pt"]
        assert all(r["cor"] for r in cf.filter_compare(rows, "todos", marked=True))

        # depois de a UCMDB aplicar o ficheiro: renovado fica igual
        rec = s.scalar(select(CmdbRecord).where(CmdbRecord.common_name == "renovado.exemplo.pt"))
        rec.valid_to = datetime(2027, 11, 10, 12, tzinfo=timezone.utc)
        s.flush()
        rows, _ = cf.compare_with_cmdb(cf.read_final_xlsx(run.xlsx), list(s.scalars(select(CmdbRecord))), TZ)
        assert {r["cn"]: r for r in rows}["renovado.exemplo.pt"]["estado"] == "igual"

        # uma geração mais recente impede publicar a anterior
        run2 = cf.start_run(s, "admin")
        run2.status = "pronto"
        s.flush()
        with pytest.raises(cf.FinalError):
            cf.publish(s, settings, run, ["csv"], "admin")


def test_generate_blocked_and_error(settings):
    (settings.import_dir / "ca1.csv").write_bytes(CA1)
    (settings.import_dir / "avi.csv").write_bytes(AVI)
    with session_scope() as s:
        run_id = cf.start_run(s, "admin").id
    # falta CA2 -> erro claro
    cf.generate(run_id, settings, fetch=lambda st: (cf.build_cmdb_table([dict(c) for c in CIS], st), []),
                live_factory=lambda s, st: live, today=TODAY)
    with session_scope() as s:
        run = s.get(FinalRun, run_id)
        assert run.status == "erro" and "CA2" in run.error
    # emissor de CA2 não configurado e não encontrado noutra fonte -> "Por verificar" (os CSV são gerados)
    (settings.import_dir / "ca2.xlsx").write_bytes(ca2_xlsx())
    st2 = replace(settings, import_issuers={"CA1": "Corp CA01"})
    with session_scope() as s:
        run_id = cf.start_run(s, "admin").id
    import copy
    cf.generate(run_id, st2, fetch=lambda st: (cf.build_cmdb_table(copy.deepcopy(CIS), st), []),
                live_factory=lambda s, st: live, today=TODAY)
    with session_scope() as s:
        run = s.get(FinalRun, run_id)
        assert run.status == "pronto" and run.csv and not run.validation
        novo = next(c for c in run.changes if c["cn"] == "novo-ca2.exemplo.pt")
        assert novo["issuer_name"] == "Por verificar" and "IssuerName" in novo["pendente"]
        assert run.summary["por_verificar"] >= 1
        line = next(x for x in run.csv.decode().splitlines() if "novo-ca2.exemplo.pt" in x)
        assert '"Por verificar"' in line


def test_folder_status_missing(settings, tmp_path):
    st = replace(settings, publish_dir=tmp_path / "nao-montada")
    info = cf.folder_status(st)
    assert not info["existe"] and "não existe" in info["detalhe"]
    assert not cf.test_write(st)[0]


def test_web_flow(settings, monkeypatch):
    import copy

    from fastapi.testclient import TestClient

    from certwatch.web import app as webapp

    monkeypatch.setattr(webapp, "get_settings", lambda: settings)

    def fake_bg(run_id, st):
        cf.generate(run_id, st, fetch=lambda s2: (cf.build_cmdb_table(copy.deepcopy(CIS), s2), []),
                    live_factory=lambda s, s2: live, today=TODAY)
    monkeypatch.setattr(cf, "generate_in_background", fake_bg)
    AUTH = ("admin", "teste-admin-123")
    (settings.import_dir / "ca1.csv").write_bytes(CA1)
    with TestClient(webapp.app) as c:
        r = c.get("/cmdb-final", auth=AUTH)
        assert r.status_code == 200 and "Falta CA2, AVI" in r.text
        token = c.cookies["cw_csrf"]
        # carregar fontes pela página
        r = c.post("/cmdb-final/fonte/CA2", data={"csrf": token}, files={"ficheiro": ("ca2.xlsx", ca2_xlsx())}, auth=AUTH)
        assert r.status_code == 200 and "ca2.xlsx" in r.text
        r = c.post("/cmdb-final/fonte/AVI", data={"csrf": token}, files={"ficheiro": ("avi.exe", b"MZ")}, auth=AUTH)
        assert "Formato não aceite" in r.text
        r = c.post("/cmdb-final/fonte/AVI", data={"csrf": "x"}, files={"ficheiro": ("avi.csv", AVI)}, auth=AUTH)
        assert r.status_code == 403
        c.post("/cmdb-final/fonte/AVI", data={"csrf": token}, files={"ficheiro": ("avi.csv", AVI)}, auth=AUTH)
        # gerar
        r = c.post("/cmdb-final/gerar", data={"csrf": token}, auth=AUTH, follow_redirects=False)
        assert r.status_code == 303
        url = r.headers["location"]
        r = c.get(url, auth=AUTH)
        assert "Pronto a publicar" in r.text and "8 alterações" in r.text and "Publicar na pasta de rede" in r.text
        for v in ("servidor", "erros", "colunas"):
            assert c.get(f"{url}?vista={v}", auth=AUTH).status_code == 200
        assert "MANTER" not in c.get(f"{url}?vista=servidor", auth=AUTH).text   # texto legível, não o código
        r = c.get(f"{url}/ficheiro/csv", auth=AUTH)
        assert r.content.startswith(b'"Display Label"|')
        assert c.get(f"{url}/ficheiro/xlsx", auth=AUTH).content[:2] == b"PK"
        for what in ("alteracoes", "erros", "servidor", "colunas"):
            assert c.get(f"{url}/exportar/{what}", auth=AUTH).status_code == 200
        # excluir uma alteração e voltar a incluí-la
        rid = url.rsplit("/", 1)[1]
        assert 'name="incluir"' in c.get(url, auth=AUTH).text
        r = c.post(f"{url}/selecao", data={"csrf": token, "k": ["1", "2"], "incluir": ["2"]}, auth=AUTH)
        assert r.status_code == 200 and "7 alterações" in r.text and "1 excluída" in r.text
        r = c.post(f"{url}/selecao", data={"csrf": token, "k": ["1"], "incluir": ["1"]}, auth=AUTH)
        assert "8 alterações" in r.text
        assert c.post(f"{url}/selecao", data={"csrf": token, "k": ["x"]}, auth=AUTH).status_code == 400
        # publicar: sem confirmação é recusado; com confirmação escreve na pasta
        assert c.post(f"{url}/publicar", data={"csrf": token, "ficheiro": ["csv"]}, auth=AUTH).status_code == 400
        r = c.post(f"{url}/publicar", data={"csrf": token, "ficheiro": ["xlsx", "csv", "csv_sem"], "confirmo": "1"}, auth=AUTH)
        assert r.status_code == 200 and "nada a substituir" in r.text
        assert sorted(p.name for p in settings.publish_dir.iterdir()) == sorted(cf.FILES.values())
        # comparar: geração, pasta e ficheiro carregado
        r = c.get("/cmdb-final/comparar", auth=AUTH)
        assert r.status_code == 200 and f"geracao:{rid}" in r.text
        r = c.get("/cmdb-final/comparar?origem=pasta&vista=todos", auth=AUTH)
        assert "na pasta de rede" in r.text and "novo-avi.exemplo.pt" in r.text
        r = c.post("/cmdb-final/comparar/carregar", data={"csrf": token},
                   files={"ficheiro": ("final.xlsx", (settings.publish_dir / "CMDB_Final.xlsx").read_bytes())}, auth=AUTH)
        assert r.status_code == 200 and "final.xlsx (carregado)" in r.text
        r = c.get(f"/cmdb-final/comparar/exportar?origem=geracao:{rid}&vista=todos", auth=AUTH)
        assert "novo-avi.exemplo.pt" in r.content.decode("utf-8-sig")
        assert c.post("/cmdb-final/testar-pasta", data={"csrf": token}, auth=AUTH).status_code == 200


def _ucmdb(topology_query_status=200):
    import json as _json

    import httpx
    full = {c["ucmdbId"]: c["properties"] for c in CIS}
    calls = {"tq": 0, "ci": 0}

    def handler(request: httpx.Request):
        path = request.url.path
        if path.endswith("/authenticate"):
            return httpx.Response(200, json={"token": "t"})
        if path.endswith("/topology"):
            # layout do TQL só com os campos confiáveis (como o TQL do certwatch)
            cis = [{"ucmdbId": c["ucmdbId"], "globalId": c["globalId"], "type": c["type"],
                    "properties": {k: c["properties"][k] for k in ("common_name", "valid_to", "issuer", "issuer_name")}}
                   for c in CIS]
            return httpx.Response(200, json={"cis": cis, "relations": []})
        if "/dataModel/ci/" in path:
            calls["ci"] += 1
            uid = path.rsplit("/", 1)[1]
            return httpx.Response(200, json={"ucmdbId": uid, "properties": {**full[uid], "root_class": "digital_certificate",
                                                                             "data_note": "x", "password_hint": "nunca"}})
        if path.endswith("/topologyQuery"):
            calls["tq"] += 1
            if topology_query_status != 200:
                return httpx.Response(topology_query_status, json={"error": "sem permissão"})
            layout = _json.loads(request.content)["nodes"][0]["layout"]
            return httpx.Response(200, json={"cis": [{"ucmdbId": u, "properties": {k: p.get(k) for k in layout}}
                                                     for u, p in full.items()], "relations": []})
        return httpx.Response(404)
    return httpx.Client(base_url="https://cmdb.test/rest-api", transport=httpx.MockTransport(handler)), calls


def test_fetch_cmdb_completes_attributes(settings):
    client, calls = _ucmdb()
    table, recs = cf.fetch_cmdb_table(settings, client)
    assert table.diag["metodo"] == "topologyQuery" and calls == {"tq": 1, "ci": 1}
    r = table.rows[0]
    assert r[P + "Aplicação"] == "Portal" and r[P + "Responsabilidade de instalação"] == "DSTI"
    assert r[P + "Global Id"] == "g1" and r[P + "ValidTo"] == "01-03-2027 12:00:00"
    assert not any("root" in h or "data_note" in h or "password" in h for h in table.headers)
    assert recs[0]["common_name"] == "igual.exemplo.pt" and len(recs) == len(CIS)
    # sem permissão para a consulta ad-hoc: lê CI a CI
    client, calls = _ucmdb(403)
    table, _ = cf.fetch_cmdb_table(settings, client)
    assert table.diag["metodo"] == "ci" and calls["ci"] == 1 + len(CIS)
    assert table.rows[1][P + "Aplicação"] == "Portal"
    assert any("topologyQuery" in a for a in table.diag["avisos"])


def _ct(session, name, not_after, triage="por_triar", serial="C1", issuer="R11", names=None):
    from certwatch.models import CtCert
    session.add(CtCert(primary_name=name, names=names or [name], issuer_cn=issuer, serial_hex=serial,
                       not_before=not_after - (date(2027, 1, 1) - date(2026, 10, 1)),
                       not_after=not_after, triage=triage, domain="exemplo.pt"))


def _fetch(st):
    import copy
    return cf.build_cmdb_table(copy.deepcopy(CIS), st), []


def test_internet_source_and_selection(settings):
    (settings.import_dir / "ca1.csv").write_bytes(CA1)
    (settings.import_dir / "ca2.xlsx").write_bytes(ca2_xlsx())
    (settings.import_dir / "avi.csv").write_bytes(AVI)
    utc = timezone.utc
    with session_scope() as s:
        _ct(s, "ct-novo.exemplo.pt", datetime(2027, 8, 1, 10, tzinfo=utc), "adicionar", "ab01", names=["ct-novo.exemplo.pt", "alt.exemplo.pt"])
        _ct(s, "ct-triar.exemplo.pt", datetime(2027, 8, 2, tzinfo=utc), "por_triar", "ab02")
        _ct(s, "ct-triar.exemplo.pt", datetime(2027, 2, 2, tzinfo=utc), "por_triar", "ab00")      # mais antigo: ignorado
        _ct(s, "ct-ignorado.exemplo.pt", datetime(2027, 8, 3, tzinfo=utc), "ignorar", "ab03")
        _ct(s, "velho.exemplo.pt", datetime(2025, 8, 3, tzinfo=utc), "adicionar", "ab04")          # expirado
        _ct(s, "igual.exemplo.pt", datetime(2027, 12, 1, tzinfo=utc), "por_triar", "ab05")        # renovação de um que existe
        items, info = cf.ct_source(s, settings, TODAY)
        assert sorted(i.cn for i in items) == ["ct-novo.exemplo.pt", "ct-triar.exemplo.pt", "igual.exemplo.pt"]
        assert info["triagem"] == {"adicionar": 1, "por_triar": 2, "investigar": 0} and info["ignorados_na_triagem"] == 1
        assert next(i for i in items if i.cn == "ct-triar.exemplo.pt").serial == "AB02"
        run_id = cf.start_run(s, "admin").id
    cf.generate(run_id, settings, fetch=_fetch, live_factory=lambda s, st: live, today=TODAY)
    with session_scope() as s:
        run = s.get(FinalRun, run_id)
        assert run.status == "pronto", run.error
        ch = {c["cn"]: c for c in run.changes}
        assert ch["ct-novo.exemplo.pt"]["incluir"] and ch["ct-novo.exemplo.pt"]["fonte"] == "INTERNET"
        assert not ch["ct-triar.exemplo.pt"]["incluir"] and "Adicionar à CMDB" in ch["ct-triar.exemplo.pt"]["porque"]
        assert ch["igual.exemplo.pt"]["tipo"] == "alterado" and not ch["igual.exemplo.pt"]["incluir"]
        assert "ct-ignorado.exemplo.pt" not in ch and run.inputs["INTERNET"]["validas"] == 3
        csv = run.csv.decode()
        assert "ct-novo.exemplo.pt" in csv and "ct-triar.exemplo.pt" not in csv and "igual.exemplo.pt" not in csv
        assert '"R11"|"R11"|"AB01"' in csv and '"INTERNET"' in csv                         # emissor do certificado
        assert run.summary["novos"] == 5 and run.summary["novos_total"] == 6 and run.summary["excluidos"] == 2
        final = {r["cn"]: r for r in cf.read_final_xlsx(run.xlsx)}
        assert "ct-triar.exemplo.pt" not in final and final["igual.exemplo.pt"]["cor"] is None
        assert final["igual.exemplo.pt"]["validto"] == "01-03-2027 12:00:00"                   # ficou como na CMDB

        # incluir o "por triar" e excluir a renovação de renovado.exemplo.pt
        keys = {c["cn"]: c["chave"] for c in run.changes}
        shown = [keys["ct-triar.exemplo.pt"], keys["renovado.exemplo.pt"]]
        assert cf.apply_selection(s, run, shown, {keys["ct-triar.exemplo.pt"]}, "ana") == 2
        assert cf.apply_selection(s, run, shown, {keys["ct-triar.exemplo.pt"]}, "ana") == 0       # nada mudou
        csv = run.csv.decode()
        assert "ct-triar.exemplo.pt" in csv and "renovado.exemplo.pt" not in csv
        final = {r["cn"]: r for r in cf.read_final_xlsx(run.xlsx)}
        assert final["renovado.exemplo.pt"]["cor"] is None and final["renovado.exemplo.pt"]["validto"] == "10-11-2026 12:00:00"
        assert run.summary["alterados"] == 3 and run.summary["excluidos"] == 2

    # a escolha fica para a geração seguinte
    with session_scope() as s:
        run2 = cf.start_run(s, "admin").id
    cf.generate(run2, settings, fetch=_fetch, live_factory=lambda s, st: live, today=TODAY)
    with session_scope() as s:
        run = s.get(FinalRun, run2)
        ch = {c["cn"]: c for c in run.changes}
        assert ch["ct-triar.exemplo.pt"]["incluir"] and "incluída por ana" in ch["ct-triar.exemplo.pt"]["porque"]
        assert not ch["renovado.exemplo.pt"]["incluir"]
        old = s.get(FinalRun, run_id)
        with pytest.raises(cf.FinalError):                      # só a mais recente pode ser alterada
            cf.apply_selection(s, old, [0], set(), "ana")


def test_exclusion_updates_pending(settings):
    (settings.import_dir / "ca1.csv").write_bytes(CA1)
    (settings.import_dir / "ca2.xlsx").write_bytes(ca2_xlsx())
    (settings.import_dir / "avi.csv").write_bytes(AVI)
    st = replace(settings, import_issuers={"CA1": "Corp CA01"}, final_ct=False)    # CA2 sem emissor -> "Por verificar"
    with session_scope() as s:
        run_id = cf.start_run(s, "admin").id
    cf.generate(run_id, st, fetch=_fetch, live_factory=lambda s, st: live, today=TODAY)
    with session_scope() as s:
        run = s.get(FinalRun, run_id)
        assert run.status == "pronto" and run.summary["por_verificar"] >= 1
        bad = [c["chave"] for c in run.changes if c["fonte"] == "CA2"]
        cf.apply_selection(s, run, bad, set(), "ana")
        assert run.status == "pronto" and run.csv and run.summary["por_verificar"] == 0
        assert "Por verificar" not in run.csv.decode()


def test_exclude_from_compare_page(settings, monkeypatch):
    from fastapi.testclient import TestClient
    from certwatch.web import app as webapp
    monkeypatch.setattr(webapp, "get_settings", lambda: settings)
    (settings.import_dir / "ca1.csv").write_bytes(CA1)
    (settings.import_dir / "ca2.xlsx").write_bytes(ca2_xlsx())
    (settings.import_dir / "avi.csv").write_bytes(AVI)
    with session_scope() as s:
        run_id = cf.start_run(s, "admin").id
    cf.generate(run_id, settings, fetch=_fetch, live_factory=lambda s, st: live, today=TODAY)
    AUTH = ("admin", "teste-admin-123")
    with TestClient(webapp.app) as c:
        url = f"/cmdb-final/comparar?origem=geracao:{run_id}&vista=todos"
        page = c.get(url, auth=AUTH).text
        assert 'name="incluir"' in page and "Guardar seleção e refazer os ficheiros" in page
        token = c.cookies["cw_csrf"]
        with session_scope() as s:
            keys = {ch["cn"]: ch["chave"] for ch in s.get(FinalRun, run_id).changes}
        r = c.post(f"/cmdb-final/{run_id}/selecao", data={"csrf": token, "next": url,
                                                         "k": [keys["novo-avi.exemplo.pt"], keys["renovado.exemplo.pt"]],
                                                         "incluir": [keys["renovado.exemplo.pt"]]}, auth=AUTH)
        assert r.status_code == 200 and "1 já excluída" in r.text and "novo-avi.exemplo.pt" not in r.text
    with session_scope() as s:
        assert "novo-avi.exemplo.pt" not in s.get(FinalRun, run_id).csv.decode()


def test_missing_serial_and_issuer(settings):
    """Sem série em nenhuma fonte -> "x"; sem emissor -> "Por verificar"; antes disso, procura noutras fontes e
    nos certificados já vistos pelo certwatch (mesmo nome e mesma data de fim)."""
    cis = [ci(1, "renovado.exemplo.pt", date(2026, 11, 10), serial="0A01"),
           ci(2, "igual.exemplo.pt", date(2027, 3, 1), serial="AA01")]
    t = cf.build_cmdb_table(cis, settings)
    st = replace(settings, import_issuers={})
    S = cf.SourceItem
    sources = {
        "CA1": [S("CA1", 2, "renovado.exemplo.pt", date(2027, 11, 10)),          # renovado, sem série -> "x"
                S("CA1", 3, "igual.exemplo.pt", date(2027, 3, 1)),               # mesmo certificado -> série fica
                S("CA1", 4, "novo1.exemplo.pt", date(2028, 1, 1)),               # nada em lado nenhum
                S("CA1", 5, "novo2.exemplo.pt", date(2028, 2, 1)),               # outra fonte tem os dados
                S("CA1", 6, "novo3.exemplo.pt", date(2028, 3, 1))],              # certwatch já o viu
        "AVI": [S("AVI", 2, "novo2.exemplo.pt", date(2028, 2, 1), serial="N2", issuer="DigiCert G2")],
    }
    known = lambda cn, day: {"issuer": "Corp CA03", "serial": "C3"} if (cn, day) == ("novo3.exemplo.pt", date(2028, 3, 1)) else {}
    res = cf.reconcile_final(t, sources, st, live, TODAY, known)
    by = {c["cn"]: c for c in res.changes}
    assert by["renovado.exemplo.pt"]["serial"] == "x" and by["renovado.exemplo.pt"]["pendente"] == ["SerialNumber"]
    assert "igual.exemplo.pt" not in by
    assert (by["novo1.exemplo.pt"]["issuer_name"], by["novo1.exemplo.pt"]["serial"]) == ("Por verificar", "x")
    assert by["novo1.exemplo.pt"]["pendente"] == ["IssuerName", "SerialNumber"]
    assert (by["novo2.exemplo.pt"]["issuer_name"], by["novo2.exemplo.pt"]["serial"], by["novo2.exemplo.pt"]["pendente"]) == \
        ("DigiCert G2", "N2", [])
    assert (by["novo3.exemplo.pt"]["issuer_name"], by["novo3.exemplo.pt"]["serial"]) == ("Corp CA03", "C3")
    # os CSV são gerados: "x"/"Por verificar" não bloqueiam nem contam como chave repetida
    xlsx, csv, csv_sem, problems, counts = cf.build_outputs(cf.unpack_state(cf.pack_state(res)), res.changes)
    assert not problems and csv and counts["por_verificar"] == 2 and counts["por_verificar_repetidos"] == 0
    rows = [ln for ln in csv.decode().splitlines() if "novo1.exemplo.pt" in ln]
    assert '"Por verificar"' in rows[0] and '"x"' in rows[0]


def test_known_lookup_from_certwatch(settings):
    from certwatch.models import Certificate, CtCert
    with session_scope() as s:
        s.add(Certificate(sha256="a" * 64, subject_cn="visto.exemplo.pt", issuer_cn="Corp CA01", serial_hex="0abc",
                          not_after=datetime(2028, 3, 1, 23, 30, tzinfo=timezone.utc), sans_dns=["alt.exemplo.pt"]))
        s.add(CtCert(names=["ct.exemplo.pt"], primary_name="ct.exemplo.pt", issuer_cn="R11", serial_hex="dd",
                     not_after=datetime(2028, 4, 1, 12, 0, tzinfo=timezone.utc)))
    with session_scope() as s:
        look = cf.make_known_lookup(s, settings)
        assert look("visto.exemplo.pt", date(2028, 3, 2)) == {"issuer": "Corp CA01", "serial": "0ABC"}   # 23:30 UTC = dia 2 em Lisboa? ±1 dia
        assert look("alt.exemplo.pt", date(2028, 3, 1))["serial"] == "0ABC"
        assert look("ct.exemplo.pt", date(2028, 4, 1)) == {"issuer": "R11", "serial": "DD"}
        assert look("visto.exemplo.pt", date(2028, 6, 1)) == {}
        assert look("outro.exemplo.pt", date(2028, 3, 1)) == {}


def test_run_page_shows_pending(settings, monkeypatch):
    from fastapi.testclient import TestClient
    from certwatch.web import app as webapp
    st = replace(settings, import_issuers={"CA1": "Corp CA01"}, final_ct=False)
    monkeypatch.setattr(webapp, "get_settings", lambda: st)
    (st.import_dir / "ca1.csv").write_bytes(CA1)
    (st.import_dir / "ca2.xlsx").write_bytes(ca2_xlsx())
    (st.import_dir / "avi.csv").write_bytes(AVI)
    with session_scope() as s:
        run_id = cf.start_run(s, "admin").id
    cf.generate(run_id, st, fetch=_fetch, live_factory=lambda s, x: live, today=TODAY)
    with TestClient(webapp.app) as c:
        page = c.get(f"/cmdb-final/{run_id}", auth=("admin", "teste-admin-123")).text
        assert "com dados por confirmar" in page and "Os CSV não foram gerados" not in page
        only = c.get(f"/cmdb-final/{run_id}?vista=alteracoes&pendente=1", auth=("admin", "teste-admin-123")).text
        assert "novo-ca2.exemplo.pt" in only and "novo-avi.exemplo.pt" not in only

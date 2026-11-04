"""Histórico da CMDB: alterações detetadas entre leituras, quem as fez (se a CMDB disser) e se foi o Atalaia."""
from dataclasses import replace

from fastapi.testclient import TestClient
from sqlalchemy import select

from certwatch.db import session_scope, utcnow
from certwatch.jobs import ingest_cmdb
from certwatch.models import CmdbChange, UcmdbWrite

AUTH = ("admin", "teste-admin-123")


def rec(uid, cn, valid_to, issuer="Corp CA01", who="", **props):
    return {"ucmdb_id": uid, "global_id": uid, "common_name": cn, "valid_to": valid_to, "issuer": issuer, "issuer_name": "",
            "props": {"common_name": cn, "valid_to": valid_to, "issuer": issuer, "last_access_time": utcnow().isoformat(),
                      "last_modified_time": "1767225600000", **({"root_updatedby": who} if who else {}), **props}}


def test_changes_detected_between_reads(env):
    st = replace(env, ucmdb_min_cis=1)
    base = [rec("1", "a.exemplo.pt", "2027-01-10T10:00:00Z", ambiente="PRD"), rec("2", "b.exemplo.pt", "2027-02-01T00:00:00Z"),
            rec("3", "c.exemplo.pt", "2027-03-01T00:00:00Z")]
    with session_scope() as s:
        out = ingest_cmdb(s, st, base)
    assert out["historico"]["alteracoes"] == 0                    # a primeira leitura é o ponto de partida
    # alguém muda à mão a data e o ambiente de 1; o Atalaia atualiza 2; 3 é apagado; 4 é criado; muda a TQL (atributo novo)
    with session_scope() as s:
        s.add(UcmdbWrite(acao="atualizar", cn="b.exemplo.pt", ucmdb_id="2", estado="ok", enviado={"valid_to": "x"},
                         por="ana@exemplo.pt", feito_em=utcnow()))
    second = [rec("1", "a.exemplo.pt", "2028-01-10T10:00:00Z", who="joao.silva", ambiente="QUA", novo_campo="x"),
              rec("2", "b.exemplo.pt", "2028-02-01T00:00:00Z"), rec("4", "d.exemplo.pt", "2028-04-01T00:00:00Z")]
    with session_scope() as s:
        out = ingest_cmdb(s, st, second)
    assert out["historico"] == {"alteracoes": 5, "fora_do_atalaia": 4}
    with session_scope() as s:
        ch = [(c.cn, c.kind, c.attribute, c.old, c.new, c.changed_by, c.by_atalaia) for c in s.scalars(select(CmdbChange))]
    assert ("a.exemplo.pt", "alterado", "valid_to", "2027-01-10T10:00:00Z", "2028-01-10T10:00:00Z", "joao.silva", False) in ch
    assert ("a.exemplo.pt", "alterado", "ambiente", "PRD", "QUA", "joao.silva", False) in ch
    assert ("b.exemplo.pt", "alterado", "valid_to", "2027-02-01T00:00:00Z", "2028-02-01T00:00:00Z", "Atalaia (ana@exemplo.pt)", True) in ch
    assert any(c[:2] == ("c.exemplo.pt", "removido") for c in ch) and any(c[:2] == ("d.exemplo.pt", "criado") for c in ch)
    assert not any(c[2] in ("novo_campo", "last_access_time") for c in ch)       # layout e atributos técnicos não contam
    with session_scope() as s:                                                    # a mesma leitura outra vez: nada de novo
        assert ingest_cmdb(s, st, second)["historico"]["alteracoes"] == 0
    from certwatch.web import app as webapp
    with TestClient(webapp.app) as c:
        page = c.get("/cmdb/historico/fora?origem=fora", auth=AUTH).text
        assert "Todas as alterações detetadas" in page and "joao.silva" in page and "Atalaia (ana" not in page
        assert "A CMDB indica quem" in page
        csv = c.get("/cmdb/historico/fora.csv", auth=AUTH).content.decode("utf-8-sig")
        assert csv.splitlines()[0].startswith("Detetado;Certificado") and "ambiente" in csv
        assert "Feitas pelo Atalaia" in c.get("/cmdb/historico", auth=AUTH).text

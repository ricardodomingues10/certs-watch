"""Certificado criado na UCMDB pelo certwatch tem de ficar visível: na leitura da CMDB (o TQL dos ativos) e nos alertas."""
import json
from datetime import timedelta

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import select

from certwatch import jobs
from certwatch import ucmdb_write as uw
from certwatch.config import get_settings
from certwatch.db import session_scope, utcnow
from certwatch.models import CmdbRecord, UcmdbWrite

AUTH = ("admin", "teste-admin-123")
NOW = utcnow()


def ci(uid, cn, status="Ativo", gerido="Sim"):
    return {"ucmdbId": uid, "type": "digital_certificate",
            "properties": {"common_name": cn, "certificate_status": status, "certificado_gerido": gerido,
                           "valid_to": int((NOW + timedelta(days=200)).timestamp() * 1000), "display_label": cn}}


class FakeTql:
    """UCMDB cujo TQL dos ativos só devolve certificados com certificado_gerido = Sim."""
    def __init__(self, cis):
        self.cis = {c["ucmdbId"]: c for c in cis}

    def handler(self, request):
        p = request.url.path
        if p.endswith("/authenticate"):
            return httpx.Response(200, json={"token": "t"})
        if p.endswith("/topology"):
            return httpx.Response(200, json={"cis": [c for c in self.cis.values()
                                                     if c["properties"]["certificado_gerido"] == "Sim"], "relations": []})
        if "/dataModel/ci/" in p:
            c = self.cis.get(p.rsplit("/", 1)[1])
            return httpx.Response(200, json=c) if c else httpx.Response(404)
        return httpx.Response(404)

    def client(self):
        return httpx.Client(base_url="https://cmdb.test/rest-api", transport=httpx.MockTransport(self.handler))


def test_created_but_filtered_by_tql_is_flagged(env):
    st = get_settings()
    fake = FakeTql([ci("c1", "a.exemplo.pt"), ci("c2", "b.exemplo.pt"), ci("c3", "c.exemplo.pt"),
                    ci("novo1", "internet.exemplo.pt", gerido="")])      # criado pelo certwatch sem "Certificado Gerido"
    with session_scope() as s:
        for uid, cn in (("novo1", "internet.exemplo.pt"), ("c9", "visivel.exemplo.pt")):
            s.add(UcmdbWrite(run_id=1, chave=1 if uid == "novo1" else 2, parte="cert", lista="certificados", lote="L",
                             acao="criar", cn=cn, ucmdb_id=uid, estado="ok", detalhe="Criado.", por="admin"))
        s.flush()
        ids = [w.id for w in s.scalars(select(UcmdbWrite))]
    fake.cis["c9"] = ci("c9", "visivel.exemplo.pt")
    from certwatch.fontes.ucmdb import UcmdbSession
    with UcmdbSession(st, fake.client()) as us:
        uw.check_created_in_tql(us, st, ids)
    with session_scope() as s:
        w = {x.ucmdb_id: x for x in s.scalars(select(UcmdbWrite))}
        assert w["novo1"].estado == "aviso" and uw.NOT_IN_TQL in w["novo1"].detalhe
        assert w["c9"].estado == "ok"
    # o "Porquê?" encontra o atributo em que o novo difere de todos os do TQL
    rep = uw.why_not_in_tql(st, "novo1", fake.client())
    assert not rep["no_tql"] and [d["atributo"] for d in rep["diferencas"]] == ["certificado_gerido"]
    assert rep["diferencas"][0]["este"] == "(vazio)" and rep["diferencas"][0]["outros"].startswith("Sim")
    # a importação da CMDB diz quais foram criados mas ficaram fora do TQL
    with session_scope() as s:
        s.add(CmdbRecord(ucmdb_id="c9", global_id="g9", common_name="visivel.exemplo.pt", cn_norm="visivel.exemplo.pt",
                         kind="host", active=True))
    with session_scope() as s:
        assert jobs.created_not_in_cmdb(s) == ["internet.exemplo.pt (novo1)"]


def test_cmdb_import_reevaluates_and_history_offers_why(env, monkeypatch):
    calls = []
    monkeypatch.setattr(jobs, "fetch_certificates", lambda settings, client=None: [
        {"ucmdb_id": f"r{i}", "global_id": f"g{i}", "common_name": f"s{i}.exemplo.pt",
         "valid_to": (NOW + timedelta(days=100)).isoformat(), "issuer": "X", "issuer_name": "X"} for i in range(4)])
    real = jobs.evaluate
    monkeypatch.setattr(jobs, "evaluate", lambda s, st: calls.append(1) or real(s, st))
    out = jobs._run("ingest_cmdb", get_settings())
    assert out["ingest_cmdb"]["novos"] == 4 and "evaluate" in out and calls       # os alertas refletem logo a CMDB
    with session_scope() as s:
        s.add(UcmdbWrite(run_id=1, chave=1, parte="cert", lista="certificados", lote="L", acao="criar",
                         cn="internet.exemplo.pt", ucmdb_id="novo1", estado="ok", detalhe="Criado.", por="admin"))
    from certwatch.web import app as webapp
    fake = FakeTql([ci("c1", "a.exemplo.pt"), ci("c2", "b.exemplo.pt"), ci("novo1", "internet.exemplo.pt", gerido="")])
    monkeypatch.setattr(webapp, "UCMDB_CLIENT", fake.client())
    with TestClient(webapp.app) as c:
        page = c.get("/cmdb/historico", auth=AUTH).text
        assert "fora da leitura da CMDB" in page and "/cmdb/historico/porque/novo1" in page
        why = c.get("/cmdb/historico/porque/novo1", auth=AUTH).text
        assert "certificado_gerido" in why and "Editar um certificado" in why
        assert c.get("/cmdb/historico/porque/..%2Fx", auth=AUTH).status_code == 404

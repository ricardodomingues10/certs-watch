import json

import httpx
import pytest
from sqlalchemy import select

from certwatch.fontes.ucmdb import UcmdbError, fetch_certificates
from certwatch.db import session_scope
from certwatch.jobs import IngestAborted, ingest_cmdb
from certwatch.models import CmdbRecord, Endpoint


def ci(uid, cn, valid_to, issuer="Exemplo Issuing CA01", issuer_name=None, serial="lixo"):
    # Formato real observado na REST API (inclui campos não confiáveis que devem ser ignorados)
    return {"ucmdbId": uid, "globalId": uid, "type": "digital_certificate", "displayLabel": cn,
            "properties": {"common_name": cn, "valid_to": valid_to, "issuer": issuer,
                           "issuer_name": issuer_name or issuer, "serial_number": serial,
                           "custom_responsavel_instalacao": "???", "global_id": uid}}


def transport(cis, auth_status=200, seen=None):
    def handler(request: httpx.Request):
        if request.url.path.endswith("/authenticate"):
            body = json.loads(request.content)
            if seen is not None:
                seen["auth"] = body
            if auth_status != 200:
                return httpx.Response(auth_status, json={"error": "x"})
            return httpx.Response(200, json={"token": "tok123", "isProviderToken": False})
        if request.url.path.endswith("/topology"):
            if seen is not None:
                seen["tql"] = request.content.decode()
                seen["authz"] = request.headers.get("authorization")
            return httpx.Response(200, json={"cis": cis, "relations": []})
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def test_fetch_extracts_only_trusted_fields(env):
    seen = {}
    client = httpx.Client(base_url="https://cmdb.test/rest-api", transport=transport(
        [ci("a1", "Portal.exemplo.pt", "2027-01-10T10:00:00.000Z")], seen=seen))
    out = fetch_certificates(env, client)
    assert seen["auth"] == {"username": "u", "password": "p", "clientContext": 1}
    assert seen["tql"] == "Certificados_Exemplo"
    assert seen["authz"] == "Bearer tok123"
    assert out == [{"ucmdb_id": "a1", "global_id": "a1", "common_name": "Portal.exemplo.pt",
                    "valid_to": "2027-01-10T10:00:00.000Z", "issuer": "Exemplo Issuing CA01",
                    "issuer_name": "Exemplo Issuing CA01"}]
    assert "serial_number" not in out[0]


def test_fetch_auth_failure(env):
    client = httpx.Client(base_url="https://cmdb.test/rest-api", transport=transport([], auth_status=401))
    with pytest.raises(UcmdbError, match="HTTP 401"):
        fetch_certificates(env, client)


def _records(n_extra=0):
    base = [
        {"ucmdb_id": "1", "global_id": "1", "common_name": "Portal.exemplo.pt", "valid_to": "2027-01-10T10:00:00Z",
         "issuer": "Exemplo Issuing CA01", "issuer_name": ""},
        {"ucmdb_id": "2", "global_id": "2", "common_name": "*.exemplo.pt", "valid_to": "2026-12-01T00:00:00Z",
         "issuer": "DigiCert", "issuer_name": "DigiCert Global G2"},
        {"ucmdb_id": "3", "global_id": "3", "common_name": "Exemplo Root CA", "valid_to": "2037-12-12T14:50:30Z",
         "issuer": "Exemplo Root CA", "issuer_name": ""},
        {"ucmdb_id": "4", "global_id": "4", "common_name": "", "valid_to": None, "issuer": "", "issuer_name": ""},
    ]
    return base + [
        {"ucmdb_id": f"x{i}", "global_id": None, "common_name": f"h{i}.exemplo.local",
         "valid_to": "2027-05-01T00:00:00Z", "issuer": "Exemplo Issuing CA02", "issuer_name": ""}
        for i in range(n_extra)
    ]


def test_ingest_and_guard(env):
    with session_scope() as s:
        summary = ingest_cmdb(s, env, _records(1))
    assert summary["novos"] == 4 and summary["sem_common_name"] == 1
    with session_scope() as s:
        recs = {r.ucmdb_id: r for r in s.scalars(select(CmdbRecord))}
        assert recs["1"].cn_norm == "portal.exemplo.pt" and recs["1"].kind == "host"
        assert recs["2"].kind == "wildcard" and recs["2"].issuer_norm == "digicert global g2"
        assert recs["3"].kind == "other"
        eps = {e.host for e in s.scalars(select(Endpoint))}
    assert eps == {"portal.exemplo.pt", "h0.exemplo.local"}  # wildcard e "other" não geram alvos

    # Resposta truncada: abaixo do mínimo, nada é desativado
    with pytest.raises(IngestAborted):
        with session_scope() as s:
            ingest_cmdb(s, env, _records()[:2])
    with session_scope() as s:
        assert s.scalar(select(CmdbRecord).where(CmdbRecord.ucmdb_id == "x0")).active

    # Registo que desaparece da CMDB fica inativo e o endpoint é desativado
    with session_scope() as s:
        summary = ingest_cmdb(s, env, _records(0))
    assert summary["desativados"] == 1 and summary["endpoints_desativados"] == 1

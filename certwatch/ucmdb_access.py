"""O que a conta da UCMDB usada pelo certwatch pode fazer pela REST API.

Leitura (nunca muda nada):
1. POST /rest-api/authenticate — a conta entra e tem acesso à API ("Access to SDK").
2. POST /rest-api/topology — executa cada TQL configurado (as "listas" de certificados e de APIs).
3. GET  /rest-api/dataModel/ci/{id} — lê um CI completo.

Escrita (só quando pedido e confirmado na página):
4. PUT  /rest-api/dataModel/ci/{id} com um atributo igual ao valor que já tem. A UCMDB verifica a permissão de
   atualização ("modifying the data inside UCMDB through the SDK") mas o valor não muda. Não cria nem apaga nada.

Criar CIs (POST /rest-api/dataModel) e apagar (DELETE /rest-api/dataModel/ci/{id}) não são testados aqui: o
único teste definitivo seria criar ou apagar um CI de verdade.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from .collectors.ucmdb import UcmdbError, UcmdbSession
from .config import Settings

DENIED = ("permission", "permiss", "authoriz", "not allowed", "denied", "forbidden", "access")
# Atributo reenviado com o mesmo valor no teste de escrita (o primeiro que o CI tiver preenchido)
WRITE_PROPS = ("description", "display_label", "name")


@dataclass
class Step:
    what: str
    call: str
    ok: bool | None            # True = pode; False = não pode; None = inconclusivo / não testado
    detail: str = ""


@dataclass
class Report:
    steps: list[Step] = field(default_factory=list)
    sample_ci: str = ""

    def verdict(self, key: str) -> bool | None:
        for s in self.steps:
            if s.call.startswith(key):
                return s.ok
        return None


def _error_text(r: httpx.Response) -> str:
    try:
        data = r.json()
        msg = (data or {}).get("error") or (data or {}).get("message") or ""
    except ValueError:
        msg = r.text
    return str(msg).strip().replace("\n", " ")[:300]


def check(settings: Settings, write_ci: str | None = None, client: httpx.Client | None = None) -> Report:
    rep = Report()
    try:
        session = UcmdbSession(settings, client)
    except UcmdbError as exc:
        rep.steps.append(Step("Entrar na UCMDB", "POST /authenticate", False, str(exc)))
        return rep
    try:
        with session as s:
            rep.steps.append(Step("Entrar na UCMDB com a conta configurada", "POST /authenticate", True,
                                  "A conta entra e tem acesso à REST API."))
            sample = ""
            for label, tql in (("certificados", settings.ucmdb_tql), ("APIs", settings.ucmdb_tql_apis)):
                if not tql:
                    continue
                try:
                    cis = s.topology(tql)
                    rep.steps.append(Step(f"Ler a lista de {label} (TQL {tql})", f"POST /topology ({tql})", True,
                                          f"{len(cis)} CI(s) devolvido(s)."))
                    sample = sample or next((c.get("ucmdbId") for c in cis if c.get("ucmdbId")), "")
                except UcmdbError as exc:
                    rep.steps.append(Step(f"Ler a lista de {label} (TQL {tql})", f"POST /topology ({tql})", False, str(exc)))
            if sample:
                try:
                    ci = s.ci(sample)
                    rep.sample_ci = sample
                    rep.steps.append(Step("Ler um CI completo", "GET /dataModel/ci/{id}", True,
                                          f"CI {sample} ({ci.get('type', '?')}), {len(ci.get('properties') or {})} atributos."))
                except UcmdbError as exc:
                    rep.steps.append(Step("Ler um CI completo", "GET /dataModel/ci/{id}", False, str(exc)))
            if write_ci:
                rep.steps.append(_write_test(s, write_ci))
    except UcmdbError as exc:
        rep.steps.append(Step("Entrar na UCMDB com a conta configurada", "POST /authenticate", False, str(exc)))
    return rep


def _write_test(s: UcmdbSession, ucmdb_id: str) -> Step:
    what = "Atualizar um CI (reenviar um atributo com o valor que já tem)"
    call = "PUT /dataModel/ci/{id}"
    try:
        ci = s.ci(ucmdb_id)
    except UcmdbError as exc:
        return Step(what, call, None, f"Não foi possível ler o CI {ucmdb_id} antes do teste: {exc}")
    props = ci.get("properties") or {}
    prop = next((p for p in WRITE_PROPS if isinstance(props.get(p), str) and props.get(p).strip()), None)
    if not prop or not ci.get("type"):
        return Step(what, call, None, f"O CI {ucmdb_id} não tem {', '.join(WRITE_PROPS)} preenchido: escolha outro.")
    body = {"ucmdbId": ci.get("ucmdbId") or ucmdb_id, "type": ci["type"], "properties": {prop: props[prop]}}
    try:
        r = s.client.request("PUT", f"/dataModel/ci/{ucmdb_id}", headers=s.headers, json=body)
    except httpx.HTTPError as exc:
        return Step(what, call, None, f"Erro de comunicação: {exc}")
    where = f"CI {ucmdb_id}, atributo {prop} reenviado com o mesmo valor"
    if r.status_code == 200:
        try:
            data = r.json() or {}
        except ValueError:
            data = {}
        lists = {k: len(data.get(k) or []) for k in ("addedCis", "updatedCis", "ignoredCis", "removedCis")}
        return Step(what, call, True, f"Aceite (HTTP 200; {where}). Resposta: " +
                    ", ".join(f"{k}={v}" for k, v in lists.items()) + ".")
    msg = _error_text(r)
    if r.status_code in (401, 403) or any(w in msg.lower() for w in DENIED):
        return Step(what, call, False, f"Recusado (HTTP {r.status_code}; {where}): {msg or 'sem mensagem'}")
    return Step(what, call, None, f"Resposta inesperada (HTTP {r.status_code}; {where}): {msg or 'sem mensagem'}")

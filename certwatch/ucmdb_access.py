"""O que a conta da UCMDB usada pelo certwatch pode fazer pela REST API.

Leitura (nunca muda nada):
1. POST /rest-api/authenticate — a conta entra e tem acesso à API ("Access to SDK").
2. POST /rest-api/topology — executa cada TQL configurado (as "listas" de certificados e de APIs).
3. GET  /rest-api/dataModel/ci/{id} — lê um CI completo.

Escrita (só quando pedido e confirmado na página):
4. PUT  /rest-api/dataModel/ci/{id} com um atributo igual ao valor que já tem. A UCMDB verifica a permissão de
   atualização ("modifying the data inside UCMDB through the SDK") mas o valor não muda. Não cria nem apaga nada.

Criação (só quando pedido e confirmado, em dois passos):
5. Descobrir o atributo que diz se o certificado está ativo: os atributos do tipo de CI com "status/estado/ativo"
   no nome, ou com o valor "Ativo" num certificado da lista, e os valores que têm em todos os certificados.
6. POST /rest-api/dataModel com um certificado de teste com esse atributo num valor NÃO ativo, nome
   certwatch-teste-<código>.invalid, série e emissor de teste únicos e a Description a dizer que é um teste.
7. GET do CI criado, confirmação de que não aparece no TQL dos ativos e DELETE (só se foi mesmo criado agora:
   está em addedCis e a Description é a do teste).
"""
from __future__ import annotations

import re
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

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


# ------------------------------------------------------------------ teste de criação
STATUS_RX = re.compile(r"status|estado|state|ativo|activ", re.I)
ACTIVE_VALUES = {"ativo", "active", "activo", "true", "1", "sim", "yes"}
MAX_VALUES = 30
TEST_PREFIX = "certwatch-teste-"
TEST_MARK = "Teste de criação do certwatch"


@dataclass
class StatusInfo:
    ci_type: str = ""
    sample: str = ""
    attrs: list[str] = field(default_factory=list)
    candidates: list[dict] = field(default_factory=list)     # {"attr", "na_lista", "valores": [(valor, n)]}
    error: str = ""


def status_candidates(settings: Settings, client: httpx.Client | None = None) -> StatusInfo:
    """Atributos que podem dizer se um certificado está ativo, com o valor nos certificados da lista e a contagem
    de cada valor em todos os certificados da UCMDB (leitura apenas)."""
    info = StatusInfo()
    try:
        with UcmdbSession(settings, client) as s:
            cis = s.topology(settings.ucmdb_tql)
            info.sample = next((c.get("ucmdbId") for c in cis if c.get("ucmdbId")), "")
            if not info.sample:
                info.error = f"O TQL {settings.ucmdb_tql} não devolveu certificados."
                return info
            ci = s.ci(info.sample)
            info.ci_type = ci.get("type") or ""
            props = ci.get("properties") or {}
            info.attrs = sorted(props)
            cands = [k for k, v in props.items()
                     if STATUS_RX.search(k) or (isinstance(v, str) and v.strip().lower() in ACTIVE_VALUES - {"1", "true"})]
            if not cands:
                info.error = "Não encontrei no certificado nenhum atributo de estado (status/estado/ativo)."
                return info
            everything = s.topology_query(info.ci_type, cands)
            for k in cands:
                cnt = Counter("" if (c.get("properties") or {}).get(k) is None else str((c.get("properties") or {}).get(k))
                              for c in everything)
                info.candidates.append({"attr": k, "na_lista": "" if props.get(k) is None else str(props.get(k)),
                                        "valores": cnt.most_common(MAX_VALUES)})
    except UcmdbError as exc:
        info.error = str(exc)
    return info


@dataclass
class CreateResult:
    steps: list[Step] = field(default_factory=list)
    created_id: str = ""
    name: str = ""
    left_behind: bool = False          # criado e não apagado


def _post(s: UcmdbSession, path: str, body: dict) -> httpx.Response:
    return s.client.request("POST", path, headers=s.headers, json=body)


def create_test(settings: Settings, ci_type: str, attr: str, value: str, actor: str, delete: bool = True,
                client: httpx.Client | None = None) -> CreateResult:
    res = CreateResult()
    code = uuid.uuid4().hex[:8]
    cn = f"{TEST_PREFIX}{code}.invalid"
    res.name = cn
    marker = f"{TEST_MARK} ({code}), pedido por {actor} em " \
             f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC. Pode ser apagado."
    try:
        with UcmdbSession(settings, client) as s:
            sample = next((c.get("ucmdbId") for c in s.topology(settings.ucmdb_tql) if c.get("ucmdbId")), "")
            sample_props = (s.ci(sample).get("properties") or {}) if sample else {}
            if attr not in sample_props:
                res.steps.append(Step("Preparar o certificado de teste", "GET /dataModel/ci/{id}", None,
                                      f"O atributo {attr} não existe nos certificados: prepare de novo."))
                return res
            if str(sample_props.get(attr)) == value:
                res.steps.append(Step("Preparar o certificado de teste", "", None,
                                      f"{attr} = {value} é o valor dos certificados da lista dos ativos: escolha outro."))
                return res
            props = {"display_label": cn, "name": cn, "description": marker, attr: value}
            for k, v in (("common_name", cn), ("issuer", "certwatch teste"), ("issuer_name", "certwatch teste"),
                         ("serial_number", f"CERTWATCH-TESTE-{code.upper()}")):
                if k in sample_props:
                    props[k] = v
            body = {"cis": [{"ucmdbId": "1", "type": ci_type, "properties": props}], "relations": []}
            what = f"Criar um certificado de teste ({cn}, {attr} = {value})"
            try:
                r = _post(s, "/dataModel", body)
            except httpx.HTTPError as exc:
                res.steps.append(Step(what, "POST /dataModel", None, f"Erro de comunicação: {exc}"))
                return res
            if r.status_code != 200:
                msg = _error_text(r)
                denied = r.status_code in (401, 403) or any(w in msg.lower() for w in DENIED)
                res.steps.append(Step(what, "POST /dataModel", False if denied else None,
                                      f"{'Recusado' if denied else 'Resposta inesperada'} (HTTP {r.status_code}): {msg or 'sem mensagem'}"))
                return res
            data = r.json() or {}
            added, updated = list(data.get("addedCis") or []), list(data.get("updatedCis") or [])
            if len(added) != 1:
                res.steps.append(Step(what, "POST /dataModel", None,
                                      f"HTTP 200 mas sem CI criado (addedCis={added}, updatedCis={updated}, "
                                      f"ignoredCis={data.get('ignoredCis') or []}). Nada foi apagado."))
                return res
            res.created_id = added[0]
            res.left_behind = True
            res.steps.append(Step(what, "POST /dataModel", True, f"Criado: CI {res.created_id}."))
            # confirmar que é o nosso
            try:
                got = s.ci(res.created_id)
                ours = (got.get("properties") or {}).get("description") == marker
                res.steps.append(Step("Ler o certificado criado", "GET /dataModel/ci/{id}", ours,
                                      f"{got.get('type')} com {attr} = {(got.get('properties') or {}).get(attr)}."
                                      if ours else "A Description lida não é a do teste: não será apagado."))
            except UcmdbError as exc:
                ours = False
                res.steps.append(Step("Ler o certificado criado", "GET /dataModel/ci/{id}", None, str(exc)))
            # não deve aparecer na lista dos ativos
            try:
                in_list = any(c.get("ucmdbId") == res.created_id for c in s.topology(settings.ucmdb_tql))
                res.steps.append(Step(f"Confirmar que não entra na lista ({settings.ucmdb_tql})", "POST /topology",
                                      not in_list, "Não aparece na lista." if not in_list else
                                      f"Aparece na lista: {attr} = {value} não o deixa de fora."))
            except UcmdbError as exc:
                res.steps.append(Step(f"Confirmar que não entra na lista ({settings.ucmdb_tql})", "POST /topology", None, str(exc)))
            if delete and ours:
                try:
                    d = s.client.request("DELETE", f"/dataModel/ci/{res.created_id}", headers=s.headers)
                except httpx.HTTPError as exc:
                    res.steps.append(Step("Apagar o certificado de teste", "DELETE /dataModel/ci/{id}", None, f"Erro de comunicação: {exc}"))
                    return res
                if d.status_code == 200:
                    res.left_behind = False
                    res.steps.append(Step("Apagar o certificado de teste", "DELETE /dataModel/ci/{id}", True, "Apagado."))
                else:
                    msg = _error_text(d)
                    denied = d.status_code in (401, 403) or any(w in msg.lower() for w in DENIED)
                    res.steps.append(Step("Apagar o certificado de teste", "DELETE /dataModel/ci/{id}", False if denied else None,
                                          f"HTTP {d.status_code}: {msg or 'sem mensagem'}"))
    except UcmdbError as exc:
        res.steps.append(Step("Entrar na UCMDB com a conta configurada", "POST /authenticate", False, str(exc)))
    return res


def delete_test(settings: Settings, ci_id: str, client: httpx.Client | None = None) -> Step:
    """Apaga um certificado de teste criado pelo certwatch — e só esse: o nome tem de ser certwatch-teste-….invalid
    e a Description a do teste."""
    what, call = f"Apagar o certificado de teste {ci_id}", "DELETE /dataModel/ci/{id}"
    if not re.fullmatch(r"[0-9a-fA-F]{8,64}", ci_id or ""):
        return Step(what, call, None, "ID do CI inválido.")
    try:
        with UcmdbSession(settings, client) as s:
            try:
                props = s.ci(ci_id).get("properties") or {}
            except UcmdbError as exc:
                return Step(what, call, None, f"Não foi possível ler o CI (já foi apagado?): {exc}")
            name = str(props.get("display_label") or props.get("name") or "")
            if not (name.startswith(TEST_PREFIX) and name.endswith(".invalid")
                    and str(props.get("description") or "").startswith(TEST_MARK)):
                return Step(what, call, False, f"O CI {ci_id} ({name or 'sem nome'}) não é um certificado de teste do "
                                               "certwatch: não foi apagado.")
            try:
                d = s.client.request("DELETE", f"/dataModel/ci/{ci_id}", headers=s.headers)
            except httpx.HTTPError as exc:
                return Step(what, call, None, f"Erro de comunicação: {exc}")
            if d.status_code == 200:
                return Step(what, call, True, f"{name} apagado.")
            return Step(what, call, False, f"HTTP {d.status_code}: {_error_text(d) or 'sem mensagem'}")
    except UcmdbError as exc:
        return Step("Entrar na UCMDB com a conta configurada", "POST /authenticate", False, str(exc))

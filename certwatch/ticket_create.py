"""Criação de pedidos (changes) de renovação de certificados no SMAX.

Fluxo (cada passo é uma ação explícita do utilizador):
  1. seleção de certificados -> lote em "rascunho" com valores sugeridos;
  2. o utilizador preenche/corrige os campos que a CMDB não dá (ambiente, tipo, Application ID,
     responsabilidade de instalação, localização) e vê os avisos (pedido já em curso, renovação automática);
  3. revisão: payload exato de cada pedido;
  4. confirmação -> o lote passa a "a_criar" de forma atómica (um duplo clique não cria nada duas vezes),
     os pedidos do SMAX são relidos para apanhar duplicados criados entretanto, e os pedidos são criados
     um a um; a primeira falha interrompe o lote. Um resultado "indeterminado" (erro 5xx, sem resposta)
     nunca é repetido automaticamente: tem de ser verificado no SMAX.

O payload segue o workflow n8n de abertura de pedidos (POST /rest/{tenant}/ems/bulk, operation CREATE).
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
from datetime import timedelta
from html import escape
from zoneinfo import ZoneInfo

import httpx
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .classify import is_auto_renew
from .fontes import smax
from .config import Settings
from .db import as_utc, session_scope, utcnow
from .models import AuditLog, SmaxTicket, TicketBatch, TicketDraft

log = logging.getLogger(__name__)

BATCH_STATES = {"rascunho": "Rascunho", "a_criar": "A criar", "concluido": "Concluído",
                "interrompido": "Interrompido", "cancelado": "Cancelado"}
DRAFT_STATES = {"pendente": "Por criar", "a_enviar": "A enviar", "criado": "Criado", "falhou": "Falhou",
                "indeterminado": "Indeterminado", "nao_tentado": "Não tentado", "excluido": "Excluído"}
DRAFT_HELP = {
    "indeterminado": "O SMAX não confirmou nem recusou (erro do servidor, tempo esgotado ou resposta inesperada). "
                     "O pedido pode ter sido criado: verifique no SMAX antes de repetir.",
    "nao_tentado": "Não foi enviado porque o lote parou num pedido anterior.",
    "excluido": "Não foi enviado (ver motivo).",
}
FIELDS = ("ambiente", "tipo", "app_id", "responsavel", "localizacao")
FIELD_LABELS = {"ambiente": "Ambiente", "tipo": "Tipo de certificado", "app_id": "Application ID",
                "responsavel": "Responsabilidade de instalação", "localizacao": "Localização"}
STALE_AFTER = timedelta(minutes=15)
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_LISBON = ZoneInfo("Europe/Lisbon")


class TicketError(RuntimeError):
    pass


# ------------------------------------------------------------------ configuração
def _conn(settings: Settings):
    from .conectores import ticket_connector

    return ticket_connector(settings)


def config_problems(settings: Settings) -> list[str]:
    """O que falta configurar para poder criar pedidos (vazio = pronto)."""
    conn = _conn(settings)
    if conn.kind != "smax":   # Jira, ServiceNow, GLPI: a ligação é configurada em Sistema → Ligações
        out = []
        if not conn.can("criar"):
            out.append(f"O sistema ligado ({conn.label}) não permite criar pedidos a partir do Atalaia.")
        elif not conn.configured():
            out.append(f"A ligação ao {conn.label} não está completa (Sistema → Ligações).")
        elif conn.p("criar_pedidos", "nao") != "sim":
            out.append(f"A criação de pedidos no {conn.label} está desligada (Sistema → Ligações → Permitir criar pedidos).")
        return out
    out = []
    if not settings.smax_create_enabled:
        out.append("A criação de pedidos está desligada (CERTWATCH_SMAX_CREATE_ENABLED=true para ligar).")
    if not smax.configured(settings):
        out.append("A ligação ao SMAX não está configurada (URL, tenant e segredos smax_user/smax_password).")
    if not re.fullmatch(r"\d+", settings.smax_change_model or ""):
        out.append("Falta o modelo de change (CERTWATCH_SMAX_CHANGE_MODEL, número).")
    if not re.fullmatch(r"\d+", settings.smax_service or ""):
        out.append("Falta o serviço afetado (CERTWATCH_SMAX_SERVICE, número).")
    if not settings.smax_env_codes:
        out.append("Falta a lista de ambientes (CERTWATCH_SMAX_ENV_CODES).")
    if not settings.smax_type_options:
        out.append("Falta a lista de tipos de certificado (CERTWATCH_SMAX_TYPE_OPTIONS).")
    return out


def can_create(settings: Settings) -> bool:
    return not config_problems(settings)


# ------------------------------------------------------------------ validação e payload
def _clean(v) -> str:
    return _CTRL.sub("", str(v or "")).strip()


def validate(d: TicketDraft, settings: Settings) -> dict[str, str]:
    """Erros por campo (vazio = pronto a criar)."""
    e: dict[str, str] = {}
    if not d.name or len(d.name) > 253:
        e["name"] = "Nome do certificado em falta."
    if d.expiry is None:
        e["expiry"] = "Sem data de expiração (nem do servidor nem da CMDB)."
    if _conn(settings).kind != "smax":
        return e   # os campos seguintes são os do modelo de change do SMAX
    if d.ambiente not in settings.smax_env_codes:
        e["ambiente"] = "Escolha o ambiente."
    if d.tipo not in settings.smax_type_options:
        e["tipo"] = "Escolha o tipo de certificado."
    if not re.fullmatch(r"[1-9]\d{0,17}", d.app_id or ""):
        e["app_id"] = "Application ID: número inteiro positivo."
    if not d.responsavel or len(d.responsavel) > 128:
        e["responsavel"] = "Indique a responsabilidade de instalação."
    if not d.localizacao or len(d.localizacao) > 256:
        e["localizacao"] = "Indique a localização (ou \"Não indicado\")."
    return e


def _ms(dt) -> int:
    return int(as_utc(dt).timestamp() * 1000)


def build_payload(d: TicketDraft, settings: Settings) -> dict:
    conn = _conn(settings)
    if conn.kind != "smax":
        return conn.preview(d)
    return _smax_payload(d, settings)


def _smax_payload(d: TicketDraft, settings: Settings) -> dict:
    """Payload do pedido, igual ao do workflow n8n (os valores vindos de fora são escapados no HTML)."""
    f = settings.smax_fields
    exp_ms = _ms(d.expiry)
    local = as_utc(d.expiry).astimezone(_LISBON)
    tipo = d.tipo if d.tipo.endswith("_c") else f"{d.tipo}_c"
    user_options = {"complexTypeProperties": [{"properties": {
        "changedUserOptionsForSimulation": f"{f['env']}&",
        f["type"]: tipo,
        f["endpoint"]: d.name,
        f["expiry"]: exp_ms,
        f["env"]: settings.smax_env_codes[d.ambiente],
    }}]}
    rows = [("Nome", d.name), ("Data de expiração", local.strftime("%d-%m-%Y %H:%M")),
            ("Issuer", d.issuer or "Não indicado"), ("Localização", d.localizacao)]
    if d.sites:
        rows.append(("Instalado em", ", ".join(d.sites)))
    description = ("<p>Solicitamos a renovação do certificado:</p>"
                   + "".join(f"<p>{escape(k)}: {escape(str(v))}</p>" for k, v in rows)
                   + (f"<p>{escape(settings.smax_description_sign)}</p>" if settings.smax_description_sign else ""))
    props = {
        "BasedOnChangeModel": settings.smax_change_model,
        "AffectsActualService": settings.smax_service,
        "AffectsServiceComponent": d.app_id,
        "UserOptions": json.dumps(user_options, ensure_ascii=False),
        "Description": description,
        "Justification": "<p>Renovação de certificado, devido a aproximação de data de expiração.</p>",
        "DisplayLabel": f"Renovacao certificado | {d.name} | {d.responsavel.replace(chr(39), '')} | | {local.strftime('%d/%m/%Y')}",
        "RequestedEndTime": exp_ms,
        "TimePeriodBreachDetails": json.dumps({
            "maintenanceWindowsContaining": [], "maintenanceWindowsPartiallyContaining": [], "blackoutsBreached": [],
            "isCoveredByMaintenanceWindows": False, "isScheduled": True, "hasService": True}),
        "DetectedEntities": json.dumps({"complexTypeProperties": []}),
    }
    if settings.smax_data_domains:
        props["DataDomains"] = list(settings.smax_data_domains)
    payload = {"entities": [{"entity_type": settings.smax_entity, "properties": props}], "operation": "CREATE"}
    json.dumps(payload, allow_nan=False)   # falha cedo se algo não for serializável
    return payload


# ------------------------------------------------------------------ lotes
def _suggest(session: Session, row: dict, settings: Settings) -> tuple[dict, dict]:
    """Valores sugeridos e a sua origem: último pedido criado aqui > último pedido do SMAX > configuração."""
    vals: dict[str, str] = {k: "" for k in FIELDS}
    src: dict[str, str] = {}
    prev = session.scalar(select(TicketDraft).where(TicketDraft.cn == row["cn"], TicketDraft.status == "criado")
                          .order_by(TicketDraft.id.desc()).limit(1))
    if prev is not None:
        for k in FIELDS:
            if getattr(prev, k):
                vals[k], src[k] = getattr(prev, k), f"pedido {prev.ticket_id} criado aqui"
    tickets = sorted(session.scalars(select(SmaxTicket).where(SmaxTicket.endpoint == row["cn"])),
                     key=lambda t: as_utc(t.last_update) or utcnow().replace(year=1970), reverse=True)
    for t in tickets:
        if not vals["ambiente"] and t.environment in settings.smax_env_codes:
            vals["ambiente"], src["ambiente"] = t.environment, f"pedido SMAX {t.id}"
        base = re.sub(r"_c$", "", t.cert_type or "", flags=re.I)
        match = next((o for o in settings.smax_type_options if o.lower() == base.lower()), None)
        if not vals["tipo"] and match:
            vals["tipo"], src["tipo"] = match, f"pedido SMAX {t.id}"
        if not vals["app_id"] and re.fullmatch(r"[1-9]\d*", t.service_component or ""):
            vals["app_id"], src["app_id"] = t.service_component, f"pedido SMAX {t.id}"
    if not vals["tipo"]:
        match = next((o for o in settings.smax_type_options if o.lower().startswith(row["scope"][:5])), None)
        if match and row["scope"] in ("interno", "externo"):
            vals["tipo"], src["tipo"] = match, "âmbito detetado"
    if not vals["app_id"] and settings.smax_default_app_id:
        vals["app_id"], src["app_id"] = settings.smax_default_app_id, "valor por omissão"
    if not vals["responsavel"] and settings.smax_default_responsible:
        vals["responsavel"], src["responsavel"] = settings.smax_default_responsible, "valor por omissão"
    return vals, src


def create_batch(session: Session, cns: list[str], actor: str, settings: Settings) -> TicketBatch:
    from .insights import build_inventory
    cns = list(dict.fromkeys(c for c in cns if c))
    if not cns:
        raise TicketError("Nenhum certificado selecionado.")
    if len(cns) > settings.smax_create_max:
        raise TicketError(f"Selecionou {len(cns)} certificados; o máximo por lote é {settings.smax_create_max}. "
                          "Filtre mais a lista ou divida em vários lotes.")
    inv = {r["cn"]: r for r in build_inventory(session, settings, utcnow())}
    missing = [c for c in cns if c not in inv]
    if missing:
        raise TicketError(f"Certificados desconhecidos: {', '.join(missing[:5])}")
    batch = TicketBatch(created_by=actor, status="rascunho")
    session.add(batch)
    session.flush()
    # Cada nome selecionado aponta para o certificado que é realmente servido (um wildcard ou um certificado
    # com vários nomes pode estar em muitos sites): um pedido por certificado, com todos os sites.
    targets: dict[str, dict] = {}
    for cn in cns:
        r = inv[cn]
        sp = r["servido_por"]
        if sp:
            tr = inv.get(sp["cn"])
            t = targets.setdefault(sp["cn"], {
                "cn": sp["cn"], "name": sp["nome"], "expiry": sp["not_after"], "expiry_source": "servidor",
                "issuer": sp["emissor"] or "", "scope": (tr or r)["scope"], "smax": r["smax"],
                "auto": is_auto_renew(settings, sp["emissor"]), "dias": r["dias"],
                "sites": {s["host"] for s in (tr["instalado_em"] if tr else sp["sites"])} | {s["host"] for s in r["instalado_em"]},
                "via": []})
            t["sites"].add(cn)
            t["via"].append(cn)
        else:
            t = targets.setdefault(cn, {
                "cn": cn, "name": r["common_name"], "expiry": r["live_not_after"] or r["cmdb_valid_to"],
                "expiry_source": "servidor" if r["live_not_after"] else "CMDB",
                "issuer": (r["live_issuer"] or ", ".join(r["issuers"])), "scope": r["scope"], "smax": r["smax"],
                "auto": r["renovacao"] == "auto", "dias": r["dias"],
                "sites": {s["host"] for s in r["instalado_em"]}, "via": []})
            if cn not in t["via"] and t["via"]:
                t["via"].append(cn)
    for pos, tg in enumerate(targets.values()):
        base = inv.get(tg["cn"]) or {"cn": tg["cn"], "scope": tg["scope"]}
        vals, src = _suggest(session, base, settings)
        warnings, include = [], True
        if tg["via"]:
            warnings.append(f"Selecionado através de {', '.join(tg['via'])}: o certificado servido é {tg['name']}.")
        if tg["smax"]["state"] == "em_curso":
            warnings.append(f"Já existe o pedido {tg['smax']['main']['id']} em curso para este certificado.")
            include = False
        elif tg["smax"]["state"] == "outra_data":
            warnings.append(f"Há um pedido aberto ({tg['smax']['main']['id']}) para outra data de expiração.")
        if tg["auto"]:
            warnings.append("Renovação automática (Let's Encrypt): normalmente não precisa de pedido.")
            include = False
        if tg["dias"] is not None and tg["dias"] < 0:
            warnings.append(f"Já expirou há {-tg['dias']} dias.")
        session.add(TicketDraft(
            batch_id=batch.id, position=pos, cn=tg["cn"], name=tg["name"], expiry=tg["expiry"],
            expiry_source=tg["expiry_source"], issuer=(tg["issuer"] or "")[:512], scope=tg["scope"], include=include,
            prefill=src, warnings=warnings, via=tg["via"], sites=sorted(tg["sites"])[:200], **vals))
    session.add(AuditLog(actor=actor, action="pedidos.lote_criado", target=f"lote {batch.id}",
                         details={"certificados": cns}))
    return batch


def drafts_of(session: Session, batch_id: int) -> list[TicketDraft]:
    return list(session.scalars(select(TicketDraft).where(TicketDraft.batch_id == batch_id)
                                .order_by(TicketDraft.position)))


def update_drafts(session: Session, batch: TicketBatch, form: dict, settings: Settings) -> None:
    """Guarda os campos do formulário (nomes "<campo>_<id>", "incluir_<id>", "duplicado_<id>")."""
    if batch.status != "rascunho":
        raise TicketError("Este lote já não pode ser alterado.")
    for d in drafts_of(session, batch.id):
        for k in FIELDS:
            key = f"{k}_{d.id}"
            if key in form:
                setattr(d, k, _clean(form[key])[:256])
        if f"linha_{d.id}" in form:   # a linha estava no formulário: checkbox ausente = desmarcada
            d.include = form.get(f"incluir_{d.id}") == "1"
            d.override_duplicate = form.get(f"duplicado_{d.id}") == "1"


def apply_all(session: Session, batch: TicketBatch, values: dict, only_empty: bool) -> int:
    if batch.status != "rascunho":
        raise TicketError("Este lote já não pode ser alterado.")
    n = 0
    for d in drafts_of(session, batch.id):
        if not d.include:
            continue
        for k in FIELDS:
            v = _clean(values.get(k))
            if v and (not only_empty or not getattr(d, k)):
                setattr(d, k, v[:256])
                n += 1
    return n


# ------------------------------------------------------------------ criação
def _parse_result(r: httpx.Response | None, exc: Exception | None, token: str) -> tuple[str, str, dict]:
    """(estado, id do pedido, detalhe sem token) — mesma regra do workflow."""
    if r is None:
        return "indeterminado", "", {"erro": str(exc)[:500]}
    body = None
    try:
        body = r.json()
    except ValueError:
        body = (r.text or "")[:1500]
    results = body.get("entity_result_list") if isinstance(body, dict) else None
    first = results[0] if isinstance(results, list) and results else None
    tid = (((first or {}).get("entity") or {}).get("properties") or {}).get("Id")
    ok = 200 <= r.status_code < 300 and isinstance(results, list) and len(results) == 1 \
        and (first or {}).get("completion_status") == "OK" and tid is not None
    if ok:
        return "criado", str(tid), {}
    status = "indeterminado" if (r.status_code >= 500 or not first or first.get("completion_status") == "OK") else "falhou"
    detail = json.dumps({"http": r.status_code, "resposta": body}, ensure_ascii=False, default=str)
    if token:
        detail = detail.replace(token, "[TOKEN REMOVIDO]")
    if len(detail) > 4000:
        detail = detail[:4000] + "…"
    return status, "", {"texto": detail, "motivo": _reason(first)}


def _reason(first) -> str:
    if not isinstance(first, dict):
        return ""
    err = first.get("errorDetails") or first.get("error") or {}
    if isinstance(err, dict):
        return str(err.get("message") or err.get("errorMessage") or "")[:300]
    return str(err)[:300]


def start(batch_id: int, actor: str, settings: Settings) -> None:
    """Passa o lote a "a_criar" (atómico) e valida. A criação corre a seguir em execute()."""
    problems = config_problems(settings)
    if problems:
        raise TicketError(" ".join(problems))
    with session_scope() as s:
        drafts = drafts_of(s, batch_id)
        chosen = [d for d in drafts if d.include]
        if not chosen:
            raise TicketError("Nenhum pedido incluído no lote.")
        bad = [d.name for d in chosen if validate(d, settings)]
        if bad:
            raise TicketError(f"Há campos por preencher em: {', '.join(bad[:5])}")
        res = s.execute(update(TicketBatch).where(TicketBatch.id == batch_id, TicketBatch.status == "rascunho")
                        .values(status="a_criar", confirmed_by=actor, confirmed_at=utcnow()))
        if res.rowcount != 1:
            raise TicketError("Este lote já foi enviado ou cancelado.")
        for d in drafts:
            d.payload = build_payload(d, settings) if d.include else {}
            if not d.include:
                d.status, d.detail = "excluido", {"motivo": "Desmarcado no lote."}
        s.add(AuditLog(actor=actor, action="pedidos.lote_confirmado", target=f"lote {batch_id}",
                       details={"pedidos": len(chosen)}))


def execute(batch_id: int, actor: str, settings: Settings, client: httpx.Client | None = None,
            pause: float = 0.5) -> dict:
    """Cria os pedidos do lote (já em "a_criar"). Devolve o resumo."""
    from .tickets import ingest_smax, link, tickets_by_endpoint
    conn = _conn(settings)
    if conn.kind != "smax":
        return _execute_generic(batch_id, actor, settings, conn, pause)
    own = client is None
    client = client or smax.client(settings)
    summary = {"criados": 0}
    try:
        # 1) Reler os pedidos do SMAX: apanha pedidos criados entretanto (noutro lote, à mão, no n8n)
        try:
            with session_scope() as s:
                ingest_smax(s, settings, smax.fetch_tickets(settings, client))
        except smax.SmaxError as exc:
            _abort(batch_id, actor, f"Não foi possível confirmar no SMAX que não há pedidos duplicados: {exc}")
            return {"erro": str(exc)}
        with session_scope() as s:
            by_ep = tickets_by_endpoint(s)
            for d in drafts_of(s, batch_id):
                if d.status != "pendente" or d.override_duplicate:
                    continue
                st = link(by_ep.get(d.cn, []), d.expiry, settings)
                others = s.scalars(select(TicketDraft).where(TicketDraft.cn == d.cn, TicketDraft.batch_id != batch_id,
                                                             TicketDraft.status.in_(("criado", "indeterminado"))))
                same = next((o for o in others if o.expiry and d.expiry and
                             abs((as_utc(o.expiry).date() - as_utc(d.expiry).date()).days) <= 1), None)
                if st["state"] == "em_curso":
                    d.status, d.detail = "excluido", {"motivo": f"Já existe o pedido {st['main']['id']} em curso."}
                elif same is not None:
                    what = f"o pedido {same.ticket_id}" if same.status == "criado" else "um pedido indeterminado"
                    d.status, d.detail = "excluido", {"motivo": f"Já foi enviado {what} no lote {same.batch_id}."}
        # 2) Login e criação, um de cada vez
        try:
            token = smax.login(client, settings)
        except smax.SmaxError as exc:
            _abort(batch_id, actor, str(exc))
            return {"erro": str(exc)}
        headers = {"Cookie": f"LWSSO_COOKIE_KEY={token}; TENANTID={settings.smax_tenant}",
                   "Accept": "application/json", "Content-Type": "application/json"}
        with session_scope() as s:
            ids = [d.id for d in drafts_of(s, batch_id) if d.status == "pendente"]
        stopped = False
        for i, did in enumerate(ids):
            with session_scope() as s:
                d = s.get(TicketDraft, did)
                if stopped:
                    d.status = "nao_tentado"
                    continue
                d.status = "a_enviar"   # se o processo morrer aqui, o pedido fica "indeterminado", nunca repetido
                payload = d.payload
            r, exc = None, None
            try:
                r = client.post(f"/rest/{settings.smax_tenant}/ems/bulk", json=payload, headers=headers,
                                timeout=httpx.Timeout(60.0))
            except httpx.HTTPError as e:
                exc = e
            status, tid, detail = _parse_result(r, exc, token)
            with session_scope() as s:
                d = s.get(TicketDraft, did)
                d.status, d.ticket_id, d.detail, d.done_at = status, tid, detail, utcnow()
                d.http_status = r.status_code if r is not None else None
                s.add(AuditLog(actor=actor, action="pedidos.criar", target=d.cn,
                               details={"lote": batch_id, "estado": status, "pedido": tid or None}))
            if status == "criado":
                summary["criados"] += 1
                if pause and i < len(ids) - 1:
                    time.sleep(pause)
            else:
                stopped = True
        with session_scope() as s:
            b = s.get(TicketBatch, batch_id)
            left = [d for d in drafts_of(s, batch_id) if d.status in ("falhou", "indeterminado", "nao_tentado")]
            b.status, b.finished_at = ("interrompido" if left else "concluido"), utcnow()
            summary["estado"] = b.status
        # 3) Reler para os novos pedidos aparecerem já ligados aos certificados
        try:
            with session_scope() as s:
                ingest_smax(s, settings, smax.fetch_tickets(settings, client))
        except smax.SmaxError:
            pass
        return summary
    finally:
        if own:
            client.close()


def _exclude_duplicates(batch_id: int, settings: Settings) -> None:
    from .tickets import link, tickets_by_endpoint

    with session_scope() as s:
        by_ep = tickets_by_endpoint(s)
        for d in drafts_of(s, batch_id):
            if d.status != "pendente" or d.override_duplicate:
                continue
            st = link(by_ep.get(d.cn, []), d.expiry, settings)
            others = s.scalars(select(TicketDraft).where(TicketDraft.cn == d.cn, TicketDraft.batch_id != batch_id,
                                                         TicketDraft.status.in_(("criado", "indeterminado"))))
            same = next((o for o in others if o.expiry and d.expiry and
                         abs((as_utc(o.expiry).date() - as_utc(d.expiry).date()).days) <= 1), None)
            if st["state"] == "em_curso":
                d.status, d.detail = "excluido", {"motivo": f"Já existe o pedido {st['main']['id']} em curso."}
            elif same is not None:
                what = f"o pedido {same.ticket_id}" if same.status == "criado" else "um pedido indeterminado"
                d.status, d.detail = "excluido", {"motivo": f"Já foi enviado {what} no lote {same.batch_id}."}


def _execute_generic(batch_id: int, actor: str, settings: Settings, conn, pause: float) -> dict:
    """Jira, ServiceNow, GLPI: as mesmas garantias do SMAX (reler antes para não duplicar, um de cada vez,
    "indeterminado" nunca se repete, parar ao primeiro erro)."""
    from .conectores import ConnectorError
    from .tickets import ingest_smax

    summary = {"criados": 0}
    try:
        with session_scope() as s:
            ingest_smax(s, settings)
    except (ConnectorError, httpx.HTTPError) as exc:
        _abort(batch_id, actor, f"Não foi possível confirmar no {conn.label} que não há pedidos duplicados: {exc}")
        return {"erro": str(exc)}
    _exclude_duplicates(batch_id, settings)
    with session_scope() as s:
        ids = [d.id for d in drafts_of(s, batch_id) if d.status == "pendente"]
    stopped = False
    for i, did in enumerate(ids):
        with session_scope() as s:
            d = s.get(TicketDraft, did)
            if stopped:
                d.status = "nao_tentado"
                continue
            d.status = "a_enviar"
            s.expunge(d)
        status, tid, detail = conn.create(d)
        with session_scope() as s:
            d = s.get(TicketDraft, did)
            d.status, d.ticket_id, d.detail, d.done_at = status, tid, detail, utcnow()
            s.add(AuditLog(actor=actor, action="pedidos.criar", target=d.cn,
                           details={"lote": batch_id, "estado": status, "pedido": tid or None, "sistema": conn.kind}))
        if status == "criado":
            summary["criados"] += 1
            if pause and i < len(ids) - 1:
                time.sleep(pause)
        else:
            stopped = True
    with session_scope() as s:
        b = s.get(TicketBatch, batch_id)
        left = [d for d in drafts_of(s, batch_id) if d.status in ("falhou", "indeterminado", "nao_tentado")]
        b.status, b.finished_at = ("interrompido" if left else "concluido"), utcnow()
        summary["estado"] = b.status
    try:
        with session_scope() as s:
            ingest_smax(s, settings)
    except (ConnectorError, httpx.HTTPError):
        pass
    return summary


def _abort(batch_id: int, actor: str, reason: str) -> None:
    """Nada foi enviado: o lote volta a rascunho para se poder tentar de novo."""
    with session_scope() as s:
        b = s.get(TicketBatch, batch_id)
        b.status, b.note = "rascunho", reason[:600]
        for d in drafts_of(s, batch_id):
            d.status, d.detail = "pendente", {}
        s.add(AuditLog(actor=actor, action="pedidos.lote_abortado", target=f"lote {batch_id}", details={"motivo": reason[:300]}))


def execute_in_background(batch_id: int, actor: str, settings: Settings) -> None:
    def run():
        try:
            execute(batch_id, actor, settings)
        except Exception:   # nunca deixar o lote preso sem registo
            log.exception("Criação de pedidos do lote %s falhou", batch_id)
            mark_stale(batch_id, force=True)
    threading.Thread(target=run, name=f"smax-lote-{batch_id}", daemon=True).start()


def mark_stale(batch_id: int, force: bool = False) -> bool:
    """Lote preso em "a_criar" (processo reiniciado): o que estava a ser enviado fica indeterminado."""
    with session_scope() as s:
        b = s.get(TicketBatch, batch_id)
        if b is None or b.status != "a_criar":
            return False
        drafts = drafts_of(s, batch_id)
        last = max([as_utc(d.done_at) for d in drafts if d.done_at] + [as_utc(b.confirmed_at) or utcnow()])
        if not force and utcnow() - last < STALE_AFTER:
            return False
        for d in drafts:
            if d.status == "a_enviar":
                d.status, d.detail = "indeterminado", {"motivo": "O processo parou durante o envio."}
            elif d.status == "pendente":
                d.status = "nao_tentado"
        b.status, b.finished_at = "interrompido", utcnow()
        return True


def retry_batch(session: Session, batch: TicketBatch, actor: str, settings: Settings) -> TicketBatch:
    """Novo lote com os pedidos que falharam ou não foram tentados (os indeterminados ficam de fora)."""
    src = [d for d in drafts_of(session, batch.id) if d.status in ("falhou", "nao_tentado")]
    if not src:
        raise TicketError("Não há pedidos para repetir (os indeterminados têm de ser verificados no SMAX).")
    new = create_batch(session, [d.cn for d in src], actor, settings)
    session.flush()
    old = {d.cn: d for d in src}
    for d in drafts_of(session, new.id):
        for k in FIELDS:
            setattr(d, k, getattr(old[d.cn], k))
    return new

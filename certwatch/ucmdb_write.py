"""Escrever certificados na UCMDB pela REST API, em vez de publicar o certs_update.csv na pasta de rede.

- A partir de uma geração (Atualizar a CMDB): cada alteração revista passa a uma chamada à API.
  Linha nova (Global Id = x) -> POST /rest-api/dataModel (criar). Linha alterada -> PUT /rest-api/dataModel/ci/{id}
  só com os campos que mudaram.
- Editar um certificado à mão: PUT só com o que o utilizador mudou.

Segurança:
- só com CERTWATCH_UCMDB_WRITE=true;
- só se escrevem os campos de WRITABLE (nunca o Global Id, datas de criação, etc.);
- antes de atualizar, lê-se o CI e confirma-se que os campos a mudar ainda têm o valor que tinham na geração
  (se alguém os mudou entretanto, não se escreve);
- depois de escrever, lê-se de novo e confirma-se que ficou o que foi enviado;
- cada escrita fica em UcmdbWrite e na auditoria.
"""
from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, time, timezone
from zoneinfo import ZoneInfo

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .cmdb_final import (OUTPUT_COLUMNS, CmdbTable, load_column_overrides, parse_day, plan_columns, format_value,
                         unpack_state)
from .collectors.ucmdb import UcmdbError, UcmdbSession
from .config import Settings
from .db import session_scope, utcnow
from .models import AuditLog, FinalRun, UcmdbWrite

log = logging.getLogger(__name__)

# Campos que o certwatch pode escrever (nomes das colunas do certs_update)
WRITABLE = ["Display Label", "Name", "CommonName", "ValidTo", "Localização", "Certificate Status", "SerialNumber",
            "Issuer", "IssuerName", "Subject Alternative Names", "Certificate Type", "Description"]
DATE_COLUMNS = {"ValidTo"}
# Campos do formulário de edição de um certificado, pela ordem em que aparecem
EDIT_COLUMNS = ["ValidTo", "Issuer", "IssuerName", "SerialNumber", "CommonName", "Certificate Status",
                "Subject Alternative Names", "Display Label", "Name", "Localização", "Certificate Type", "Description"]
DONE = ("ok", "aviso")
BUSY = ("pendente", "a_aplicar")
STATE_LABELS = {"pendente": "na fila", "a_aplicar": "a aplicar", "ok": "aplicado", "aviso": "aplicado, com aviso",
                "erro": "erro", "ignorado": "não aplicado"}


class WriteError(RuntimeError):
    pass


def enabled_problem(settings: Settings) -> str:
    if not settings.ucmdb_write:
        return "A escrita na UCMDB está desligada: defina CERTWATCH_UCMDB_WRITE=true no .env e reinicie."
    if not (settings.ucmdb_url and settings.ucmdb_user and settings.ucmdb_password):
        return "A ligação à UCMDB não está configurada (CERTWATCH_UCMDB_URL e segredos ucmdb_user / ucmdb_password)."
    return ""


# ------------------------------------------------------------------ colunas <-> atributos
def columns_from_run(columns_diag: dict | None) -> dict[str, str]:
    """Coluna -> atributo da UCMDB, como ficou decidido na geração."""
    out: dict[str, str] = {}
    for m in (columns_diag or {}).get("mapeamento") or []:
        how = m.get("como") or ""
        if m.get("coluna") and m.get("atributo") and not how.startswith(("não incluído", "ignorado", "excluído")):
            out.setdefault(m["coluna"], m["atributo"])
    return out


def columns_for_ci(props: dict, settings: Settings) -> dict[str, str]:
    """Coluna -> atributo para um CI lido da API (mesma regra da geração)."""
    overrides, order, _ = load_column_overrides(settings)
    plan, _ = plan_columns(sorted(props), set(props), overrides, order, settings.final_header_prefix)
    return {col: attr for attr, col in plan if attr and not attr.startswith("(")}


def api_value(col: str, text: str, tz: ZoneInfo, as_ms: bool = False):
    """Texto da célula -> valor para a API. Datas: ISO 8601 (00:00 em Lisboa) ou milissegundos."""
    text = (text or "").strip()
    if col in DATE_COLUMNS:
        d = parse_day(text).day
        if d is None:
            return None
        dt = datetime.combine(d, time(0, 0), tz)
        return int(dt.timestamp() * 1000) if as_ms else dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return text


def same(col: str, a, b) -> bool:
    if col in DATE_COLUMNS:
        return parse_day(a).day == parse_day(b).day
    return str(a or "").strip() == str(b or "").strip()


# ------------------------------------------------------------------ plano de cada alteração
@dataclass
class Plan:
    acao: str                                  # criar | atualizar
    cn: str
    ucmdb_id: str = ""
    ci_type: str = ""
    campos: dict[str, str] = field(default_factory=dict)     # coluna -> texto novo
    esperado: dict[str, str] = field(default_factory=dict)   # coluna -> texto antes (atualizar)
    sem_atributo: list[str] = field(default_factory=list)    # colunas que mudaram mas não têm atributo


def plan_change(state: dict, change: dict, col_attr: dict[str, str], settings: Settings) -> Plan:
    i = int(change["chave"])
    display = state["display"]
    row = state["rows"][i]
    if change["tipo"] == "novo":
        p = Plan("criar", change.get("cn") or "", ci_type=settings.ucmdb_cert_type)
        for col in WRITABLE:
            v = (row.get(display.get(col, ""), "") or "").strip()
            if not v:
                continue
            if col in col_attr:
                p.campos[col] = v
            else:
                p.sem_atributo.append(col)
        return p
    inv = {h: c for c, h in display.items()}
    orig = state["originals"].get(str(i)) or state["originals"].get(i) or {}
    p = Plan("atualizar", change.get("cn") or "", ucmdb_id=state["ids"][i] if i < len(state["ids"]) else "")
    for h in state["mods"].get(str(i)) or state["mods"].get(i) or []:
        col = inv.get(h, h)
        if col not in WRITABLE:
            continue
        if col not in col_attr:
            p.sem_atributo.append(col)
            continue
        p.campos[col] = row.get(h, "") or ""
        p.esperado[col] = orig.get(h, "") or ""
    return p


# ------------------------------------------------------------------ chamadas
def _error(r: httpx.Response) -> str:
    try:
        d = r.json() or {}
        msg = d.get("error") or d.get("message") or ""
    except ValueError:
        msg = r.text
    return f"HTTP {r.status_code}: {str(msg).strip()[:400] or 'sem mensagem'}"


def _looks_like_date_problem(r: httpx.Response) -> bool:
    t = r.text.lower()
    return r.status_code == 400 and any(w in t for w in ("date", "data", "parse", "format", "long"))


def _props(campos: dict[str, str], col_attr: dict[str, str], tz: ZoneInfo, as_ms: bool) -> dict:
    out = {}
    for col, v in campos.items():
        val = api_value(col, v, tz, as_ms)
        if val is None and col in DATE_COLUMNS:
            continue
        out[col_attr[col]] = val
    return out


@dataclass
class Outcome:
    estado: str
    ucmdb_id: str = ""
    enviado: dict = field(default_factory=dict)
    antes: dict = field(default_factory=dict)
    resposta: dict = field(default_factory=dict)
    verificado: bool | None = None
    detalhe: str = ""


def execute(s: UcmdbSession, plan: Plan, col_attr: dict[str, str], settings: Settings) -> Outcome:
    tz = ZoneInfo(settings.timezone)
    if not plan.campos:
        return Outcome("ignorado", plan.ucmdb_id, detalhe="Nada para escrever (os campos alterados não existem na UCMDB: "
                                                          + ", ".join(plan.sem_atributo) + ")." if plan.sem_atributo
                       else "Nada para escrever.")
    if plan.acao == "atualizar":
        if not plan.ucmdb_id:
            return Outcome("erro", detalhe="Linha sem ID do CI na UCMDB.")
        try:
            cur = s.ci(plan.ucmdb_id)
        except UcmdbError as exc:
            return Outcome("erro", plan.ucmdb_id, detalhe=f"Não foi possível ler o CI antes de o atualizar: {exc}")
        cprops = cur.get("properties") or {}
        antes = {col_attr[c]: format_value(col_attr[c], cprops.get(col_attr[c]), tz) for c in plan.campos}
        changed_meanwhile = [f"{c}: está \"{antes[col_attr[c]] or '(vazio)'}\", na geração era \"{plan.esperado[c] or '(vazio)'}\""
                             for c in plan.esperado if not same(c, antes[col_attr[c]], plan.esperado[c])]
        if changed_meanwhile:
            return Outcome("ignorado", plan.ucmdb_id, antes=antes,
                           detalhe="Mudou na UCMDB depois da geração; não foi escrito (gere de novo). "
                                   + "; ".join(changed_meanwhile))
        ci_type = cur.get("type") or settings.ucmdb_cert_type
    else:
        antes, ci_type = {}, plan.ci_type
    as_ms = False
    for attempt in (1, 2):
        props = _props(plan.campos, col_attr, tz, as_ms)
        try:
            if plan.acao == "criar":
                r = s.client.request("POST", "/dataModel", headers=s.headers,
                                     json={"cis": [{"ucmdbId": "1", "type": ci_type, "properties": props}], "relations": []})
            else:
                r = s.client.request("PUT", f"/dataModel/ci/{plan.ucmdb_id}", headers=s.headers,
                                     json={"ucmdbId": plan.ucmdb_id, "type": ci_type, "properties": props})
        except httpx.HTTPError as exc:
            return Outcome("erro", plan.ucmdb_id, enviado=props, antes=antes, detalhe=f"Erro de comunicação: {exc}")
        if r.status_code == 200 or attempt == 2 or not _looks_like_date_problem(r) \
                or not any(c in DATE_COLUMNS for c in plan.campos):
            break
        as_ms = True                      # a UCMDB não aceitou a data em ISO 8601: tenta em milissegundos
    if r.status_code != 200:
        return Outcome("erro", plan.ucmdb_id, enviado=props, antes=antes, detalhe=_error(r))
    try:
        resp = r.json() or {}
    except ValueError:
        resp = {}
    lists = {k: list(resp.get(k) or []) for k in ("addedCis", "updatedCis", "ignoredCis", "removedCis")}
    estado, detalhe = "ok", ""
    if plan.acao == "criar":
        if lists["addedCis"]:
            cid = lists["addedCis"][0]
            detalhe = f"Criado: CI {cid}."
        elif lists["updatedCis"]:
            cid = lists["updatedCis"][0]
            estado, detalhe = "aviso", (f"A UCMDB identificou-o como um CI que já existia ({cid}) e atualizou-o em vez "
                                        "de criar um novo. Confirme na UCMDB.")
        else:
            return Outcome("erro", "", enviado=props, resposta=lists,
                           detalhe=f"A UCMDB não criou o certificado (ignoredCis={lists['ignoredCis']}).")
    else:
        cid = plan.ucmdb_id
        detalhe = "Atualizado." if (lists["updatedCis"] or not lists["ignoredCis"]) else "A UCMDB respondeu sem alterações."
    # confirmar o que ficou
    verificado, diffs = None, []
    try:
        after = s.ci(cid).get("properties") or {}
        for col, v in plan.campos.items():
            got = format_value(col_attr[col], after.get(col_attr[col]), tz)
            if not same(col, got, v):
                diffs.append(f"{col}: ficou \"{got or '(vazio)'}\", enviado \"{v}\"")
        verificado = not diffs
    except UcmdbError as exc:
        diffs.append(f"não foi possível ler o CI depois: {exc}")
    if diffs:
        estado = "aviso"
        detalhe += " Verificação: " + "; ".join(diffs)
    if as_ms:
        detalhe += " (datas enviadas em milissegundos)"
    return Outcome(estado, cid, enviado=props, antes=antes, resposta=lists, verificado=verificado, detalhe=detalhe.strip())


# ------------------------------------------------------------------ a partir de uma geração
def run_columns(run: FinalRun) -> dict[str, str]:
    return columns_from_run(run.columns)


def queue(session: Session, run: FinalRun, keys: list[int], actor: str) -> str:
    """Põe na fila as alterações escolhidas (as que ainda não foram aplicadas). Devolve o código do lote."""
    if session.scalar(select(UcmdbWrite.id).where(UcmdbWrite.estado.in_(BUSY)).limit(1)) is not None:
        raise WriteError("Já há escritas na UCMDB a decorrer. Aguarde que terminem.")
    by_key = {c["chave"]: c for c in (run.changes or [])}
    done = {w.chave for w in session.scalars(select(UcmdbWrite).where(UcmdbWrite.run_id == run.id,
                                                                     UcmdbWrite.estado.in_(DONE)))}
    lote = uuid.uuid4().hex[:12]
    n = 0
    for k in keys:
        c = by_key.get(k)
        if c is None or k in done:
            continue
        session.add(UcmdbWrite(run_id=run.id, chave=k, lote=lote, acao="criar" if c["tipo"] == "novo" else "atualizar",
                               cn=c.get("cn") or "", estado="pendente", por=actor))
        n += 1
    if not n:
        raise WriteError("Nada para aplicar: as alterações escolhidas já foram aplicadas na UCMDB.")
    return lote


def process(lote: str, settings: Settings, client: httpx.Client | None = None) -> None:
    """Aplica um lote, uma alteração de cada vez. Nunca deixa escritas em "pendente"/"a_aplicar"."""
    with session_scope() as s:
        writes = list(s.scalars(select(UcmdbWrite).where(UcmdbWrite.lote == lote).order_by(UcmdbWrite.id)))
        if not writes:
            return
        run = s.get(FinalRun, writes[0].run_id)
        state = unpack_state(run.state) if run is not None and run.state else None
        col_attr = run_columns(run) if run is not None else {}
        changes = {c["chave"]: c for c in (run.changes or [])} if run is not None else {}
        ids = [w.id for w in writes]
    try:
        if state is None:
            raise WriteError("A geração já não tem os dados necessários (foi apagada?).")
        with UcmdbSession(settings, client) as us:
            for wid in ids:
                with session_scope() as s:
                    w = s.get(UcmdbWrite, wid)
                    w.estado = "a_aplicar"
                    chave = w.chave
                plan = plan_change(state, changes[chave], col_attr, settings)
                try:
                    out = execute(us, plan, col_attr, settings)
                except Exception as exc:          # noqa: BLE001 - uma falha não pára o lote
                    log.exception("Escrita na UCMDB falhou")
                    out = Outcome("erro", plan.ucmdb_id, detalhe=f"{type(exc).__name__}: {exc}"[:500])
                with session_scope() as s:
                    w = s.get(UcmdbWrite, wid)
                    w.estado, w.ucmdb_id, w.enviado, w.antes = out.estado, out.ucmdb_id, out.enviado, out.antes
                    w.resposta, w.verificado, w.detalhe, w.feito_em = out.resposta, out.verificado, out.detalhe, utcnow()
                    s.add(AuditLog(actor=w.por, action="ucmdb.escrever", target=f"{w.acao} {w.cn}"[:600],
                                   details={"geracao": w.run_id, "ci": out.ucmdb_id, "estado": out.estado,
                                            "campos": sorted(plan.campos), "detalhe": out.detalhe[:300]}))
    except (UcmdbError, WriteError) as exc:
        with session_scope() as s:
            for w in s.scalars(select(UcmdbWrite).where(UcmdbWrite.lote == lote, UcmdbWrite.estado.in_(BUSY))):
                w.estado, w.detalhe, w.feito_em = "erro", str(exc)[:500], utcnow()


def process_in_background(lote: str, settings: Settings) -> None:
    threading.Thread(target=process, args=(lote, settings), name=f"ucmdb-{lote}", daemon=True).start()


def writes_for_run(session: Session, run_id: int) -> dict[int, UcmdbWrite]:
    """A escrita mais recente de cada alteração da geração."""
    out: dict[int, UcmdbWrite] = {}
    for w in session.scalars(select(UcmdbWrite).where(UcmdbWrite.run_id == run_id).order_by(UcmdbWrite.id)):
        out[w.chave] = w
    return out


def recover_stale(session: Session) -> None:
    """Escritas deixadas a meio (o processo parou)."""
    from datetime import timedelta
    limit = utcnow() - timedelta(minutes=30)
    for w in session.scalars(select(UcmdbWrite).where(UcmdbWrite.estado.in_(BUSY), UcmdbWrite.pedido_em < limit)):
        w.estado, w.detalhe = "erro", "Interrompido (o processo parou). Confirme na UCMDB antes de repetir."


# ------------------------------------------------------------------ editar um certificado
@dataclass
class EditForm:
    ucmdb_id: str
    ci_type: str
    cn: str
    col_attr: dict[str, str]
    atual: dict[str, str]          # coluna -> texto atual


def load_for_edit(settings: Settings, ucmdb_id: str, client: httpx.Client | None = None) -> EditForm:
    tz = ZoneInfo(settings.timezone)
    with UcmdbSession(settings, client) as s:
        ci = s.ci(ucmdb_id)
    props = ci.get("properties") or {}
    col_attr = {c: a for c, a in columns_for_ci(props, settings).items() if c in EDIT_COLUMNS}
    atual = {c: format_value(a, props.get(a), tz) for c, a in col_attr.items()}
    if "ValidTo" in atual and atual["ValidTo"]:
        d = parse_day(atual["ValidTo"]).day
        atual["ValidTo"] = d.isoformat() if d else atual["ValidTo"]
    return EditForm(ucmdb_id, ci.get("type") or settings.ucmdb_cert_type,
                    atual.get("CommonName") or atual.get("Display Label") or ucmdb_id, col_attr, atual)


def edit_changes(form: EditForm, new: dict[str, str]) -> dict[str, tuple[str, str]]:
    """Coluna -> (antes, depois) só do que mudou."""
    out = {}
    for c in form.col_attr:
        if c not in new:
            continue
        v = (new[c] or "").replace("\r\n", "\n").strip()
        if not same(c, form.atual.get(c, ""), v):
            out[c] = (form.atual.get(c, ""), v)
    return out


def describe_edit(settings: Settings, changes: dict[str, tuple[str, str]]) -> str:
    """Description no estilo do workflow: "<prefixo> - X alterado de A para B; ..."."""
    parts = []
    for c, (a, b) in changes.items():
        if c == "Description":
            continue
        label = "Data de expiracao" if c == "ValidTo" else c
        fa = (_day_text(a) if c in DATE_COLUMNS else a) or "(vazio)"
        fb = (_day_text(b) if c in DATE_COLUMNS else b) or "(vazio)"
        parts.append(f"{label} alterado de {fa} para {fb}")
    return f"{settings.final_description} - " + "; ".join(parts) if parts else ""


def _day_text(v: str) -> str:
    d = parse_day(v).day
    return d.strftime("%d/%m/%Y") if d else (v or "")


def apply_edit(settings: Settings, form: EditForm, changes: dict[str, tuple[str, str]], actor: str,
               client: httpx.Client | None = None) -> UcmdbWrite:
    plan = Plan("atualizar", form.cn, ucmdb_id=form.ucmdb_id,
                campos={c: b for c, (a, b) in changes.items()}, esperado={c: a for c, (a, b) in changes.items()})
    try:
        with UcmdbSession(settings, client) as s:
            out = execute(s, plan, form.col_attr, settings)
    except UcmdbError as exc:
        out = Outcome("erro", form.ucmdb_id, detalhe=str(exc))
    with session_scope() as s:
        w = UcmdbWrite(run_id=None, chave=None, lote="", acao="atualizar", cn=form.cn, ucmdb_id=form.ucmdb_id,
                       estado=out.estado, enviado=out.enviado, antes=out.antes, resposta=out.resposta,
                       verificado=out.verificado, detalhe=out.detalhe, por=actor, feito_em=utcnow())
        s.add(w)
        s.add(AuditLog(actor=actor, action="ucmdb.editar", target=form.cn[:600],
                       details={"ci": form.ucmdb_id, "estado": out.estado, "campos": sorted(changes),
                                "detalhe": out.detalhe[:300]}))
        s.flush()
        s.expunge(w)
    return w


__all__ = ["WRITABLE", "EDIT_COLUMNS", "STATE_LABELS", "WriteError", "enabled_problem", "queue", "process",
           "process_in_background", "writes_for_run", "load_for_edit", "edit_changes", "describe_edit", "apply_edit",
           "OUTPUT_COLUMNS", "CmdbTable", "date"]


def edit_signature(form: EditForm, changes: dict[str, tuple[str, str]]) -> str:
    """Assinatura do que foi revisto (estado atual + alterações), para gravar exatamente isso."""
    import hashlib
    import json
    data = json.dumps({"id": form.ucmdb_id, "atual": form.atual, "mud": changes}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:32]

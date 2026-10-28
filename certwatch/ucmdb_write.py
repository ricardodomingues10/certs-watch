"""Escrever certificados na UCMDB pela REST API, em vez de publicar o certs_update.csv na pasta de rede.

- A partir de uma reconciliação (Reconciliar e atualizar): cada alteração revista passa a uma chamada à API.
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
import re
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
from .fontes.ucmdb import UcmdbError, UcmdbSession
from .config import Settings
from .db import session_scope, utcnow
from .models import AuditLog, FinalRun, UcmdbWrite

log = logging.getLogger(__name__)

# Campos que o Atalaia Cert pode escrever (nomes das colunas do certs_update)
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


# Formatos de data tentados, por esta ordem, até a UCMDB aceitar (o primeiro que funcionar fica a ser usado).
# A UCMDB recusou "2026-12-29T00:00:00Z" ("malformed at Z"): espera a data sem fuso.
DATE_FORMATS = ("local", "local_ms", "epoch_ms", "utc")
DATE_FORMAT_LABELS = {"local": "AAAA-MM-DDThh:mm:ss (hora de Lisboa)", "local_ms": "AAAA-MM-DDThh:mm:ss.sss (hora de Lisboa)",
                      "epoch_ms": "milissegundos desde 1970", "utc": "ISO 8601 em UTC (…Z)"}
_working_format: list[str] = []


def date_formats() -> list[str]:
    return [*_working_format, *[f for f in DATE_FORMATS if f not in _working_format]]


def api_value(col: str, text: str, tz: ZoneInfo, fmt: str = "local"):
    """Texto da célula -> valor para a API. Datas: 00:00 em Lisboa, no formato pedido."""
    text = (text or "").strip()
    if col in DATE_COLUMNS:
        d = parse_day(text).day
        if d is None:
            return None
        dt = datetime.combine(d, time(0, 0), tz)
        if fmt == "epoch_ms":
            return int(dt.timestamp() * 1000)
        if fmt == "utc":
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if fmt == "local_ms":
            return dt.strftime("%Y-%m-%dT%H:%M:%S.000")
        return dt.strftime("%Y-%m-%dT%H:%M:%S")
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
    fixos: dict = field(default_factory=dict)                # atributo -> valor enviado tal e qual (ao criar)


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
    return r.status_code in (400, 500) and any(w in t for w in ("malformed", "invalid format", "date", "parse", "format", "long"))


def _props(campos: dict[str, str], col_attr: dict[str, str], tz: ZoneInfo, fmt: str) -> dict:
    out = {}
    for col, v in campos.items():
        val = api_value(col, v, tz, fmt)
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
        changed_meanwhile = [f"{c}: está \"{antes[col_attr[c]] or '(vazio)'}\", na reconciliação era \"{plan.esperado[c] or '(vazio)'}\""
                             for c in plan.esperado if not same(c, antes[col_attr[c]], plan.esperado[c])]
        if changed_meanwhile:
            return Outcome("ignorado", plan.ucmdb_id, antes=antes,
                           detalhe="Mudou na UCMDB depois da reconciliação; não foi escrito (reconcilie de novo). "
                                   + "; ".join(changed_meanwhile))
        ci_type = cur.get("type") or settings.ucmdb_cert_type
    else:
        antes, ci_type = {}, plan.ci_type
    has_date = any(c in DATE_COLUMNS for c in plan.campos)
    formats = date_formats() if has_date else ["local"]
    tried: list[str] = []
    for fmt in formats:
        props = {**plan.fixos, **_props(plan.campos, col_attr, tz, fmt)}
        tried.append(fmt)
        try:
            if plan.acao == "criar":
                r = s.client.request("POST", "/dataModel", headers=s.headers,
                                     json={"cis": [{"ucmdbId": "1", "type": ci_type, "properties": props}], "relations": []})
            else:
                r = s.client.request("PUT", f"/dataModel/ci/{plan.ucmdb_id}", headers=s.headers,
                                     json={"ucmdbId": plan.ucmdb_id, "type": ci_type, "properties": props})
        except httpx.HTTPError as exc:
            return Outcome("erro", plan.ucmdb_id, enviado=props, antes=antes, detalhe=f"Erro de comunicação: {exc}")
        if r.status_code == 200:
            if has_date and _working_format[:1] != [fmt]:
                _working_format[:] = [fmt]
            break
        if not has_date or not _looks_like_date_problem(r):
            break                         # outro erro: não adianta mudar o formato da data
    if r.status_code != 200:
        extra = (" Formatos de data tentados: " + ", ".join(DATE_FORMAT_LABELS[f] for f in tried) + ".") if len(tried) > 1 else ""
        return Outcome("erro", plan.ucmdb_id, enviado=props, antes=antes, detalhe=_error(r) + extra)
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
        got_ci = s.ci(cid)
        after = dict(got_ci.get("properties") or {})
        missing = sorted({col_attr[c] for c in plan.campos if col_attr[c] not in after})
        if missing and got_ci.get("type"):
            # o GET nem sempre devolve todos os atributos (ex.: datas): pede-os numa consulta ad-hoc
            try:
                for c in s.topology_query(str(got_ci["type"]), missing, [cid]):
                    if str(c.get("ucmdbId")) == str(cid):
                        after.update({k: v for k, v in (c.get("properties") or {}).items() if v not in (None, "")})
            except UcmdbError:
                pass
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
    if has_date and fmt != "local":
        detalhe += f" (data enviada como {DATE_FORMAT_LABELS[fmt]})"
    return Outcome(estado, cid, enviado=props, antes=antes, resposta=lists, verificado=verificado, detalhe=detalhe.strip())


# ------------------------------------------------------------------ a partir de uma reconciliação
def run_columns(run: FinalRun) -> dict[str, str]:
    return columns_from_run(run.columns)


def queue(session: Session, run: FinalRun, keys: list[int], actor: str) -> str:
    """Põe na fila as alterações escolhidas (as que ainda não foram aplicadas). Devolve o código do lote."""
    if session.scalar(select(UcmdbWrite.id).where(UcmdbWrite.estado.in_(BUSY)).limit(1)) is not None:
        raise WriteError("Já há escritas na UCMDB a decorrer. Aguarde que terminem.")
    by_key = {c["chave"]: c for c in (run.changes or [])}
    done = {w.chave for w in session.scalars(select(UcmdbWrite).where(UcmdbWrite.run_id == run.id, UcmdbWrite.parte == "cert",
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
        azure = {x["chave"]: x for x in ((run.vistas or {}).get("azure") or [])} if run is not None else {}
        ids = [w.id for w in writes]
        used_x = [w.enviado for w in s.scalars(select(UcmdbWrite).where(UcmdbWrite.estado.in_(DONE)))]
    try:
        if state is None:
            raise WriteError("A reconciliação já não tem os dados necessários (foi apagada?).")
        ctx = AzureContext(state=state, col_attr=col_attr, used=used_x)
        with UcmdbSession(settings, client) as us:
            for wid in ids:
                with session_scope() as s:
                    w = s.get(UcmdbWrite, wid)
                    w.estado = "a_aplicar"
                    chave, parte, lista, acao = w.chave, w.parte, w.lista, w.acao
                try:
                    if parte == "azure":
                        plan, attrs = plan_azure(us, azure[chave], lista, acao, ctx, settings)
                    else:
                        plan, attrs = plan_change(state, changes[chave], col_attr, settings), col_attr
                    out = execute(us, plan, attrs, settings)
                    if parte == "azure" and lista == "apis" and plan.acao == "criar" and out.estado == "erro":
                        out = _retry_required(us, plan, attrs, out, ctx, settings)
                    if out.estado in DONE and plan.acao == "criar":
                        ctx.used.append(out.enviado)
                except (UcmdbError, WriteError) as exc:
                    plan, out = Plan(acao, ""), Outcome("erro", detalhe=str(exc)[:500])
                except Exception as exc:          # noqa: BLE001 - uma falha não pára o lote
                    log.exception("Escrita na UCMDB falhou")
                    plan, out = Plan(acao, ""), Outcome("erro", detalhe=f"{type(exc).__name__}: {exc}"[:500])
                with session_scope() as s:
                    w = s.get(UcmdbWrite, wid)
                    w.estado, w.ucmdb_id, w.enviado, w.antes = out.estado, out.ucmdb_id, out.enviado, out.antes
                    w.resposta, w.verificado, w.detalhe, w.feito_em = out.resposta, out.verificado, out.detalhe, utcnow()
                    s.add(AuditLog(actor=w.por, action="ucmdb.escrever", target=f"{w.acao} {w.cn}"[:600],
                                   details={"geracao": w.run_id, "parte": w.parte, "lista": w.lista, "ci": out.ucmdb_id,
                                            "estado": out.estado, "campos": sorted(plan.campos), "detalhe": out.detalhe[:300]}))
            check_created_in_tql(us, settings, ids)
    except (UcmdbError, WriteError) as exc:
        with session_scope() as s:
            for w in s.scalars(select(UcmdbWrite).where(UcmdbWrite.lote == lote, UcmdbWrite.estado.in_(BUSY))):
                w.estado, w.detalhe, w.feito_em = "erro", str(exc)[:500], utcnow()
                s.add(AuditLog(actor=w.por, action="ucmdb.escrever", target=f"{w.acao} {w.cn}"[:600],
                               details={"geracao": w.run_id, "estado": "erro", "detalhe": str(exc)[:300]}))


# ------------------------------------------------------------------ Azure: incluir na lista de APIs ou na de certificados
AZURE_API_LOCATION = "AzureAD - App Registration - Client Secret"


@dataclass
class AzureContext:
    state: dict
    col_attr: dict[str, str]
    used: list = field(default_factory=list)              # enviado de escritas anteriores (para o próximo x<n>)
    api: dict | None = None                               # {"type", "fields", "props", "location"}


def next_placeholder_serial(state: dict, used: list) -> str:
    """SerialNumber x<n> seguinte: depois do maior da CMDB lida e dos já enviados pelo Atalaia Cert."""
    import re as _re
    rx = _re.compile(r"^x(\d+)$", _re.I)
    n = 0
    col = state["display"].get("SerialNumber")
    for r in state["rows"]:
        m = rx.match(str(r.get(col, "") or "").strip()) if col else None
        if m:
            n = max(n, int(m.group(1)))
    for env in used:
        for v in (env or {}).values():
            m = rx.match(str(v or "").strip())
            if m:
                n = max(n, int(m.group(1)))
    return f"x{n + 1}"


def labels_of(attrs: list[dict]) -> dict[str, str]:
    return {a["name"]: a.get("label") or "" for a in attrs}


def api_model(us: UcmdbSession, settings: Settings) -> dict:
    """Tipo de CI e atributos da lista de APIs, a partir dos CIs do TQL das APIs."""
    from collections import Counter
    from .fontes.ucmdb import (APP_KEY, LOCATION_KEY, _is_date, _internal, class_attributes, date_attributes,
                                   detect_api_fields, enrich_cis, pick_expiry)
    if not settings.ucmdb_tql_apis:
        raise WriteError("Defina CERTWATCH_UCMDB_TQL_APIS (a lista de APIs) para incluir segredos do Azure.")
    cis = us.topology(settings.ucmdb_tql_apis)
    if not cis:
        raise WriteError(f"O TQL {settings.ucmdb_tql_apis} não devolveu APIs: não sei que tipo de CI criar.")
    ci_type = Counter(c.get("type") for c in cis if c.get("type")).most_common(1)[0][0] if any(c.get("type") for c in cis) else ""
    # o modelo de classes da UCMDB diz que atributos de data o tipo tem (mesmo sem valor nos CIs)
    cls_attrs, cls_note = class_attributes(us, ci_type)
    cls_attr, cls_dates = pick_expiry(cls_attrs), date_attributes(cls_attrs)
    fields = detect_api_fields(cis, settings)
    have = {k for c in cis for k, v in (c.get("properties") or {}).items() if v not in (None, "")}
    if any(not fields.get(k) or fields[k] not in have for k in ("nome", "validade", "aplicacao", "localizacao")):
        # o layout do TQL não traz todos os atributos: vai buscá-los à REST API (como a importação das APIs)
        cis, _, _ = enrich_cis(us, cis, settings.apis_enrich if settings.apis_enrich in ("query", "ci") else "auto",
                               [a for a in (settings.apis_field_expiry, cls_attr) if a])
        fields = detect_api_fields(cis, settings)
    seen = sorted({k for c in cis for k, v in (c.get("properties") or {}).items() if v not in (None, "")})
    # nomes do .env que não são atributos deste tipo: dizer logo, em vez de os ignorar ou enviar
    known = {a["name"] for a in cls_attrs} | {k for c in cis for k in (c.get("properties") or {})}
    env_fields = {"CERTWATCH_APIS_FIELD_NAME": settings.apis_field_name, "CERTWATCH_APIS_FIELD_EXPIRY": settings.apis_field_expiry,
                  "CERTWATCH_APIS_FIELD_APP": settings.apis_field_app, "CERTWATCH_APIS_FIELD_LOCATION": settings.apis_field_location}
    wrong = [f"{var}={val}" for var, val in env_fields.items() if val and val not in known]
    wrong += [f"CERTWATCH_APIS_CREATE_DEFAULTS: {k}" for k in settings.apis_create_defaults if k not in known]
    if wrong and cls_attrs:
        raise WriteError("O .env tem nomes que não são atributos do tipo " + ci_type + ": " + "; ".join(wrong)
                         + ". Retire essas linhas (ou corrija o nome) e reinicie. Os nomes certos estão em Sistema > "
                           "Ligação à UCMDB > Ver atributos das APIs.")
    in_type = {a["name"] for a in cls_dates}
    date_like = sorted({k for c in cis for k, v in (c.get("properties") or {}).items() if v not in (None, "") and _is_date(v)})
    if fields.get("nome") and fields["nome"] not in seen:
        fields["nome"] = None                         # definido no .env mas nenhuma API o tem
    if fields.get("validade") and fields["validade"] not in seen and fields["validade"] not in in_type:
        fields["validade"] = None
    if not fields.get("validade") and cls_attr:
        fields["validade"] = cls_attr
    if not fields.get("nome") or not fields.get("validade"):
        listed = ", ".join(f"{a['name']} ({a['label']})" if a.get("label") else a["name"] for a in cls_dates)
        raise WriteError("Não foi possível reconhecer na lista de APIs o atributo do "
                         + " e do ".join(x for x, k in (("nome", "nome"), ("fim da validade", "validade")) if not fields.get(k))
                         + f". Foram lidas {len(cis)} APIs pela REST API. Atributos com valor: {', '.join(seen[:60]) or 'nenhum'}. "
                         + (f"Com datas: {', '.join(date_like)}. " if date_like else "")
                         + (f"Atributos de data do tipo {ci_type} na UCMDB: {listed}. " if listed else
                            f"Não consegui ler os atributos do tipo {ci_type} ({cls_note or 'sem atributos de data'}). ")
                         + "Indique o atributo no .env (CERTWATCH_APIS_FIELD_EXPIRY=<atributo>) e reinicie.")
    # obrigatórios que são a aplicação ou a localização: são esses os campos (o Atalaia Cert preenche-os)
    required = [x["name"] for x in cls_attrs if x.get("required")]
    for key, rx in (("aplicacao", APP_KEY), ("localizacao", LOCATION_KEY)):
        if not fields.get(key):
            cand = [a for a in required if rx.search(a) or rx.search(labels_of(cls_attrs).get(a, ""))]
            if cand:
                fields[key] = cand[0]
    types = Counter(c.get("type") for c in cis if c.get("type"))
    props = set()
    for c in cis[:50]:
        props.update((c.get("properties") or {}).keys())
    locs = Counter(str((c.get("properties") or {}).get(fields["localizacao"]) or "") for c in cis) if fields.get("localizacao") else Counter()
    azure_locs = [(n, l) for l, n in locs.items() if "azure" in l.lower() and "secret" in l.lower()]
    location = max(azure_locs)[1] if azure_locs else AZURE_API_LOCATION
    # atributos obrigatórios do tipo (modelo de classes) e valores que todas as APIs existentes partilham
    mapped = {v for v in fields.values() if v} | {"display_label", "description"}
    name_attrs = [a for a in ("name",) if a != fields["nome"] and (a in props or any(x["name"] == a for x in cls_attrs))]
    common: dict[str, tuple] = {}
    for k in props:
        vals = [v for c in cis if (v := (c.get("properties") or {}).get(k)) not in (None, "") and isinstance(v, (str, int, float, bool))]
        if vals:
            val, cnt = Counter(vals).most_common(1)[0]
            common[k] = (val, cnt, len(vals), len(set(vals)))
    skip = re.compile(r"name|label|descr|url|uri|global_id|ucmdb|create|modif|time|date|data|secret|password|token|key$", re.I)
    labels = {a["name"]: a.get("label") or "" for a in cls_attrs}
    fixed, missing = {}, []
    for a in [x["name"] for x in cls_attrs if x.get("required")]:
        if a in mapped or a in name_attrs or a in settings.apis_create_defaults:
            continue
        c = common.get(a)
        if c and c[1] * 2 >= len(cis):           # metade ou mais das APIs têm o mesmo valor
            fixed[a] = c[0]
        else:
            missing.append(a)
    fixed.update(settings.apis_create_defaults)
    # para tentar de novo se a UCMDB disser que falta um obrigatório (quando o modelo de classes não diz quais são):
    # os atributos preenchidos em todas as APIs, com poucos valores diferentes
    retry = {k: c[0] for k, c in common.items()
             if c[2] == len(cis) and c[3] <= 5 and k not in mapped and k not in fixed and k not in name_attrs
             and not skip.search(k) and not _internal(k)}
    return {"type": types.most_common(1)[0][0], "fields": fields, "props": props, "location": location,
            "name_attrs": name_attrs, "fixed": fixed, "missing": missing, "retry": retry, "labels": labels,
            "required": [x["name"] for x in cls_attrs if x.get("required")], "cls_note": cls_note}


def _retry_required(us: UcmdbSession, plan: Plan, attrs: dict, out: Outcome, ctx: AzureContext,
                    settings: Settings) -> Outcome:
    """"Not all required attributes are provided": tenta de novo com os atributos que todas as APIs têm iguais;
    se ainda falhar, diz o que foi enviado e o que pode faltar."""
    if "required" not in (out.detalhe or "").lower() or ctx.api is None:
        return out
    api = ctx.api
    extra = {k: v for k, v in api["retry"].items() if k not in out.enviado}
    note = ""
    if extra:
        plan.fixos.update(extra)
        again = execute(us, plan, attrs, settings)
        note = "Faltavam atributos obrigatórios: foram preenchidos como em todas as outras APIs (" + \
               ", ".join(f"{k}={v}" for k, v in extra.items()) + "). "
        again.detalhe = note + (again.detalhe or "")
        if again.estado != "erro" or "required" not in again.detalhe.lower():
            return again
        out = again
    lab = api["labels"]
    req = [a for a in api["required"] if a not in out.enviado]
    out.detalhe += (f" Enviados: {', '.join(sorted(out.enviado))}."
                    + (f" Obrigatórios no tipo {api['type']} que não foram enviados: "
                       + ", ".join(f"{a} ({lab[a]})" if lab.get(a) else a for a in req) + "." if req else
                       f" O modelo de classes do tipo {api['type']} não indica quais são os obrigatórios"
                       + (f" ({api['cls_note']})" if api.get("cls_note") else "") + ".")
                    + " Indique os que faltam no .env (CERTWATCH_APIS_CREATE_DEFAULTS=atributo=valor;outro=valor) e reinicie."
                    " O pormenor do erro fica nos logs do servidor UCMDB, não no Atalaia Cert.")
    return out


def plan_azure(us: UcmdbSession, row: dict, lista: str, acao: str, ctx: AzureContext,
               settings: Settings) -> tuple[Plan, dict[str, str]]:
    nome, fim = row["nome"], row.get("fim") or ""
    if lista == "apis":
        if ctx.api is None:
            ctx.api = api_model(us, settings)
        f, props = ctx.api["fields"], ctx.api["props"]
        col_attr = {"Name": f["nome"], "ValidTo": f["validade"]}
        if f.get("aplicacao"):
            col_attr["Aplicação"] = f["aplicacao"]
        if f.get("localizacao"):
            col_attr["Localização"] = f["localizacao"]
        if "display_label" in props and f["nome"] != "display_label":
            col_attr["Display Label"] = "display_label"
        if "description" in props:
            col_attr["Description"] = "description"
        if acao == "atualizar":
            alvo = row.get("alvo")
            cur = next((c for c in row.get("cmdb") or [] if c["ucmdb_id"] == alvo), None)
            if not alvo or cur is None:
                raise WriteError("Há mais de um registo para este nome na lista de APIs: atualize à mão (Editar).")
            return Plan("atualizar", nome, ucmdb_id=alvo, campos={"ValidTo": fim}, esperado={"ValidTo": cur["data"]}), \
                {"ValidTo": f["validade"]}
        campos = {"Name": nome, "ValidTo": fim, "Aplicação": row.get("app") or nome,
                  "Localização": ctx.api["location"], "Display Label": nome,
                  "Description": f"{settings.final_description} - novo segredo do Azure ({row.get('tipo_credencial') or 'credencial'}"
                                 + (f", KeyId {row['key_id']}" if row.get("key_id") else "") + ")"}
        if ctx.api["missing"]:
            lab = ctx.api["labels"]
            raise WriteError("A UCMDB exige estes atributos para criar uma API e as APIs existentes não têm um valor comum: "
                             + ", ".join(f"{a} ({lab[a]})" if lab.get(a) else a for a in ctx.api["missing"])
                             + ". Indique o valor no .env: CERTWATCH_APIS_CREATE_DEFAULTS=atributo=valor;outro=valor e reinicie.")
        fixos = {**ctx.api["fixed"], **{a: nome for a in ctx.api["name_attrs"]}}
        return Plan("criar", nome, ci_type=ctx.api["type"], campos={c: v for c, v in campos.items() if c in col_attr},
                    fixos=fixos), col_attr
    # lista de certificados
    col_attr = ctx.col_attr
    if acao == "atualizar":
        alvo = row.get("alvo")
        cur = next((c for c in row.get("cmdb") or [] if c["ucmdb_id"] == alvo), None)
        if not alvo or cur is None:
            raise WriteError("Há mais de um certificado com este nome: atualize à mão (Editar).")
        return Plan("atualizar", nome, ucmdb_id=alvo, campos={"ValidTo": fim}, esperado={"ValidTo": cur["data"]}), col_attr
    campos = {"Display Label": nome, "Name": nome, "CommonName": nome, "ValidTo": fim, "Issuer": "Por verificar",
              "IssuerName": "Por verificar", "SerialNumber": next_placeholder_serial(ctx.state, ctx.used),
              "Certificate Status": "Ativo", "Localização": "AZURE", "Certificate Type": "SSL",
              "Description": f"{settings.final_description} - novo certificado (Azure, App Registration {nome})"}
    return Plan("criar", nome, ci_type=settings.ucmdb_cert_type,
                campos={c: v for c, v in campos.items() if c in col_attr}), col_attr


def queue_azure(session: Session, run: FinalRun, chave: int, lista: str, actor: str) -> str:
    if session.scalar(select(UcmdbWrite.id).where(UcmdbWrite.estado.in_(BUSY)).limit(1)) is not None:
        raise WriteError("Já há escritas na UCMDB a decorrer. Aguarde que terminem.")
    row = next((x for x in ((run.vistas or {}).get("azure") or []) if x["chave"] == chave), None)
    if row is None:
        raise WriteError("Linha do Azure não encontrada nesta reconciliação.")
    if lista not in ("apis", "certificados"):
        raise WriteError("Escolha a lista: APIs ou certificados.")
    if row["estado"] == "novo":
        acao = "criar"
    elif row["estado"] == "data_posterior" and row.get("alvo"):
        acao = "atualizar"
    else:
        raise WriteError("Esta linha não tem nada para aplicar automaticamente: use Editar.")
    done = session.scalar(select(UcmdbWrite.id).where(UcmdbWrite.run_id == run.id, UcmdbWrite.parte == "azure",
                                                      UcmdbWrite.chave == chave, UcmdbWrite.estado.in_(DONE)).limit(1))
    if done is not None:
        raise WriteError("Esta linha do Azure já foi aplicada na UCMDB.")
    lote = uuid.uuid4().hex[:12]
    session.add(UcmdbWrite(run_id=run.id, chave=chave, lote=lote, parte="azure", lista=lista, acao=acao,
                           cn=row["nome"], estado="pendente", por=actor))
    return lote


NOT_IN_TQL = "não aparece no TQL"


def check_created_in_tql(us: UcmdbSession, settings: Settings, write_ids: list[int]) -> None:
    """Um certificado criado tem de aparecer no TQL dos certificados ativos (a leitura da CMDB do Atalaia Cert e da
    reconciliação). Se não aparecer, a escrita fica com aviso: foi criado, mas ninguém o vai ver."""
    if not settings.ucmdb_tql:
        return
    with session_scope() as s:
        created = [w for w in s.scalars(select(UcmdbWrite).where(UcmdbWrite.id.in_(write_ids)))
                   if w.acao == "criar" and w.parte == "cert" and w.estado in DONE and w.ucmdb_id]
        if not created:
            return
        try:
            seen = {str(c.get("ucmdbId")) for c in us.topology(settings.ucmdb_tql)}
        except UcmdbError as exc:
            log.warning("Não foi possível confirmar no TQL os certificados criados: %s", exc)
            return
        for w in created:
            if w.ucmdb_id not in seen:
                w.estado = "aviso"
                w.detalhe = (f"{w.detalhe} Atenção: criado na UCMDB, mas {NOT_IN_TQL} {settings.ucmdb_tql} (os certificados "
                             "ativos): a importação da CMDB não o vai ver e continua a dar \"em uso sem registo na CMDB\". "
                             "Veja \"Porquê?\" no histórico de alterações.").strip()


def why_not_in_tql(settings: Settings, ucmdb_id: str, client: httpx.Client | None = None) -> dict:
    """Compara um CI que o TQL não devolve com os certificados que o TQL devolve: tipo e atributos em que difere
    da (quase) totalidade deles. Só leitura."""
    from collections import Counter
    with UcmdbSession(settings, client) as us:
        ci = us.ci(ucmdb_id)
        props = ci.get("properties") or {}
        tql = us.topology(settings.ucmdb_tql)
        in_tql = any(str(c.get("ucmdbId")) == str(ucmdb_id) for c in tql)
        sample = [str(c.get("ucmdbId")) for c in tql[:40] if c.get("ucmdbId")]
        others = []
        for cid in sample:
            try:
                others.append(us.ci(cid))
            except UcmdbError:
                continue
    diffs = []
    types = Counter(o.get("type") for o in others)
    if others and ci.get("type") and types and ci.get("type") not in types:
        diffs.append({"atributo": "tipo do CI", "este": ci.get("type"), "outros": ", ".join(f"{t} ({n})" for t, n in types.most_common(3))})
    n = len(others)
    keys = {k for o in others for k in (o.get("properties") or {})}
    for k in sorted(keys):
        if k in ("display_label", "name", "global_id", "create_time", "last_modified_time", "description") or \
                re.search(r"date|time|valid|serial|common_name|issuer|subject|label|id$", k, re.I):
            continue
        vals = [str((o.get("properties") or {}).get(k)) for o in others if (o.get("properties") or {}).get(k) not in (None, "")]
        if n and len(vals) >= 0.9 * n:
            top, cnt = Counter(vals).most_common(1)[0]
            mine = props.get(k)
            if cnt >= 0.9 * n and str(mine) != top:
                diffs.append({"atributo": k, "este": "(vazio)" if mine in (None, "") else str(mine)[:80],
                              "outros": f"{top[:80]} (em {cnt} de {n})"})
    return {"ci": ucmdb_id, "tipo": ci.get("type"), "cn": props.get("common_name") or props.get("display_label") or "",
            "no_tql": in_tql, "tql": settings.ucmdb_tql, "amostra": n, "diferencas": diffs}


def process_in_background(lote: str, settings: Settings) -> None:
    threading.Thread(target=process, args=(lote, settings), name=f"ucmdb-{lote}", daemon=True).start()


def writes_for_run(session: Session, run_id: int, parte: str = "cert") -> dict[int, UcmdbWrite]:
    """A escrita mais recente de cada alteração (ou linha do Azure) da reconciliação."""
    out: dict[int, UcmdbWrite] = {}
    for w in session.scalars(select(UcmdbWrite).where(UcmdbWrite.run_id == run_id, UcmdbWrite.parte == parte)
                             .order_by(UcmdbWrite.id)):
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


ORIGINS = {"reconciliacao": "Reconciliação", "azure": "Azure", "edicao": "Edição à mão"}
RESULTS = {"aplicado": "Aplicadas", "aviso": "Com aviso", "erro": "Com erro", "ignorado": "Não aplicadas", "fila": "Na fila"}


def origin_of(w: UcmdbWrite) -> str:
    if not w.run_id:
        return "edição à mão"
    if w.parte == "azure":
        lista = {"apis": "lista de APIs", "certificados": "lista de certificados"}.get(w.lista or "", "")
        return f"Azure, reconciliação #{w.run_id}" + (f" ({lista})" if lista else "")
    return f"reconciliação #{w.run_id}"


def history_rows(writes: list[UcmdbWrite]) -> list[dict]:
    """Escritas para o histórico: o que mudou em cada certificado (atributo: antes -> enviado)."""
    out = []
    for w in writes:
        mud = []
        for attr, v in (w.enviado or {}).items():
            before = (w.antes or {}).get(attr)
            mud.append({"atributo": attr, "antes": "" if before is None else str(before), "depois": "" if v is None else str(v)})
        out.append({"w": w, "mudancas": mud, "origem": origin_of(w)})
    return out


def history_conditions(q: str = "", ci: str = "", por: str = "", origem: str = "", resultado: str = "",
                       acao: str = "", de: datetime | None = None, ate: datetime | None = None) -> list:
    """Filtros do histórico de alterações na UCMDB (para a página e para a exportação)."""
    from sqlalchemy import func as sfunc
    conds = []
    if q.strip():
        ql = f"%{q.strip().lower()}%"
        conds.append(sfunc.lower(UcmdbWrite.cn).like(ql) | (UcmdbWrite.ucmdb_id == q.strip()))
    if ci.strip():
        conds.append(UcmdbWrite.ucmdb_id == ci.strip())
    if por.strip():
        conds.append(UcmdbWrite.por == por.strip())
    if origem == "edicao":
        conds.append(UcmdbWrite.run_id.is_(None))
    elif origem == "azure":
        conds.append(UcmdbWrite.parte == "azure")
    elif origem == "reconciliacao":
        conds.append(UcmdbWrite.run_id.is_not(None) & (sfunc.coalesce(UcmdbWrite.parte, "cert") != "azure"))
    states = {"aplicado": DONE, "aviso": ("aviso",), "erro": ("erro",), "ignorado": ("ignorado",), "fila": BUSY}.get(resultado)
    if states:
        conds.append(UcmdbWrite.estado.in_(states))
    if acao in ("criar", "atualizar"):
        conds.append(UcmdbWrite.acao == acao)
    if de is not None:
        conds.append(UcmdbWrite.pedido_em >= de)
    if ate is not None:
        conds.append(UcmdbWrite.pedido_em < ate)
    return conds




def api_type_report(settings: Settings, client: httpx.Client | None = None) -> dict:
    """Só leitura: os atributos do tipo de CI das APIs (modelo de classes + o que as APIs têm) e o que o Atalaia Cert
    envia ao criar uma API. Para escolher CERTWATCH_APIS_FIELD_EXPIRY e CERTWATCH_APIS_CREATE_DEFAULTS."""
    from collections import Counter
    from .fontes.ucmdb import SENSITIVE_KEY, class_attributes, enrich_cis, safe_properties
    if not settings.ucmdb_tql_apis:
        raise WriteError("Defina CERTWATCH_UCMDB_TQL_APIS (a lista de APIs).")
    with UcmdbSession(settings, client) as us:
        model, erro = None, ""
        try:
            model = api_model(us, settings)
        except WriteError as exc:
            erro = str(exc)
        cis = us.topology(settings.ucmdb_tql_apis)
        ci_type = model["type"] if model else (Counter(c.get("type") for c in cis if c.get("type")).most_common(1) or [("", 0)])[0][0]
        attrs, note = class_attributes(us, ci_type)
        cis, _, _ = enrich_cis(us, cis, "auto", [a["name"] for a in attrs if re.search(r"date|time", a["type"], re.I)][:20])
    cis = [{**c, "properties": safe_properties(c.get("properties") or {})} for c in cis]   # nunca mostrar segredos
    n = len(cis)
    uses: dict[str, str] = {}
    if model:
        f = model["fields"]
        for k, label in (("nome", "nome"), ("validade", "fim da validade"), ("aplicacao", "aplicação"),
                         ("localizacao", "localização"), ("expirado", "expirado?"), ("registo", "data de registo")):
            if f.get(k):
                uses.setdefault(f[k], f"lido como {label}")
        for a in model["name_attrs"]:
            uses.setdefault(a, "enviado com o nome da API")
        for a, v in model["fixed"].items():
            uses[a] = f"enviado sempre com \"{v}\"" + (" (.env)" if a in settings.apis_create_defaults else " (o valor da maioria)")
        for a, v in model["retry"].items():
            uses.setdefault(a, f"enviado com \"{v}\" se a UCMDB disser que falta um obrigatório")
        for a in model["missing"]:
            uses[a] = "obrigatório sem valor: definir em CERTWATCH_APIS_CREATE_DEFAULTS"
    names = [a["name"] for a in attrs] or sorted({k for c in cis for k in (c.get("properties") or {})})
    by = {a["name"]: a for a in attrs}
    rows = []
    for k in names:
        vals = [v for c in cis if (v := (c.get("properties") or {}).get(k)) not in (None, "")]
        common = Counter(str(v)[:60] for v in vals if isinstance(v, (str, int, float, bool))).most_common(1)
        rows.append({"name": k, "label": (by.get(k) or {}).get("label", ""), "type": (by.get(k) or {}).get("type", ""),
                     "required": bool((by.get(k) or {}).get("required")), "filled": len(vals),
                     "common": f"{common[0][0]} ({common[0][1]})" if common and not SENSITIVE_KEY.search(k) else "",
                     "uso": uses.get(k, "")})
    rows.sort(key=lambda r: (not r["required"], not r["uso"], r["name"]))
    return {"type": ci_type, "n": n, "rows": rows, "model_note": note, "erro": erro}

"""Interface web e API de leitura."""
from __future__ import annotations

import csv
import json
import io
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote, urlencode
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from .. import __version__
from ..checks import CHECK_BY_ID, CHECKS, LAYERS, STATUS_LABELS, evaluate_endpoint
from ..collectors.smax import configured as smax_configured
from ..collectors.ssllabs import GOOD_GRADES, GRADE_ORDER, report_url
from ..classify import (AUTO_RENEW_HELP, AUTO_RENEW_LABELS, SCOPE_HELP, SCOPE_LABELS, TYPE_HELP, TYPE_LABELS,
                        cert_type, is_auto_renew, scope_of)
from ..config import get_settings
from ..db import as_utc, init_db, session_scope, utcnow
from ..evaluator import FINDING_CHECK, FINDING_TYPES, SEV_RANK, SEVERITIES, days_left, load_snapshot
from ..insights import STATE_LABELS, ancestry, build_inventory, check_matrix, check_totals, dashboard_stats
from ..jobs import apis_configured, JOBS, enqueue
from ..collectors.ct import SOURCE_LABELS
from ..discovery import CT_STATE_HELP, CT_STATES, CT_TABS, TRIAGE_LABELS, classify_ct
from ..models import (ApiRecord, AuditLog, Certificate, CmdbRecord, CtCert, Endpoint, FinalInput, FinalPublish,
                      FinalPublishFile, FinalRun, Finding, ImportFile, JobRun, ScanResult, SslLabsResult, TicketBatch, SmaxTicket)
from .. import ticket_create as tc
from .. import cmdb_final as cf
from ..collectors.smax import ticket_url
from ..tickets import TICKET_HELP, TICKET_STATES, TICKET_VIEWS, ticket_list, tickets_by_label, link as ticket_link, tickets_by_endpoint
from ..reconcile import REC_HELP, REC_STATES, REC_TABS, scan_import_dir, reconcile
from ..trust import local_trust_files
from ..normalize import norm_label, split_api_name, is_ip, is_valid_hostname, norm_host, norm_issuer
from .security import check_csrf, current_user, security_middleware

BASE = Path(__file__).parent
MONTHS = ["jan", "fev", "mar", "abr", "mai", "jun", "jul", "ago", "set", "out", "nov", "dez"]
JOB_LABELS = {"pipeline": "Executar tudo", "ingest_cmdb": "Importar certificados da CMDB",
              "ingest_apis": "Importar lista de APIs", "ingest_imports": "Ler ficheiros de reconciliação",
              "ingest_smax": "Ler pedidos do SMAX",
              "ingest_ct": "Procurar na internet (CT)", "scan": "Verificar servidores",
              "ssllabs": "Avaliação externa (SSL Labs)", "evaluate": "Reavaliar regras"}
JOB_HELP = {"pipeline": "Faz todos os passos pela ordem: CMDB, APIs, ficheiros, SMAX, internet, servidores, SSL Labs e regras.",
            "ingest_cmdb": "Lê os certificados da UCMDB (nome, validade e emissor).",
            "ingest_apis": "Lê a lista de APIs da UCMDB.",
            "ingest_imports": "Lê os ficheiros CA1, CA2, AVI e Azure da diretoria de importação.",
            "ingest_smax": "Lê os pedidos (changes) de certificados do SMAX, só leitura.",
            "ingest_ct": "Consulta crt.sh, Cert Spotter e ctlogs.dev para os domínios configurados.",
            "scan": "Liga-se a cada servidor e recolhe o certificado e a cadeia.",
            "ssllabs": "Pede ao Qualys SSL Labs a nota dos nomes externos (demora 1 a 2 minutos por nome).",
            "evaluate": "Volta a aplicar as regras e atualiza os alertas, sem novas ligações."}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if not get_settings().admin_password:
        raise RuntimeError("Defina o segredo admin_password antes de arrancar a interface web")
    init_db()
    yield


app = FastAPI(title="certwatch", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.middleware("http")(security_middleware)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")


def _tz() -> ZoneInfo:
    return ZoneInfo(get_settings().timezone)


def fmt_dt(value, with_time: bool = False) -> str:
    if not value:
        return "—"
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    local = as_utc(value).astimezone(_tz())
    return local.strftime("%d-%m-%Y %H:%M" if with_time else "%d-%m-%Y")


templates.env.filters["dt"] = fmt_dt
templates.env.filters["dtt"] = lambda v: fmt_dt(v, True)
templates.env.globals.update(
    FINDING_TYPES=FINDING_TYPES, FINDING_CHECK=FINDING_CHECK, SEVERITIES=SEVERITIES, version=__version__,
    TYPE_LABELS=TYPE_LABELS, TYPE_HELP=TYPE_HELP, SCOPE_LABELS=SCOPE_LABELS, SCOPE_HELP=SCOPE_HELP,
    AUTO_RENEW_LABELS=AUTO_RENEW_LABELS, AUTO_RENEW_HELP=AUTO_RENEW_HELP, ssllabs_report=report_url,
    TICKET_STATES=TICKET_STATES, TICKET_HELP=TICKET_HELP,
    STATE_LABELS=STATE_LABELS, STATUS_LABELS=STATUS_LABELS, CHECKS=CHECKS, CHECK_BY_ID=CHECK_BY_ID,
    LAYERS=LAYERS, MONTHS=MONTHS, JOB_LABELS=JOB_LABELS, JOB_HELP=JOB_HELP,
    CT_STATES=CT_STATES, CT_TABS=CT_TABS, CT_SOURCE_LABELS=SOURCE_LABELS, CT_STATE_HELP=CT_STATE_HELP, TRIAGE_LABELS=TRIAGE_LABELS,
    REC_STATES=REC_STATES, REC_TABS=REC_TABS, REC_HELP=REC_HELP,
    FINAL_FILES=cf.FILES, FINAL_FILE_LABELS=cf.FILE_LABELS, LIVE_LABELS=cf.LIVE_LABELS,
    COMPARE_VIEWS=cf.COMPARE_VIEWS, COMPARE_HELP=cf.COMPARE_HELP,
)

_NAV_CACHE: dict = {"at": 0.0, "data": None}


def nav_counts() -> dict:
    """Contadores da navegação lateral (cache de 30 s para não pesar em cada página)."""
    if _NAV_CACHE["data"] is not None and time.monotonic() - _NAV_CACHE["at"] < 30:
        return _NAV_CACHE["data"]
    data = {"alertas": 0, "alertas_altos": 0, "ct_por_triar": 0, "reconc_dif": 0}
    try:
        settings = get_settings()
        with session_scope() as s:
            sevs = [f.severity for f in s.scalars(select(Finding).where(Finding.status == "aberto"))]
            data["alertas"] = len(sevs)
            data["alertas_altos"] = sum(1 for x in sevs if x in ("alta", "critica"))
            if s.scalar(select(CtCert.id).limit(1)) is not None:
                data["ct_por_triar"] = sum(1 for r in classify_ct(s, settings)
                                           if r["state"] != "na_cmdb" and r["ct"].triage == "por_triar" and not r["expired"])
            if s.scalar(select(ImportFile.id).where(ImportFile.is_current.is_(True)).limit(1)) is not None:
                c = reconcile(s, settings)["counts"]
                data["reconc_dif"] = c.get("novo", 0) + c.get("data_posterior", 0) + c.get("data_anterior", 0)
    except Exception:
        pass
    _NAV_CACHE.update(at=time.monotonic(), data=data)
    return data


def invalidate_nav() -> None:
    _NAV_CACHE["data"] = None


def render(request: Request, name: str, user: str, **ctx):
    return templates.TemplateResponse(request, name, {"user": user, "csrf": request.state.csrf, "nav": nav_counts(), **ctx})


def csv_response(filename: str, header: list[str], rows: list[list]) -> Response:
    """CSV para Excel PT (BOM UTF-8, ponto e vírgula), com proteção contra injeção de fórmulas."""
    def safe(v):
        s = "" if v is None else str(v)
        return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";", lineterminator="\r\n")
    w.writerow(header)
    for r in rows:
        w.writerow([safe(v) for v in r])
    return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def safe_next(value: str | None, default: str) -> str:
    """Só permite redirecionar para caminhos locais."""
    if value and value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    return default


def audit(s, actor: str, action: str, target: str = "", **details) -> None:
    s.add(AuditLog(actor=actor, action=action, target=target[:600], details=details))


# ------------------------------------------------------------------ páginas
@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"estado": "ok"}


def _last_ok(s, key: str):
    """Última execução em que o passo `key` correu sem erro (job próprio ou dentro do pipeline)."""
    for jr in s.scalars(select(JobRun).where(JobRun.status.in_(("ok", "error"))).order_by(JobRun.id.desc()).limit(40)):
        part = (jr.summary or {}).get(key)
        if isinstance(part, dict) and "erro" not in part:
            return jr, part
    return None, None


def setup_checklist(s, settings, stats) -> list[dict]:
    items = []
    jr, part = _last_ok(s, "ingest_cmdb")
    items.append({"ok": bool(jr), "title": "Certificados importados da CMDB",
                  "hint": (f"{part.get('recebidos', 0)} registos em {fmt_dt(jr.finished_at, True)}" if jr else
                           "Ainda não houve uma importação bem-sucedida. Veja o erro em Execuções e auditoria.")})
    trust = local_trust_files(settings)
    items.append({"ok": bool(trust), "title": "Raiz interna de confiança configurada",
                  "hint": (", ".join(f.name for f in trust) if trust else
                           "Coloque a raiz da PKI interna em trust/ (ver README, secção 1.2).")})
    items.append({"ok": stats["ep_verified"] > 0, "title": "Servidores verificados",
                  "hint": (f"{stats['ep_tls_ok']} de {stats['ep_total']} responderam por TLS" if stats["ep_verified"] else
                           "Execute a verificação em Execuções e auditoria.")})
    if apis_configured(settings):
        jr, part = _last_ok(s, "ingest_apis")
        com = part.get("com_validade") if jr else None
        items.append({"ok": bool(jr) and bool(com), "title": "Lista de APIs importada",
                      "hint": (f"{part.get('recebidos', 0)} APIs, {com} com data de expiração "
                               f"({ {'tql': 'TQL', 'topologyQuery': 'REST, consulta ad-hoc', 'ci': 'REST, CI a CI', 'ficheiro': 'ficheiro'}.get((part.get('campos') or {}).get('metodo'), 'TQL') })"
                               if jr else "Ainda não importada com sucesso.")})
    else:
        items.append({"ok": None, "title": "Lista de APIs", "hint": "Opcional: definir CERTWATCH_UCMDB_TQL_APIS no .env."})
    if smax_configured(settings):
        jr, part = _last_ok(s, "ingest_smax")
        items.append({"ok": bool(jr), "title": "Pedidos do SMAX",
                      "hint": (f"{part.get('tickets', 0)} pedidos lidos, {part.get('abertos', 0)} abertos" if jr
                               else "Ainda não lidos com sucesso. Ver Execuções e auditoria.")})
    else:
        items.append({"ok": None, "title": "Pedidos do SMAX",
                      "hint": "Opcional: definir CERTWATCH_SMAX_URL, CERTWATCH_SMAX_TENANT e os segredos smax_user/smax_password."})
    if settings.ct_domains:
        jr, part = _last_ok(s, "ingest_ct")
        items.append({"ok": bool(jr), "title": "Procura na internet",
                      "hint": (f"{', '.join(settings.ct_domains)}: {part.get('total', 0)} certificados conhecidos" if jr else
                               f"Domínios: {', '.join(settings.ct_domains)}. Ainda sem resultados; o servidor precisa de saída para a internet.")})
    else:
        items.append({"ok": None, "title": "Procura na internet", "hint": "Opcional: definir CERTWATCH_CT_DOMAINS no .env."})
    if settings.ssllabs_email:
        n_ext = s.query(SslLabsResult).filter(SslLabsResult.status == "READY").count()
        items.append({"ok": bool(n_ext), "title": "Avaliação externa SSL Labs",
                      "hint": f"{n_ext} nomes externos com nota" if n_ext else "Ainda sem notas; corre na próxima execução completa."})
    else:
        items.append({"ok": None, "title": "Avaliação externa SSL Labs",
                      "hint": "Opcional: registar um email da organização e definir CERTWATCH_SSLLABS_EMAIL."})
    files = list(s.scalars(select(ImportFile).where(ImportFile.is_current.is_(True))))
    items.append({"ok": True if files else None, "title": "Ficheiros de reconciliação",
                  "hint": (", ".join(f"{f.source}: {f.name}" for f in files) if files else
                           "Opcional: colocar exportações CA1*, CA2*, AVI* e Azure* na diretoria import/.")})
    folder = cf.folder_status(settings)
    items.append({"ok": True if folder["existe"] and folder["gravavel"] else (False if folder["existe"] else None),
                  "title": "Pasta de rede para atualizar a CMDB",
                  "hint": ("Montada, com escrita." if folder["existe"] and folder["gravavel"] else
                           folder["detalhe"] if folder["existe"] else
                           "Opcional: definir CERTWATCH_PUBLISH_HOST_DIR no .env (ver README 5.1).")})
    last = s.scalar(select(JobRun).where(JobRun.job == "pipeline", JobRun.requested_by == "agendador",
                                         JobRun.status.in_(("ok", "error"))).order_by(JobRun.id.desc()).limit(1))
    recent = last is not None and last.finished_at and as_utc(last.finished_at) > utcnow() - timedelta(hours=26)
    items.append({"ok": bool(recent), "title": f"Execução automática diária às {settings.pipeline_daily_at}",
                  "hint": (f"Última: {fmt_dt(last.finished_at, True)} ({last.status})" if last else
                           "Ainda não correu automaticamente. Confirme que o worker está ativo.")})
    return items


@app.get("/")
def dashboard(request: Request, user: str = Depends(current_user)):
    now, settings = utcnow(), get_settings()
    with session_scope() as s:
        snap = load_snapshot(s)
        inv = build_inventory(s, settings, now, snap)
        matrix = check_matrix(s, settings, now, snap)
        stats = dashboard_stats(inv, matrix, now)
        open_findings = list(s.scalars(select(Finding).where(Finding.status == "aberto")))
        last_jobs = list(s.scalars(select(JobRun).order_by(JobRun.id.desc()).limit(5)))
        n_apis = len(snap.apis)
        setup = setup_checklist(s, settings, stats)
    sev_counts = {sv: sum(1 for f in open_findings if f.severity == sv) for sv in SEVERITIES}
    urgent = [r for r in inv if r["state"] == "falha"][:12]
    soon30 = sum(1 for r in inv if r["dias"] is not None and 0 <= r["dias"] <= 30)
    soon30_sem_pedido = sum(1 for r in inv if r["dias"] is not None and 0 <= r["dias"] <= 30
                            and r["smax"]["state"] != "em_curso")
    with session_scope() as s:
        _, tcounts = ticket_list(s, settings, "atrasados")
    # Renovações: certificados ativos (não expirados) e a situação do pedido no SMAX
    active = [r for r in inv if r["dias"] is not None and r["dias"] >= 0]
    renew = {"ativos": len(active),
             "em_curso": sum(1 for r in active if r["smax"]["state"] == "em_curso"),
             "outra_data": sum(1 for r in active if r["smax"]["state"] == "outra_data"),
             "sem": sum(1 for r in active if r["smax"]["state"] in ("fechado", "sem_pedido")),
             "sem_30": soon30_sem_pedido, "atrasados": tcounts["atrasados"]}
    return render(request, "dashboard.html", user, s=stats, sev_counts=sev_counts, urgent=urgent, setup=setup,
                  last_jobs=last_jobs, n_apis=n_apis, n_open=len(open_findings), soon30=soon30,
                  soon30_sem_pedido=soon30_sem_pedido, smax_on=smax_configured(settings), renew=renew)


@app.get("/pesquisa")
def pesquisa(request: Request, q: str = "", user: str = Depends(current_user)):
    q = q.strip()
    certs, eps, cts = [], [], []
    if q:
        ql = q.lower()
        with session_scope() as s:
            inv = build_inventory(s, get_settings(), utcnow())
            certs = [r for r in inv if ql in r["cn"] or ql in r["common_name"].lower()
                     or any(ql in i.lower() for i in r["issuers"]) or ql in (r["live_issuer"] or "").lower()
                     or any(ql in a.lower() for a in r["apis"])][:100]
            eps = [e for e in s.scalars(select(Endpoint)) if ql in e.host or ql in e.expected_cn_norm][:50]
            cts = [c for c in s.scalars(select(CtCert)) if any(ql in n for n in c.names or [])][:50]
        if len(certs) == 1 and not cts and len(eps) <= 1:
            return RedirectResponse(f"/certificados/detalhe?cn={quote(certs[0]['cn'])}", status_code=303)
    return render(request, "pesquisa.html", user, q=q, certs=certs, eps=eps, cts=cts)


TICKET_FILTERS = {"em_curso": "Com pedido em curso", "nao_em_curso": "Sem pedido em curso",
                  "outra_data": "Pedido aberto para outra data", "fechado": "Só pedidos fechados", "sem_pedido": "Nenhum pedido"}


CERT_FILTERS = {"proprio": "Com certificado próprio", "outro": "Servidos por outro certificado (wildcard ou vários nomes)",
                "partilhado": "Certificados instalados em vários sites"}


def _inventory_filtered(q: str, dias: str, estado: str, tipo: str, ambito: str, renovacao: str, pedido: str = "",
                        servido: str = ""):
    with session_scope() as s:
        rows = build_inventory(s, get_settings(), utcnow())
    total = len(rows)
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in r["cn"] or any(ql in i.lower() for i in r["issuers"])
                or ql in (r["live_issuer"] or "").lower() or any(ql in a.lower() for a in r["apis"])
                or any(ql == x["id"].lower() for x in r["smax"]["open"] + r["smax"]["closed"])]
    # Prazo: "≤ N dias" = de hoje até N dias (sem os já expirados); -1 = só expirados; "ativos" = não expirados
    if dias == "ativos":
        rows = [r for r in rows if r["dias"] is not None and r["dias"] >= 0]
    elif dias.lstrip("-").isdigit():
        lim = int(dias)
        rows = [r for r in rows if r["dias"] is not None and (r["dias"] < 0 if lim < 0 else 0 <= r["dias"] <= lim)]
    if estado in STATE_LABELS:
        rows = [r for r in rows if r["state"] == estado]
    if tipo in TYPE_LABELS:
        rows = [r for r in rows if r["type"] == tipo]
    if ambito in SCOPE_LABELS:
        rows = [r for r in rows if r["scope"] == ambito]
    if renovacao in AUTO_RENEW_LABELS:
        rows = [r for r in rows if r["renovacao"] == renovacao]
    if servido == "proprio":
        rows = [r for r in rows if not r["servido_por"]]
    elif servido == "outro":
        rows = [r for r in rows if r["servido_por"]]
    elif servido == "partilhado":
        rows = [r for r in rows if len({s["host"] for s in r["instalado_em"]}) > 1]
    if pedido == "nao_em_curso":
        rows = [r for r in rows if r["smax"]["state"] != "em_curso"]
    elif pedido in TICKET_STATES:
        rows = [r for r in rows if r["smax"]["state"] == pedido]
    return rows, total


@app.get("/certificados")
def certificados(request: Request, q: str = "", dias: str = "", estado: str = "", tipo: str = "", ambito: str = "",
                 renovacao: str = "", pedido: str = "", servido: str = "", user: str = Depends(current_user)):
    rows, total = _inventory_filtered(q, dias, estado, tipo, ambito, renovacao, pedido, servido)
    return render(request, "certificados.html", user, rows=rows, total=total, q=q, dias=dias,
                  estado=estado, tipo=tipo, ambito=ambito, renovacao=renovacao, pedido=pedido, servido=servido,
                  cert_filters=CERT_FILTERS,
                  ticket_filters=TICKET_FILTERS, smax_on=smax_configured(get_settings()),
                  create_on=tc.can_create(get_settings()),
                  export_qs=urlencode({k: v for k, v in dict(q=q, dias=dias, estado=estado, tipo=tipo, ambito=ambito,
                                                                 renovacao=renovacao, pedido=pedido, servido=servido).items() if v}))


@app.get("/certificados/exportar")
def certificados_csv(q: str = "", dias: str = "", estado: str = "", tipo: str = "", ambito: str = "",
                     renovacao: str = "", pedido: str = "", servido: str = "", user: str = Depends(current_user)):
    rows, _ = _inventory_filtered(q, dias, estado, tipo, ambito, renovacao, pedido, servido)
    return csv_response("certificados.csv",
                        ["Certificado", "Estado", "Tipo", "Âmbito", "Renovação automática", "Dias", "Expira",
                         "Data de", "Emissor (servidor)", "Emissores (CMDB)", "Situação", "Registos CMDB", "APIs",
                         "Pedido SMAX", "Situação do pedido", "Fase do pedido", "Pedidos abertos", "Link do pedido",
                         "Servido pelo certificado", "Instalado em"],
                        [[r["common_name"], STATE_LABELS.get(r["state"], r["state"]), TYPE_LABELS.get(r["type"], r["type"]),
                          SCOPE_LABELS.get(r["scope"], r["scope"]), "Sim" if r["renovacao"] == "auto" else "Não",
                          r["dias"], fmt_dt(r["live_not_after"] or r["cmdb_valid_to"]),
                          {"live": "servidor", "cmdb": "CMDB"}.get(r["fonte_data"], ""), r["live_issuer"] or "",
                          ", ".join(r["issuers"]), r["summary"], r["registos"], ", ".join(r["apis"]),
                          (r["smax"]["main"] or {}).get("id", ""), r["smax"]["label"], (r["smax"]["main"] or {}).get("fase", ""),
                          ", ".join(x["id"] for x in r["smax"]["open"]), (r["smax"]["main"] or {}).get("url", ""),
                          (r["servido_por"] or {}).get("nome", ""),
                          ", ".join(sorted({x["host"] for x in r["instalado_em"]}))]
                         for r in rows])


@app.get("/certificados/detalhe")
def certificado_detalhe(request: Request, cn: str, user: str = Depends(current_user)):
    settings, now = get_settings(), utcnow()
    with session_scope() as s:
        snap = load_snapshot(s, include_disabled=True)
        recs = sorted(snap.by_cn.get(cn, []), key=lambda r: as_utc(r.valid_to) or now, reverse=True)
        inactive = list(s.scalars(select(CmdbRecord).where(CmdbRecord.cn_norm == cn, CmdbRecord.active.is_(False))))
        eps = [e for e in snap.endpoints if e.expected_cn_norm == cn]
        apis = [a for a in snap.apis if a.host == cn]
        if not recs and not eps and not inactive:
            raise HTTPException(404, "Certificado não encontrado")
        latest = snap.latest_by_issuer(cn)
        ep_data = []
        for ep in eps:
            sr = snap.scan_for(ep)
            leaf = snap.leaf_for(sr)
            ev = evaluate_endpoint(ep, sr, leaf, latest or snap.latest_for(ep, leaf), settings, now)
            history = list(s.scalars(select(ScanResult).where(ScanResult.endpoint_id == ep.id)
                                     .order_by(ScanResult.id.desc()).limit(10)))
            chain_up = ancestry(s, settings, leaf.sha256)[0] if leaf else []
            ep_data.append({"ep": ep, "scan": sr, "leaf": leaf, "ev": ev, "history": history, "chain_up": chain_up})
        findings = list(s.scalars(select(Finding).where(Finding.cn_norm == cn).order_by(Finding.status, Finding.last_seen.desc())))
        kind = recs[0].kind if recs else (inactive[0].kind if inactive else "host")
        leaf0 = next((d["leaf"] for d in ep_data if d["leaf"]), None)
        sr0 = next((d["scan"] for d in ep_data if d["leaf"]), None)
        issuer_norm = norm_issuer(leaf0.issuer_cn) if leaf0 else (recs[0].issuer_norm if recs else "")
        ctype = cert_type(cn, kind, is_api=bool(apis), issuer_norm=issuer_norm,
                          common_name=recs[0].common_name if recs else cn)
        scope = scope_of(cn, kind, settings, issuer_norm=issuer_norm, resolved_ip=sr0.resolved_ip if sr0 else "")
        auto_cmdb = any(is_auto_renew(settings, r.issuer, r.issuer_name) for r in recs)
        auto_live = bool(leaf0) and is_auto_renew(settings, leaf0.issuer_dn, leaf0.issuer_cn)
        ext = s.scalar(select(SslLabsResult).where(SslLabsResult.host == cn))
        inv_row = next((r for r in build_inventory(s, settings, now, snap) if r["cn"] == cn), None)
        servido_por = inv_row["servido_por"] if inv_row else None
        instalado_em = inv_row["instalado_em"] if inv_row else []
        effective = leaf0.not_after if leaf0 else (recs[0].valid_to if recs else None)
        smax = inv_row["smax"] if inv_row else ticket_link(tickets_by_endpoint(s).get(cn, []), effective, settings)
    return render(request, "certificado.html", user, smax=smax, smax_on=smax_configured(settings),
                  servido_por=servido_por, instalado_em=instalado_em,
                  create_on=tc.can_create(settings), cn=cn, recs=recs, inactive=inactive, eps=ep_data, apis=apis,
                  findings=findings, ctype=ctype, scope=scope, now=now, ext=ext, ssllabs_on=bool(settings.ssllabs_email),
                  auto_renew="auto" if (auto_cmdb or auto_live) else "manual",
                  auto_src=", ".join(x for x, ok in (("CMDB", auto_cmdb), ("servidor", auto_live)) if ok),
                  max_until=(now + timedelta(days=365)).astimezone(_tz()).strftime("%Y-%m-%d"))


@app.get("/cert/{sha256}")
def cert_page(request: Request, sha256: str, user: str = Depends(current_user)):
    settings = get_settings()
    with session_scope() as s:
        up, node = ancestry(s, settings, sha256)
        if node is None:
            raise HTTPException(404, "Certificado não encontrado")
        cert = s.get(Certificate, sha256)
        cmdb_refs = []
        if node.is_ca:
            cmdb_refs = list(s.scalars(select(CmdbRecord).where(
                CmdbRecord.active.is_(True), CmdbRecord.issuer_norm == norm_issuer(node.subject_cn)
            ).order_by(CmdbRecord.valid_to).limit(300)))
    return render(request, "cert.html", user, node=node, up=up, cert=cert, cmdb_refs=cmdb_refs, now=utcnow(),
                  days_left=days_left)


@app.get("/testes")
def testes(request: Request, teste: str = "", estado: str = "", tipo: str = "", ambito: str = "", q: str = "",
           user: str = Depends(current_user)):
    with session_scope() as s:
        matrix = check_matrix(s, get_settings(), utcnow())
    totals = check_totals(matrix)
    rows = matrix
    if teste in CHECK_BY_ID:
        rows = [r for r in rows if r.results.get(teste) and r.results[teste].status in (("falha", "aviso") if not estado else (estado,))]
    elif estado in STATUS_LABELS:
        rows = [r for r in rows if r.worst == estado]
    if tipo in TYPE_LABELS:
        rows = [r for r in rows if r.type == tipo]
    if ambito in SCOPE_LABELS:
        rows = [r for r in rows if r.scope == ambito]
    if q:
        rows = [r for r in rows if q.lower() in r.ep.host or q.lower() in r.ep.expected_cn_norm]
    with session_scope() as s:
        ext = sorted(s.scalars(select(SslLabsResult)), key=lambda r: (
            -(GRADE_ORDER.index(r.grade) if r.grade in GRADE_ORDER else -1), r.host))
    return render(request, "testes.html", user, matrix=matrix, rows=rows[:500], n_rows=len(rows), totals=totals,
                  teste=teste, estado=estado, tipo=tipo, ambito=ambito, q=q, ext=ext,
                  ssllabs_on=bool(get_settings().ssllabs_email), GOOD_GRADES=GOOD_GRADES)


@app.get("/testes/como-funciona")
def catalogo(request: Request, user: str = Depends(current_user)):
    return render(request, "catalogo.html", user)


API_VIEWS = {"": "Todos", "expirados": "Expirados", "90": "Expiram em 90 dias",
             "90_sem_pedido": "Expiram em 90 dias sem pedido em curso", "sem_data": "Sem data de expiração",
             "divergentes": "CMDB diz outra coisa"}


def _api_rows(settings, now, s, vista: str = "", q: str = ""):
    snap = load_snapshot(s)
    inv = {r["cn"]: r for r in build_inventory(s, settings, now, snap)}
    from ..tickets import last_comments
    by_label, comments = tickets_by_label(s), last_comments(s)
    rows = []
    for a in snap.apis:
        dl = days_left(a.expiry, now) if a.expiry else None
        base, suffix = split_api_name(a.name)
        computed_expired = dl is not None and dl < 0
        rows.append({"api": a, "dias": dl, "nome": base or a.name, "sufixo": suffix,
                     "divergente": a.cmdb_expired is not None and dl is not None and a.cmdb_expired != computed_expired,
                     "smax": ticket_link(by_label.get(norm_label(a.name), []), a.expiry, settings, comments),
                     "servidor": inv.get(a.host) if a.host else None})
    counts = {"": len(rows), "expirados": sum(1 for r in rows if r["dias"] is not None and r["dias"] < 0),
              "90": sum(1 for r in rows if r["dias"] is not None and 0 <= r["dias"] <= 90),
              "sem_data": sum(1 for r in rows if r["dias"] is None),
              "divergentes": sum(1 for r in rows if r["divergente"]),
              "90_sem_pedido": sum(1 for r in rows if r["dias"] is not None and 0 <= r["dias"] <= 90
                                   and r["smax"]["state"] != "em_curso")}
    if vista == "expirados":
        rows = [r for r in rows if r["dias"] is not None and r["dias"] < 0]
    elif vista == "90":
        rows = [r for r in rows if r["dias"] is not None and 0 <= r["dias"] <= 90]
    elif vista == "sem_data":
        rows = [r for r in rows if r["dias"] is None]
    elif vista == "divergentes":
        rows = [r for r in rows if r["divergente"]]
    elif vista == "90_sem_pedido":
        rows = [r for r in rows if r["dias"] is not None and 0 <= r["dias"] <= 90 and r["smax"]["state"] != "em_curso"]
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in " ".join((r["api"].name, r["api"].application, r["api"].location,
                                                   r["api"].url)).lower()]
    # Primeiro o que está para expirar, depois os expirados (mais recentes primeiro), por fim sem data
    rows.sort(key=lambda r: (r["dias"] is None, r["dias"] is not None and r["dias"] < 0,
                             abs(r["dias"]) if r["dias"] is not None else 0, r["nome"].lower()))
    return rows, counts


@app.get("/apis")
def apis_page(request: Request, vista: str = "", q: str = "", user: str = Depends(current_user)):
    settings, now = get_settings(), utcnow()
    vista = vista if vista in API_VIEWS else ""
    with session_scope() as s:
        rows, counts = _api_rows(settings, now, s, vista, q)
        last = s.scalar(select(JobRun).where(JobRun.job.in_(("ingest_apis", "pipeline")), JobRun.status != "pending")
                        .order_by(JobRun.id.desc()).limit(1))
        summary = (last.summary or {}).get("ingest_apis", {}) if last else {}
    return render(request, "apis.html", user, rows=rows, counts=counts, vista=vista, q=q, views=API_VIEWS,
                  configured=apis_configured(settings), tql=settings.ucmdb_tql_apis,
                  campos=summary.get("campos") if isinstance(summary, dict) else None,
                  resumo=summary if isinstance(summary, dict) else {},
                  any_host=any(r["api"].host for r in rows), smax_on=smax_configured(settings))


@app.get("/apis/exportar")
def apis_csv(vista: str = "", q: str = "", user: str = Depends(current_user)):
    settings, now = get_settings(), utcnow()
    with session_scope() as s:
        rows, _ = _api_rows(settings, now, s, vista if vista in API_VIEWS else "", q)
        data = [[r["api"].name, r["api"].application, r["api"].location, fmt_dt(r["api"].expiry, True), r["dias"],
                 {True: "Sim", False: "Não"}.get(r["api"].cmdb_expired, ""), fmt_dt(r["api"].registered_at, True),
                 r["api"].url, r["api"].ucmdb_id, (r["smax"]["main"] or {}).get("id", ""), r["smax"]["label"],
                 (r["smax"]["main"] or {}).get("url", "")] for r in rows]
    return csv_response("apis.csv", ["Nome", "Aplicação", "Localização", "Data de expiração", "Dias",
                                     "Expirado? (CMDB)", "Registo na CMDB", "URL", "UCMDB ID", "Pedido SMAX",
                                     "Situação do pedido", "Link do pedido"], data)


# ------------------------------------------------------------------ pedidos SMAX (criação)
def _batch_or_404(s, batch_id: int):
    b = s.get(TicketBatch, batch_id)
    if b is None:
        raise HTTPException(404, "Lote não encontrado")
    return b


@app.post("/pedidos/novo")
async def pedidos_novo(request: Request, user: str = Depends(current_user)):
    form = await request.form()
    check_csrf(request, form.get("csrf"))
    settings = get_settings()
    if not tc.can_create(settings):
        raise HTTPException(409, " ".join(tc.config_problems(settings)))
    if form.get("modo") == "vista":
        rows, _ = _inventory_filtered(*(str(form.get(k) or "") for k in ("q", "dias", "estado", "tipo", "ambito",
                                                                          "renovacao", "pedido", "servido")))
        cns = [r["cn"] for r in rows]
    else:
        cns = [str(c) for c in form.getlist("cn")]
    try:
        with session_scope() as s:
            batch = tc.create_batch(s, cns, user, settings)
            s.flush()
            bid = batch.id
    except tc.TicketError as exc:
        return render(request, "pedido_erro.html", user, message=str(exc), back=safe_next(str(form.get("next") or ""), "/certificados"))
    return RedirectResponse(f"/pedidos/{bid}", status_code=303)


@app.get("/pedidos")
def pedidos_smax(request: Request, vista: str = "abertos", q: str = "", user: str = Depends(current_user)):
    settings = get_settings()
    vista = vista if vista in TICKET_VIEWS else "abertos"
    with session_scope() as s:
        rows, counts = ticket_list(s, settings, vista, q)
        n_lotes = s.query(TicketBatch).count()
        fetched = s.scalar(select(SmaxTicket.fetched_at).limit(1))
    return render(request, "pedidos_smax.html", user, rows=rows[:1000], n_rows=len(rows), counts=counts, vista=vista,
                  q=q, views=TICKET_VIEWS, n_lotes=n_lotes, fetched=fetched, smax_on=smax_configured(settings))


@app.get("/pedidos/lotes")
def pedidos(request: Request, user: str = Depends(current_user)):
    settings = get_settings()
    with session_scope() as s:
        batches = list(s.scalars(select(TicketBatch).order_by(TicketBatch.id.desc()).limit(100)))
        counts = {}
        for b in batches:
            ds = tc.drafts_of(s, b.id)
            counts[b.id] = {"total": len(ds), "incluidos": sum(1 for d in ds if d.include),
                            "criados": sum(1 for d in ds if d.status == "criado"),
                            "problemas": sum(1 for d in ds if d.status in ("falhou", "indeterminado"))}
    return render(request, "pedidos.html", user, batches=batches, counts=counts, problems=tc.config_problems(settings),
                  BATCH_STATES=tc.BATCH_STATES)


@app.get("/pedidos/{batch_id}")
def pedido_lote(request: Request, batch_id: int, user: str = Depends(current_user)):
    settings = get_settings()
    tc.mark_stale(batch_id)
    with session_scope() as s:
        b = _batch_or_404(s, batch_id)
        drafts = tc.drafts_of(s, batch_id)
        errors = {d.id: tc.validate(d, settings) for d in drafts}
    chosen = [d for d in drafts if d.include]
    return render(request, "pedido_lote.html", user, b=b, drafts=drafts, errors=errors,
                  n_incl=len(chosen), n_ok=sum(1 for d in chosen if not errors[d.id]),
                  envs=list(settings.smax_env_codes), tipos=settings.smax_type_options,
                  FIELDS=tc.FIELDS, FIELD_LABELS=tc.FIELD_LABELS, BATCH_STATES=tc.BATCH_STATES,
                  DRAFT_STATES=tc.DRAFT_STATES, DRAFT_HELP=tc.DRAFT_HELP, problems=tc.config_problems(settings),
                  ticket_url=lambda i: ticket_url(settings, i))


@app.post("/pedidos/{batch_id}/guardar")
async def pedido_guardar(request: Request, batch_id: int, user: str = Depends(current_user)):
    form = await request.form()
    check_csrf(request, form.get("csrf"))
    try:
        with session_scope() as s:
            b = _batch_or_404(s, batch_id)
            tc.update_drafts(s, b, {k: str(v) for k, v in form.items()}, get_settings())
    except tc.TicketError as exc:
        raise HTTPException(409, str(exc))
    dest = f"/pedidos/{batch_id}/rever" if form.get("acao") == "rever" else f"/pedidos/{batch_id}"
    return RedirectResponse(dest, status_code=303)


@app.post("/pedidos/{batch_id}/aplicar")
async def pedido_aplicar(request: Request, batch_id: int, user: str = Depends(current_user)):
    form = await request.form()
    check_csrf(request, form.get("csrf"))
    try:
        with session_scope() as s:
            b = _batch_or_404(s, batch_id)
            tc.apply_all(s, b, {k: str(form.get(k) or "") for k in tc.FIELDS}, only_empty=form.get("so_vazios") == "1")
    except tc.TicketError as exc:
        raise HTTPException(409, str(exc))
    return RedirectResponse(f"/pedidos/{batch_id}", status_code=303)


@app.get("/pedidos/{batch_id}/rever")
def pedido_rever(request: Request, batch_id: int, user: str = Depends(current_user)):
    settings = get_settings()
    with session_scope() as s:
        b = _batch_or_404(s, batch_id)
        drafts = [d for d in tc.drafts_of(s, batch_id) if d.include]
    if b.status != "rascunho":
        return RedirectResponse(f"/pedidos/{batch_id}", status_code=303)
    if not drafts or any(tc.validate(d, settings) for d in drafts):
        return RedirectResponse(f"/pedidos/{batch_id}", status_code=303)
    previews = [(d, tc.build_payload(d, settings)) for d in drafts]
    return render(request, "pedido_rever.html", user, b=b, previews=previews, problems=tc.config_problems(settings),
                  json_pretty=lambda o: json.dumps(o, ensure_ascii=False, indent=2))


@app.post("/pedidos/{batch_id}/criar")
def pedido_criar(request: Request, batch_id: int, csrf: str = Form(""), confirmo: str = Form(""), n: str = Form(""),
                 user: str = Depends(current_user)):
    check_csrf(request, csrf)
    settings = get_settings()
    with session_scope() as s:
        _batch_or_404(s, batch_id)
        expected = sum(1 for d in tc.drafts_of(s, batch_id) if d.include)
    if confirmo != "1" or n != str(expected):
        raise HTTPException(400, "Confirmação em falta ou o número de pedidos mudou entretanto; reveja o lote.")
    try:
        tc.start(batch_id, user, settings)
    except tc.TicketError as exc:
        return render(request, "pedido_erro.html", user, message=str(exc), back=f"/pedidos/{batch_id}")
    tc.execute_in_background(batch_id, user, settings)
    invalidate_nav()
    return RedirectResponse(f"/pedidos/{batch_id}", status_code=303)


@app.post("/pedidos/{batch_id}/cancelar")
def pedido_cancelar(request: Request, batch_id: int, csrf: str = Form(""), user: str = Depends(current_user)):
    check_csrf(request, csrf)
    with session_scope() as s:
        b = _batch_or_404(s, batch_id)
        if b.status != "rascunho":
            raise HTTPException(409, "Só um rascunho pode ser cancelado.")
        b.status, b.finished_at = "cancelado", utcnow()
        audit(s, user, "pedidos.lote_cancelado", f"lote {batch_id}")
    return RedirectResponse("/pedidos/lotes", status_code=303)


@app.post("/pedidos/{batch_id}/repetir")
def pedido_repetir(request: Request, batch_id: int, csrf: str = Form(""), user: str = Depends(current_user)):
    check_csrf(request, csrf)
    try:
        with session_scope() as s:
            b = _batch_or_404(s, batch_id)
            new = tc.retry_batch(s, b, user, get_settings())
            s.flush()
            nid = new.id
    except tc.TicketError as exc:
        return render(request, "pedido_erro.html", user, message=str(exc), back=f"/pedidos/{batch_id}")
    return RedirectResponse(f"/pedidos/{nid}", status_code=303)


@app.get("/findings")
def findings_page(request: Request, status: str = "aberto", sev: str = "", tipo: str = "", q: str = "",
                  user: str = Depends(current_user)):
    with session_scope() as s:
        stmt = select(Finding)
        if status in ("aberto", "aceite", "resolvido"):
            stmt = stmt.where(Finding.status == status)
        if sev in SEV_RANK:
            stmt = stmt.where(Finding.severity == sev)
        if tipo in FINDING_TYPES:
            stmt = stmt.where(Finding.type == tipo)
        items = list(s.scalars(stmt.order_by(Finding.last_seen.desc()).limit(2000)))
    if q:
        ql = q.lower()
        items = [f for f in items if ql in f.subject.lower() or ql in f.cn_norm]
    items.sort(key=lambda f: (-SEV_RANK.get(f.severity, 0), f.subject))
    max_until = (utcnow() + timedelta(days=365)).astimezone(_tz()).strftime("%Y-%m-%d")
    return render(request, "findings.html", user, items=items, status=status, sev=sev, tipo=tipo, q=q, max_until=max_until)


@app.post("/findings/{fid}/aceitar")
def finding_accept(request: Request, fid: str, reason: str = Form(...), until: str = Form(...),
                   csrf: str = Form(""), next: str = Form(""), user: str = Depends(current_user)):
    check_csrf(request, csrf)
    reason = reason.strip()
    if len(reason) < 10:
        raise HTTPException(400, "Justificação demasiado curta (mínimo 10 caracteres)")
    try:
        until_dt = datetime.strptime(until, "%Y-%m-%d").replace(hour=23, minute=59, tzinfo=_tz())
    except ValueError:
        raise HTTPException(400, "Data inválida")
    if until_dt <= utcnow() or until_dt > utcnow() + timedelta(days=366):
        raise HTTPException(400, "A aceitação tem de expirar entre amanhã e 1 ano")
    with session_scope() as s:
        f = s.get(Finding, fid)
        if f is None:
            raise HTTPException(404)
        f.status, f.accepted_until, f.accepted_by, f.accept_reason = "aceite", until_dt, user, reason
        audit(s, user, "finding.aceitar", f.subject, finding=fid, tipo=f.type, ate=until, motivo=reason)
    invalidate_nav()
    return RedirectResponse(safe_next(next, "/findings"), status_code=303)


@app.post("/findings/{fid}/reabrir")
def finding_reopen(request: Request, fid: str, csrf: str = Form(""), next: str = Form(""), user: str = Depends(current_user)):
    check_csrf(request, csrf)
    with session_scope() as s:
        f = s.get(Finding, fid)
        if f is None:
            raise HTTPException(404)
        if f.status == "aceite":
            f.status, f.accepted_until = "aberto", None
            audit(s, user, "finding.reabrir", f.subject, finding=fid)
    return RedirectResponse(safe_next(next, "/findings"), status_code=303)


@app.get("/endpoints")
def endpoints_page(request: Request, q: str = "", user: str = Depends(current_user)):
    with session_scope() as s:
        eps = list(s.scalars(select(Endpoint).order_by(Endpoint.host, Endpoint.port)))
        scan_ids = [e.last_scan_id for e in eps if e.last_scan_id]
        scans = {x.id: x for x in s.scalars(select(ScanResult).where(ScanResult.id.in_(scan_ids)))} if scan_ids else {}
    if q:
        eps = [e for e in eps if q.lower() in e.host or q.lower() in e.expected_cn_norm]
    s_cfg = get_settings()
    return render(request, "endpoints.html", user, eps=eps, scans=scans, q=q,
                  allowed_ports=s_cfg.scan_allowed_ports, default_port=s_cfg.scan_default_port)


@app.post("/endpoints")
def endpoint_add(request: Request, host: str = Form(...), port: int = Form(443), expected_cn: str = Form(""),
                 note: str = Form(""), csrf: str = Form(""), user: str = Depends(current_user)):
    check_csrf(request, csrf)
    h = norm_host(host)
    if not (is_valid_hostname(h) or is_ip(h)):
        raise HTTPException(400, "Hostname ou IP inválido")
    if port not in get_settings().scan_allowed_ports:
        raise HTTPException(400, "Porta não permitida")
    exp = norm_host(expected_cn) if expected_cn.strip() else h
    with session_scope() as s:
        ep = s.scalar(select(Endpoint).where(Endpoint.host == h, Endpoint.port == port))
        if ep is None:
            ep = Endpoint(host=h, port=port, expected_cn_norm=exp, source="manual", note=note[:500])
            s.add(ep)
        else:
            ep.expected_cn_norm, ep.enabled, ep.note = exp, True, note[:500] or ep.note
        audit(s, user, "endpoint.adicionar", f"{h}:{port}", cn_esperado=exp)
    return RedirectResponse("/endpoints", status_code=303)


@app.post("/endpoints/{eid}/alternar")
def endpoint_toggle(request: Request, eid: int, csrf: str = Form(""), next: str = Form(""), user: str = Depends(current_user)):
    check_csrf(request, csrf)
    with session_scope() as s:
        ep = s.get(Endpoint, eid)
        if ep is None:
            raise HTTPException(404)
        ep.enabled = not ep.enabled
        audit(s, user, "endpoint.ativar" if ep.enabled else "endpoint.desativar", f"{ep.host}:{ep.port}")
    return RedirectResponse(safe_next(next, "/endpoints"), status_code=303)


@app.get("/jobs")
def jobs_page(request: Request, user: str = Depends(current_user)):
    with session_scope() as s:
        runs = list(s.scalars(select(JobRun).order_by(JobRun.id.desc()).limit(50)))
        audits = list(s.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(50)))
    st = get_settings()
    jobs = [j for j in JOBS if (j != "ingest_apis" or apis_configured(st)) and (j != "ingest_ct" or st.ct_domains)
            and (j != "ssllabs" or st.ssllabs_email) and (j != "ingest_smax" or smax_configured(st))]
    return render(request, "jobs.html", user, runs=runs, audits=audits, jobs=jobs, daily_at=st.pipeline_daily_at)


@app.post("/jobs/{job}")
def job_enqueue(request: Request, job: str, csrf: str = Form(""), next: str = Form(""), user: str = Depends(current_user)):
    check_csrf(request, csrf)
    if job not in JOBS:
        raise HTTPException(404)
    jid = enqueue(job, user)
    with session_scope() as s:
        audit(s, user, "job.pedir", job, job_id=jid)
    invalidate_nav()
    return RedirectResponse(safe_next(next, "/jobs"), status_code=303)


# ------------------------------------------------------------------ descoberta (CT)
def _ct_filter(rows, estado, triagem, q, expirados):
    if not expirados:
        rows = [r for r in rows if not r["expired"]]
    if estado in CT_STATES:
        rows = [r for r in rows if r["state"] == estado]
    if triagem in TRIAGE_LABELS:
        rows = [r for r in rows if r["ct"].triage == triagem]
    if q:
        rows = [r for r in rows if any(q.lower() in n for n in r["ct"].names) or q.lower() in (r["ct"].issuer_cn or "").lower()]
    return rows


@app.get("/descoberta")
def descoberta(request: Request, estado: str = "", triagem: str = "", q: str = "", expirados: int = 0,
               user: str = Depends(current_user)):
    settings = get_settings()
    with session_scope() as s:
        all_rows = classify_ct(s, settings, include_expired=bool(expirados))
        total = s.query(CtCert).count()
        jr, part = _last_ok(s, "ingest_ct")
    if not estado and not triagem and not q:
        estado = "pendentes"
    base = [r for r in all_rows if expirados or not r["expired"]]
    counts = {k: sum(1 for r in base if r["state"] == k) for k in CT_STATES}
    pending = [r for r in base if r["state"] != "na_cmdb" and r["ct"].triage == "por_triar"]
    rows = pending if estado == "pendentes" else _ct_filter(all_rows, estado, triagem, q, expirados)
    if estado == "pendentes" and q:
        rows = _ct_filter(rows, "", "", q, expirados)
    return render(request, "descoberta.html", user, rows=rows[:1000], n_rows=len(rows), counts=counts,
                  n_pending=len(pending), estado=estado, triagem=triagem, q=q, expirados=expirados, total=total,
                  domains=settings.ct_domains, sources=settings.ct_sources, last=jr, last_part=part)


@app.post("/descoberta/{cid}/triagem")
def descoberta_triagem(request: Request, cid: int, decisao: str = Form(...), nota: str = Form(""),
                       csrf: str = Form(""), next: str = Form(""), user: str = Depends(current_user)):
    check_csrf(request, csrf)
    if decisao not in TRIAGE_LABELS:
        raise HTTPException(400, "Decisão inválida")
    if decisao in ("ignorar", "investigar") and len(nota.strip()) < 5:
        raise HTTPException(400, "Indique o motivo (mínimo 5 caracteres)")
    with session_scope() as s:
        c = s.get(CtCert, cid)
        if c is None:
            raise HTTPException(404)
        c.triage, c.triage_note, c.triage_by, c.triage_at = decisao, nota.strip()[:2000], user, utcnow()
        audit(s, user, f"descoberta.{decisao}", c.primary_name, nomes=c.names[:10], nota=nota.strip()[:500])
    invalidate_nav()
    return RedirectResponse(safe_next(next, "/descoberta"), status_code=303)


@app.get("/descoberta/exportar")
def descoberta_exportar(triagem: str = "adicionar", user: str = Depends(current_user)):
    with session_scope() as s:
        rows = [r for r in classify_ct(s, get_settings(), include_expired=True)
                if triagem == "todos" or r["ct"].triage == triagem]
    return csv_response(f"certificados-internet-{triagem}.csv",
                        ["Nomes", "Emissor", "Válido desde", "Válido até", "Serial", "Situação na CMDB", "Triagem",
                         "Nota", "Decidido por", "Fontes"],
                        [[", ".join(r["ct"].names), r["ct"].issuer_cn, fmt_dt(r["ct"].not_before), fmt_dt(r["ct"].not_after),
                          r["ct"].serial_hex, CT_STATES[r["state"]], TRIAGE_LABELS.get(r["ct"].triage, r["ct"].triage),
                          r["ct"].triage_note, r["ct"].triage_by, ", ".join(r["ct"].sources)] for r in rows])


# ------------------------------------------------------------------ reconciliação
@app.get("/reconciliacao")
def reconciliacao(request: Request, estado: str = "", fonte: str = "", q: str = "", user: str = Depends(current_user)):
    settings = get_settings()
    with session_scope() as s:
        res = reconcile(s, settings)
        history = list(s.scalars(select(ImportFile).order_by(ImportFile.id.desc()).limit(20)))
        dir_files = scan_import_dir(settings)
        for f in dir_files:   # último resultado de leitura deste ficheiro (para mostrar erros de colunas, datas...)
            last = s.scalar(select(ImportFile).where(ImportFile.name == f["name"]).order_by(ImportFile.id.desc()).limit(1))
            f["last"] = last
            if last is not None and last.status == "erro":
                f["ok"] = False
                f["what"] += " — a última leitura falhou"
    rows = res["rows"]
    if not estado:
        estado = "diferencas"
    if estado == "diferencas":
        rows = [r for r in rows if r["state"] in ("novo", "data_posterior", "data_anterior", "so_na_cmdb")]
    elif estado in REC_STATES:
        rows = [r for r in rows if r["state"] == estado]
    if fonte:
        rows = [r for r in rows if r["source"] == fonte]
    if q:
        rows = [r for r in rows if q.lower() in r["cn_norm"]]
    n_diff = sum(res["counts"].get(k, 0) for k in ("novo", "data_posterior", "data_anterior", "so_na_cmdb"))
    return render(request, "reconciliacao.html", user, rows=rows[:2000], n_rows=len(rows), counts=res["counts"],
                  n_diff=n_diff, files=res["files"], history=history, estado=estado, fonte=fonte, q=q,
                  sources=sorted(settings.import_sources), prefixes=settings.import_sources,
                  import_dir=str(settings.import_dir), dir_files=dir_files)


@app.get("/reconciliacao/exportar")
def reconciliacao_exportar(estado: str = "diferencas", user: str = Depends(current_user)):
    with session_scope() as s:
        rows = reconcile(s, get_settings())["rows"]
    if estado == "diferencas":
        rows = [r for r in rows if r["state"] in ("novo", "data_posterior", "data_anterior", "so_na_cmdb")]
    elif estado in REC_STATES:
        rows = [r for r in rows if r["state"] == estado]
    return csv_response(f"reconciliacao-{estado}.csv",
                        ["Fonte", "Nome (CommonName ou App Registration)", "Situação", "Validade na fonte", "Validade na CMDB", "Validade no servidor",
                         "Servidor confirma a fonte", "Serial ou KeyId", "Emissor ou tipo de credencial", "SAN", "Encontrado na CMDB em",
                         "Ficheiro", "Linha"],
                        [[r["source"], r["cn"], REC_STATES[r["state"]], fmt_dt(r["valid_to"]), fmt_dt(r["cmdb_valid_to"]),
                          fmt_dt(r["live_valid_to"]), "sim" if r["live_confirma"] else "", r["serial"], r["issuer"],
                          r["san"], " e ".join(r.get("onde") or []), r["file"], r["row_no"] or ""] for r in rows])


# ------------------------------------------------------------------ CMDB final (CMDB_Final.xlsx, certs_update) e pasta de rede
FINAL_STATES = {"a_gerar": "A gerar", "pronto": "Pronto a publicar", "bloqueado": "CSV bloqueados", "erro": "Com erro"}
FINAL_VIEWS = {"alteracoes": "Alterações", "servidor": "Verificação no servidor", "erros": "Relatório de erros",
               "colunas": "Colunas"}


def _final_error(request: Request, user: str, message: str, back: str):
    return render(request, "final_erro.html", user, message=message, back=back)


def _run_or_404(s, run_id: int) -> FinalRun:
    run = s.get(FinalRun, run_id)
    if run is None:
        raise HTTPException(404)
    return run


def _stale_runs(s) -> None:
    for run in s.scalars(select(FinalRun).where(FinalRun.status == "a_gerar")):
        if utcnow() - as_utc(run.created_at) > cf.STALE_AFTER:
            run.status, run.error, run.finished_at = "erro", "Interrompido (o processo parou durante a geração).", utcnow()


@app.get("/cmdb-final")
def final_page(request: Request, user: str = Depends(current_user)):
    settings = get_settings()
    with session_scope() as s:
        _stale_runs(s)
        inputs = cf.current_inputs(s, settings)
        runs = list(s.scalars(select(FinalRun).order_by(FinalRun.id.desc()).limit(30)))
        for r in runs:
            s.expunge(r)
        last_pub = s.scalar(select(FinalPublish).order_by(FinalPublish.id.desc()).limit(1))
        if last_pub is not None:
            s.expunge(last_pub)
        cmdb_at = s.scalar(select(CmdbRecord.last_seen).order_by(CmdbRecord.last_seen.desc()).limit(1))
    folder = cf.folder_status(settings)
    latest = runs[0] if runs else None
    return render(request, "final.html", user, inputs=inputs, runs=runs, latest=latest, folder=folder,
                  last_pub=last_pub, cmdb_at=cmdb_at, settings=settings, FINAL_STATES=FINAL_STATES,
                  issuers={k: settings.import_issuers.get(k, "") for k in settings.final_sources})


@app.post("/cmdb-final/gerar")
def final_generate(request: Request, csrf: str = Form(""), user: str = Depends(current_user)):
    check_csrf(request, csrf)
    settings = get_settings()
    try:
        with session_scope() as s:
            _stale_runs(s)
            run = cf.start_run(s, user)
            run_id = run.id
            audit(s, user, "cmdb_final.gerar", f"geração {run_id}")
    except cf.FinalError as exc:
        return _final_error(request, user, str(exc), "/cmdb-final")
    cf.generate_in_background(run_id, settings)
    return RedirectResponse(f"/cmdb-final/{run_id}", status_code=303)


@app.post("/cmdb-final/fonte/{source}")
async def final_upload(request: Request, source: str, csrf: str = Form(""), ficheiro: UploadFile = File(...),
                       user: str = Depends(current_user)):
    check_csrf(request, csrf)
    settings = get_settings()
    source = source.upper()
    if source not in settings.final_sources:
        raise HTTPException(404)
    name = Path(ficheiro.filename or "").name[:200]
    data = await ficheiro.read(cf.MAX_UPLOAD + 1)
    if Path(name).suffix.lower() not in cf.ALLOWED_EXT:
        return _final_error(request, user, "Formato não aceite: use CSV ou Excel (.xlsx).", "/cmdb-final")
    if len(data) > cf.MAX_UPLOAD:
        return _final_error(request, user, f"Ficheiro demasiado grande (máximo {cf.MAX_UPLOAD // 1024 // 1024} MB).", "/cmdb-final")
    try:
        items, info = cf.read_source(source, name, data, utcnow().astimezone(_tz()).date())
    except Exception as exc:   # ficheiro ilegível ou sem as colunas esperadas
        return _final_error(request, user, f"Não foi possível usar o ficheiro de {source}: {exc}", "/cmdb-final")
    if not items:
        return _final_error(request, user, f"O ficheiro de {source} não tem linhas.", "/cmdb-final")
    import hashlib
    with session_scope() as s:
        s.add(FinalInput(source=source, name=name, sha256=hashlib.sha256(data).hexdigest(), size=len(data), data=data,
                         uploaded_by=user))
        audit(s, user, "cmdb_final.carregar", f"{source}: {name}", linhas=len(items), validas=info["validas"])
    return RedirectResponse("/cmdb-final", status_code=303)


@app.post("/cmdb-final/testar-pasta")
def final_test_folder(request: Request, csrf: str = Form(""), user: str = Depends(current_user)):
    check_csrf(request, csrf)
    ok, msg = cf.test_write(get_settings())
    with session_scope() as s:
        audit(s, user, "cmdb_final.testar_pasta", str(get_settings().publish_dir), ok=ok, detalhe=msg)
    return RedirectResponse(f"/cmdb-final?teste={'ok' if ok else 'falhou'}&msg={quote(msg)}#pasta", status_code=303)


@app.get("/cmdb-final/comparar")
def final_compare(request: Request, origem: str = "", vista: str = "diferencas", q: str = "", marcadas: int = 0,
                  user: str = Depends(current_user)):
    settings = get_settings()
    vista = vista if vista in cf.COMPARE_VIEWS else "diferencas"
    try:
        label, origem, data, choices = _compare_source(origem, settings)
    except cf.FinalError as exc:
        return _final_error(request, user, str(exc), "/cmdb-final")
    rows, counts, cmdb_at, err = [], {}, None, ""
    if data is not None:
        try:
            final_rows = cf.read_final_xlsx(data)
            with session_scope() as s:
                recs = list(s.scalars(select(CmdbRecord).where(CmdbRecord.active.is_(True))))
                cmdb_at = s.scalar(select(CmdbRecord.last_seen).order_by(CmdbRecord.last_seen.desc()).limit(1))
                for r in recs:
                    s.expunge(r)
            all_rows, counts = cf.compare_with_cmdb(final_rows, recs, _tz())
            rows = cf.filter_compare(all_rows, vista, q, bool(marcadas))
        except cf.FinalError as exc:
            err = str(exc)
        except Exception as exc:   # ficheiro que não é um Excel válido
            err = f"Não foi possível ler o ficheiro: {exc}"
    return render(request, "final_comparar.html", user, rows=rows[:3000], n_rows=len(rows), counts=counts, vista=vista,
                  q=q, marcadas=marcadas, origem=origem, label=label, choices=choices, cmdb_at=cmdb_at, err=err)


def _compare_source(origem: str, settings) -> tuple[str, str, bytes | None, list[tuple[str, str]]]:
    """Ficheiro CMDB_Final a comparar: uma geração, o que está na pasta de rede ou um carregado."""
    with session_scope() as s:
        runs = list(s.execute(select(FinalRun.id, FinalRun.created_at).where(FinalRun.xlsx.is_not(None))
                              .order_by(FinalRun.id.desc()).limit(15)))
        ups = list(s.execute(select(FinalInput.id, FinalInput.name, FinalInput.uploaded_at)
                             .where(FinalInput.source == "CMDB_FINAL").order_by(FinalInput.id.desc()).limit(5)))
        choices = [(f"geracao:{r.id}", f"Geração #{r.id} de {fmt_dt(r.created_at, True)}") for r in runs]
        folder_file = settings.publish_dir / cf.FILES["xlsx"]
        if folder_file.is_file():
            choices.append(("pasta", f"{cf.FILES['xlsx']} na pasta de rede"))
        choices += [(f"carregado:{u.id}", f"Carregado: {u.name} ({fmt_dt(u.uploaded_at, True)})") for u in ups]
        if not origem:
            origem = choices[0][0] if choices else ""
        if not origem:
            return "", "", None, choices
        kind, _, ident = origem.partition(":")
        if kind == "geracao" and ident.isdigit():
            run = s.get(FinalRun, int(ident))
            if run is None or run.xlsx is None:
                raise cf.FinalError("Essa geração já não tem o ficheiro (só se guardam as mais recentes).")
            return f"CMDB_Final.xlsx da geração #{run.id}", origem, run.xlsx, choices
        if kind == "pasta":
            try:
                return f"{cf.FILES['xlsx']} na pasta de rede", origem, folder_file.read_bytes(), choices
            except OSError as exc:
                raise cf.FinalError(f"Não foi possível ler o ficheiro da pasta de rede: {exc}")
        if kind == "carregado" and ident.isdigit():
            up = s.get(FinalInput, int(ident))
            if up is None or up.source != "CMDB_FINAL" or up.data is None:
                raise HTTPException(404)
            return f"{up.name} (carregado)", origem, up.data, choices
    raise HTTPException(404)


@app.post("/cmdb-final/comparar/carregar")
async def final_compare_upload(request: Request, csrf: str = Form(""), ficheiro: UploadFile = File(...),
                               user: str = Depends(current_user)):
    check_csrf(request, csrf)
    name = Path(ficheiro.filename or "").name[:200]
    data = await ficheiro.read(cf.MAX_UPLOAD + 1)
    if Path(name).suffix.lower() not in (".xlsx", ".xlsm") or len(data) > cf.MAX_UPLOAD:
        return _final_error(request, user, "Carregue um ficheiro Excel (.xlsx) até 25 MB.", "/cmdb-final/comparar")
    try:
        cf.read_final_xlsx(data)
    except Exception as exc:
        return _final_error(request, user, f"O ficheiro não pode ser comparado: {exc}", "/cmdb-final/comparar")
    import hashlib
    with session_scope() as s:
        up = FinalInput(source="CMDB_FINAL", name=name, sha256=hashlib.sha256(data).hexdigest(), size=len(data),
                        data=data, uploaded_by=user)
        s.add(up)
        s.flush()
        uid = up.id
    return RedirectResponse(f"/cmdb-final/comparar?origem=carregado:{uid}", status_code=303)


@app.get("/cmdb-final/comparar/exportar")
def final_compare_export(origem: str = "", vista: str = "diferencas", q: str = "", marcadas: int = 0,
                         user: str = Depends(current_user)):
    settings = get_settings()
    label, origem, data, _ = _compare_source(origem, settings)
    if data is None:
        raise HTTPException(404)
    with session_scope() as s:
        recs = list(s.scalars(select(CmdbRecord).where(CmdbRecord.active.is_(True))))
        for r in recs:
            s.expunge(r)
    rows, _ = cf.compare_with_cmdb(cf.read_final_xlsx(data), recs, _tz())
    rows = cf.filter_compare(rows, vista if vista in cf.COMPARE_VIEWS else "diferencas", q, bool(marcadas))
    estado = {"igual": "Igual", "diferente": "Diferente", "nao_existe": "Não existe na CMDB", "so_na_cmdb": "Só na CMDB"}
    d = lambda v: v.strftime("%d-%m-%Y") if v else ""
    return csv_response(f"comparacao-cmdb-{vista}.csv",
                        ["Linha no ficheiro", "CommonName", "Global Id", "Marcação no ficheiro", "Situação", "Diferenças",
                         "ValidTo no ficheiro", "ValidTo na CMDB", "Issuer no ficheiro", "Issuer na CMDB",
                         "IssuerName no ficheiro", "IssuerName na CMDB"],
                        [[r["linha"] or "", r["cn"], r["global_id"], r["cor"] or "", estado[r["estado"]],
                          ", ".join({"data": "data", "issuer": "Issuer", "issuer_name": "IssuerName"}[x] for x in r["dif"]),
                          d(r["f_validto"]) or str(r["f_validto_raw"] or ""), d(r["c_validto"]), r["f_issuer"], r["c_issuer"],
                          r["f_issuer_name"], r["c_issuer_name"]] for r in rows])


@app.get("/cmdb-final/{run_id}")
def final_run(request: Request, run_id: int, vista: str = "alteracoes", tipo: str = "", q: str = "",
              user: str = Depends(current_user)):
    settings = get_settings()
    vista = vista if vista in FINAL_VIEWS else "alteracoes"
    with session_scope() as s:
        _stale_runs(s)
        run = _run_or_404(s, run_id)
        newest = s.scalar(select(FinalRun.id).where(FinalRun.status.in_(("pronto", "bloqueado")))
                          .order_by(FinalRun.id.desc()).limit(1))
        pubs = list(s.scalars(select(FinalPublish).where(FinalPublish.run_id == run_id).order_by(FinalPublish.id.desc())))
        pub_files = {p.id: list(s.execute(select(FinalPublishFile.id, FinalPublishFile.name, FinalPublishFile.ok,
                                                 FinalPublishFile.error, FinalPublishFile.previous_sha256,
                                                 FinalPublishFile.previous_mtime)
                                          .where(FinalPublishFile.publish_id == p.id))) for p in pubs}
        sizes = {k: len(v) if v else 0 for k, v in (("xlsx", run.xlsx), ("csv", run.csv), ("csv_sem", run.csv_sem))}
        s.expunge(run)
        for p in pubs:
            s.expunge(p)
    changes = run.changes or []
    if tipo in ("novo", "alterado"):
        changes = [c for c in changes if c["tipo"] == tipo]
    if q:
        changes = [c for c in changes if q.lower() in (c["cn"] or "").lower() or q.lower() in (c["global_id"] or "").lower()]
    folder = cf.folder_status(settings) if run.status == "pronto" else None
    return render(request, "final_run.html", user, run=run, vista=vista, views=FINAL_VIEWS, changes=changes[:3000],
                  n_changes=len(changes), tipo=tipo, q=q, newest=newest, pubs=pubs, pub_files=pub_files, sizes=sizes,
                  folder=folder, FINAL_STATES=FINAL_STATES, settings=settings,
                  age_min=(utcnow() - as_utc(run.created_at)).total_seconds() / 60)


@app.get("/cmdb-final/{run_id}/ficheiro/{key}")
def final_download(run_id: int, key: str, user: str = Depends(current_user)):
    if key not in cf.FILES:
        raise HTTPException(404)
    with session_scope() as s:
        run = _run_or_404(s, run_id)
        data = cf.run_file(run, key)
        if data is None:
            raise HTTPException(404, "Ficheiro não disponível nesta geração.")
        audit(s, user, "cmdb_final.descarregar", f"geração {run_id}: {cf.FILES[key]}")
    media = ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" if key == "xlsx"
             else "text/csv; charset=utf-8")
    name = cf.FILES[key]
    return Response(data, media_type=media, headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.get("/cmdb-final/{run_id}/exportar/{what}")
def final_export(run_id: int, what: str, user: str = Depends(current_user)):
    with session_scope() as s:
        run = _run_or_404(s, run_id)
        changes, problems, live, columns = run.changes or [], run.problems or [], run.live or [], run.columns or {}
    if what == "alteracoes":
        return csv_response(f"cmdb-final-{run_id}-alteracoes.csv",
                            ["Linha", "Tipo", "CommonName", "Global Id", "Fonte", "Campo", "Antes", "Depois", "Validado no servidor", "Description"],
                            [[c["linha"], c["tipo"], c["cn"], c["global_id"], c.get("fonte", ""), f["campo"], f["antes"], f["depois"],
                              "sim" if c["servidor"] else "", c["descricao"]]
                             for c in changes for f in (c.get("campos") or [{"campo": "(linha nova)", "antes": "", "depois": ""}])])
    if what == "erros":
        return csv_response(f"cmdb-final-{run_id}-erros.csv", ["Fonte", "Linha", "Referência", "CommonName", "Data", "Data na CMDB", "Erro"],
                            [[p["fonte"], p.get("linha", ""), p.get("ref", ""), p["cn"], p["data"], p["cmdb"], p["erro"]] for p in problems])
    if what == "servidor":
        return csv_response(f"cmdb-final-{run_id}-servidor.csv",
                            ["CommonName", "Fonte", "Data na fonte", "Data na CMDB", "Decisão", "Data no servidor", "Série no servidor",
                             "Emissor no servidor", "Origem", "Detalhe"],
                            [[x["cn"], x["fonte"], x["data_fonte"], x["data_cmdb"], x["decisao_texto"], x.get("data_servidor", ""),
                              x.get("serie_servidor", ""), x.get("emissor_servidor", ""), x.get("origem", ""), x.get("detalhe", "")] for x in live])
    if what == "colunas":
        # Modelo do ficheiro import/cmdb-colunas.csv com o mapeamento usado nesta geração
        buf = io.StringIO()
        buf.write("atributo;coluna\r\n")
        for m in columns.get("mapeamento", []):
            buf.write(f"{m['atributo']};{m['coluna']}\r\n")
        return Response(buf.getvalue().encode("utf-8"), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": 'attachment; filename="cmdb-colunas.csv"'})
    raise HTTPException(404)


@app.post("/cmdb-final/{run_id}/publicar")
async def final_publish(request: Request, run_id: int, user: str = Depends(current_user)):
    form = await request.form()
    check_csrf(request, form.get("csrf"))
    keys = [str(k) for k in form.getlist("ficheiro")]
    if form.get("confirmo") != "1":
        raise HTTPException(400, "Confirmação em falta.")
    settings = get_settings()
    try:
        with session_scope() as s:
            run = _run_or_404(s, run_id)
            pub = cf.publish(s, settings, run, keys, user)
            audit(s, user, "cmdb_final.publicar", f"geração {run_id}", pasta=str(settings.publish_dir),
                  ficheiros=[r["nome"] for r in pub.result], ok=pub.ok)
    except cf.FinalError as exc:
        return _final_error(request, user, str(exc), f"/cmdb-final/{run_id}")
    return RedirectResponse(f"/cmdb-final/{run_id}#publicacoes", status_code=303)


@app.get("/cmdb-final/publicacao/{file_id}/anterior")
def final_previous(file_id: int, user: str = Depends(current_user)):
    with session_scope() as s:
        f = s.get(FinalPublishFile, file_id)
        if f is None or f.previous is None:
            raise HTTPException(404)
        data, name = f.previous, f.name
        audit(s, user, "cmdb_final.descarregar_anterior", name, publicacao=f.publish_id)
    stem, dot, ext = name.rpartition(".")
    media = ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" if ext == "xlsx" else "text/csv; charset=utf-8")
    return Response(data, media_type=media, headers={"Content-Disposition": f'attachment; filename="{stem}_anterior.{ext}"'})


# ------------------------------------------------------------------ API (só leitura)
def _jsonable(v):
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    return v


@app.get("/api/inventario")
def api_inventory(user: str = Depends(current_user)):
    with session_scope() as s:
        rows = build_inventory(s, get_settings(), utcnow())
    return JSONResponse([{k: _jsonable(v) for k, v in r.items()} for r in rows])


@app.get("/api/testes")
def api_testes(user: str = Depends(current_user)):
    with session_scope() as s:
        matrix = check_matrix(s, get_settings(), utcnow())
    return JSONResponse([
        {"endpoint": f"{r.ep.host}:{r.ep.port}", "cn": r.ep.expected_cn_norm, "tipo": r.type, "ambito": r.scope,
         "pior": r.worst, "testes": {cid: {"estado": res.status, "detalhe": res.detail} for cid, res in r.results.items()}}
        for r in matrix
    ])


@app.get("/api/findings")
def api_findings(status: str = "aberto", user: str = Depends(current_user)):
    with session_scope() as s:
        items = list(s.scalars(select(Finding).where(Finding.status == status)))
    return JSONResponse([
        {"id": f.id, "tipo": f.type, "severidade": f.severity, "alvo": f.subject, "cn": f.cn_norm,
         "estado": f.status, "detalhes": f.details, "primeira_vez": f.first_seen.isoformat(),
         "ultima_vez": f.last_seen.isoformat()}
        for f in items
    ])

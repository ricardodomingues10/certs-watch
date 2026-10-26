"""Interface web e API de leitura."""
from __future__ import annotations

import csv
import json
import io
import re
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, urlencode
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select

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
from ..models import (ApiRecord, AuditLog, Certificate, CmdbRecord, CtCert, Endpoint, FinalInput,
                      EmailReport, EmailTemplate, FinalRun, Finding, JobRun, Renewal, ScanResult, SmaxComment, SmaxFile,
                      SslLabsResult, TicketBatch, SmaxTicket, UcmdbWrite)
from .. import ticket_create as tc
from .. import cmdb_final as cf
from .. import renewal as rn
from .. import report as rp
from .. import ucmdb_access as ua
from .. import ucmdb_write as uw
from ..azure_rec import CLASS_LABELS as AZ_CLASSES, STATE_LABELS as AZ_STATES
from ..collectors.smax import ticket_url
from ..tickets import TICKET_HELP, TICKET_ORDER, TICKET_STATES, TICKET_VIEWS, comment_files, filter_tickets, ticket_list, tickets_by_label, link as ticket_link, tickets_by_endpoint
from ..trust import local_trust_files
from ..normalize import norm_label, split_api_name, is_ip, is_valid_hostname, norm_host, norm_issuer
from .security import check_csrf, current_user, security_middleware

BASE = Path(__file__).parent
MONTHS = ["jan", "fev", "mar", "abr", "mai", "jun", "jul", "ago", "set", "out", "nov", "dez"]
JOB_LABELS = {"pipeline": "Executar tudo", "ingest_cmdb": "Importar certificados da CMDB",
              "ingest_apis": "Importar lista de APIs",
              "ingest_smax": "Ler pedidos do SMAX",
              "ingest_ct": "Procurar na internet (CT)", "scan": "Verificar servidores",
              "ssllabs": "Avaliação externa (SSL Labs)", "evaluate": "Reavaliar regras"}
JOB_HELP = {"pipeline": "Faz todos os passos pela ordem: CMDB, APIs, SMAX, internet, servidores, SSL Labs e regras.",
            "ingest_cmdb": "Lê os certificados da UCMDB (nome, validade e emissor).",
            "ingest_apis": "Lê a lista de APIs da UCMDB.",
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


app = FastAPI(title="Atalaia Cert", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
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
templates.env.filters["source_name"] = lambda v: cf.source_name(v)


def fmt_ago(value) -> str:
    """"há 5 min", "há 3 h", "há 2 dias" (ou "nunca")."""
    if not value:
        return "nunca"
    secs = (utcnow() - as_utc(value)).total_seconds()
    if secs < 90:
        return "agora"
    if secs < 3600:
        return f"há {round(secs / 60)} min"
    if secs < 86400 * 2:
        return f"há {round(secs / 3600)} h"
    return f"há {round(secs / 86400)} dias"


templates.env.filters["ago"] = fmt_ago
templates.env.globals.update(
    FINDING_TYPES=FINDING_TYPES, FINDING_CHECK=FINDING_CHECK, SEVERITIES=SEVERITIES, version=__version__,
    TYPE_LABELS=TYPE_LABELS, TYPE_HELP=TYPE_HELP, SCOPE_LABELS=SCOPE_LABELS, SCOPE_HELP=SCOPE_HELP,
    AUTO_RENEW_LABELS=AUTO_RENEW_LABELS, AUTO_RENEW_HELP=AUTO_RENEW_HELP, ssllabs_report=report_url,
    TICKET_STATES=TICKET_STATES, TICKET_HELP=TICKET_HELP,
    STATE_LABELS=STATE_LABELS, STATUS_LABELS=STATUS_LABELS, CHECKS=CHECKS, CHECK_BY_ID=CHECK_BY_ID,
    LAYERS=LAYERS, MONTHS=MONTHS, JOB_LABELS=JOB_LABELS, JOB_HELP=JOB_HELP,
    CT_STATES=CT_STATES, CT_TABS=CT_TABS, CT_SOURCE_LABELS=SOURCE_LABELS, CT_STATE_HELP=CT_STATE_HELP, TRIAGE_LABELS=TRIAGE_LABELS,
    FINAL_FILES=cf.FILES, FINAL_FILE_LABELS=cf.FILE_LABELS, LIVE_LABELS=cf.LIVE_LABELS, FINAL_SOURCE_LABELS=cf.SOURCE_LABELS,
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
            run = s.scalar(select(FinalRun).where(FinalRun.status.in_(("pronto", "bloqueado")))
                           .order_by(FinalRun.id.desc()).limit(1))
            if run is not None:
                done = {w.chave for w in s.scalars(select(UcmdbWrite).where(UcmdbWrite.run_id == run.id,
                                                                            UcmdbWrite.parte == "cert",
                                                                            UcmdbWrite.estado.in_(("ok", "aviso"))))}
                data["reconc_dif"] = sum(1 for c in (run.changes or []) if c.get("incluir", True) and c["chave"] not in done)
                data["reconc_run"] = run.id
    except Exception:
        pass
    _NAV_CACHE.update(at=time.monotonic(), data=data)
    return data


def invalidate_nav() -> None:
    _NAV_CACHE["data"] = None


# Navegação por tarefas: cada grupo responde a "o que vou fazer?"; as páginas do grupo aparecem como separadores.
NAV_GROUPS = [
    ("hoje", "Hoje", [("/", "Painel", None), ("/findings", "Alertas", "alertas")]),
    ("inventario", "Inventário", [("/certificados", "Certificados", None), ("/apis", "APIs e segredos", None),
                                  ("/endpoints", "Servidores", None), ("/testes", "Testes", None),
                                  ("/descoberta", "Na internet", "ct_por_triar")]),
    ("renovar", "Renovar", [("/pedidos", "Pedidos SMAX", None), ("/relatorio", "Relatório por email", None)]),
    ("cmdb", "CMDB", [("/cmdb-final", "Atualizar a CMDB", "reconc_dif"), ("/ucmdb/certificado", "Editar um certificado", None),
                      ("/cmdb/historico", "Histórico de alterações", None)]),
    ("sistema", "Sistema", [("/jobs", "Execuções e auditoria", None), ("/cmdb-final/permissoes", "Ligação à UCMDB", None),
                            ("/cmdb-final/avi", "AVI pela API", None), ("/testes/como-funciona", "Como funciona", None)]),
]
_NAV_ALIASES = {"/cert/": "/certificados", "/reconciliacao": "/cmdb-final"}
PALETTES = {"consola": "Consola (escuro)", "assinatura": "Assinatura (escuro)", "relatorio": "Relatório (claro)"}


def nav_tree(path: str, counts: dict) -> list[dict]:
    """Grupos e páginas com o ativo marcado: a página cujo endereço é o prefixo mais longo do caminho atual."""
    for old, new in _NAV_ALIASES.items():
        if path.startswith(old):
            path = new
    best, best_len = None, -1
    for _, _, links in NAV_GROUPS:
        for href, _, _ in links:
            hit = path == "/" if href == "/" else (path == href or path.startswith(href + "/") or path.startswith(href + "?"))
            if hit and len(href) > best_len:
                best, best_len = href, len(href)
    out = []
    for key, label, links in NAV_GROUPS:
        items = [{"href": h, "label": lb, "on": h == best, "n": counts.get(c) if c else None,
                  "hot": c == "alertas" and counts.get("alertas_altos")} for h, lb, c in links]
        out.append({"key": key, "label": label, "href": links[0][0], "on": any(i["on"] for i in items), "items": items,
                    "n": sum(i["n"] or 0 for i in items if i["n"]) or None})
    return out


LOGO_FILES = (("logo.svg", "image/svg+xml"), ("logo.png", "image/png"), ("logo.webp", "image/webp"))


def client_logo() -> tuple[Path, str] | None:
    """O logo do cliente na pasta de marca (nomes fixos: nada vem do pedido)."""
    d = get_settings().branding_dir
    for name, mime in LOGO_FILES:
        p = d / name
        try:
            if p.is_file() and p.stat().st_size <= 2_000_000:
                return p, mime
        except OSError:
            continue
    return None


@app.get("/marca/logo")
def brand_logo(user: str = Depends(current_user)):
    found = client_logo()
    if found is None:
        raise HTTPException(404)
    path, mime = found
    # um SVG aberto diretamente não corre scripts nem carrega nada de fora
    return Response(path.read_bytes(), media_type=mime,
                    headers={"Cache-Control": "private, max-age=3600",
                             "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox"})


def palette_of(request: Request) -> str:
    p = request.cookies.get("cw_tema", "")
    return p if p in PALETTES else (get_settings().ui_palette if get_settings().ui_palette in PALETTES else "consola")


def render(request: Request, name: str, user: str, **ctx):
    counts = nav_counts()
    return templates.TemplateResponse(request, name, {"user": user, "csrf": request.state.csrf, "nav": counts,
                                                      "navtree": nav_tree(request.url.path, counts),
                                                      "palette": palette_of(request), "PALETTES": PALETTES,
                                                      "client": {"name": get_settings().client_name,
                                                                 "logo": client_logo() is not None,
                                                                 "style": get_settings().logo_style if get_settings().logo_style
                                                                 in ("original", "claro", "placa") else "original"}, **ctx})


@app.post("/tema")
def set_palette(request: Request, csrf: str = Form(""), tema: str = Form(""), next: str = Form(""),
                user: str = Depends(current_user)):
    """Tema da interface, guardado só neste browser."""
    check_csrf(request, csrf)
    if tema not in PALETTES:
        raise HTTPException(400, "Tema desconhecido")
    r = RedirectResponse(safe_next(next, "/"), status_code=303)
    r.set_cookie("cw_tema", tema, max_age=365 * 86400, httponly=True, samesite="strict",
                 secure=get_settings().cookie_secure, path="/")
    return r


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
    files = cf.current_inputs(s, settings)
    items.append({"ok": True if files else None, "title": "Fontes da reconciliação",
                  "hint": (", ".join(f"{k}: {v['nome']}" for k, v in files.items()) if files else
                           "Colocar exportações ca1*, ca2*, avi* e azure* na diretoria import/ ou carregá-las em Reconciliar e atualizar.")})
    items.append({"ok": True if settings.ucmdb_write else None, "title": "Escrita na UCMDB",
                  "hint": ("Ligada: a reconciliação aplica as alterações diretamente na UCMDB." if settings.ucmdb_write else
                           "Opcional: definir CERTWATCH_UCMDB_WRITE=true no .env para aplicar as alterações na UCMDB.")})
    last = s.scalar(select(JobRun).where(JobRun.job == "pipeline", JobRun.requested_by == "agendador",
                                         JobRun.status.in_(("ok", "error"))).order_by(JobRun.id.desc()).limit(1))
    recent = last is not None and last.finished_at and as_utc(last.finished_at) > utcnow() - timedelta(hours=26)
    items.append({"ok": bool(recent), "title": f"Execução automática diária às {settings.pipeline_daily_at}",
                  "hint": (f"Última: {fmt_dt(last.finished_at, True)} ({last.status})" if last else
                           "Ainda não correu automaticamente. Confirme que o worker está ativo.")})
    return items


SOURCE_JOBS = [("ingest_cmdb", "CMDB"), ("ingest_apis", "APIs"), ("ingest_smax", "SMAX"), ("scan", "Servidores"),
               ("ingest_ct", "Internet (CT)")]


def _freshness(s) -> list[dict]:
    """Quando cada fonte foi lida pela última vez com sucesso."""
    out = []
    for job, label in SOURCE_JOBS:
        j = s.scalar(select(JobRun).where(JobRun.job.in_([job, "pipeline"]), JobRun.status == "ok")
                     .order_by(JobRun.finished_at.desc()).limit(1))
        q = as_utc(j.finished_at) if j and j.finished_at else None
        out.append({"fonte": label, "quando": q, "velho": q is None or utcnow() - q > timedelta(hours=48)})
    return out


@app.get("/")
def dashboard(request: Request, janela: int = 24, user: str = Depends(current_user)):
    """Painel orientado à ação: o que expira sem pedido, o que se moveu, o que está parado, a conformidade."""
    import certwatch.dashboard as db_
    now, settings = utcnow(), get_settings()
    janela = 168 if janela >= 168 else 24
    with session_scope() as s:
        snap = load_snapshot(s)
        inv = build_inventory(s, settings, now, snap)
        stats = dashboard_stats(inv, check_matrix(s, settings, now, snap), now)
        open_findings = list(s.scalars(select(Finding).where(Finding.status == "aberto")))
        items = db_.expiring_without_ticket(inv, snap, s, settings, now)
        activity = db_.ticket_activity(s, settings, now, janela)
        from ..tickets import current_expiry
        stale = db_.stale_tickets(s, settings, now, current_expiry(s, settings, inv))
        nis = db_.nis2(inv, snap, s, settings, now, open_findings)
        fresh = _freshness(s)
        setup = setup_checklist(s, settings, stats)
        _, tcounts = ticket_list(s, settings, "atrasados", inventory=inv)
    k = db_.kpis(items, stale, activity, nis, open_findings)
    k["atrasados"], k["ja_renovado"] = tcounts["atrasados"], tcounts["ja_renovado"]
    sev_counts = {sv: sum(1 for f in open_findings if f.severity == sv) for sv in SEVERITIES}
    return render(request, "dashboard.html", user, s=stats, items=items, activity=activity, stale=stale, nis=nis, k=k,
                  janela=janela, fresh=fresh, sev_counts=sev_counts, setup=setup, smax_on=smax_configured(settings),
                  can_create=tc.can_create(settings), limit=settings.dash_expiry_days, stale_days=settings.dash_stale_days,
                  now=now)


@app.get("/painel/evidencia.csv")
def dashboard_evidence(user: str = Depends(current_user)):
    """Relatório de evidência (NIS2): cada certificado e API com a data, o pedido e os alertas, à data de hoje."""
    import certwatch.dashboard as db_
    now, settings = utcnow(), get_settings()
    with session_scope() as s:
        snap = load_snapshot(s)
        inv = build_inventory(s, settings, now, snap)
        rows = db_.evidence_rows(inv, snap, s, settings, now)
        audit(s, user, "painel.evidencia", f"{len(rows)} linhas")
    return csv_response(f"evidencia-certificados-{now.astimezone(_tz()):%Y-%m-%d}.csv", db_.EVIDENCE_HEADER, rows)


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


def _date_param(v: str):
    try:
        return datetime.strptime(v, "%Y-%m-%d").date() if v else None
    except ValueError:
        raise HTTPException(400, "Data inválida (use AAAA-MM-DD)")


@app.get("/pedidos")
def pedidos_smax(request: Request, vista: str = "abertos", q: str = "", fase: str = "", desde: str = "", ate: str = "",
                 sem_comentario: int = 0, ordem: str = "", user: str = Depends(current_user)):
    settings = get_settings()
    vista = vista if vista in TICKET_VIEWS else "abertos"
    ordem = ordem if ordem in TICKET_ORDER else ""
    d1, d2 = _date_param(desde), _date_param(ate)
    with session_scope() as s:
        rows, counts = ticket_list(s, settings, vista, q)
        fases = sorted({p for p in s.scalars(select(SmaxTicket.phase).distinct()) if p})
        n_lotes = s.query(TicketBatch).count()
        fetched = s.scalar(select(SmaxTicket.fetched_at).limit(1))
    rows = filter_tickets(rows, fase, d1, d2, bool(sem_comentario), ordem, _tz())
    with session_scope() as s:     # percurso de renovação dos pedidos abertos mostrados
        ctx = rn.load_context(s)
        for r in rows[:1000]:
            if r["aberto"] and r["t"].endpoint:
                p = rn.pipeline(r["t"], settings, ctx)
                r["percurso"] = {"done": p["done"], "current": p["current"], "current_label": p["current_label"]}
    filtros = {"q": q, "fase": fase, "desde": desde, "ate": ate, "sem_comentario": sem_comentario, "ordem": ordem}
    return render(request, "pedidos_smax.html", user, rows=rows[:1000], n_rows=len(rows), counts=counts, vista=vista,
                  q=q, views=TICKET_VIEWS, n_lotes=n_lotes, fetched=fetched, smax_on=smax_configured(settings),
                  fases=fases, filtros=filtros, ordens=TICKET_ORDER,
                  qs="&".join(f"{k}={quote(str(v))}" for k, v in filtros.items() if v))


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


# ------------------------------------------------------------------ pedido SMAX: comentários, percurso de renovação, fechar/reabrir
def _ticket_or_404(s, tid: str) -> SmaxTicket:
    t = s.get(SmaxTicket, tid)
    if t is None:
        raise HTTPException(404, "Pedido não encontrado (leia o SMAX de novo)")
    return t


def _back(tid: str, msg: str = "", erro: str = "", anchor: str = "") -> RedirectResponse:
    q = urlencode({k: v for k, v in (("msg", msg), ("erro", erro)) if v})
    return RedirectResponse(f"/pedidos/smax/{quote(tid)}{'?' + q if q else ''}{'#' + anchor if anchor else ''}", status_code=303)


@app.get("/pedidos/smax/{tid}")
def pedido_smax(request: Request, tid: str, user: str = Depends(current_user)):
    settings = get_settings()
    with session_scope() as s:
        t = _ticket_or_404(s, tid)
        ctx = rn.load_context(s)
        p = rn.pipeline(t, settings, ctx)
        comments = list(s.scalars(select(SmaxComment).where(SmaxComment.ticket_id == tid).order_by(SmaxComment.created_at.desc())))
        files = comment_files(s, [tid])
        others = list(s.scalars(select(SmaxTicket).where(SmaxTicket.endpoint == t.endpoint, SmaxTicket.id != tid)
                                .order_by(SmaxTicket.last_update.desc()).limit(10))) if t.endpoint else []
        for x in {id(o): o for o in [t, *comments, *others, *p["renewals"], *p["cmdb"]]}.values():
            if x in s:
                s.expunge(x)
    return render(request, "pedido_smax.html", user, t=t, perc=p, comments=comments, files=files, others=others,
                  url=ticket_url(settings, t.id), discussao=cf_discussions(settings, t.id),
                  can_update=smax_configured(settings) and settings.smax_update_enabled, settings=settings,
                  msg=request.query_params.get("msg", ""), erro=request.query_params.get("erro", ""),
                  ORIGIN_LABELS=rn.ORIGIN_LABELS, today=utcnow().astimezone(_tz()).date())


def cf_discussions(settings, tid):
    from ..collectors.smax import discussions_url
    return discussions_url(settings, tid)


@app.get("/pedidos/ficheiro/{fid}")
def pedido_ficheiro(fid: int, download: int = 0, user: str = Depends(current_user)):
    from ..collectors.smax import IMAGE_TYPES
    with session_scope() as s:
        f = s.get(SmaxFile, fid)
        if f is None or not f.data:
            raise HTTPException(404)
        data, mime, name = f.data, f.mime, f.name or f"ficheiro-{fid}"
    inline = mime in IMAGE_TYPES and not download
    headers = {"Content-Security-Policy": "default-src 'none'; sandbox", "Cache-Control": "private, max-age=3600",
               "Content-Disposition": f'{"inline" if inline else "attachment"}; filename="{quote(name)}"'}
    return Response(data, media_type=mime if inline else "application/octet-stream", headers=headers)


@app.post("/pedidos/smax/{tid}/verificar")
def pedido_verificar(request: Request, tid: str, csrf: str = Form(""), user: str = Depends(current_user)):
    check_csrf(request, csrf)
    settings = get_settings()
    with session_scope() as s:
        t = _ticket_or_404(s, tid)
        res = rn.scan_now(s, settings, norm_host(t.endpoint or ""))
        audit(s, user, "pedido.verificar_servidor", tid, sites=[r["site"] for r in res])
    if not res:
        return _back(tid, erro="Não há servidor para verificar (nome sem servidor registado ou wildcard).", anchor="percurso")
    parts = [f"{r['site']}: " + (f"válido até {fmt_dt(r['not_after'])}" if r["not_after"] else (r["erro"] or r["estado"]))
             for r in res]
    return _back(tid, msg="Verificação: " + "; ".join(parts), anchor="percurso")


@app.post("/pedidos/smax/{tid}/renovacao")
async def pedido_renovacao(request: Request, tid: str, user: str = Depends(current_user)):
    form = await request.form()
    check_csrf(request, form.get("csrf"))
    settings = get_settings()
    modo = str(form.get("modo") or "")
    with session_scope() as s:
        t = _ticket_or_404(s, tid)
        cn = norm_host(t.endpoint or "")
        if not cn:
            return _back(tid, erro="O pedido não indica o certificado (campo do endpoint vazio no SMAX).")
        try:
            if modo == "servidor":
                res = [r for r in rn.scan_now(s, settings, cn) if r["not_after"] and rn.name_matches(cn, [r["cn"], *r["nomes"]])]
                if not res:
                    return _back(tid, erro="Nenhum servidor apresentou um certificado para este nome.", anchor="renovar")
                best = max(res, key=lambda r: r["not_after"])
                r = rn.register(s, ticket_id=tid, cn=cn, valid_to=best["not_after"], serial=best["serial"],
                                issuer=best["emissor"], san=", ".join(best["nomes"]), origin="servidor", actor=user,
                                note=f"Certificado apresentado em {best['site']}")
            elif modo == "ficheiro":
                up = form.get("ficheiro")
                data = await up.read(2 * 1024 * 1024 + 1) if up is not None and hasattr(up, "read") else b""
                if not data or len(data) > 2 * 1024 * 1024:
                    return _back(tid, erro="Escolha o ficheiro do certificado (.cer, .crt, .pem ou .der, até 2 MB).", anchor="renovar")
                info = rn.parse_certificate(data)
                if info["is_ca"]:
                    return _back(tid, erro="Esse ficheiro é de uma autoridade de certificação, não do certificado do servidor.", anchor="renovar")
                if not rn.name_matches(cn, [info["cn"], *info["nomes"]]) and form.get("aceitar_nome") != "1":
                    return _back(tid, erro=f"O certificado é para {info['cn'] or ', '.join(info['nomes'][:3])}, não para {cn}. "
                                           "Se for mesmo este, volte a carregar com \"aceitar nome diferente\".", anchor="renovar")
                r = rn.register(s, ticket_id=tid, cn=cn, valid_to=info["not_after"], serial=info["serial"],
                                issuer=info["emissor"], san=", ".join(info["nomes"]), origin="ficheiro", actor=user,
                                sha256=info["sha256"], note=str(form.get("nota") or ""))
            elif modo == "manual":
                d = _date_param(str(form.get("validade") or ""))
                if d is None:
                    return _back(tid, erro="Indique a nova data de expiração.", anchor="renovar")
                if d <= utcnow().date():
                    return _back(tid, erro="A nova data de expiração tem de ser no futuro.", anchor="renovar")
                r = rn.register(s, ticket_id=tid, cn=cn, valid_to=datetime(d.year, d.month, d.day, 12, tzinfo=_tz()),
                                serial=str(form.get("serie") or ""), issuer=str(form.get("emissor") or ""),
                                origin="manual", actor=user, note=str(form.get("nota") or ""))
            else:
                raise HTTPException(400, "Modo inválido")
        except rn.RenewalError as exc:
            return _back(tid, erro=str(exc), anchor="renovar")
        audit(s, user, "pedido.registar_renovacao", tid, cn=cn, origem=r.origin, validade=r.valid_to.isoformat(),
              serie=r.serial)
        d = r.valid_to
    return _back(tid, msg=f"Renovação registada: válido até {fmt_dt(d)}. Entra na próxima reconciliação da CMDB.",
                 anchor="percurso")


@app.post("/pedidos/smax/{tid}/renovacao/{rid}/anular")
def pedido_renovacao_anular(request: Request, tid: str, rid: int, csrf: str = Form(""), user: str = Depends(current_user)):
    check_csrf(request, csrf)
    with session_scope() as s:
        r = s.get(Renewal, rid)
        if r is None or r.ticket_id != tid:
            raise HTTPException(404)
        r.active = False
        audit(s, user, "pedido.anular_renovacao", tid, renovacao=rid)
    return _back(tid, msg="Renovação anulada: deixa de entrar na atualização da CMDB.", anchor="percurso")


@app.post("/pedidos/smax/{tid}/instalado")
def pedido_instalado(request: Request, tid: str, csrf: str = Form(""), nota: str = Form(""), desfazer: str = Form(""),
                     user: str = Depends(current_user)):
    check_csrf(request, csrf)
    with session_scope() as s:
        _ticket_or_404(s, tid)
        rn.confirm_step(s, tid, "instalado", user, nota, undo=desfazer == "1")
        audit(s, user, "pedido.confirmar_instalacao", tid, desfazer=desfazer == "1", nota=nota[:200])
    return _back(tid, anchor="percurso")


@app.post("/pedidos/smax/{tid}/fase")
def pedido_fase(request: Request, tid: str, csrf: str = Form(""), acao: str = Form(""), comentario: str = Form(""),
                confirmo: str = Form(""), user: str = Depends(current_user)):
    check_csrf(request, csrf)
    settings = get_settings()
    if not (smax_configured(settings) and settings.smax_update_enabled):
        raise HTTPException(409, "Alterar pedidos no SMAX não está ativo (CERTWATCH_SMAX_UPDATE_ENABLED=true).")
    if acao not in ("fechar", "reabrir") or confirmo != "1":
        raise HTTPException(400, "Confirmação em falta.")
    with session_scope() as s:
        _ticket_or_404(s, tid)
    from ..collectors.smax import SmaxError, change_phase
    try:
        res = change_phase(settings, tid, acao, comentario.strip()[:4000])
    except SmaxError as exc:
        with session_scope() as s:
            audit(s, user, f"pedido.{acao}", tid, ok=False, erro=str(exc)[:300])
        return _back(tid, erro=str(exc), anchor="fase")
    with session_scope() as s:
        t = _ticket_or_404(s, tid)
        if res.get("pedido"):
            for k in ("phase", "last_update", "owner_group", "owner_person"):
                setattr(t, k, res["pedido"][k])
        com = res.get("comentario")
        audit(s, user, f"pedido.{acao}", tid, ok=res["ok"], estado=res["estado"], fase_antes=res["fase_antes"],
              fase_depois=res["fase_depois"], motivo=res["motivo"], comentario=(com[0] if com else None))
    com_txt = "" if com is None else (" Comentário registado." if com[0] else f" O comentário não foi registado: {com[1]}")
    if res["ok"]:
        return _back(tid, msg=f"Pedido {'fechado' if acao == 'fechar' else 'reaberto'} no SMAX: fase {res['fase_depois']}.{com_txt}", anchor="fase")
    return _back(tid, erro=f"O SMAX não {'fechou' if acao == 'fechar' else 'reabriu'} o pedido ({res['estado']}): "
                           f"{res['motivo']} Fase atual: {res['fase_depois'] or 'desconhecida'}.{com_txt}", anchor="fase")


# ------------------------------------------------------------------ relatório por email
def _report_or_404(s, rid: int) -> EmailReport:
    r = s.get(EmailReport, rid)
    if r is None:
        raise HTTPException(404)
    return r


def _report_data(rep: EmailReport, settings):
    with session_scope() as s:
        rows = rp.build_rows(s, settings)
        internet = rp.internet_rows(s, settings, rep.ct_dias if rep.ct_dias is not None else 30)
    return rows, rp.select_rows(rows, rep.desde, rep.ate, set(rep.excluded or []), internet)


def _template(s) -> EmailTemplate | None:
    return s.scalar(select(EmailTemplate).where(EmailTemplate.key == "default"))


def _texts(rep: EmailReport) -> dict:
    """Texto efetivo do relatório: original ⊕ modelo guardado ⊕ alterações deste relatório."""
    with session_scope() as s:
        t = _template(s)
        base = dict(t.textos or {}) if t else {}
    return rp.texts_for(base, rep.textos)


def _edits(rep: EmailReport) -> dict:
    return dict((rep.editados or {}).get("secoes") or {})


def _subject(key: str, sel: dict, rep: EmailReport, texts: dict) -> str:
    edited = ((rep.editados or {}).get("assuntos") or {}).get("alertas" if key == "ambos" else key)
    if edited:
        return edited
    return rp.subject_for(key, sel, rep.desde, rep.ate, rep.alerta, texts, rep.ct_dias or 0, utcnow().astimezone(_tz()))


def _group_subject(group: list[str], sel: dict, rep: EmailReport, texts: dict) -> str:
    key = "alertas" if "alertas" in group else ("reconciliacao" if "reconciliacao" in group else "internet")
    return _subject(key, sel, rep, texts)


def _group_attachments(group: list[str], sel: dict, rep: EmailReport) -> list[tuple[str, bytes]]:
    att = []
    if "reconciliacao" in group:
        att.append((rp.excel_name(rep.ate), rp.excel(sel, rep.alerta)))
    if "internet" in group:
        att.append((rp.INTERNET_EXCEL, rp.internet_excel(sel)))
    return att


@app.get("/relatorio")
def relatorio(request: Request, user: str = Depends(current_user)):
    settings = get_settings()
    with session_scope() as s:
        reps = list(s.scalars(select(EmailReport).order_by(EmailReport.id.desc()).limit(15)))
        for r in reps:
            s.expunge(r)
    return render(request, "relatorio.html", user, reps=reps, settings=settings, problems=rp.smtp_problems(settings))


@app.post("/relatorio")
def relatorio_criar(request: Request, csrf: str = Form(""), desde: int = Form(0), ate: int = Form(90),
                    alerta: int = Form(20), ct_dias: int = Form(30), user: str = Depends(current_user)):
    check_csrf(request, csrf)
    if not (-365 <= desde <= ate <= 3650) or not (0 <= alerta <= 3650) or not (0 <= ct_dias <= 3650):
        raise HTTPException(400, "Intervalo inválido: o início tem de ser menor ou igual ao fim.")
    with session_scope() as s:
        rep = EmailReport(created_by=user, desde=desde, ate=ate, alerta=alerta, ct_dias=ct_dias, excluded=[], sends=[])
        s.add(rep)
        s.flush()
        rid = rep.id
    return RedirectResponse(f"/relatorio/{rid}", status_code=303)


@app.get("/relatorio/{rid}")
def relatorio_ver(request: Request, rid: int, user: str = Depends(current_user)):
    settings = get_settings()
    with session_scope() as s:
        rep = _report_or_404(s, rid)
        s.expunge(rep)
        prev_to = ""
        for r in s.scalars(select(EmailReport).order_by(EmailReport.id.desc()).limit(30)):
            if r.sends:
                prev_to = ", ".join(r.sends[-1].get("para") or [])
                break
    rows, sel = _report_data(rep, settings)
    excl = set(rep.excluded or [])
    janela = sorted(sel["todos_janela"], key=lambda r: (r["dias"], r["cn"]))
    extra = [r for r in sel["todos_renovados"] if r not in sel["todos_janela"]]
    alerta = [r for r in sel["janela"] if 0 <= r["dias"] <= rep.alerta]
    with session_scope() as s:
        t = _template(s)
        modelo = {"textos": dict(t.textos or {}), "por": t.updated_by, "em": t.updated_at} if t and t.textos else None
    texts = rp.texts_for(modelo["textos"] if modelo else None, rep.textos)
    base = rp.texts_for(modelo["textos"] if modelo else None)
    groups = {}
    for k in rp.DEFAULT_TEXTS:
        groups.setdefault(k.split(".")[0], []).append(k)
    return render(request, "relatorio_ver.html", user, rep=rep, janela=janela, extra=extra, excl=excl, sel=sel,
                  n_alerta=len(alerta), problems=rp.smtp_problems(settings), settings=settings,
                  para=prev_to or ", ".join(settings.report_to),
                  assuntos={k: _subject(k, sel, rep, texts) for k in ("alertas", "reconciliacao", "internet")},
                  texts=texts, base_texts=base, text_groups=groups, TEXT_GROUPS=rp.TEXT_GROUPS, TEXT_LABELS=rp.TEXT_LABELS,
                  TEXT_VARS=rp.TEXT_VARS, ORIGINAL=rp.DEFAULT_TEXTS, modelo=modelo, MAX_TEXT=rp.MAX_TEXT,
                  n_proprios=len(rep.textos or {}),
                  editado={k: k in _edits(rep) or k in ((rep.editados or {}).get("assuntos") or {}) for k in rp.PARTS},
                  comum_editado=bool({"inicio", "fim"} & set(_edits(rep))), editados=rep.editados or {},
                  internet=sel["todos_internet"], INTERNET_EXCEL=rp.INTERNET_EXCEL,
                  msg=request.query_params.get("msg", ""), erro=request.query_params.get("erro", ""))


@app.post("/relatorio/{rid}/selecao")
async def relatorio_selecao(request: Request, rid: int, user: str = Depends(current_user)):
    form = await request.form()
    check_csrf(request, form.get("csrf"))
    shown = {str(x) for x in form.getlist("k")}
    chosen = {str(x) for x in form.getlist("inc")}
    with session_scope() as s:
        rep = _report_or_404(s, rid)
        excl = (set(rep.excluded or []) - shown) | (shown - chosen)
        rep.excluded = sorted(excl)
    return RedirectResponse(f"/relatorio/{rid}#previsao", status_code=303)


@app.post("/relatorio/{rid}/textos")
async def relatorio_textos(request: Request, rid: int, user: str = Depends(current_user)):
    """Edição do texto dos emails: neste relatório, como modelo para os próximos, ou repor."""
    form = await request.form()
    check_csrf(request, form.get("csrf"))
    acao = str(form.get("acao") or "")
    if acao not in ("relatorio", "modelo", "repor", "original"):
        raise HTTPException(400, "Ação desconhecida.")
    sent = rp.clean_texts({k: form.get(k) for k in rp.DEFAULT_TEXTS if form.get(k) is not None})
    with session_scope() as s:
        rep = _report_or_404(s, rid)
        t = _template(s)
        base = rp.texts_for(t.textos if t else None)
        if acao == "relatorio":
            rep.textos = {k: v for k, v in sent.items() if v != base[k]} or None
            msg = (f"Texto deste relatório guardado ({len(rep.textos)} bloco(s) diferente(s) do modelo)." if rep.textos
                   else "O texto é igual ao do modelo: nada a guardar neste relatório.")
        elif acao == "modelo":
            effective = {**base, **(rep.textos or {}), **sent}
            if t is None:
                t = EmailTemplate(key="default")
                s.add(t)
            t.textos = {k: v for k, v in effective.items() if v != rp.DEFAULT_TEXTS[k]}
            t.updated_by, t.updated_at = user, utcnow()
            rep.textos = None
            msg = "Texto guardado como modelo: os próximos relatórios usam este texto."
        elif acao == "repor":
            rep.textos = None
            msg = "Alterações deste relatório descartadas: usa o texto do modelo."
        else:
            if t is not None:
                t.textos, t.updated_by, t.updated_at = {}, user, utcnow()
            rep.textos = None
            msg = "Reposto o texto original da aplicação (o modelo guardado foi apagado)."
        audit(s, user, "relatorio.textos", f"relatório {rid}", acao=acao, blocos=sorted(sent) if acao in ("relatorio", "modelo") else [])
    return RedirectResponse(f"/relatorio/{rid}?{urlencode({'msg': msg})}#texto", status_code=303)


@app.get("/relatorio/{rid}/previsao/{parte}")
def relatorio_previsao(rid: int, parte: str, user: str = Depends(current_user)):
    if parte not in ("alertas", "reconciliacao", "internet", "ambos"):
        raise HTTPException(404)
    settings = get_settings()
    with session_scope() as s:
        rep = _report_or_404(s, rid)
        s.expunge(rep)
    _, sel = _report_data(rep, settings)
    body = rp.email_html(parte, sel, rep.desde, rep.ate, rep.alerta, settings.report_signature, utcnow().astimezone(_tz()),
                         rep.ct_dias or 0, _texts(rep), _edits(rep))
    page = f'<!doctype html><html lang="pt-PT"><head><meta charset="utf-8"></head><body style="margin:12px;background:#fff">{body}</body></html>'
    return Response(page, media_type="text/html; charset=utf-8", headers={
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'self'; sandbox",
        "X-Frame-Options": "SAMEORIGIN"})


@app.get("/relatorio/{rid}/editor/{parte}")
def relatorio_editor(rid: int, parte: str, user: str = Depends(current_user)):
    """O email desta parte, com as secções marcadas, para editar na página (sem scripts; mesma origem)."""
    if parte not in rp.PARTS:
        raise HTTPException(404)
    settings = get_settings()
    with session_scope() as s:
        rep = _report_or_404(s, rid)
        s.expunge(rep)
    _, sel = _report_data(rep, settings)
    body = rp.email_html(parte, sel, rep.desde, rep.ate, rep.alerta, settings.report_signature, utcnow().astimezone(_tz()),
                         rep.ct_dias or 0, _texts(rep), _edits(rep), markers=True)
    page = f'<!doctype html><html lang="pt-PT"><head><meta charset="utf-8"></head><body style="margin:12px;background:#fff">{body}</body></html>'
    return Response(page, media_type="text/html; charset=utf-8", headers={
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'self'",
        "X-Frame-Options": "SAMEORIGIN", "Cache-Control": "no-store"})


@app.post("/relatorio/{rid}/email/{parte}")
async def relatorio_email_editar(request: Request, rid: int, parte: str, user: str = Depends(current_user)):
    """Guarda o email editado na página (só as secções alteradas) ou volta ao email gerado."""
    if parte not in rp.PARTS:
        raise HTTPException(404)
    form = await request.form()
    check_csrf(request, form.get("csrf"))
    acao = str(form.get("acao") or "guardar")
    with session_scope() as s:
        rep = _report_or_404(s, rid)
        ed = dict(rep.editados or {})
        secoes = dict(ed.get("secoes") or {})
        assuntos = dict(ed.get("assuntos") or {})
        if acao == "repor":
            for k in ("inicio", parte, "fim"):
                secoes.pop(k, None)
            assuntos.pop(parte, None)
            msg = "Voltou ao email gerado pela aplicação."
            mudou = [parte]
        elif acao == "guardar":
            mudou = []
            for k in ("inicio", parte, "fim"):
                v = form.get(f"sec_{k}")
                if v is None:
                    continue
                if len(str(v)) > rp.MAX_HTML:
                    raise HTTPException(400, "Email demasiado grande.")
                secoes[k] = rp.sanitize_html(str(v))
                mudou.append(k)
            assunto = re.sub(r"\s+", " ", str(form.get("assunto") or "")).strip()[:250]
            if assunto and assunto != str(form.get("assunto_original") or "").strip():
                assuntos[parte] = assunto
                mudou.append("assunto")
            msg = "Email guardado: a pré-visualização e o envio usam o texto editado." if mudou else "Nada mudou no email."
        else:
            raise HTTPException(400, "Ação desconhecida.")
        rep.editados = {"secoes": secoes, "assuntos": assuntos, "por": user, "em": utcnow().isoformat()} \
            if (secoes or assuntos) else None
        audit(s, user, "relatorio.editar_email", f"relatório {rid}", parte=parte, acao=acao, secoes=mudou)
    return RedirectResponse(f"/relatorio/{rid}?{urlencode({'msg': msg})}#email-{parte}", status_code=303)


@app.get("/relatorio/{rid}/excel")
def relatorio_excel(rid: int, parte: str = "reconciliacao", user: str = Depends(current_user)):
    settings = get_settings()
    with session_scope() as s:
        rep = _report_or_404(s, rid)
        s.expunge(rep)
    _, sel = _report_data(rep, settings)
    data, name = ((rp.internet_excel(sel), rp.INTERNET_EXCEL) if parte == "internet"
                  else (rp.excel(sel, rep.alerta), rp.excel_name(rep.ate)))
    return Response(data, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.post("/relatorio/{rid}/enviar")
async def relatorio_enviar(request: Request, rid: int, user: str = Depends(current_user)):
    form = await request.form()
    check_csrf(request, form.get("csrf"))
    settings = get_settings()
    partes = [p for p in ("alertas", "reconciliacao", "internet") if p in form.getlist("parte")]
    modo = str(form.get("modo") or "junto")
    back = f"/relatorio/{rid}"
    if form.get("confirmo") != "1":
        raise HTTPException(400, "Confirmação em falta.")
    try:
        if not partes:
            raise rp.ReportError("Escolha o que enviar: alertas, reconciliação e/ou certificados novos na internet.")
        to = rp.parse_recipients(str(form.get("para") or ""), settings)
        with session_scope() as s:
            rep = _report_or_404(s, rid)
            s.expunge(rep)
        _, sel = _report_data(rep, settings)
        now = utcnow().astimezone(_tz())
        groups = [partes] if modo == "junto" else [[p] for p in partes]
        texts = _texts(rep)
        msgs, subjects = [], []
        for g in groups:
            subj = _group_subject(g, sel, rep, texts)
            msgs.append(rp.build_message(settings, to, subj,
                                         rp.email_html(g, sel, rep.desde, rep.ate, rep.alerta, settings.report_signature, now,
                                                       rep.ct_dias or 0, texts, _edits(rep)), _group_attachments(g, sel, rep)))
            subjects.append(subj)
        rp.send(settings, msgs, SMTP_FACTORY)
        ok, erro = True, ""
    except rp.ReportError as exc:
        ok, erro, to, subjects = False, str(exc), locals().get("to") or [], locals().get("subjects") or []
    with session_scope() as s:
        rep = _report_or_404(s, rid)
        rep.sends = [*(rep.sends or []), {"em": utcnow().isoformat(), "por": user, "para": to, "partes": partes,
                                          "modo": modo, "assuntos": subjects, "ok": ok, "erro": erro}]
        audit(s, user, "relatorio.enviar", f"relatório {rid}", para=to, partes=partes, modo=modo, ok=ok, erro=erro[:300])
    q = urlencode({"msg": f"Enviado para {', '.join(to)}: {' | '.join(subjects)}"} if ok else {"erro": erro})
    return RedirectResponse(f"{back}?{q}#enviar", status_code=303)


SMTP_FACTORY = None    # nos testes: substitui o servidor SMTP


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
        writes = list(s.scalars(select(UcmdbWrite).order_by(UcmdbWrite.id.desc()).limit(10)))
        n_writes = s.scalar(select(func.count()).select_from(UcmdbWrite)) or 0
        for w in writes:
            s.expunge(w)
    st = get_settings()
    jobs = [j for j in JOBS if (j != "ingest_apis" or apis_configured(st)) and (j != "ingest_ct" or st.ct_domains)
            and (j != "ssllabs" or st.ssllabs_email) and (j != "ingest_smax" or smax_configured(st))]
    return render(request, "jobs.html", user, runs=runs, audits=audits, jobs=jobs, daily_at=st.pipeline_daily_at,
                  ucmdb_writes=uw.history_rows(writes), n_writes=n_writes, WRITE_STATES=uw.STATE_LABELS)


def _history_args(q: str, ci: str, por: str, origem: str, resultado: str, acao: str, de: str, ate: str) -> tuple[list, dict]:
    """Converte os filtros da página do histórico em condições (datas de Lisboa, ao dia)."""
    tz = _tz()

    def day(v: str, plus: int = 0):
        try:
            d = datetime.strptime(v.strip(), "%Y-%m-%d").date() if v.strip() else None
        except ValueError:
            return None
        return datetime.combine(d + timedelta(days=plus), datetime.min.time(), tzinfo=tz).astimezone(timezone.utc) if d else None
    f = {"q": q[:200], "ci": ci[:64], "por": por[:128], "origem": origem if origem in uw.ORIGINS else "",
         "resultado": resultado if resultado in uw.RESULTS else "", "acao": acao if acao in ("criar", "atualizar") else "",
         "de": de[:10] if day(de) else "", "ate": ate[:10] if day(ate) else ""}
    conds = uw.history_conditions(f["q"], f["ci"], f["por"], f["origem"], f["resultado"], f["acao"],
                                  day(f["de"]), day(f["ate"], 1))
    return conds, f


@app.get("/cmdb/historico")
def cmdb_history(request: Request, q: str = "", ci: str = "", por: str = "", origem: str = "", resultado: str = "",
                 acao: str = "", de: str = "", ate: str = "", n: int = 200, user: str = Depends(current_user)):
    """Histórico de todas as alterações feitas na UCMDB pelo certwatch, com filtros."""
    conds, f = _history_args(q, ci, por, origem, resultado, acao, de, ate)
    n = max(50, min(n, 5000))
    with session_scope() as s:
        base = select(UcmdbWrite).where(*conds)
        total = s.scalar(select(func.count()).select_from(base.subquery())) or 0
        by_state = dict(s.execute(select(UcmdbWrite.estado, func.count()).where(*conds).group_by(UcmdbWrite.estado)).all())
        by_action = dict(s.execute(select(UcmdbWrite.acao, func.count()).where(*conds, UcmdbWrite.estado.in_(uw.DONE))
                                   .group_by(UcmdbWrite.acao)).all())
        writes = list(s.scalars(base.order_by(UcmdbWrite.id.desc()).limit(n)))
        users = sorted(x for x in s.scalars(select(UcmdbWrite.por).distinct()) if x)
        active_ids = set(s.scalars(select(CmdbRecord.ucmdb_id).where(CmdbRecord.active.is_(True))))
        fora_tql = {w.ucmdb_id for w in writes if w.acao == "criar" and w.parte == "cert" and w.estado in uw.DONE
                    and w.ucmdb_id and active_ids and w.ucmdb_id not in active_ids}
        for w in writes:
            s.expunge(w)
    from urllib.parse import urlencode
    qs = urlencode({k: v for k, v in f.items() if v})
    counts = {"total": total, "aplicadas": sum(by_state.get(x, 0) for x in uw.DONE), "erros": by_state.get("erro", 0),
              "criadas": by_action.get("criar", 0), "atualizadas": by_action.get("atualizar", 0),
              "fila": sum(by_state.get(x, 0) for x in uw.BUSY)}
    return render(request, "cmdb_historico.html", user, rows=uw.history_rows(writes), f=f, n=n, qs=qs, counts=counts,
                  fora_tql=fora_tql, tql=get_settings().ucmdb_tql,
                  users=users, ORIGINS=uw.ORIGINS, RESULTS=uw.RESULTS, WRITE_STATES=uw.STATE_LABELS)


@app.get("/cmdb/historico/porque/{ucmdb_id}")
def cmdb_history_why(request: Request, ucmdb_id: str, user: str = Depends(current_user)):
    """Porque é que um certificado criado não aparece no TQL dos ativos (só leitura)."""
    if not re.fullmatch(r"[0-9a-zA-Z_-]{1,64}", ucmdb_id):
        raise HTTPException(404)
    settings = get_settings()
    try:
        rep, erro = uw.why_not_in_tql(settings, ucmdb_id, UCMDB_CLIENT), ""
    except (ua.UcmdbError, uw.WriteError) as exc:
        rep, erro = None, str(exc)
    return render(request, "cmdb_porque.html", user, rep=rep, erro=erro, ucmdb_id=ucmdb_id, settings=settings)


@app.get("/cmdb/historico.csv")
def cmdb_history_export(q: str = "", ci: str = "", por: str = "", origem: str = "", resultado: str = "",
                        acao: str = "", de: str = "", ate: str = "", user: str = Depends(current_user)):
    """O histórico filtrado em CSV, uma linha por atributo alterado."""
    conds, _ = _history_args(q, ci, por, origem, resultado, acao, de, ate)
    out = []
    tz = _tz()
    with session_scope() as s:
        for r in uw.history_rows(list(s.scalars(select(UcmdbWrite).where(*conds).order_by(UcmdbWrite.id)))):
            w = r["w"]
            when = w.feito_em or w.pedido_em
            base = [as_utc(when).astimezone(tz).strftime("%d-%m-%Y %H:%M:%S") if when else "", w.por, r["origem"], w.acao,
                    w.cn, w.ucmdb_id, uw.STATE_LABELS.get(w.estado, w.estado)]
            tail = ["" if w.verificado is None else ("sim" if w.verificado else "não"), w.detalhe]
            for m in r["mudancas"] or [{"atributo": "", "antes": "", "depois": ""}]:
                out.append(base + [m["atributo"], m["antes"], m["depois"]] + tail)
    return csv_response("historico-alteracoes-cmdb.csv", ["Quando", "Quem", "Origem", "Ação", "Certificado", "CI", "Resultado",
                                                          "Atributo", "Antes", "Depois", "Verificado", "Detalhe"], out)


@app.get("/jobs/ucmdb.csv")
def jobs_ucmdb_export(user: str = Depends(current_user)):
    return RedirectResponse("/cmdb/historico.csv", status_code=301)


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
def reconciliation_page(user: str = Depends(current_user)):
    """A reconciliação com as exportações passou a fazer parte de Reconciliar e atualizar."""
    return RedirectResponse("/cmdb-final", status_code=301)


# ------------------------------------------------------------------ CMDB final (CMDB_Final.xlsx, certs_update)
FINAL_STATES = {"a_gerar": "A reconciliar", "pronto": "Pronta", "bloqueado": "Pronta (CSV bloqueados)", "erro": "Com erro"}
FINAL_VIEWS = {**{k: v["label"] for k, v in cf.VIEWS.items()}, "detalhes": "Detalhes técnicos"}
_OLD_VIEWS = {"alteracoes": "novos", "colunas": "detalhes"}


def recon_guide(*, missing: list[str], run, busy: bool, to_apply: int, applied: int, write_on: bool,
                on_run_page: bool, superseded_by: int | None = None) -> dict:
    """Os 5 passos de "Atualizar a CMDB" com o estado de cada um e o próximo passo, numa frase e um botão."""
    ready = run is not None and run.status in ("pronto", "bloqueado")
    changes = len(run.changes or []) if ready else 0
    st = {k: "todo" for k in ("fontes", "comparar", "rever", "aplicar", "confirmar")}
    sub = {"fontes": "ficheiros e dados a comparar", "comparar": "ler a CMDB e comparar",
           "rever": "decidir o que entra", "aplicar": "escrever na UCMDB", "confirmar": "comparar de novo: zero diferenças"}
    st["fontes"] = "bad" if missing else "done"
    sub["fontes"] = ("falta " + ", ".join(missing)) if missing else "prontas"
    if busy:
        st["comparar"], sub["comparar"] = "current", "a comparar…"
    elif run is not None and run.status == "erro":
        st["comparar"], sub["comparar"] = "bad", f"#{run.id} falhou"
    elif ready:
        st["comparar"], sub["comparar"] = "done", f"#{run.id}, {fmt_dt(run.created_at, True)}"
    elif not missing:
        st["comparar"] = "current"
    if ready:
        if not changes:
            st.update(rever="done", aplicar="done", confirmar="done")
            sub.update(rever="sem diferenças", aplicar="nada a aplicar", confirmar="a CMDB coincide com as fontes")
        elif to_apply and not applied:
            st["rever"], sub["rever"] = "current", f"{to_apply} alteraç{'ões' if to_apply != 1 else 'ão'} por rever"
        elif to_apply:
            st.update(rever="done", aplicar="current")
            sub.update(rever=f"{changes} revistas", aplicar=f"{applied} aplicadas, faltam {to_apply}")
        else:
            st.update(rever="done", aplicar="done", confirmar="current")
            sub.update(rever="revistas", aplicar=f"{applied} aplicadas" if applied else "nada incluído")
    nxt = {"texto": "", "botao": "", "href": "", "post": ""}
    if superseded_by:
        nxt.update(texto=f"Esta reconciliação foi substituída pela #{superseded_by}; só a mais recente pode ser aplicada.",
                   botao=f"Abrir a #{superseded_by}", href=f"/cmdb-final/{superseded_by}")
    elif missing:
        nxt.update(texto=f"Falta o ficheiro de {', '.join(missing)}. Coloque-o na diretoria import/ ou carregue-o aqui. "
                         "Também pode comparar só as fontes que tem (\"Comparar só esta fonte\").",
                   botao="Ver as fontes", href="/cmdb-final#fontes")
    elif busy:
        nxt.update(texto="A ler a CMDB e as fontes e a comparar. A página atualiza-se sozinha.")
    elif not ready:
        nxt.update(texto="Compare as fontes com a CMDB. Nada é escrito na UCMDB sem a sua confirmação.",
                   botao="Comparar agora", post="/cmdb-final/gerar")
    elif not changes:
        nxt.update(texto="A CMDB coincide com as fontes: não há nada a fazer.", botao="Comparar de novo", post="/cmdb-final/gerar")
    elif st["rever"] == "current":
        nxt.update(texto=f"Reveja as {to_apply} alterações encontradas e exclua o que não deve entrar na CMDB. Cada linha diz porquê.",
                   botao="Rever as alterações", href="#alteracoes" if on_run_page else f"/cmdb-final/{run.id}")
    elif st["aplicar"] == "current":
        nxt.update(texto=(f"Faltam aplicar {to_apply} alterações na UCMDB." if write_on else
                          "A escrita na UCMDB está desligada (CERTWATCH_UCMDB_WRITE=true no .env)."),
                   botao="Aplicar na UCMDB", href="#ucmdb" if on_run_page else f"/cmdb-final/{run.id}#ucmdb")
    else:
        nxt.update(texto="Tudo o que estava incluído foi aplicado. Compare de novo para confirmar que não ficaram diferenças.",
                   botao="Comparar de novo", post="/cmdb-final/gerar")
    if not on_run_page and ready and changes and st["rever"] == "current":
        nxt["botao"] = "Rever as alterações"
    labels = {"fontes": "Fontes", "comparar": "Comparar", "rever": "Rever", "aplicar": "Aplicar", "confirmar": "Confirmar"}
    return {"steps": [{"n": i + 1, "label": labels[k], "state": st[k], "sub": sub[k]} for i, k in enumerate(labels)],
            "next": nxt}


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
            run.status, run.error, run.finished_at = "erro", "Interrompido (o processo parou durante a reconciliação).", utcnow()


@app.get("/cmdb-final")
def final_page(request: Request, user: str = Depends(current_user)):
    settings = get_settings()
    today = utcnow().astimezone(_tz()).date()
    with session_scope() as s:
        _stale_runs(s)
        inputs = cf.current_inputs(s, settings)
        files = cf.source_files(s, settings)
        runs = list(s.scalars(select(FinalRun).order_by(FinalRun.id.desc()).limit(30)))
        for r in runs:
            s.expunge(r)
        applied = dict(s.execute(select(UcmdbWrite.run_id, func.count()).where(UcmdbWrite.estado.in_(uw.DONE))
                                 .group_by(UcmdbWrite.run_id)).all())
        lr = runs[0] if runs else None
        to_apply_n = 0
        if lr is not None and lr.status in ("pronto", "bloqueado"):
            done = {w.chave for w in s.scalars(select(UcmdbWrite).where(UcmdbWrite.run_id == lr.id, UcmdbWrite.parte == "cert",
                                                                        UcmdbWrite.estado.in_(uw.DONE)))}
            to_apply_n = sum(1 for c in (lr.changes or []) if c.get("incluir", True) and c["chave"] not in done)
        cmdb_at = s.scalar(select(CmdbRecord.last_seen).order_by(CmdbRecord.last_seen.desc()).limit(1))
        apis_at = s.scalar(select(ApiRecord.last_seen).order_by(ApiRecord.last_seen.desc()).limit(1))
        ct = cf.ct_source(s, settings, today)[1] if settings.final_ct else None
        renewals = len(rn.source_items(s, today))
    from ..reconcile import scan_import_dir
    latest = runs[0] if runs else None
    guide = recon_guide(missing=[x for x in settings.final_sources if x not in inputs], run=latest,
                        busy=bool(latest and latest.status == "a_gerar"), to_apply=to_apply_n,
                        applied=applied.get(latest.id, 0) if latest else 0, write_on=settings.ucmdb_write, on_run_page=False)
    return render(request, "final.html", user, guide=guide, inputs=inputs, files=files, runs=runs, latest=latest, cmdb_at=cmdb_at,
                  apis_at=apis_at, settings=settings, FINAL_STATES=FINAL_STATES, ct=ct, renewals=renewals,
                  applied=applied, AZURE=cf.AZURE_SOURCE, dir_files=scan_import_dir(settings),
                  issuers={k: settings.import_issuers.get(k, "") for k in settings.final_sources})


@app.post("/cmdb-final/gerar")
def final_generate(request: Request, csrf: str = Form(""), fonte: list[str] = Form([]),
                   user: str = Depends(current_user)):
    """Reconcilia todas as fontes ou só as indicadas em `fonte` (ex.: só CA1)."""
    check_csrf(request, csrf)
    settings = get_settings()
    valid = cf.all_sources(settings)
    only = [x for x in valid if x in {f.upper() for f in fonte}] or None
    if fonte and not only:
        raise HTTPException(400, "Fonte desconhecida")
    try:
        with session_scope() as s:
            _stale_runs(s)
            run = cf.start_run(s, user, only)
            run_id = run.id
            audit(s, user, "cmdb_final.gerar", f"reconciliação {run_id}",
                  **({"fontes": only} if only else {}))
    except cf.FinalError as exc:
        return _final_error(request, user, str(exc), "/cmdb-final")
    cf.generate_in_background(run_id, settings, only)
    return RedirectResponse(f"/cmdb-final/{run_id}", status_code=303)


AVI_CLIENT = None       # testes: cliente httpx para o AVI
AVI_DIAGNOSE = None     # testes: substitui o diagnóstico de rede


def _avi_file(s, settings):
    """O ficheiro do AVI que a reconciliação usa sem a API: o da diretoria import/ ou o último carregado à mão."""
    f = cf.source_files(s, settings).get(cf.AVI) or {}
    up = s.scalar(select(FinalInput).where(FinalInput.source == cf.AVI, FinalInput.uploaded_by != cf.AVI_API_ACTOR)
                  .order_by(FinalInput.id.desc()).limit(1))
    d = f.get("diretoria")
    if up is not None and (d is None or as_utc(up.uploaded_at) >= d["quando"]):
        return up.name, up.data, f"carregado por {up.uploaded_by}, {fmt_dt(up.uploaded_at, True)}"
    if d is not None:
        return d["nome"], Path(d["path"]).read_bytes(), f"import/{d['nome']}, {fmt_dt(d['quando'], True)}"
    return None, None, ""


def _avi_render(request, user, **kw):
    from ..collectors import avi as avi_api
    settings = get_settings()
    return render(request, "avi.html", user, settings=settings, problem=avi_api.configured(settings),
                  **{"res": None, "cmp": None, "erro": "", "ficheiro": "", "cas": [], "diag": None, **kw})


@app.get("/cmdb-final/avi")
def avi_page(request: Request, user: str = Depends(current_user)):
    return _avi_render(request, user)


@app.post("/cmdb-final/avi/testar")
def avi_test(request: Request, csrf: str = Form(""), user: str = Depends(current_user)):
    """Lê o AVI pela API (só leitura) e compara com o ficheiro atual. Não muda a fonte da reconciliação."""
    from ..collectors import avi as avi_api
    check_csrf(request, csrf)
    settings = get_settings()
    try:
        res = avi_api.fetch(settings, AVI_CLIENT)
    except avi_api.AviError as exc:
        with session_scope() as s:
            audit(s, user, "avi.testar", settings.avi_url, resultado="erro", erro=str(exc)[:300])
        return _avi_render(request, user, erro=str(exc))
    cmp, ficheiro = None, ""
    with session_scope() as s:
        try:
            name, data, ficheiro = _avi_file(s, settings)
        except OSError as exc:
            name, data, ficheiro = None, None, f"não foi possível ler o ficheiro: {exc}"
        if data is not None:
            try:
                cmp = cf.avi_compare(name, data, avi_api.to_csv(res.vs))
            except Exception as exc:  # ficheiro ilegível: a leitura pela API continua a ser mostrada
                ficheiro += f" (não comparado: {exc})"
        audit(s, user, "avi.testar", settings.avi_url, resultado="ok", certificados=len(res.vs), cas=len(res.ca),
              pedidos=res.pedidos)
    today = utcnow().astimezone(_tz()).date()
    cas = sorted(res.ca, key=lambda r: (cf.parse_day(r["Validity_NotAfter"]).day or today))
    for r in cas:
        d = cf.parse_day(r["Validity_NotAfter"]).day
        r["dias"] = (d - today).days if d else None
    return _avi_render(request, user, res=res, cmp=cmp, ficheiro=ficheiro, cas=cas)


@app.post("/cmdb-final/avi/diagnosticar")
def avi_diagnose(request: Request, csrf: str = Form(""), user: str = Depends(current_user)):
    """DNS, TCP, TLS, login e uma leitura: diz em que passo a ligação ao AVI para."""
    from ..collectors import avi as avi_api
    check_csrf(request, csrf)
    settings = get_settings()
    steps = AVI_DIAGNOSE(settings) if AVI_DIAGNOSE else avi_api.diagnose(settings)
    with session_scope() as s:
        audit(s, user, "avi.diagnosticar", settings.avi_url, passos={x["passo"]: x["ok"] for x in steps})
    return _avi_render(request, user, diag=steps)


@app.post("/cmdb-final/avi/usar")
def avi_use(request: Request, csrf: str = Form(""), user: str = Depends(current_user)):
    """Lê o AVI pela API e guarda a leitura como fonte AVI da próxima reconciliação (o ficheiro fica onde está)."""
    from ..collectors import avi as avi_api
    check_csrf(request, csrf)
    settings = get_settings()
    try:
        with session_scope() as s:
            up, info = cf.store_avi_api(s, settings, utcnow().astimezone(_tz()).date(), AVI_CLIENT)
            audit(s, user, "avi.usar", up.name, **info)
    except (avi_api.AviError, cf.FinalError) as exc:
        return _avi_render(request, user, erro=str(exc))
    return RedirectResponse("/cmdb-final#fontes", status_code=303)


@app.get("/cmdb-final/avi/csv")
def avi_csv(tipo: str = "vs", user: str = Depends(current_user)):
    """O CSV no formato do script, lido agora pela API (certificados dos virtual services ou CAs)."""
    from ..collectors import avi as avi_api
    settings = get_settings()
    try:
        res = avi_api.fetch(settings, AVI_CLIENT, with_ca=tipo == "ca")
    except avi_api.AviError as exc:
        raise HTTPException(502, str(exc))
    with session_scope() as s:
        audit(s, user, "avi.exportar", tipo, certificados=len(res.ca if tipo == "ca" else res.vs))
    data = avi_api.to_csv(res.ca if tipo == "ca" else res.vs)
    name = f"avi-{'ca' if tipo == 'ca' else 'certificados'}-api.csv"
    return Response(data, media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.post("/cmdb-final/fonte/{source}/diretoria")
def final_use_dir(request: Request, source: str, csrf: str = Form(""), user: str = Depends(current_user)):
    """Esquece os ficheiros carregados desta fonte: volta a usar o da diretoria import/."""
    check_csrf(request, csrf)
    settings = get_settings()
    source = source.upper()
    if source not in settings.final_sources and source != cf.AZURE_SOURCE:
        raise HTTPException(404)
    with session_scope() as s:
        ups = list(s.scalars(select(FinalInput).where(FinalInput.source == source)))
        for up in ups:
            s.delete(up)
        audit(s, user, "cmdb_final.usar_diretoria", source, carregados_removidos=len(ups))
    return RedirectResponse("/cmdb-final#fontes", status_code=303)


@app.post("/cmdb-final/fonte/{source}")
async def final_upload(request: Request, source: str, csrf: str = Form(""), ficheiro: UploadFile = File(...),
                       user: str = Depends(current_user)):
    check_csrf(request, csrf)
    settings = get_settings()
    source = source.upper()
    if source not in settings.final_sources and source != cf.AZURE_SOURCE:
        raise HTTPException(404)
    name = Path(ficheiro.filename or "").name[:200]
    data = await ficheiro.read(cf.MAX_UPLOAD + 1)
    if Path(name).suffix.lower() not in cf.ALLOWED_EXT:
        return _final_error(request, user, "Formato não aceite: use CSV ou Excel (.xlsx).", "/cmdb-final")
    if len(data) > cf.MAX_UPLOAD:
        return _final_error(request, user, f"Ficheiro demasiado grande (máximo {cf.MAX_UPLOAD // 1024 // 1024} MB).", "/cmdb-final")
    try:
        if source == cf.AZURE_SOURCE:
            from ..azure_rec import read_azure
            items, info = read_azure(data, name, utcnow().astimezone(_tz()).date())
        else:
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




@app.post("/cmdb-final/{run_id}/ucmdb")
def final_apply_ucmdb(request: Request, run_id: int, csrf: str = Form(""), modo: str = Form("um"), chave: int = Form(-1),
                      confirmo: str = Form(""), vista: str = Form(""), user: str = Depends(current_user)):
    """Aplica na UCMDB, pela REST API, uma alteração (modo=um) ou todas as incluídas e ainda não aplicadas."""
    check_csrf(request, csrf)
    settings = get_settings()
    back = f"/cmdb-final/{run_id}?vista={vista if vista in FINAL_VIEWS else 'novos'}"
    problem = uw.enabled_problem(settings)
    if problem:
        return RedirectResponse(f"{back}&{urlencode({'erro': problem})}#ucmdb", status_code=303)
    try:
        with session_scope() as s:
            run = _run_or_404(s, run_id)
            if not cf.editable(s, run):
                raise uw.WriteError("Só a reconciliação mais recente pode ser aplicada na UCMDB. Reconcilie de novo.")
            if modo == "todas":
                if confirmo != "1":
                    raise uw.WriteError("Confirme a aplicação na UCMDB.")
                keys = [c["chave"] for c in (run.changes or []) if c.get("incluir", True)]
            else:
                keys = [chave]
            lote = uw.queue(s, run, keys, user)
            n = len(keys)
            run_changes = list(run.changes or [])
    except uw.WriteError as exc:
        return RedirectResponse(f"{back}&{urlencode({'erro': str(exc)})}#ucmdb", status_code=303)
    if modo == "um" and vista not in FINAL_VIEWS:
        tipo = next((c["tipo"] for c in (run_changes or []) if c["chave"] == chave), "novo")
        back = f"/cmdb-final/{run_id}?vista={'novos' if tipo == 'novo' else 'alterados'}"
    if modo == "um" or UCMDB_WRITE_SYNC:
        uw.process(lote, settings, UCMDB_CLIENT)
        msg = "Aplicado na UCMDB: veja o resultado na linha." if modo == "um" else "Aplicado na UCMDB."
    else:
        uw.process_in_background(lote, settings)
        msg = f"A aplicar {n} alteração(ões) na UCMDB. A página atualiza-se sozinha."
    anchor = f"#alt-{chave}" if modo == "um" else "#ucmdb"
    return RedirectResponse(f"{back}&{urlencode({'msg': msg})}{anchor}", status_code=303)


@app.get("/ucmdb/certificado")
def ucmdb_cert_search(request: Request, q: str = "", user: str = Depends(current_user)):
    """Procurar um certificado da CMDB para o editar na UCMDB."""
    settings = get_settings()
    rows = []
    if q.strip():
        ql = q.strip().lower()
        with session_scope() as s:
            stmt = select(CmdbRecord).where((CmdbRecord.cn_norm.contains(ql)) | (CmdbRecord.ucmdb_id == q.strip())
                                            | (CmdbRecord.global_id == q.strip())).order_by(CmdbRecord.cn_norm).limit(50)
            for r in s.scalars(stmt):
                rows.append({"id": r.ucmdb_id, "cn": r.common_name, "issuer": r.issuer_name or r.issuer,
                             "valid_to": r.valid_to, "active": r.active})
    return render(request, "ucmdb_editar.html", user, EDIT_COLUMNS=uw.EDIT_COLUMNS, settings=settings, q=q, rows=rows, form=None, changes=None,
                  result=None, write_problem=uw.enabled_problem(settings), erro="")


def _edit_form(settings, ucmdb_id: str):
    if not re.fullmatch(r"[0-9a-zA-Z_-]{1,64}", ucmdb_id):
        raise HTTPException(404)
    try:
        return uw.load_for_edit(settings, ucmdb_id, UCMDB_CLIENT), ""
    except ua.UcmdbError as exc:
        return None, str(exc)


@app.get("/ucmdb/certificado/{ucmdb_id}")
def ucmdb_cert_edit(request: Request, ucmdb_id: str, user: str = Depends(current_user)):
    settings = get_settings()
    form, erro = _edit_form(settings, ucmdb_id)
    return render(request, "ucmdb_editar.html", user, EDIT_COLUMNS=uw.EDIT_COLUMNS, settings=settings, q="", rows=[], form=form, changes=None,
                  result=None, write_problem=uw.enabled_problem(settings), erro=erro, novo={})


@app.post("/ucmdb/certificado/{ucmdb_id}")
async def ucmdb_cert_save(request: Request, ucmdb_id: str, user: str = Depends(current_user)):
    """Passo "rever" (mostra o que muda) e passo "gravar" (escreve na UCMDB)."""
    data = await request.form()
    check_csrf(request, data.get("csrf"))
    settings = get_settings()
    form, erro = _edit_form(settings, ucmdb_id)
    if form is None:
        return render(request, "ucmdb_editar.html", user, EDIT_COLUMNS=uw.EDIT_COLUMNS, settings=settings, q="", rows=[], form=None, changes=None,
                      result=None, write_problem=uw.enabled_problem(settings), erro=erro)
    novo = {c: str(data.get(f"f_{i}") or "") for i, c in enumerate(uw.EDIT_COLUMNS) if data.get(f"f_{i}") is not None}
    changes = uw.edit_changes(form, novo)
    if changes and "Description" not in changes and data.get("registar") == "1":
        desc = uw.describe_edit(settings, changes)
        if desc and "Description" in form.col_attr:
            changes["Description"] = (form.atual.get("Description", ""), desc)
    result = None
    if data.get("acao") == "gravar" and changes:
        problem = uw.enabled_problem(settings)
        if problem:
            erro = problem
        elif data.get("confirmo") != "1":
            erro = "Confirme a gravação na UCMDB."
        elif data.get("assinatura") != uw.edit_signature(form, changes):
            erro = "O certificado mudou na UCMDB ou o formulário foi alterado depois de rever. Reveja de novo."
        else:
            result = uw.apply_edit(settings, form, changes, user, UCMDB_CLIENT)
            form, _ = _edit_form(settings, ucmdb_id)
    elif data.get("acao") == "gravar":
        erro = "Nada mudou."
    return render(request, "ucmdb_editar.html", user, EDIT_COLUMNS=uw.EDIT_COLUMNS, settings=settings, q="", rows=[], form=form,
                  changes=None if result else changes, result=result, write_problem=uw.enabled_problem(settings),
                  erro=erro, novo=novo if not result else {}, registar=data.get("registar") == "1",
                  assinatura=uw.edit_signature(form, changes) if changes and form and not result else "")


UCMDB_WRITE_SYNC = False    # nos testes: aplica o lote no próprio pedido


@app.get("/cmdb-final/permissoes")
def ucmdb_permissoes(request: Request, user: str = Depends(current_user)):
    settings = get_settings()
    return render(request, "ucmdb_permissoes.html", user, settings=settings, rep=None, write_ci="", erro="")


@app.post("/cmdb-final/permissoes")
def ucmdb_permissoes_testar(request: Request, csrf: str = Form(""), escrita: str = Form(""), ci: str = Form(""),
                            confirmo: str = Form(""), user: str = Depends(current_user)):
    """Verifica o que a conta da UCMDB pode fazer. A escrita só é testada com confirmação e num CI escolhido."""
    check_csrf(request, csrf)
    settings = get_settings()
    write_ci, erro = "", ""
    if escrita:
        ref = ci.strip()
        with session_scope() as s:
            rec = None
            if ref:
                rec = s.scalar(select(CmdbRecord).where((CmdbRecord.ucmdb_id == ref) | (CmdbRecord.global_id == ref)))
                if rec is None:
                    rec = s.scalar(select(CmdbRecord).where(CmdbRecord.cn_norm == ref.lower(), CmdbRecord.active.is_(True))
                                   .order_by(CmdbRecord.valid_to.desc()))
            write_ci = rec.ucmdb_id if rec is not None else ""
        if not write_ci:
            erro = f"Não encontrei na CMDB o certificado \"{ref}\" (use o CommonName, o Global Id ou o ID do CI)."
        elif confirmo != "1":
            erro = "Confirme o teste de escrita."
            write_ci = ""
    rep = ua.check(settings, write_ci or None, UCMDB_CLIENT)
    with session_scope() as s:
        audit(s, user, "ucmdb.permissoes", write_ci or "leitura",
              resultado={st.call: st.ok for st in rep.steps})
    return render(request, "ucmdb_permissoes.html", user, settings=settings, rep=rep, write_ci=write_ci or ci, erro=erro)


@app.get("/cmdb-final/permissoes/apis")
def ucmdb_api_attributes(request: Request, ver: str = "", user: str = Depends(current_user)):
    """Só leitura: atributos do tipo de CI das APIs e o que o certwatch envia ao criar uma."""
    settings = get_settings()
    rep, erro = None, ""
    if ver:
        try:
            rep = uw.api_type_report(settings, UCMDB_CLIENT)
        except (ua.UcmdbError, uw.WriteError) as exc:
            erro = str(exc)
    return render(request, "ucmdb_apis_atributos.html", user, settings=settings, rep=rep, erro=erro)


@app.post("/cmdb-final/permissoes/criacao/preparar")
def ucmdb_criacao_preparar(request: Request, csrf: str = Form(""), user: str = Depends(current_user)):
    """Passo 1 do teste de criação: descobre o atributo de estado (só leitura)."""
    check_csrf(request, csrf)
    settings = get_settings()
    status = ua.status_candidates(settings, UCMDB_CLIENT)
    return render(request, "ucmdb_permissoes.html", user, settings=settings, rep=None, write_ci="", erro=status.error,
                  status=status)


@app.post("/cmdb-final/permissoes/criacao")
def ucmdb_criacao(request: Request, csrf: str = Form(""), ci_type: str = Form(""), escolha: str = Form(""),
                  valor_outro: str = Form(""), atributo_outro: str = Form(""), apagar: str = Form(""),
                  confirmo: str = Form(""), user: str = Depends(current_user)):
    """Passo 2: cria um certificado de teste não ativo, confirma-o e apaga-o."""
    check_csrf(request, csrf)
    settings = get_settings()
    attr, _, value = escolha.partition("::")
    if escolha == "outro":
        attr, value = atributo_outro.strip(), valor_outro.strip()
    erro = ""
    if confirmo != "1":
        erro = "Confirme a criação do certificado de teste."
    elif not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,99}", attr or "") or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,99}", ci_type):
        erro = "Escolha o atributo de estado."
    elif not value or len(value) > 120:
        erro = "Indique o valor de estado não ativo (até 120 caracteres)."
    created = None
    if not erro:
        created = ua.create_test(settings, ci_type, attr, value, user, delete=apagar == "1", client=UCMDB_CLIENT)
        with session_scope() as s:
            audit(s, user, "ucmdb.teste_criacao", created.created_id or "nada criado", tipo=ci_type, atributo=attr,
                  valor=value, ficou=created.left_behind, resultado={st.call or st.what: st.ok for st in created.steps})
    return render(request, "ucmdb_permissoes.html", user, settings=settings, rep=None, write_ci="", erro=erro,
                  created=created)


@app.post("/cmdb-final/permissoes/criacao/apagar")
def ucmdb_criacao_apagar(request: Request, csrf: str = Form(""), ci_id: str = Form(""), user: str = Depends(current_user)):
    """Apaga um certificado de teste deixado na UCMDB (só certwatch-teste-….invalid com a Description do teste)."""
    check_csrf(request, csrf)
    settings = get_settings()
    step = ua.delete_test(settings, ci_id.strip(), UCMDB_CLIENT)
    with session_scope() as s:
        audit(s, user, "ucmdb.teste_apagar", ci_id.strip()[:64], ok=step.ok, detalhe=step.detail[:300])
    return render(request, "ucmdb_permissoes.html", user, settings=settings, rep=None, write_ci="", erro="",
                  created=ua.CreateResult(steps=[step]))


UCMDB_CLIENT = None    # nos testes: cliente httpx para a UCMDB simulada


@app.get("/cmdb-final/{run_id}")
def final_run(request: Request, run_id: int, vista: str = "", q: str = "", fonte: str = "",
              incluida: str = "", user: str = Depends(current_user)):
    settings = get_settings()
    vista = _OLD_VIEWS.get(vista, vista)
    with session_scope() as s:
        _stale_runs(s)
        run = _run_or_404(s, run_id)
        newest = s.scalar(select(FinalRun.id).where(FinalRun.status.in_(("pronto", "bloqueado")))
                          .order_by(FinalRun.id.desc()).limit(1))
        sizes = {k: len(v) if v else 0 for k, v in (("xlsx", run.xlsx), ("csv", run.csv), ("csv_sem", run.csv_sem))}
        can_edit = cf.editable(s, run)
        uw.recover_stale(s)
        writes = uw.writes_for_run(s, run_id)
        writes_az = uw.writes_for_run(s, run_id, "azure")
        for w in [*writes.values(), *writes_az.values()]:
            s.expunge(w)
        s.expunge(run)
    all_changes = run.changes or []
    vistas = run.vistas or {}
    azure = vistas.get("azure") or []
    groups = {
        "novos": [c for c in all_changes if c["tipo"] == "novo"],
        "alterados": [c for c in all_changes if c["tipo"] != "novo"],
        "confirmar": [c for c in all_changes if c.get("pendente") or c.get("chave_repetida")],
    }
    counts = {"novos": len(groups["novos"]), "alterados": len(groups["alterados"]), "confirmar": len(groups["confirmar"]),
              "servidor": len(run.live or []), "so_na_cmdb": len(vistas.get("so_na_cmdb") or []),
              "azure": sum(1 for x in azure if x["estado"] not in ("igual", "expirado")), "erros": len(run.problems or [])}
    if vista not in FINAL_VIEWS:
        vista = next((k for k in ("novos", "alterados", "azure", "so_na_cmdb") if counts.get(k)), "novos")
    changes = groups.get(vista, [])
    if fonte:
        changes = [c for c in changes if c.get("fonte") == fonte]
    if incluida in ("sim", "nao"):
        changes = [c for c in changes if c.get("incluir", True) == (incluida == "sim")]
    if q:
        ql = q.lower()
        changes = [c for c in changes if any(ql in (c.get(k) or "").lower() for k in ("cn", "global_id", "serial", "issuer_name"))]
    az_view = request.query_params.get("az", "")
    azure_shown = [x for x in azure if (az_view == "todos" or x["estado"] not in ("igual", "expirado"))]
    to_apply = [c for c in all_changes if c.get("incluir", True)
                and not (writes.get(c["chave"]) and writes[c["chave"]].estado in uw.DONE)]
    will = {"criar": sum(1 for c in to_apply if c["tipo"] == "novo"), "atualizar": sum(1 for c in to_apply if c["tipo"] != "novo"),
            "excluidas": sum(1 for c in all_changes if not c.get("incluir", True))}
    guide = recon_guide(missing=[], run=run, busy=run.status == "a_gerar", to_apply=len(to_apply),
                        applied=sum(1 for w in writes.values() if w.estado in uw.DONE), write_on=settings.ucmdb_write,
                        on_run_page=True,
                        superseded_by=newest if newest and newest != run.id and run.status in ("pronto", "bloqueado") else None)
    return render(request, "final_run.html", user, run=run, guide=guide, will=will, vista=vista, views=FINAL_VIEWS, VIEWS=cf.VIEWS,
                  changes=changes[:3000], n_changes=len(changes), counts=counts, q=q, newest=newest, sizes=sizes,
                  FINAL_STATES=FINAL_STATES, settings=settings, fonte=fonte, incluida=incluida,
                  can_edit=can_edit, writes=writes, writes_az=writes_az, WRITE_STATES=uw.STATE_LABELS,
                  write_problem=uw.enabled_problem(settings),
                  write_busy=any(w.estado in uw.BUSY for w in [*writes.values(), *writes_az.values()]),
                  to_apply=[c["chave"] for c in all_changes if c.get("incluir", True)
                            and not (writes.get(c["chave"]) and writes[c["chave"]].estado in uw.DONE)],
                  msg=request.query_params.get("msg", ""), erro_msg=request.query_params.get("erro", ""),
                  fontes=sorted({c.get("fonte") for c in all_changes if c.get("fonte")}),
                  n_excl=sum(1 for c in all_changes if not c.get("incluir", True)),
                  so_na_cmdb=vistas.get("so_na_cmdb") or [], azure=azure_shown, az_view=az_view,
                  azure_total=len(azure), AZ_STATES=AZ_STATES, AZ_CLASSES=AZ_CLASSES, flow=cf.data_flow(run, settings.ucmdb_tql),
                  age_min=(utcnow() - as_utc(run.created_at)).total_seconds() / 60)


@app.post("/cmdb-final/{run_id}/azure")
def final_apply_azure(request: Request, run_id: int, csrf: str = Form(""), chave: int = Form(-1),
                      lista: str = Form(""), user: str = Depends(current_user)):
    """Inclui uma credencial do Azure na lista de APIs ou na de certificados (ou atualiza a data do registo)."""
    check_csrf(request, csrf)
    settings = get_settings()
    back = f"/cmdb-final/{run_id}?vista=azure"
    problem = uw.enabled_problem(settings)
    if problem:
        return RedirectResponse(f"{back}&{urlencode({'erro': problem})}", status_code=303)
    try:
        with session_scope() as s:
            run = _run_or_404(s, run_id)
            if not cf.editable(s, run):
                raise uw.WriteError("Só a reconciliação mais recente pode ser aplicada na UCMDB. Reconcilie de novo.")
            lote = uw.queue_azure(s, run, chave, lista, user)
    except uw.WriteError as exc:
        return RedirectResponse(f"{back}&{urlencode({'erro': str(exc)})}", status_code=303)
    uw.process(lote, settings, UCMDB_CLIENT)
    return RedirectResponse(f"{back}&{urlencode({'msg': 'Aplicado na UCMDB: veja o resultado na linha.'})}#az-{chave}",
                            status_code=303)


@app.get("/cmdb-final/{run_id}/ficheiro/{key}")
def final_download(run_id: int, key: str, user: str = Depends(current_user)):
    if key not in cf.FILES:
        raise HTTPException(404)
    with session_scope() as s:
        run = _run_or_404(s, run_id)
        data = cf.run_file(run, key)
        if data is None:
            raise HTTPException(404, "Ficheiro não disponível nesta reconciliação.")
        audit(s, user, "cmdb_final.descarregar", f"reconciliação {run_id}: {cf.FILES[key]}")
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
                            ["Linha", "Tipo", "Incluída nos ficheiros", "CommonName", "Global Id", "Fonte", "Campo", "Antes", "Depois",
                             "Validado no servidor", "Description"],
                            [[c["linha"] or "", c["tipo"], "sim" if c.get("incluir", True) else "não", c["cn"], c["global_id"],
                              c.get("fonte", ""), f["campo"], f["antes"], f["depois"], "sim" if c["servidor"] else "", c["descricao"]]
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


@app.post("/cmdb-final/{run_id}/selecao")
async def final_selection(request: Request, run_id: int, user: str = Depends(current_user)):
    form = await request.form()
    check_csrf(request, form.get("csrf"))
    try:
        shown = [int(x) for x in form.getlist("k")]
        chosen = {int(x) for x in form.getlist("incluir")}
    except ValueError:
        raise HTTPException(400, "Seleção inválida")
    try:
        with session_scope() as s:
            run = _run_or_404(s, run_id)
            n = cf.apply_selection(s, run, shown, chosen, user)
            if n:
                audit(s, user, "cmdb_final.selecao", f"reconciliação {run_id}", alteradas=n,
                      excluidas=sum(1 for c in run.changes if not c.get("incluir", True)))
    except cf.FinalError as exc:
        return _final_error(request, user, str(exc), f"/cmdb-final/{run_id}")
    back = safe_next(str(form.get("next") or ""), f"/cmdb-final/{run_id}")
    return RedirectResponse(back, status_code=303)


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

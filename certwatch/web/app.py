"""Interface web e API de leitura."""
from __future__ import annotations

from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select

from .. import __version__
from ..config import get_settings
from ..db import as_utc, init_db, session_scope, utcnow
from ..evaluator import FINDING_TYPES, SEV_RANK, SEVERITIES, days_left
from ..jobs import JOBS, enqueue
from ..models import AuditLog, Certificate, CmdbRecord, Endpoint, Finding, JobRun, ScanResult
from ..normalize import is_ip, is_valid_hostname, norm_host
from .security import check_csrf, current_user, security_middleware

BASE = Path(__file__).parent


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
templates.env.globals.update(FINDING_TYPES=FINDING_TYPES, SEVERITIES=SEVERITIES, version=__version__)


def render(request: Request, name: str, user: str, **ctx):
    return templates.TemplateResponse(request, name, {"user": user, "csrf": request.state.csrf, **ctx})


def safe_next(value: str | None, default: str) -> str:
    """Só permite redirecionar para caminhos locais."""
    if value and value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    return default


def audit(s, actor: str, action: str, target: str = "", **details) -> None:
    s.add(AuditLog(actor=actor, action=action, target=target[:600], details=details))


# ------------------------------------------------------------------ dados agregados
def build_inventory(s, now: datetime) -> list[dict]:
    records = list(s.scalars(select(CmdbRecord).where(CmdbRecord.active.is_(True))))
    by_cn: dict[str, list[CmdbRecord]] = defaultdict(list)
    for r in records:
        by_cn[r.cn_norm].append(r)

    endpoints = list(s.scalars(select(Endpoint).where(Endpoint.enabled.is_(True))))
    ep_by_cn: dict[str, list[Endpoint]] = defaultdict(list)
    for e in endpoints:
        ep_by_cn[e.expected_cn_norm].append(e)
    scan_ids = [e.last_scan_id for e in endpoints if e.last_scan_id]
    scans = {x.id: x for x in s.scalars(select(ScanResult).where(ScanResult.id.in_(scan_ids)))} if scan_ids else {}
    leafs = {x.leaf_sha256 for x in scans.values() if x.leaf_sha256}
    certs = {c.sha256: c for c in s.scalars(select(Certificate).where(Certificate.sha256.in_(leafs)))} if leafs else {}

    open_f: dict[str, list[Finding]] = defaultdict(list)
    for f in s.scalars(select(Finding).where(Finding.status == "aberto")):
        open_f[f.cn_norm].append(f)

    rows = []
    for cn, recs in by_cn.items():
        latest = max(recs, key=lambda r: as_utc(r.valid_to) or datetime.min.replace(tzinfo=timezone.utc))
        live_cert, statuses = None, []
        for ep in ep_by_cn.get(cn, []):
            sr = scans.get(ep.last_scan_id) if ep.last_scan_id else None
            if sr is None:
                continue
            statuses.append(sr.status)
            if sr.status == "ok" and sr.leaf_sha256 in certs:
                live_cert = certs[sr.leaf_sha256]
                break
        live_status = "ok" if live_cert else (statuses[0] if statuses else None)
        effective = live_cert.not_after if live_cert else latest.valid_to
        fl = open_f.get(cn, [])
        max_sev = max((f.severity for f in fl), key=lambda x: SEV_RANK[x], default=None)
        rows.append({
            "cn": cn,
            "common_name": latest.common_name,
            "kind": latest.kind,
            "issuers": sorted({r.issuer_name or r.issuer for r in recs if (r.issuer_name or r.issuer)}),
            "registos": len(recs),
            "cmdb_valid_to": latest.valid_to,
            "live_status": live_status,
            "live_not_after": live_cert.not_after if live_cert else None,
            "live_issuer": live_cert.issuer_cn if live_cert else None,
            "dias": days_left(effective, now) if effective else None,
            "fonte_data": "live" if live_cert else "cmdb",
            "findings": len(fl),
            "max_sev": max_sev,
        })
    rows.sort(key=lambda r: (r["dias"] is None, r["dias"] if r["dias"] is not None else 0, r["cn"]))
    return rows


# ------------------------------------------------------------------ páginas
@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"estado": "ok"}


@app.get("/")
def dashboard(request: Request, user: str = Depends(current_user)):
    now = utcnow()
    with session_scope() as s:
        inv = build_inventory(s, now)
        sev_counts = dict(s.execute(
            select(Finding.severity, func.count()).where(Finding.status == "aberto").group_by(Finding.severity)
        ).all())
        type_counts = s.execute(
            select(Finding.type, func.count()).where(Finding.status == "aberto").group_by(Finding.type)
            .order_by(func.count().desc())
        ).all()
        last_jobs = list(s.scalars(select(JobRun).order_by(JobRun.id.desc()).limit(5)))
        n_endpoints = s.scalar(select(func.count()).select_from(Endpoint).where(Endpoint.enabled.is_(True)))
    buckets = {"expirados": 0, "7": 0, "20": 0, "30": 0, "90": 0}
    for r in inv:
        d = r["dias"]
        if d is None:
            continue
        if d < 0:
            buckets["expirados"] += 1
        elif d <= 7:
            buckets["7"] += 1
        elif d <= 20:
            buckets["20"] += 1
        elif d <= 30:
            buckets["30"] += 1
        elif d <= 90:
            buckets["90"] += 1
    urgent = [r for r in inv if r["dias"] is not None and -30 <= r["dias"] <= 20][:15]
    return render(request, "dashboard.html", user, total=len(inv), buckets=buckets, sev_counts=sev_counts,
                  type_counts=type_counts, last_jobs=last_jobs, n_endpoints=n_endpoints,
                  live_ok=sum(1 for r in inv if r["live_status"] == "ok"), urgent=urgent)


@app.get("/certificados")
def certificados(request: Request, q: str = "", dias: str = "", sev: str = "", tipo: str = "",
                 user: str = Depends(current_user)):
    with session_scope() as s:
        rows = build_inventory(s, utcnow())
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in r["cn"] or any(ql in i.lower() for i in r["issuers"])]
    if dias.lstrip("-").isdigit():
        lim = int(dias)
        rows = [r for r in rows if r["dias"] is not None and r["dias"] <= lim]
    if sev in SEV_RANK:
        rows = [r for r in rows if r["max_sev"] and SEV_RANK[r["max_sev"]] >= SEV_RANK[sev]]
    if tipo in ("host", "wildcard", "ip", "other"):
        rows = [r for r in rows if r["kind"] == tipo]
    return render(request, "certificados.html", user, rows=rows, q=q, dias=dias, sev=sev, tipo=tipo)


@app.get("/certificados/detalhe")
def certificado_detalhe(request: Request, cn: str, user: str = Depends(current_user)):
    with session_scope() as s:
        recs = list(s.scalars(select(CmdbRecord).where(CmdbRecord.cn_norm == cn).order_by(CmdbRecord.valid_to.desc())))
        eps = list(s.scalars(select(Endpoint).where(Endpoint.expected_cn_norm == cn)))
        if not recs and not eps:
            raise HTTPException(404, "Certificado não encontrado")
        ep_data = []
        for ep in eps:
            sr = s.get(ScanResult, ep.last_scan_id) if ep.last_scan_id else None
            leaf = s.get(Certificate, sr.leaf_sha256) if sr and sr.leaf_sha256 else None
            history = list(s.scalars(select(ScanResult).where(ScanResult.endpoint_id == ep.id)
                                     .order_by(ScanResult.id.desc()).limit(10)))
            ep_data.append({"ep": ep, "scan": sr, "leaf": leaf, "history": history})
        findings = list(s.scalars(select(Finding).where(Finding.cn_norm == cn).order_by(Finding.status, Finding.last_seen.desc())))
    return render(request, "certificado.html", user, cn=cn, recs=recs, eps=ep_data, findings=findings, now=utcnow())


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
    return render(request, "jobs.html", user, runs=runs, audits=audits, jobs=JOBS,
                  daily_at=get_settings().pipeline_daily_at)


@app.post("/jobs/{job}")
def job_enqueue(request: Request, job: str, csrf: str = Form(""), user: str = Depends(current_user)):
    check_csrf(request, csrf)
    if job not in JOBS:
        raise HTTPException(404)
    jid = enqueue(job, user)
    with session_scope() as s:
        audit(s, user, "job.pedir", job, job_id=jid)
    return RedirectResponse("/jobs", status_code=303)


# ------------------------------------------------------------------ API (só leitura)
@app.get("/api/inventario")
def api_inventory(user: str = Depends(current_user)):
    with session_scope() as s:
        rows = build_inventory(s, utcnow())
    return JSONResponse([{k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in r.items()} for r in rows])


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

"""Percurso de renovação de um certificado a partir do pedido SMAX:

    1 Pedido aberto -> 2 Certificado renovado -> 3 Instalado no servidor -> 4 CMDB atualizada -> 5 Pedido fechado

Cada passo fica feito quando há prova (o pedido, uma renovação registada, o que o servidor apresenta, a CMDB lida
pelo Atalaia Cert, a fase no SMAX). O que falta mostra a ação seguinte.

Uma renovação registada aqui (do certificado que o servidor apresenta, do ficheiro do certificado ou à mão a
partir de um print) entra como fonte "RENOVACAO" na atualização da CMDB (cmdb_final).
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from cryptography import x509
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings
from .db import as_utc, utcnow
from .evaluator import Snapshot, load_snapshot
from .models import CtCert, FinalRun, Renewal, SmaxTicket, TicketStep, UcmdbWrite
from .normalize import norm_host

STEPS = [
    ("pedido", "Pedido aberto"),
    ("renovado", "Certificado renovado"),
    ("instalado", "Instalado no servidor"),
    ("cmdb", "CMDB atualizada"),
    ("fechado", "Pedido fechado"),
]
STEP_LABELS = dict(STEPS)
ORIGIN_LABELS = {"servidor": "certificado apresentado pelo servidor", "ficheiro": "ficheiro do certificado",
                 "manual": "indicada à mão"}


class RenewalError(RuntimeError):
    pass


# ------------------------------------------------------------------ certificado carregado
def parse_certificate(data: bytes) -> dict:
    """Ficheiro .cer/.crt/.pem/.der: devolve nome, datas, série, emissor e SAN (do primeiro certificado)."""
    cert = None
    try:
        if b"-----BEGIN CERTIFICATE-----" in data:
            cert = x509.load_pem_x509_certificates(data)[0]
        else:
            cert = x509.load_der_x509_certificate(data)
    except (ValueError, IndexError):
        cert = None
    if cert is None:
        raise RenewalError("O ficheiro não é um certificado X.509 (PEM ou DER). Exporte o certificado em .cer/.crt/.pem.")
    from .scanner import summarize
    from cryptography.hazmat.primitives.serialization import Encoding
    s = summarize(cert.public_bytes(Encoding.DER))
    return {"cn": s["subject_cn"], "nomes": s["sans_dns"], "not_before": s["not_before"], "not_after": s["not_after"],
            "serial": s["serial_hex"].upper(), "emissor": s["issuer_cn"], "sha256": s["sha256"], "is_ca": s["is_ca"]}


def name_matches(cn: str, names: list[str]) -> bool:
    cn = norm_host(cn)
    for n in names:
        n = norm_host(n)
        if n == cn:
            return True
        if n.startswith("*.") and cn.count(".") == n.count(".") and cn.endswith(n[1:]):
            return True
    return False


def register(session: Session, *, ticket_id: str, cn: str, valid_to: datetime, serial: str = "", issuer: str = "",
             san: str = "", origin: str, actor: str, note: str = "", sha256: str = "") -> Renewal:
    if origin not in ORIGIN_LABELS:
        raise RenewalError("Origem inválida")
    cn = norm_host(cn)
    if not cn:
        raise RenewalError("Falta o nome do certificado.")
    # Uma renovação por pedido e nome: a nova substitui a anterior
    for old in session.scalars(select(Renewal).where(Renewal.cn == cn, Renewal.ticket_id == ticket_id,
                                                     Renewal.active.is_(True))):
        old.active = False
    r = Renewal(ticket_id=ticket_id, cn=cn, valid_to=as_utc(valid_to), serial=serial.strip()[:128],
                issuer=issuer.strip()[:512], san=san[:4000], origin=origin, cert_sha256=sha256, note=note.strip()[:2000],
                created_by=actor)
    session.add(r)
    session.flush()
    return r


def scan_now(session: Session, settings: Settings, cn: str) -> list[dict]:
    """Verifica agora os servidores deste certificado (até 10). Sem servidores registados, liga-se a cn:443."""
    from .jobs import _store_outcome, _valid_target
    from .models import Endpoint
    from .scanner import scan_endpoint, summarize
    from .trust import build_bundle
    from .normalize import is_ip, is_valid_hostname
    cafile = build_bundle(settings)
    eps = [e for e in session.scalars(select(Endpoint).where(Endpoint.expected_cn_norm == cn, Endpoint.enabled.is_(True)))
           if _valid_target(e, settings)][:10]
    out = []
    for e in eps:
        o = scan_endpoint(e.host, e.port, cafile, settings.scan_timeout)
        sr = _store_outcome(session, e, o)
        leaf = summarize(o.chain_der[0]) if o.chain_der else None
        out.append({"site": f"{e.host}:{e.port}", "estado": sr.status, "erro": sr.error,
                    "not_after": leaf["not_after"] if leaf else None, "serial": leaf["serial_hex"].upper() if leaf else "",
                    "emissor": leaf["issuer_cn"] if leaf else "", "nomes": leaf["sans_dns"] if leaf else [],
                    "cn": leaf["subject_cn"] if leaf else "", "guardado": True})
    if not eps and not cn.startswith("*.") and (is_valid_hostname(cn) or is_ip(cn)):
        o = scan_endpoint(cn, 443, cafile, settings.scan_timeout)
        leaf = summarize(o.chain_der[0]) if o.chain_der else None
        out.append({"site": f"{cn}:443", "estado": o.status, "erro": o.error,
                    "not_after": leaf["not_after"] if leaf else None, "serial": leaf["serial_hex"].upper() if leaf else "",
                    "emissor": leaf["issuer_cn"] if leaf else "", "nomes": leaf["sans_dns"] if leaf else [],
                    "cn": leaf["subject_cn"] if leaf else "", "guardado": False})
    return out


# ------------------------------------------------------------------ percurso
@dataclass
class Context:
    """Dados partilhados para calcular o percurso de vários pedidos de uma vez."""
    snap: Snapshot
    renewals: dict[str, list[Renewal]] = field(default_factory=dict)
    ct: dict[str, list[CtCert]] = field(default_factory=dict)
    steps: dict[str, dict[str, TicketStep]] = field(default_factory=dict)
    runs: list[FinalRun] = field(default_factory=list)
    writes: dict[tuple[int, int], UcmdbWrite] = field(default_factory=dict)   # (reconciliação, alteração) -> escrita


def load_context(session: Session) -> Context:
    ctx = Context(snap=load_snapshot(session))
    ren: dict[str, list[Renewal]] = defaultdict(list)
    for r in session.scalars(select(Renewal).where(Renewal.active.is_(True)).order_by(Renewal.id.desc())):
        ren[r.cn].append(r)
    ctx.renewals = ren
    ct: dict[str, list[CtCert]] = defaultdict(list)
    for c in session.scalars(select(CtCert).where(CtCert.triage != "ignorar")):
        if c.primary_name:
            ct[norm_host(c.primary_name)].append(c)
    ctx.ct = ct
    st: dict[str, dict[str, TicketStep]] = defaultdict(dict)
    for x in session.scalars(select(TicketStep)):
        st[x.ticket_id][x.step] = x
    ctx.steps = st
    ctx.runs = list(session.scalars(select(FinalRun).where(FinalRun.status.in_(("pronto", "bloqueado")))
                                    .order_by(FinalRun.id.desc()).limit(3)))
    ids = [r.id for r in ctx.runs]
    if ids:
        for w in session.scalars(select(UcmdbWrite).where(UcmdbWrite.run_id.in_(ids)).order_by(UcmdbWrite.id)):
            ctx.writes[(w.run_id, w.chave)] = w
    return ctx


def _day(dt, tz) -> date | None:
    return as_utc(dt).astimezone(tz).date() if dt else None


def pipeline(t: SmaxTicket, settings: Settings, ctx: Context) -> dict:
    tz = ZoneInfo(settings.timezone)
    closed = (t.phase or "").lower() in set(settings.smax_closed_phases)
    cn = norm_host(t.endpoint or "")
    old = _day(t.cert_expiry, tz)
    manual = ctx.steps.get(t.id, {})

    # 2) provas de renovação: data mais recente do que a do pedido
    ev: list[dict] = []
    for r in ctx.renewals.get(cn, []):
        d = _day(r.valid_to, tz)
        if d and (old is None or d > old):
            ev.append({"fonte": f"Registada no Atalaia Cert ({ORIGIN_LABELS.get(r.origin, r.origin)})", "data": d,
                       "serie": r.serial, "emissor": r.issuer, "por": r.created_by, "id": r.id, "registada": True})
    live: list[dict] = []
    for ep in ctx.snap.ep_by_cn.get(cn, []):
        if not ep.enabled:
            continue
        sr = ctx.snap.scan_for(ep)
        leaf = ctx.snap.leaf_for(sr)
        live.append({"site": f"{ep.host}:{ep.port}", "estado": sr.status if sr else None,
                     "data": _day(leaf.not_after, tz) if leaf else None, "quando": sr.scanned_at if sr else None,
                     "serie": (leaf.serial_hex or "").upper() if leaf else "", "emissor": leaf.issuer_cn if leaf else ""})
        if leaf and leaf.not_after and old and _day(leaf.not_after, tz) > old:
            ev.append({"fonte": f"Servidor {ep.host}:{ep.port}", "data": _day(leaf.not_after, tz),
                       "serie": (leaf.serial_hex or "").upper(), "emissor": leaf.issuer_cn, "servidor": True})
    cmdb = [r for r in ctx.snap.by_cn.get(cn, []) if r.valid_to]
    for r in cmdb:
        d = _day(r.valid_to, tz)
        if old and d > old:
            ev.append({"fonte": "CMDB", "data": d, "serie": "", "emissor": r.issuer_name or r.issuer})
    for c in ctx.ct.get(cn, []):
        d = _day(c.not_after, tz)
        if old and d and d > old:
            ev.append({"fonte": "Internet (CT)", "data": d, "serie": (c.serial_hex or "").upper(), "emissor": c.issuer_cn})
    registered = [e for e in ev if e.get("registada")]
    target = (registered[0]["data"] if registered else max((e["data"] for e in ev), default=None))

    steps: dict[str, dict] = {k: {"key": k, "label": lbl, "done": False, "detail": "", "manual": None} for k, lbl in STEPS}
    steps["pedido"].update(done=True, detail=f"{t.id} · fase {t.phase or '?'}")
    s2 = steps["renovado"]
    if target:
        s2.update(done=True, detail=f"Nova validade {target:%d-%m-%Y}" + (f" (antes {old:%d-%m-%Y})" if old else ""))
    else:
        s2["detail"] = ("Ainda sem prova de um certificado novo" + (f" (o pedido refere {old:%d-%m-%Y})" if old else "")
                        + ". Veja os comentários e registe a renovação.")

    s3 = steps["instalado"]
    ok_sites = [x for x in live if x["estado"] == "ok" and x["data"]]
    if manual.get("instalado"):
        m = manual["instalado"]
        s3.update(done=True, manual=m, detail=f"Confirmado por {m.by} em {as_utc(m.at).astimezone(tz):%d-%m-%Y}")
    elif not live:
        s3["detail"] = "Sem servidores verificados para este nome. Verifique agora ou confirme à mão."
    elif target and ok_sites and all(x["data"] >= target - timedelta(days=1) for x in ok_sites):
        s3.update(done=True, detail=f"{len(ok_sites)} servidor(es) já apresentam o certificado novo")
    elif target:
        behind = [x["site"] for x in ok_sites if x["data"] < target - timedelta(days=1)]
        s3["detail"] = (f"Ainda com o certificado antigo: {', '.join(behind[:4])}" if behind
                        else "Os servidores não responderam na última verificação.")
    else:
        s3["detail"] = "Depende da renovação."

    s4 = steps["cmdb"]
    in_cmdb = [r for r in cmdb if target and abs((_day(r.valid_to, tz) - target).days) <= 1]
    s4["run"] = None
    if in_cmdb:
        s4.update(done=True, detail=f"A CMDB já tem {target:%d-%m-%Y}")
    elif target:
        for run in ctx.runs:
            ch = next((c for c in (run.changes or []) if norm_host(c.get("cn") or "") == cn), None)
            if ch is None:
                continue
            from .cmdb_final import parse_day
            if parse_day(ch.get("validto")).day and abs((parse_day(ch.get("validto")).day - target).days) <= 1:
                inc = ch.get("incluir", True)
                w = ctx.writes.get((run.id, ch.get("chave")))
                applied = w is not None and w.estado in ("ok", "aviso")
                s4["run"] = {"id": run.id, "incluida": inc, "aplicada": applied, "chave": ch.get("chave")}
                if applied:
                    s4.update(done=True, detail=f"Aplicada na UCMDB na reconciliação #{run.id} "
                                                f"({as_utc(w.feito_em or w.pedido_em).astimezone(tz):%d-%m-%Y})")
                else:
                    s4["detail"] = (f"Na reconciliação #{run.id}, " + ("incluída, por aplicar na UCMDB" if inc else "excluída"))
                break
        else:
            s4["detail"] = ("Ainda não está numa reconciliação. Reconcilie em CMDB → Atualizar a CMDB"
                            + (" (a renovação registada entra automaticamente)." if registered else
                               "; registe a renovação para garantir que entra."))
    else:
        s4["detail"] = "Depende da renovação."

    s5 = steps["fechado"]
    if closed:
        s5.update(done=True, detail=f"Fase {t.phase}")
    else:
        s5["detail"] = "Feche o pedido quando os passos anteriores estiverem feitos."

    order = [k for k, _ in STEPS]
    current = next((k for k in order if not steps[k]["done"]), None)
    warnings = []
    if closed and current and current != "fechado":
        warnings.append(f"O pedido está fechado, mas falta: {STEP_LABELS[current].lower()}.")
    return {"cn": cn, "old": old, "target": target, "evidence": ev, "live": live, "cmdb": cmdb, "steps": [steps[k] for k in order],
            "current": current, "current_label": STEP_LABELS.get(current, "Concluído"), "closed": closed,
            "done": sum(1 for k in order if steps[k]["done"]), "warnings": warnings,
            "renewals": ctx.renewals.get(cn, [])}


def confirm_step(session: Session, ticket_id: str, step: str, actor: str, note: str = "", undo: bool = False) -> None:
    if step != "instalado":
        raise RenewalError("Só a instalação pode ser confirmada à mão; os outros passos dependem de provas.")
    cur = session.scalar(select(TicketStep).where(TicketStep.ticket_id == ticket_id, TicketStep.step == step))
    if undo:
        if cur is not None:
            session.delete(cur)
        return
    if cur is None:
        cur = TicketStep(ticket_id=ticket_id, step=step)
        session.add(cur)
    cur.by, cur.at, cur.note = actor, utcnow(), note.strip()[:1000]


def source_items(session: Session, today: date) -> list[dict]:
    """Renovações ativas como linhas de fonte para a atualização da CMDB (uma por nome: a mais recente)."""
    seen: dict[str, Renewal] = {}
    for r in session.scalars(select(Renewal).where(Renewal.active.is_(True)).order_by(Renewal.id.desc())):
        if r.cn not in seen and as_utc(r.valid_to).date() >= today:
            seen[r.cn] = r
    return [{"cn": r.cn, "day": as_utc(r.valid_to).date(), "serial": r.serial, "issuer": r.issuer, "san": r.san, "origin": r.origin,
             "ref": f"pedido {r.ticket_id}" if r.ticket_id else f"renovação #{r.id}", "id": r.id}
            for r in seen.values()]

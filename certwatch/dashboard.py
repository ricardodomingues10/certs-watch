"""Painel orientado à ação: o que expira sem pedido, o que se moveu nos pedidos, o que está parado e os
indicadores de conformidade (NIS2). Funções sem efeitos: leem a base de dados e devolvem listas e números."""
from __future__ import annotations

import statistics
from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings
from .db import as_utc
from .evaluator import Snapshot, days_left
from .models import Finding, SmaxComment, SmaxEvent, SmaxTicket
from .normalize import norm_label, split_api_name
from .tickets import already_renewed, is_open, last_comments, link as ticket_link, tickets_by_label, ticket_url

EXPIRED_WINDOW = 30          # expirados há até N dias continuam na lista (sem pedido = o mais urgente)
COVERAGE_DAYS = 90           # cobertura: certificados e APIs que expiram nos próximos N dias


def _expiry_of(r: dict) -> datetime | None:
    return r["live_not_after"] or r["cmdb_valid_to"]


def expiring_without_ticket(inv: list[dict], snap: Snapshot, session: Session, settings: Settings,
                            now: datetime) -> list[dict]:
    """Certificados e APIs que expiram nos próximos N dias (ou expiraram há pouco) sem pedido em curso no SMAX.
    Um certificado servido em vários nomes (wildcard, SAN) conta uma vez, com todos os nomes."""
    limit = settings.dash_expiry_days
    items: dict[str, dict] = {}
    for r in inv:
        d = r["dias"]
        if d is None or d > limit or d < -EXPIRED_WINDOW or r["smax"]["state"] == "em_curso":
            continue
        key = r["servido_por"]["cn"] if r["servido_por"] else r["cn"]
        if key in items:
            items[key]["nomes"].append(r["cn"])
            continue
        items[key] = {
            "tipo": "certificado", "nome": key, "nomes": [r["cn"]], "dias": d, "expira": _expiry_of(r),
            "emissor": r["live_issuer"] or (r["issuers"][0] if r["issuers"] else ""),
            "onde": [x["site"] for x in r["instalado_em"]][:8] if r["instalado_em"] else [],
            "n_sites": len(r["instalado_em"] or []),
            "confirmado": r["fonte_data"] == "live", "auto": r["renovacao"] == "auto",
            "pedido": r["smax"], "url": f"/certificados/detalhe?cn={key}", "criar": r["cn"],
        }
    by_label, comments = tickets_by_label(session), last_comments(session)
    for a in snap.apis:
        if a.expiry is None:
            continue
        d = days_left(a.expiry, now)
        if d > limit or d < -EXPIRED_WINDOW:
            continue
        lk = ticket_link(by_label.get(norm_label(a.name), []), a.expiry, settings, comments)
        if lk["state"] == "em_curso":
            continue
        base, _ = split_api_name(a.name)
        items[f"api:{a.ucmdb_id}"] = {
            "tipo": "API", "nome": base or a.name, "nomes": [a.name], "dias": d, "expira": a.expiry,
            "emissor": a.application or "", "onde": [a.location] if a.location else [], "n_sites": 0,
            "confirmado": True, "auto": False, "pedido": lk, "url": f"/apis?q={base or a.name}", "criar": None,
        }
    return sorted(items.values(), key=lambda x: (x["dias"], x["nome"]))


def _ticket_index(session: Session) -> dict[str, SmaxTicket]:
    return {t.id: t for t in session.scalars(select(SmaxTicket))}


def ticket_activity(session: Session, settings: Settings, now: datetime, hours: int) -> list[dict]:
    """O que se moveu nos pedidos no período: pedidos novos, mudanças de fase e comentários."""
    since = now - timedelta(hours=hours)
    tickets = _ticket_index(session)
    out = []
    for e in session.scalars(select(SmaxEvent).where(SmaxEvent.at >= since)):
        t = tickets.get(e.ticket_id)
        out.append({"quando": as_utc(e.at), "pedido": e.ticket_id, "url": ticket_url(settings, e.ticket_id),
                    "alvo": e.endpoint or (t.endpoint if t else ""), "titulo": e.label or (t.display_label if t else ""),
                    "tipo": e.kind, "de": e.de, "para": e.para, "autor": "", "texto": ""})
    for c in session.scalars(select(SmaxComment).where(SmaxComment.created_at >= since)):
        t = tickets.get(c.ticket_id)
        out.append({"quando": as_utc(c.created_at), "pedido": c.ticket_id, "url": ticket_url(settings, c.ticket_id),
                    "alvo": t.endpoint if t else "", "titulo": t.display_label if t else "", "tipo": "comentario",
                    "de": "", "para": t.phase if t else "", "autor": c.author or "",
                    "texto": " ".join((c.body or "").split())[:220]})
    out.sort(key=lambda x: x["quando"], reverse=True)
    return out


def stale_tickets(session: Session, settings: Settings, now: datetime, current: dict | None = None) -> list[dict]:
    """Pedidos abertos sem movimento (atualização, comentário ou mudança de fase) há N dias ou mais."""
    days = settings.dash_stale_days
    last_comment: dict[str, datetime] = {}
    for tid, at in session.execute(select(SmaxComment.ticket_id, SmaxComment.created_at)):
        if at is not None and (tid not in last_comment or as_utc(at) > last_comment[tid]):
            last_comment[tid] = as_utc(at)
    last_event: dict[str, datetime] = {}
    for tid, at in session.execute(select(SmaxEvent.ticket_id, SmaxEvent.at)):
        if tid not in last_event or as_utc(at) > last_event[tid]:
            last_event[tid] = as_utc(at)
    out = []
    for t in session.scalars(select(SmaxTicket)):
        if not is_open(t, settings):
            continue
        moments = [x for x in (as_utc(t.last_update), last_comment.get(t.id), last_event.get(t.id)) if x]
        last = max(moments) if moments else None
        idle = (now - last).days if last else None
        if idle is not None and idle < days:
            continue
        exp = as_utc(t.cert_expiry)
        out.append({"pedido": t.id, "url": ticket_url(settings, t.id), "alvo": t.endpoint, "titulo": t.display_label,
                    "fase": t.phase, "grupo": t.owner_group, "responsavel": t.owner_person, "parado": idle,
                    "ultimo": last, "cert_dias": days_left(exp, now) if exp else None,
                    "urgente": exp is not None and days_left(exp, now) <= settings.dash_expiry_days,
                    "renovado": already_renewed(t, current or {}, settings)})
    out.sort(key=lambda x: (x["cert_dias"] is None, x["cert_dias"] if x["cert_dias"] is not None else 0, x["pedido"]))
    return out


def _median(values: list[float]) -> float | None:
    return round(statistics.median(values), 1) if values else None


def nis2(inv: list[dict], snap: Snapshot, session: Session, settings: Settings, now: datetime,
         open_findings: list[Finding]) -> dict:
    """Indicadores para demonstrar e acompanhar as medidas do artigo 21.º da NIS2 (gestão de ativos,
    criptografia, continuidade, eficácia) e apoiar a avaliação de incidentes do artigo 23.º."""
    ftypes = Counter(f.type for f in open_findings)
    seen_live = [r for r in inv if r["fonte_data"] == "live"]
    # Cobertura: o que expira nos próximos 90 dias (renovação manual) e já tem pedido em curso
    due = [r for r in inv if r["dias"] is not None and 0 <= r["dias"] <= COVERAGE_DAYS and r["renovacao"] != "auto"]
    by_label, comments = tickets_by_label(session), last_comments(session)
    api_due = []
    for a in snap.apis:
        if a.expiry is not None and 0 <= days_left(a.expiry, now) <= COVERAGE_DAYS:
            api_due.append(ticket_link(by_label.get(norm_label(a.name), []), a.expiry, settings, comments)["state"])
    covered = sum(1 for r in due if r["smax"]["state"] == "em_curso") + sum(1 for s in api_due if s == "em_curso")
    total_due = len(due) + len(api_due)
    # Antecedência e tempo de reação dos pedidos criados nos últimos 180 dias (precisa da data de criação do SMAX)
    since = now - timedelta(days=180)
    first_alert: dict[str, datetime] = {}
    for f in session.scalars(select(Finding).where(Finding.type == "EXPIRACAO")):
        if f.cn_norm and (f.cn_norm not in first_alert or as_utc(f.first_seen) < first_alert[f.cn_norm]):
            first_alert[f.cn_norm] = as_utc(f.first_seen)
    lead, react = [], []
    for t in session.scalars(select(SmaxTicket).where(SmaxTicket.created.is_not(None))):
        created = as_utc(t.created)
        if created < since:
            continue
        if t.cert_expiry is not None:
            lead.append((as_utc(t.cert_expiry) - created).total_seconds() / 86400)
        fa = first_alert.get(t.endpoint)
        if fa is not None and created >= fa:
            react.append((created - fa).total_seconds() / 86400)
    expired_live = [r for r in seen_live if r["dias"] is not None and r["dias"] < 0]
    return {
        "inventario": {"certificados": len(inv), "confirmados": len(seen_live), "apis": len(snap.apis),
                       "sem_cmdb": sum(1 for r in seen_live if not r["in_cmdb"])},
        "cripto": {"fraca": ftypes.get("CRIPTO_FRACA", 0), "tls_legado": ftypes.get("TLS_LEGADO", 0),
                   "autoassinados": ftypes.get("SELF_SIGNED", 0), "cadeia": ftypes.get("CHAIN_INVALIDA", 0),
                   "api_sem_tls": ftypes.get("API_SEM_TLS", 0)},
        "cobertura": {"total": total_due, "com_pedido": covered,
                      "pct": round(100 * covered / total_due) if total_due else None},
        "antecedencia": _median(lead), "reacao": _median(react), "n_pedidos": len(lead),
        "expirados_em_uso": expired_live,
    }


def kpis(items: list[dict], stale: list[dict], activity: list[dict], nis: dict, open_findings: list[Finding]) -> dict:
    return {
        "expirados_em_uso": len(nis["expirados_em_uso"]),
        "sem_pedido": sum(1 for x in items if x["dias"] >= 0),
        "sem_pedido_7": sum(1 for x in items if 0 <= x["dias"] <= 7),
        "expirados_sem_pedido": sum(1 for x in items if x["dias"] < 0),
        "nao_instalados": sum(1 for f in open_findings if f.type == "RENOVACAO_NAO_INSTALADA"),
        "parados": len(stale),
        "parados_urgentes": sum(1 for x in stale if x["urgente"]),
        "criticos": sum(1 for f in open_findings if f.severity == "critica"),
        "movimento": len(activity),
    }


def evidence_rows(inv: list[dict], snap: Snapshot, session: Session, settings: Settings, now: datetime) -> list[list]:
    """Linhas do relatório de evidência: cada certificado e API, a data, o pedido e o estado dos testes."""
    by_label, comments = tickets_by_label(session), last_comments(session)
    rows = []
    for r in inv:
        main = r["smax"]["main"] or {}
        exp = _expiry_of(r)
        rows.append(["certificado", r["cn"], as_utc(exp).strftime("%Y-%m-%d") if exp else "", r["dias"] if r["dias"] is not None else "",
                     r["live_issuer"] or ", ".join(r["issuers"]), "servidor" if r["fonte_data"] == "live" else r["fonte_data"],
                     "sim" if r["in_cmdb"] else "não", r["renovacao"], r["smax"]["label"], main.get("id", ""),
                     main.get("fase", ""), r["max_sev"] or "", r["findings"]])
    for a in snap.apis:
        lk = ticket_link(by_label.get(norm_label(a.name), []), a.expiry, settings, comments)
        main = lk["main"] or {}
        rows.append(["API", a.name, as_utc(a.expiry).strftime("%Y-%m-%d") if a.expiry else "",
                     days_left(a.expiry, now) if a.expiry else "", a.application or "", "CMDB", "sim", "manual",
                     lk["label"], main.get("id", ""), main.get("fase", ""), "", ""])
    return rows


EVIDENCE_HEADER = ["Tipo", "Nome", "Expira", "Dias", "Emissor / aplicação", "Data confirmada por", "Na CMDB",
                   "Renovação", "Situação do pedido", "Pedido", "Fase", "Alerta mais grave", "Alertas abertos"]

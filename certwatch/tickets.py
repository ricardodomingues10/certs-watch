"""Tickets do SMAX: guardar a última leitura e ligar cada certificado aos seus pedidos.

Um ticket refere-se a um certificado pelo endpoint (nome) e pela data de expiração do certificado a renovar.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .collectors.smax import discussions_url, fetch_comments, fetch_tickets, ticket_url
from .config import Settings
from .db import as_utc, utcnow
from .models import SmaxComment, SmaxTicket

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

TICKET_STATES = {
    "em_curso": "Pedido em curso",
    "outra_data": "Pedido aberto para outra data",
    "fechado": "Só pedidos fechados",
    "sem_pedido": "Sem pedido",
}
TICKET_HELP = {
    "em_curso": "Há um pedido aberto no SMAX para este certificado (mesmo nome e mesma data de expiração).",
    "outra_data": "Há um pedido aberto para este nome, mas com outra data de expiração: pode ser de um certificado "
                  "anterior que ficou por fechar, ou o pedido tem a data errada.",
    "fechado": "Existem pedidos para este nome, todos fechados. Se o certificado está a expirar, é preciso um pedido novo.",
    "sem_pedido": "Não há nenhum pedido no SMAX para este nome.",
}


def ingest_smax(session: Session, settings: Settings, tickets: list[dict] | None = None,
                comments: bool | None = None) -> dict:
    if tickets is None:
        tickets = fetch_tickets(settings)
        comments = settings.smax_comments if comments is None else comments
    now = utcnow()
    session.execute(delete(SmaxTicket))
    seen = set()
    for t in tickets:
        if t["id"] in seen:
            continue
        seen.add(t["id"])
        session.add(SmaxTicket(**t, fetched_at=now))
    session.flush()
    closed = set(settings.smax_closed_phases)
    out = {"tickets": len(seen), "com_endpoint": sum(1 for t in tickets if t["endpoint"]),
           "abertos": sum(1 for t in tickets if t["phase"].lower() not in closed)}
    if comments:
        # Comentários dos pedidos abertos (os mais recentes primeiro)
        opened = [t["id"] for t in sorted(tickets, key=lambda x: x["last_update"] or _EPOCH, reverse=True)
                  if t["phase"].lower() not in closed]
        try:
            found, info = fetch_comments(settings, opened)
        except Exception as exc:   # comentários são extra: nunca falham a leitura dos pedidos
            out["comentarios"] = {"erro": str(exc)[:300]}
            return out
        fetched = opened[: settings.smax_comments_max]
        if fetched:
            session.execute(delete(SmaxComment).where(SmaxComment.ticket_id.in_(fetched)))
        seen_c = set()
        for c in found:
            if c["id"] not in seen_c:
                seen_c.add(c["id"])
                session.add(SmaxComment(**c))
        out["comentarios"] = info
    return out


def last_comments(session: Session) -> dict[str, dict]:
    """Por pedido: número de comentários e o mais recente."""
    out: dict[str, dict] = {}
    for c in session.scalars(select(SmaxComment).order_by(SmaxComment.created_at)):
        e = out.setdefault(c.ticket_id, {"n": 0, "ultimo": None})
        e["n"] += 1
        e["ultimo"] = {"quando": c.created_at, "autor": c.author or (f"utilizador {c.author_id}" if c.author_id else ""),
                       "texto": c.body}
    return out


def is_open(t: SmaxTicket, settings: Settings) -> bool:
    return (t.phase or "").lower() not in set(settings.smax_closed_phases)


def tickets_by_endpoint(session: Session) -> dict[str, list[SmaxTicket]]:
    out: dict[str, list[SmaxTicket]] = defaultdict(list)
    for t in session.scalars(select(SmaxTicket).where(SmaxTicket.endpoint != "")):
        out[t.endpoint].append(t)
    return out


def link(tickets: list[SmaxTicket], expiry: datetime | None, settings: Settings, comments: dict | None = None) -> dict:
    """Resumo dos pedidos de um certificado: estado, pedido principal (com link) e listas."""
    def recent(t: SmaxTicket) -> datetime:
        return as_utc(t.last_update) or _EPOCH

    def same_date(t: SmaxTicket) -> bool:
        if t.cert_expiry is None or expiry is None:
            return t.cert_expiry is None   # pedido sem data: conta como deste certificado
        return abs((as_utc(t.cert_expiry).date() - as_utc(expiry).date()).days) <= 1

    ordered = sorted(tickets, key=recent, reverse=True)
    opened = [t for t in ordered if is_open(t, settings)]
    closed = [t for t in ordered if not is_open(t, settings)]
    matching = [t for t in opened if same_date(t)]
    if matching:
        state, main = "em_curso", matching[0]
    elif opened:
        state, main = "outra_data", opened[0]
    elif closed:
        state, main = "fechado", closed[0]
    else:
        state, main = "sem_pedido", None
    def as_dict(x: SmaxTicket) -> dict:
        return {"id": x.id, "url": ticket_url(settings, x.id), "titulo": x.display_label, "fase": x.phase,
                "aberto": is_open(x, settings), "ambiente": x.environment, "expira": x.cert_expiry,
                "deste_certificado": same_date(x), "grupo": x.owner_group, "responsavel": x.owner_person,
                "atualizado": x.last_update, "tipo": x.cert_type,
                "discussao": discussions_url(settings, x.id),
                "comentarios": (comments or {}).get(x.id, {}).get("n", 0),
                "ultimo_comentario": (comments or {}).get(x.id, {}).get("ultimo")}

    return {
        "state": state, "label": TICKET_STATES[state],
        "main": as_dict(main) if main else None,
        "open": [as_dict(x) for x in opened], "closed": [as_dict(x) for x in closed],
        "varios_abertos": len(matching) > 1,
    }


def tickets_by_label(session: Session) -> dict[str, list[SmaxTicket]]:
    """Pedidos indexados pelo nome normalizado (para ligar às APIs, cujo "endpoint" é um nome e não um host)."""
    from .normalize import norm_label
    out: dict[str, list[SmaxTicket]] = defaultdict(list)
    for t in session.scalars(select(SmaxTicket).where(SmaxTicket.endpoint != "")):
        out[norm_label(t.endpoint)].append(t)
    return out


TICKET_VIEWS = {
    "abertos": "Abertos",
    "atrasados": "Abertos com certificado já expirado",
    "fim_ultrapassado": "Abertos com fim planeado ultrapassado",
    "comentarios": "Com comentários",
    "fechados": "Fechados",
    "todos": "Todos",
}


def ticket_list(session: Session, settings: Settings, view: str = "abertos", q: str = "") -> tuple[list[dict], dict]:
    """Todos os pedidos lidos do SMAX, com a ligação ao certificado ou API e o último comentário."""
    from .models import ApiRecord, CmdbRecord, Endpoint
    from .normalize import norm_label
    now = utcnow()
    comments = last_comments(session)
    cert_names = {r.cn_norm for r in session.scalars(select(CmdbRecord).where(CmdbRecord.active.is_(True)))}
    cert_names |= {e.expected_cn_norm for e in session.scalars(select(Endpoint))}
    apis = {norm_label(a.name): a.name for a in session.scalars(select(ApiRecord).where(ApiRecord.active.is_(True)))}
    rows = []
    for t in session.scalars(select(SmaxTicket)):
        aberto = is_open(t, settings)
        exp = as_utc(t.cert_expiry)
        end = as_utc(t.scheduled_end)
        alvo = None
        if t.endpoint in cert_names:
            alvo = {"tipo": "certificado", "nome": t.endpoint, "url": f"/certificados/detalhe?cn={t.endpoint}"}
        elif norm_label(t.endpoint) in apis:
            nome = apis[norm_label(t.endpoint)]
            alvo = {"tipo": "API", "nome": nome, "url": f"/apis?q={nome}"}
        c = comments.get(t.id, {})
        rows.append({
            "t": t, "aberto": aberto, "url": ticket_url(settings, t.id), "discussao": discussions_url(settings, t.id),
            "cert_expirado": aberto and exp is not None and exp < now,
            "dias_expirado": (now - exp).days if exp and exp < now else None,
            "fim_ultrapassado": aberto and end is not None and end < now,
            "alvo": alvo, "comentarios": c.get("n", 0), "ultimo_comentario": c.get("ultimo"),
        })
    counts = {
        "abertos": sum(1 for r in rows if r["aberto"]),
        "atrasados": sum(1 for r in rows if r["cert_expirado"]),
        "fim_ultrapassado": sum(1 for r in rows if r["fim_ultrapassado"]),
        "comentarios": sum(1 for r in rows if r["comentarios"]),
        "fechados": sum(1 for r in rows if not r["aberto"]),
        "todos": len(rows),
    }
    pick = {"abertos": lambda r: r["aberto"], "atrasados": lambda r: r["cert_expirado"],
            "fim_ultrapassado": lambda r: r["fim_ultrapassado"], "comentarios": lambda r: r["comentarios"] > 0,
            "fechados": lambda r: not r["aberto"], "todos": lambda r: True}.get(view, lambda r: r["aberto"])
    rows = [r for r in rows if pick(r)]
    if q:
        ql = q.lower().strip()
        rows = [r for r in rows if ql in r["t"].id.lower() or ql in (r["t"].endpoint or "")
                or ql in (r["t"].display_label or "").lower() or ql in (r["t"].owner_group or "").lower()]

    def sort_key(r):
        lc = (r["ultimo_comentario"] or {}).get("quando")
        if view == "comentarios":
            return (-(as_utc(lc).timestamp() if lc else 0),)
        exp = as_utc(r["t"].cert_expiry)
        return (exp is None, exp.timestamp() if exp else 0, r["t"].id)
    rows.sort(key=sort_key)
    return rows, counts

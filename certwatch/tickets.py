"""Tickets do SMAX: guardar a última leitura e ligar cada certificado aos seus pedidos.

Um ticket refere-se a um certificado pelo endpoint (nome) e pela data de expiração do certificado a renovar.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .collectors.smax import fetch_tickets, ticket_url
from .config import Settings
from .db import as_utc, utcnow
from .models import SmaxTicket

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


def ingest_smax(session: Session, settings: Settings, tickets: list[dict] | None = None) -> dict:
    if tickets is None:
        tickets = fetch_tickets(settings)
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
    return {"tickets": len(seen), "com_endpoint": sum(1 for t in tickets if t["endpoint"]),
            "abertos": sum(1 for t in tickets if t["phase"].lower() not in closed)}


def is_open(t: SmaxTicket, settings: Settings) -> bool:
    return (t.phase or "").lower() not in set(settings.smax_closed_phases)


def tickets_by_endpoint(session: Session) -> dict[str, list[SmaxTicket]]:
    out: dict[str, list[SmaxTicket]] = defaultdict(list)
    for t in session.scalars(select(SmaxTicket).where(SmaxTicket.endpoint != "")):
        out[t.endpoint].append(t)
    return out


def link(tickets: list[SmaxTicket], expiry: datetime | None, settings: Settings) -> dict:
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
                "atualizado": x.last_update, "tipo": x.cert_type}

    return {
        "state": state, "label": TICKET_STATES[state],
        "main": as_dict(main) if main else None,
        "open": [as_dict(x) for x in opened], "closed": [as_dict(x) for x in closed],
        "varios_abertos": len(matching) > 1,
    }

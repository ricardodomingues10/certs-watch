"""Tickets do SMAX: guardar a última leitura e ligar cada certificado aos seus pedidos.

Um ticket refere-se a um certificado pelo endpoint (nome) e pela data de expiração do certificado a renovar.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .fontes.smax import discussions_url, fetch_comments, fetch_tickets, ticket_url
from .config import Settings
from .db import as_utc, utcnow
from .models import SmaxComment, SmaxEvent, SmaxFile, SmaxTicket

EVENT_KEEP_DAYS = 400

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
    before = {tid: (phase or "") for tid, phase in session.execute(select(SmaxTicket.id, SmaxTicket.phase))}
    session.execute(delete(SmaxTicket))
    seen = set()
    events = 0
    for t in tickets:
        if t["id"] in seen:
            continue
        seen.add(t["id"])
        session.add(SmaxTicket(**t, fetched_at=now))
        # o histórico de fases não vem do SMAX: guarda-se o que mudou entre duas leituras
        # (na primeira leitura não há "antes", por isso nada é contado como novo)
        if before and t["id"] not in before:
            session.add(SmaxEvent(ticket_id=t["id"], at=t.get("created") or t.get("last_update") or now, kind="novo",
                                  para=t.get("phase") or "", endpoint=t.get("endpoint") or "", label=t.get("display_label") or ""))
            events += 1
        elif t["id"] in before and before[t["id"]] != (t.get("phase") or ""):
            session.add(SmaxEvent(ticket_id=t["id"], at=t.get("last_update") or now, kind="fase", de=before[t["id"]],
                                  para=t.get("phase") or "", endpoint=t.get("endpoint") or "", label=t.get("display_label") or ""))
            events += 1
    session.execute(delete(SmaxEvent).where(SmaxEvent.at < now - timedelta(days=EVENT_KEEP_DAYS)))
    session.flush()
    closed = set(settings.smax_closed_phases)
    out = {"tickets": len(seen), "mudancas": events, "com_endpoint": sum(1 for t in tickets if t["endpoint"]),
           "abertos": sum(1 for t in tickets if t["phase"].lower() not in closed)}
    if comments:
        # Comentários dos pedidos abertos (os mais recentes primeiro)
        opened = [t["id"] for t in sorted(tickets, key=lambda x: x["last_update"] or _EPOCH, reverse=True)
                  if t["phase"].lower() not in closed]
        known = {(f.comment_id, f.ref) for f in session.execute(select(SmaxFile.comment_id, SmaxFile.ref)
                                                                 .where(SmaxFile.error == ""))}
        try:
            found, info = fetch_comments(settings, opened, known_files=known)
        except Exception as exc:   # comentários são extra: nunca falham a leitura dos pedidos
            out["comentarios"] = {"erro": str(exc)[:300]}
            return out
        store_comments(session, found, opened[: settings.smax_comments_max])
        out["comentarios"] = info
    return out


def store_comments(session: Session, found: list[dict], fetched: list[str]) -> None:
    """Substitui os comentários dos pedidos lidos e guarda as imagens/anexos novos."""
    import hashlib
    if fetched:
        session.execute(delete(SmaxComment).where(SmaxComment.ticket_id.in_(fetched)))
    seen_c = set()
    for c in found:
        if c["id"] in seen_c:
            continue
        seen_c.add(c["id"])
        files = c.pop("files", [])
        session.add(SmaxComment(**c))
        for f in files:
            if f.get("existing") or f.get("skipped"):
                continue
            old = session.scalar(select(SmaxFile).where(SmaxFile.comment_id == c["id"], SmaxFile.ref == f["ref"][:1024]))
            if old is not None:
                session.delete(old)       # tentativa anterior falhou: substitui
            data = f.get("data")
            session.add(SmaxFile(comment_id=c["id"], ticket_id=c["ticket_id"], ref=f["ref"][:1024], kind=f["kind"],
                                 name=(f.get("name") or "")[:255], mime=f.get("mime") or "", size=len(data or b""),
                                 sha256=hashlib.sha256(data).hexdigest() if data else "", data=data,
                                 error=(f.get("error") or "")[:300]))
    session.flush()
    # Ficheiros de comentários que já não existem
    alive = select(SmaxComment.id)
    session.execute(delete(SmaxFile).where(SmaxFile.comment_id.not_in(alive)))


def comment_files(session: Session, ticket_ids: list[str] | None = None) -> dict[str, list[dict]]:
    """Por comentário: imagens e anexos guardados (sem o conteúdo)."""
    stmt = select(SmaxFile.id, SmaxFile.comment_id, SmaxFile.kind, SmaxFile.name, SmaxFile.mime, SmaxFile.size,
                  SmaxFile.error).order_by(SmaxFile.id)
    if ticket_ids is not None:
        stmt = stmt.where(SmaxFile.ticket_id.in_(ticket_ids))
    out: dict[str, list[dict]] = defaultdict(list)
    for f in session.execute(stmt):
        out[f.comment_id].append({"id": f.id, "kind": f.kind, "name": f.name, "mime": f.mime, "size": f.size,
                                  "error": f.error, "imagem": f.mime.startswith("image/") and not f.error})
    return out


def last_comments(session: Session) -> dict[str, dict]:
    """Por pedido: número de comentários e o mais recente."""
    out: dict[str, dict] = {}
    files = comment_files(session)
    for c in session.scalars(select(SmaxComment).order_by(SmaxComment.created_at)):
        e = out.setdefault(c.ticket_id, {"n": 0, "ultimo": None, "ficheiros": 0})
        e["n"] += 1
        e["ficheiros"] += len(files.get(c.id, []))
        e["ultimo"] = {"quando": c.created_at, "autor": c.author or (f"utilizador {c.author_id}" if c.author_id else ""),
                       "texto": c.body, "ficheiros": files.get(c.id, [])}
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


def current_expiry(session: Session, settings: Settings, inventory: list[dict] | None = None) -> dict[str, dict]:
    """Por nome: a data de fim do certificado atual (a do servidor, se foi verificado; senão a da CMDB)."""
    if inventory is None:
        from .insights import build_inventory
        inventory = build_inventory(session, settings, utcnow())
    out = {}
    for r in inventory:
        d = r["live_not_after"] or r["cmdb_valid_to"]
        if d is not None:
            out[r["cn"]] = {"data": as_utc(d), "fonte": "servidor" if r["live_not_after"] else "CMDB"}
    return out


def already_renewed(t: SmaxTicket, current: dict[str, dict], settings: Settings) -> dict | None:
    """Pedido aberto cujo certificado já foi renovado: o certificado atual expira depois da data do pedido
    (mais de 1 dia). O pedido ficou por fechar no SMAX."""
    if not is_open(t, settings) or t.cert_expiry is None:
        return None
    cur = current.get(t.endpoint)
    if cur and (cur["data"].date() - as_utc(t.cert_expiry).date()).days > 1:
        return cur
    return None


TICKET_VIEWS = {
    "abertos": "Abertos",
    "ja_renovado": "Abertos com o certificado já renovado",
    "atrasados": "Abertos com certificado já expirado",
    "fim_ultrapassado": "Abertos com fim planeado ultrapassado",
    "comentarios": "Com comentários",
    "fechados": "Fechados",
    "todos": "Todos",
}


def ticket_list(session: Session, settings: Settings, view: str = "abertos", q: str = "",
                inventory: list[dict] | None = None) -> tuple[list[dict], dict]:
    """Todos os pedidos lidos do SMAX, com a ligação ao certificado ou API e o último comentário."""
    from .models import ApiRecord, CmdbRecord, Endpoint
    from .normalize import norm_label
    now = utcnow()
    comments = last_comments(session)
    cert_names = {r.cn_norm for r in session.scalars(select(CmdbRecord).where(CmdbRecord.active.is_(True)))}
    cert_names |= {e.expected_cn_norm for e in session.scalars(select(Endpoint))}
    apis = {norm_label(a.name): a.name for a in session.scalars(select(ApiRecord).where(ApiRecord.active.is_(True)))}
    current = current_expiry(session, settings, inventory)
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
        renewed = already_renewed(t, current, settings)
        rows.append({
            "t": t, "aberto": aberto, "url": ticket_url(settings, t.id), "discussao": discussions_url(settings, t.id),
            "ja_renovado": renewed,
            # atrasado = o certificado do pedido expirou e não há outro mais recente (se já foi renovado, é "já renovado")
            "cert_expirado": aberto and exp is not None and exp < now and not renewed,
            "dias_expirado": (now - exp).days if exp and exp < now else None,
            "fim_ultrapassado": aberto and end is not None and end < now,
            "alvo": alvo, "comentarios": c.get("n", 0), "ultimo_comentario": c.get("ultimo"),
            "ficheiros": c.get("ficheiros", 0),
        })
    counts = {
        "abertos": sum(1 for r in rows if r["aberto"]),
        "ja_renovado": sum(1 for r in rows if r["ja_renovado"]),
        "atrasados": sum(1 for r in rows if r["cert_expirado"]),
        "fim_ultrapassado": sum(1 for r in rows if r["fim_ultrapassado"]),
        "comentarios": sum(1 for r in rows if r["comentarios"]),
        "fechados": sum(1 for r in rows if not r["aberto"]),
        "todos": len(rows),
    }
    pick = {"abertos": lambda r: r["aberto"], "ja_renovado": lambda r: bool(r["ja_renovado"]),
            "atrasados": lambda r: r["cert_expirado"],
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


TICKET_ORDER = {"expiracao": "Expiração do certificado", "comentario": "Último comentário (mais recente primeiro)",
                "atualizacao": "Última atualização no SMAX", "pedido": "Número do pedido (mais recente primeiro)"}


def filter_tickets(rows: list[dict], fase: str = "", desde=None, ate=None, sem_comentario: bool = False,
                   ordem: str = "", tz=None) -> list[dict]:
    """Filtros da página de pedidos: fase, data do último comentário (de/até, inclusive) e ordenação."""
    out = rows
    if fase:
        out = [r for r in out if (r["t"].phase or "").lower() == fase.lower()]

    def last_day(r):
        lc = (r.get("ultimo_comentario") or {}).get("quando")
        if not lc:
            return None
        d = as_utc(lc)
        return (d.astimezone(tz) if tz else d).date()
    if desde or ate:
        out = [r for r in out if last_day(r) is not None and (not desde or last_day(r) >= desde) and (not ate or last_day(r) <= ate)]
    if sem_comentario:
        out = [r for r in out if not r.get("comentarios")]
    if ordem == "comentario":
        out = sorted(out, key=lambda r: as_utc((r.get("ultimo_comentario") or {}).get("quando") or _EPOCH), reverse=True)
    elif ordem == "atualizacao":
        out = sorted(out, key=lambda r: as_utc(r["t"].last_update or _EPOCH), reverse=True)
    elif ordem == "pedido":
        out = sorted(out, key=lambda r: (len(r["t"].id), r["t"].id), reverse=True)
    return out

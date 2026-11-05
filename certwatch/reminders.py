"""Próximos 90 dias: certificados e segredos de API a expirar, com o pedido de cada um, quem o tem no SMAX (grupo e
pessoa), se isso bate certo com o dono no Atalaia, e lembretes por email à pessoa de cada pedido (à mão).

Nada é automático: os lembretes enviam-se depois de rever, com pré-visualização. Cada envio fica registado.
"""
from __future__ import annotations

import html
from collections import defaultdict
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings
from .db import as_utc, utcnow
from .models import Reminder, Team

CHECKS = {
    "sem_pedido": ("Sem pedido aberto", "r"),
    "sem_pessoa": ("Pedido sem pessoa", "a"),
    "sem_grupo": ("Pedido sem grupo", "a"),
    "grupo_diferente": ("Grupo ≠ equipa dona", "a"),
    "pessoa_diferente": ("Pessoa ≠ dono", "a"),
    "confere": ("Confere com o dono", "ok"),
    "sem_dono": ("Sem dono para comparar", "n"),
}


def _iso(v):
    return as_utc(v).isoformat() if isinstance(v, datetime) else v


def _ticket(smax: dict | None) -> tuple[dict | None, list[dict]]:
    """O pedido aberto principal (o desta data, senão o mais recente aberto) e todos os abertos."""
    smax = smax or {}
    opened = smax.get("open") or []
    main = smax.get("main") if (smax.get("main") or {}).get("aberto") else (opened[0] if opened else None)
    return main, opened


def check(row: dict, teams: dict[int, Team]) -> list[str]:
    t = row["pedido"]
    if not t:
        return ["sem_pedido"]
    out = []
    if not t.get("grupo"):
        out.append("sem_grupo")
    if not t.get("responsavel"):
        out.append("sem_pessoa")
    dono = row.get("dono") or {}
    if not dono or dono.get("origem") != "atribuido":
        return out or ["sem_dono"]
    team = teams.get(dono.get("equipa_id")) if dono.get("equipa_id") else None
    if team and team.smax_group and t.get("grupo") and team.smax_group.strip().lower() != t["grupo"].strip().lower():
        out.append("grupo_diferente")
    if dono.get("pessoa") and t.get("responsavel") and dono["pessoa"].strip().lower() != t["responsavel"].strip().lower():
        out.append("pessoa_diferente")
    return out or ["confere"]


def rows(session: Session, settings: Settings, days: int = 90, expired: bool = False, now: datetime | None = None) -> list[dict]:
    """Certificados e segredos de API que expiram nos próximos `days` dias (e os expirados há até 30 dias, se
    `expired`), ordenados por data."""
    from .evaluator import days_left, load_snapshot
    from .insights import build_inventory
    from .normalize import norm_label
    from .tickets import last_comments, link, tickets_by_label
    now = now or utcnow()
    snap = load_snapshot(session)
    inv = build_inventory(session, settings, now, snap)
    lo = -30 if expired else 0
    teams = {t.id: t for t in session.scalars(select(Team))}
    out = []
    for r in inv:
        d = r["dias"]
        when = r["live_not_after"] or r["cmdb_valid_to"]
        if d is None or when is None or not lo <= d <= days:
            continue
        main, opened = _ticket(r.get("smax"))
        out.append({"key": "c:" + r["cn"], "tipo": "certificado", "nome": r["common_name"], "cn": r["cn"],
                    "expira": when, "dias": d, "ambito": r["scope"], "auto": r["renovacao"] == "auto",
                    "dono": r.get("dono"), "pedido": main, "abertos": opened, "detalhe": f"/certificados/detalhe?cn={r['cn']}"})
    by_label, comments = tickets_by_label(session), last_comments(session)
    for a in snap.apis:
        if a.expiry is None:
            continue
        d = days_left(a.expiry, now)
        if not lo <= d <= days:
            continue
        sm = link(by_label.get(norm_label(a.name), []), a.expiry, settings, comments)
        main, opened = _ticket(sm)
        out.append({"key": "a:" + a.ucmdb_id, "tipo": "api", "nome": a.name, "cn": "", "expira": a.expiry, "dias": d,
                    "ambito": a.application or a.location, "auto": False, "dono": None, "pedido": main, "abertos": opened,
                    "detalhe": f"/apis?q={a.name}"})
    last = last_sent(session)
    for x in out:
        x["checks"] = check(x, teams)
        x["lembrete"] = last.get((x["pedido"] or {}).get("id")) if x["pedido"] else None
    out.sort(key=lambda x: (as_utc(x["expira"]), x["nome"].lower()))
    return out


def last_sent(session: Session) -> dict[str, datetime]:
    out: dict[str, datetime] = {}
    for r in session.scalars(select(Reminder).where(Reminder.ok.is_(True)).order_by(Reminder.id.desc()).limit(2000)):
        for t in r.tickets or []:
            out.setdefault(str(t), r.sent_at)
    return out


def group_by_person(selected: list[dict]) -> tuple[dict[str, list[dict]], list[dict]]:
    """Pessoa responsável -> as linhas dela; e as linhas sem pessoa (não há a quem enviar)."""
    by: dict[str, list[dict]] = defaultdict(list)
    orphan = []
    for x in selected:
        p = ((x.get("pedido") or {}).get("responsavel") or "").strip()
        (by[p].append(x) if p else orphan.append(x))
    return dict(sorted(by.items(), key=lambda kv: kv[0].lower())), orphan


DEFAULT_SUBJECT = "Lembrete | {n} certificado(s) e segredo(s) a expirar com pedidos atribuídos a si"
DEFAULT_INTRO = ("Os certificados e segredos abaixo expiram em breve e os respetivos pedidos de renovação estão "
                 "atribuídos a si. Pedimos que confirme o andamento de cada um e, se o pedido não for seu, que nos avise "
                 "para o reatribuirmos.")

_TD = 'style="border:1px solid #bfbfbf;padding:6px 10px;"'
_TH = 'style="border:1px solid #bfbfbf;padding:6px 10px;background:#f2f2f2;text-align:left;"'


def email_html(person: str, items: list[dict], intro: str, signature: str, now: datetime) -> str:
    e = lambda v: html.escape("" if v is None else str(v))  # noqa: E731
    greet = "Bom dia" if now.hour < 13 else "Boa tarde"
    def day(v):
        d = as_utc(v)
        return (d.astimezone(now.tzinfo) if now.tzinfo else d).strftime("%d/%m/%Y")

    def ticket(t):
        return f'<a href="{e(t.get("url"))}">{e(t["id"])}</a>' if t.get("url") else e(t["id"])
    body = "".join(
        f"<tr><td {_TD}>{day(x['expira'])}</td><td {_TD}><b>{e(x['dias'])}</b></td><td {_TD}>{e(x['nome'])}</td>"
        f"<td {_TD}>{'Certificado' if x['tipo'] == 'certificado' else 'Segredo de API'}</td>"
        f"<td {_TD}>{ticket(x['pedido'])}</td><td {_TD}>{e(x['pedido'].get('fase'))}</td></tr>" for x in items)
    table = ('<table style="border-collapse:collapse;font-family:Arial,sans-serif;font-size:14px;"><thead><tr>'
             f"<th {_TH}>Expira</th><th {_TH}>Dias</th><th {_TH}>Certificado / segredo</th><th {_TH}>Tipo</th>"
             f"<th {_TH}>Pedido</th><th {_TH}>Fase</th></tr></thead><tbody>{body}</tbody></table>")
    paras = "".join(f"<p>{e(p)}</p>" for p in (intro or "").split("\n") if p.strip())
    return (f'<div style="font-family:Arial,sans-serif;font-size:14px;color:#222;"><p>{greet} {e(person.split(" ")[0])},</p>'
            f"{paras}{table}<p>Cumprimentos,<br>{e(signature or 'Atalaia Cert')}</p></div>")


def subject(template: str, items: list[dict]) -> str:
    import re
    return re.sub(r"\s+", " ", (template or DEFAULT_SUBJECT).replace("{n}", str(len(items)))).strip()[:250]


def serial(items: list[dict]) -> list[dict]:
    return [{"nome": x["nome"], "tipo": x["tipo"], "expira": _iso(x["expira"]), "pedido": (x["pedido"] or {}).get("id")}
            for x in items]

"""Calendário de expirações em iCalendar (.ics, RFC 5545), para o Outlook, Google ou Apple.

Um evento de dia inteiro no dia em que cada certificado (ou segredo de API) expira, com o emissor, o dono, o pedido do
SMAX e o link para o Atalaia Cert, e lembretes 30 e 7 dias antes. O UID de cada evento é estável (nome + data), por
isso uma subscrição atualiza o evento em vez de o duplicar quando a data muda.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from .db import as_utc
from .evaluator import days_left


def _esc(text: str) -> str:
    return (text or "").replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\r\n", "\\n").replace("\n", "\\n")


def _fold(line: str) -> list[str]:
    """Linhas de no máximo 75 octetos; as seguintes começam por um espaço."""
    out, cur = [], b""
    for ch in line:
        b = ch.encode("utf-8")
        if len(cur) + len(b) > (75 if not out else 74):
            out.append(cur.decode("utf-8"))
            cur = b""
        cur += b
    out.append(cur.decode("utf-8"))
    return [out[0]] + [" " + x for x in out[1:]]


def _event(uid: str, day, summary: str, description: str, url: str, stamp: str) -> list[str]:
    d0, d1 = day.strftime("%Y%m%d"), (day + timedelta(days=1)).strftime("%Y%m%d")
    lines = ["BEGIN:VEVENT", f"UID:{uid}", f"DTSTAMP:{stamp}", f"DTSTART;VALUE=DATE:{d0}", f"DTEND;VALUE=DATE:{d1}",
             f"SUMMARY:{_esc(summary)}", f"DESCRIPTION:{_esc(description)}", "TRANSP:TRANSPARENT", "CATEGORIES:Atalaia Cert"]
    if url:
        lines.append(f"URL:{url}")
    for days in (30, 7):
        lines += ["BEGIN:VALARM", "ACTION:DISPLAY", f"DESCRIPTION:{_esc(summary)}", f"TRIGGER:-P{days}D", "END:VALARM"]
    return lines + ["END:VEVENT"]


def build(inv: list[dict], apis: list, now: datetime, base_url: str, team_id: int | None = None,
          horizon_days: int = 400, name: str = "Atalaia Cert · expirações") -> str:
    stamp = now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Atalaia Cert//Expirações//PT", "CALSCALE:GREGORIAN",
             "METHOD:PUBLISH", f"X-WR-CALNAME:{_esc(name)}", "X-WR-TIMEZONE:Europe/Lisbon", "REFRESH-INTERVAL;VALUE=DURATION:PT12H"]
    base = base_url.rstrip("/")
    for r in inv:
        when = r["live_not_after"] or r["cmdb_valid_to"]
        if when is None or r["dias"] is None or not -30 <= r["dias"] <= horizon_days:
            continue
        dono = r.get("dono") or {}
        if team_id is not None and dono.get("equipa_id") != team_id:
            continue
        day = as_utc(when).date()
        main = (r.get("smax") or {}).get("main") or {}
        desc = [f"Certificado {r['common_name']} expira a {day.strftime('%d-%m-%Y')}.",
                f"Emissor: {r['live_issuer'] or ', '.join(r['issuers']) or '—'}",
                f"Dono: {dono.get('equipa') or 'sem dono'}{' · ' + dono['pessoa'] if dono.get('pessoa') else ''}",
                f"Pedido SMAX: {main.get('id') + ' (' + (main.get('fase') or '') + ')' if main.get('id') else 'sem pedido'}",
                f"Renovação: {'automática' if r['renovacao'] == 'auto' else 'manual'}"]
        url = f"{base}/certificados/detalhe?cn={quote(r['cn'])}" if base else ""
        if url:
            desc.append(url)
        uid = hashlib.sha1(f"cert|{r['cn']}|{day}".encode()).hexdigest() + "@atalaia-cert"
        lines += _event(uid, day, f"Expira: {r['common_name']}", "\n".join(desc), url, stamp)
    if team_id is None:
        for a in apis:
            if a.expiry is None or not -30 <= days_left(a.expiry, now) <= horizon_days:
                continue
            day = as_utc(a.expiry).date()
            uid = hashlib.sha1(f"api|{a.ucmdb_id}|{day}".encode()).hexdigest() + "@atalaia-cert"
            url = f"{base}/apis?q={quote(a.name)}" if base else ""
            desc = f"Segredo da API {a.name} expira a {day.strftime('%d-%m-%Y')}.\nAplicação: {a.application or '—'}\n{url}".strip()
            lines += _event(uid, day, f"Expira o segredo: {a.name}", desc, url, stamp)
    lines.append("END:VCALENDAR")
    return "\r\n".join(x for line in lines for x in _fold(line)) + "\r\n"

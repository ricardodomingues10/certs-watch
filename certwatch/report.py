"""Relatório por email (estrutura do workflow n8n "Certificados a expirar nos próximos 90 dias").

Duas partes, que se podem enviar sozinhas, juntas num email ou em dois emails:
- **alertas**: os certificados a N dias ou menos da expiração (prazo de alerta definido pelo utilizador) e as
  tabelas dos internos e externos que expiram na janela escolhida (de X a Y dias);
- **reconciliação**: os certificados cujo servidor já apresenta uma validade posterior à da CMDB (renovados e
  ainda não refletidos), com o Excel de análise em anexo.

A validade "efetiva" é a que o servidor apresenta (quando verificado) ou a da CMDB.
"""
from __future__ import annotations

import html
import io
import re
import smtplib
import ssl
from datetime import date, datetime
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from zoneinfo import ZoneInfo

from sqlalchemy.orm import Session

from .config import Settings
from .db import as_utc, utcnow

PARTS = {"alertas": "Alertas", "reconciliacao": "Reconciliação com o Excel em anexo"}
_EMAIL = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
MAX_TO = 20


class ReportError(RuntimeError):
    pass


# ------------------------------------------------------------------ dados
def _ticket_info(smax: dict | None) -> dict:
    smax = smax or {}
    opened = smax.get("open") or []
    closed = smax.get("closed") or []
    main = opened[0] if opened else None
    if len(opened) > 1:
        alt = f"ATENÇÃO - {len(opened)} pedidos abertos ({', '.join(o['id'] for o in opened)})"
    elif opened:
        alt = f"Pedido {opened[0]['id']}"
    else:
        alt = "Sem pedido ativo"
    return {"alteracao": alt, "abertos": len(opened), "fechados": len(closed), "total": len(opened) + len(closed),
            "main": main, "ultimo_fechado": closed[0]["id"] if closed else "", "abertos_ids": " ; ".join(o["id"] for o in opened),
            "ambiente": (main or (closed[0] if closed else {}) or {}).get("ambiente", "")}


def build_rows(session: Session, settings: Settings, now: datetime | None = None) -> list[dict]:
    """Uma linha por certificado do inventário, com validade efetiva, pedidos e estado da análise."""
    from .insights import build_inventory
    now = now or utcnow()
    tz = ZoneInfo(settings.timezone)
    today = now.astimezone(tz).date()
    out = []
    for r in build_inventory(session, settings, now):
        if r.get("type") == "ca":
            continue
        cmdb = as_utc(r["cmdb_valid_to"]).astimezone(tz).date() if r.get("cmdb_valid_to") else None
        live = as_utc(r["live_not_after"]).astimezone(tz).date() if r.get("live_not_after") else None
        eff = live or cmdb
        if eff is None:
            continue
        if live and cmdb:
            atual = "Não" if live > cmdb else ("Sim" if live == cmdb else "Verificar")
        else:
            atual = ""
        t = _ticket_info(r.get("smax"))
        out.append({
            "cn": r["cn"], "common_name": r.get("common_name") or r["cn"], "scope": r.get("scope") or "",
            "cmdb": cmdb, "servidor": live, "efetiva": eff, "dias": (eff - today).days,
            "cmdb_atualizada": atual, "estado_servidor": r.get("live_status") or "",
            "origem": "Servidor" if live else "CMDB", "issuer_cmdb": ", ".join(r.get("issuers") or []),
            "issuer_servidor": r.get("live_issuer") or "", "auto": "Sim" if r.get("renovacao") == "auto" else "Não",
            "ticket": t, "smax_state": (r.get("smax") or {}).get("state", ""),
        })
    return out


def analyse(row: dict, alert_days: int) -> tuple[str, str]:
    """(Estado_Analise, Observacao), com as regras do workflow."""
    t = row["ticket"]
    obs = []
    if row["cmdb_atualizada"] == "Não":
        obs.append(f"O servidor apresenta validade até {row['servidor']:%d-%m-%Y}, posterior à CMDB ({row['cmdb']:%d-%m-%Y}). "
                   "Provável renovação ainda não refletida na CMDB.")
        return "RENOVADO_NAO_REFLETIDO_CMDB", " ".join(obs)
    if row["cmdb_atualizada"] == "Verificar":
        obs.append(f"O servidor apresenta validade anterior à CMDB ({row['servidor']:%d-%m-%Y} vs {row['cmdb']:%d-%m-%Y}).")
    if 0 <= row["dias"] <= alert_days and t["abertos"] == 0:
        return f"ALERTA_{alert_days}_DIAS_SEM_TICKET_ATIVO", " ".join(obs + ["A expirar sem pedido ativo no SMAX."])
    if t["abertos"] > 1:
        return "MULTIPLOS_TICKETS_ABERTOS", " ".join(obs + [f"Existem {t['abertos']} pedidos abertos ({t['abertos_ids']})."])
    if t["abertos"] == 1:
        if row["smax_state"] == "em_curso":
            return "OK_TICKET_ABERTO", " ".join(obs + ["Existe um pedido aberto para esta data de expiração."])
        return "TICKET_ABERTO_DATA_DIFERENTE", " ".join(obs + ["O pedido aberto tem outra data de expiração."])
    if t["total"] == 0:
        return "SEM_TICKET", " ".join(obs + ["Não há pedidos no SMAX para este certificado."])
    return "SEM_TICKET_ATIVO", " ".join(obs + [f"Só pedidos fechados (último: {t['ultimo_fechado']})."])


def select_rows(rows: list[dict], desde: int, ate: int, excluded: set[str] | None = None) -> dict:
    excluded = excluded or set()
    window = [r for r in rows if desde <= r["dias"] <= ate]
    renewed = [r for r in rows if r["cmdb_atualizada"] == "Não"]
    pick = lambda xs: [r for r in xs if r["cn"] not in excluded]
    return {"janela": pick(window), "renovados": pick(renewed),
            "todos_janela": window, "todos_renovados": renewed}


# ------------------------------------------------------------------ HTML (estilos inline, como no workflow)
_TD = 'style="border:1px solid #bfbfbf;padding:6px 10px;"'
_TH = 'style="border:1px solid #bfbfbf;padding:6px 10px;background:#f2f2f2;"'


def _e(v) -> str:
    return html.escape("" if v is None else str(v))


def _d(v) -> str:
    return v.strftime("%d/%m/%Y") if isinstance(v, date) else _e(v)


def _table(rows: list[dict], alert: bool = False) -> str:
    if not rows:
        return "<p><em>Não foram identificados certificados nesta categoria.</em></p>"
    head = (f"<th {_TH}>CommonName</th><th {_TH}>ValidTo</th><th {_TH}>Alteração</th><th {_TH}>Renovação Automática?</th>"
            + ('<th style="border:1px solid #bfbfbf;padding:6px 10px;background:#fff2cc;">Dias restantes</th>' if alert else ""))
    body = "".join(
        f"<tr><td {_TD}>{_e(r['common_name'])}</td><td {_TD}>{_d(r['efetiva'])}</td><td {_TD}>{_e(r['ticket']['alteracao'])}</td>"
        f"<td {_TD}>{_e(r['auto'])}</td>"
        + (f'<td style="border:1px solid #bfbfbf;padding:6px 10px;font-weight:bold;">{r["dias"]}</td>' if alert else "")
        + "</tr>" for r in rows)
    return ('<table style="border-collapse:collapse;font-family:Arial,sans-serif;font-size:14px;">'
            f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>")


def _greeting(now: datetime) -> str:
    return "Bom dia," if now.hour < 13 else "Boa tarde,"


def alerts_html(sel: dict, desde: int, ate: int, alert_days: int) -> str:
    rel = sorted(sel["janela"], key=lambda r: (r["dias"], r["cn"]))
    internos = [r for r in rel if r["scope"] == "interno"]
    externos = [r for r in rel if r["scope"] != "interno"]
    alerta = [r for r in rel if 0 <= r["dias"] <= alert_days]
    janela = f"nos próximos {ate} dias" if desde <= 0 else f"entre {desde} e {ate} dias"
    if alerta:
        box = ('<div style="border:2px solid #d97706;background:#fff7ed;padding:12px;margin:16px 0;">'
               f"<p><strong>⚠ ALERTA — Certificados fora do prazo de renovação ({alert_days} dias antes da sua expiração)</strong></p>"
               f"<p>Os certificados abaixo encontram-se a {alert_days} dias ou menos da respetiva data de expiração efetiva "
               f"e devem ser acompanhados com prioridade:</p>{_table(alerta, True)}</div>")
    else:
        box = ('<div style="border:1px solid #bfbfbf;background:#f7f7f7;padding:10px;margin:16px 0;">'
               f"<strong>Certificados fora do prazo de renovação ({alert_days} dias antes da sua expiração):</strong> "
               "não foram identificados certificados nesta situação.</div>")
    return (f"{box}<p>Verificamos que {janela} os seguintes certificados internos têm data de expiração:</p>{_table(internos)}"
            f"<p>Verificamos, também, que os seguintes certificados externos têm data de expiração {janela}:</p>{_table(externos)}")


def reconciliation_html(sel: dict) -> str:
    ren = sorted(sel["renovados"], key=lambda r: r["cn"])
    if ren:
        rows = "".join(f"<tr><td {_TD}>{_e(r['common_name'])}</td><td {_TD}>{_d(r['cmdb'])}</td><td {_TD}>{_d(r['servidor'])}</td>"
                       f"<td {_TD}>{_e(r['ticket']['alteracao'])}</td></tr>" for r in ren)
        table = ('<table style="border-collapse:collapse;font-family:Arial,sans-serif;font-size:14px;"><thead><tr>'
                 f"<th {_TH}>CommonName</th><th {_TH}>ValidTo na CMDB</th><th {_TH}>ValidTo no servidor</th><th {_TH}>Alteração</th>"
                 f"</tr></thead><tbody>{rows}</tbody></table>")
        note = (f"<p><strong>Nota:</strong> foram identificados {len(ren)} certificado(s) cuja validade apresentada pelo "
                f"servidor é posterior à registada na CMDB. Provável renovação ainda não refletida na CMDB:</p>{table}")
    else:
        note = ("<p><strong>Reconciliação:</strong> não foram identificados certificados com validade no servidor "
                "posterior à registada na CMDB.</p>")
    return note + "<p>Segue em anexo o ficheiro Excel com o detalhe da análise, incluindo a verificação dos servidores.</p>"


def subject_for(part: str, sel: dict, desde: int, ate: int, alert_days: int) -> str:
    alerta = [r for r in sel["janela"] if 0 <= r["dias"] <= alert_days]
    if part in ("alertas", "ambos"):
        if alerta:
            return f"ALERTA | {len(alerta)} certificado(s) a {alert_days} dias ou menos da expiração"
        return f"Certificados a expirar nos próximos {ate} dias" if desde <= 0 else f"Certificados a expirar entre {desde} e {ate} dias"
    n = len(sel["renovados"])
    return (f"Reconciliação de certificados | {n} renovado(s) por refletir na CMDB" if n
            else "Reconciliação de certificados | CMDB coincide com os servidores")


def email_html(part: str, sel: dict, desde: int, ate: int, alert_days: int, signature: str, now: datetime) -> str:
    body = ""
    if part in ("alertas", "ambos"):
        body += alerts_html(sel, desde, ate, alert_days)
    if part in ("reconciliacao", "ambos"):
        body += reconciliation_html(sel)
    sig = "<br>".join(_e(x) for x in signature.splitlines()) or "certwatch"
    return (f'<div style="font-family:Arial,sans-serif;font-size:14px;color:#222;"><p>{_greeting(now)}</p>{body}'
            f"<p>Cumprimentos,<br>{sig}</p></div>")


# ------------------------------------------------------------------ Excel de análise
EXCEL_COLUMNS = ["Certificado", "Ambiente", "Âmbito", "ValidTo_CMDB", "ValidTo_Servidor", "ValidTo_Efetivo",
                 "Dias_Para_Expirar_Efetivo", "Fora_Prazo_Renovacao", "CMDB_Atualizada", "Estado_Servidor", "Origem",
                 "CommonName", "Issuer_CMDB", "Issuer_Servidor", "Renovacao_Automatica", "Ticket_Ativo_Encontrado",
                 "Tickets_Abertos", "Tickets_Fechados", "Total_Tickets_Historico", "Ticket_Atual_ID", "Ticket_Atual_Fase",
                 "Ticket_Atual_Data_Expiracao", "Ticket_Atual_Data_Coincide", "Ultimo_Ticket_Fechado_ID",
                 "Tickets_Abertos_IDs", "Estado_Analise", "Observacao"]


def excel(sel: dict, alert_days: int) -> bytes:
    from openpyxl import Workbook
    from openpyxl.cell import WriteOnlyCell
    from openpyxl.styles import Font, PatternFill
    wb = Workbook(write_only=True)
    ws = wb.create_sheet("Certificados")
    head = []
    for c in EXCEL_COLUMNS:
        cell = WriteOnlyCell(ws, value=c)
        cell.font, cell.fill = Font(bold=True), PatternFill("solid", fgColor="FFF2F2F2")
        head.append(cell)
    ws.append(head)
    seen = set()
    rows = sorted([*sel["janela"], *sel["renovados"]], key=lambda r: (r["dias"], r["cn"]))
    for r in rows:
        if r["cn"] in seen:
            continue
        seen.add(r["cn"])
        t = r["ticket"]
        main = t["main"] or {}
        estado, obs = analyse(r, alert_days)
        exp = main.get("expira")
        values = [r["cn"], t["ambiente"], r["scope"], r["cmdb"], r["servidor"], r["efetiva"], r["dias"],
                  "Sim" if 0 <= r["dias"] <= alert_days else "Não", r["cmdb_atualizada"], r["estado_servidor"], r["origem"],
                  r["common_name"], r["issuer_cmdb"], r["issuer_servidor"], r["auto"], "Sim" if t["abertos"] else "Não",
                  t["abertos"], t["fechados"], t["total"], main.get("id", ""), main.get("fase", ""),
                  as_utc(exp).date() if exp else None,
                  ("Sim" if main.get("deste_certificado") else "Não") if main else "", t["ultimo_fechado"],
                  t["abertos_ids"], estado, obs]
        cells = []
        for v in values:
            cell = WriteOnlyCell(ws, value=v)
            if isinstance(v, date):
                cell.number_format = "DD/MM/YYYY"
            elif isinstance(v, str):
                cell.data_type = "s"
            cells.append(cell)
        ws.append(cells)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def excel_name(ate: int) -> str:
    return f"Certificados_{ate}_Dias.xlsx"


# ------------------------------------------------------------------ envio
def parse_recipients(value: str, settings: Settings) -> list[str]:
    out = []
    for x in re.split(r"[,;\s]+", value or ""):
        x = x.strip()
        if not x:
            continue
        if not _EMAIL.match(x) or len(x) > 254:
            raise ReportError(f"Endereço inválido: {x}")
        dom = x.rsplit("@", 1)[1].lower()
        if settings.report_allowed_domains and not any(dom == d or dom.endswith("." + d) for d in settings.report_allowed_domains):
            raise ReportError(f"{x}: só são permitidos endereços de {', '.join(settings.report_allowed_domains)}.")
        if x.lower() not in {o.lower() for o in out}:
            out.append(x)
    if not out:
        raise ReportError("Indique pelo menos um destinatário.")
    if len(out) > MAX_TO:
        raise ReportError(f"No máximo {MAX_TO} destinatários.")
    return out


def smtp_problems(settings: Settings) -> list[str]:
    p = []
    if not settings.smtp_host:
        p.append("CERTWATCH_SMTP_HOST não definido")
    if not settings.smtp_from:
        p.append("CERTWATCH_SMTP_FROM não definido")
    if settings.smtp_security not in ("starttls", "ssl", "none"):
        p.append("CERTWATCH_SMTP_SECURITY tem de ser starttls, ssl ou none")
    if settings.smtp_user and not settings.smtp_password:
        p.append("CERTWATCH_SMTP_USER definido mas falta o segredo smtp_password")
    return p


def build_message(settings: Settings, to: list[str], subject: str, html_body: str,
                  attachment: tuple[str, bytes] | None) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = settings.smtp_from
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=settings.smtp_from.rsplit("@", 1)[-1] if "@" in settings.smtp_from else None)
    text = re.sub(r"<(br|/p|/tr|/div)\s*/?>", "\n", html_body)
    text = html.unescape(re.sub(r"<[^>]+>", " ", text))
    msg.set_content(re.sub(r"[ \t]+", " ", re.sub(r"\n\s*\n+", "\n\n", text)).strip())
    msg.add_alternative(html_body, subtype="html")
    if attachment:
        msg.add_attachment(attachment[1], maintype="application",
                           subtype="vnd.openxmlformats-officedocument.spreadsheetml.sheet", filename=attachment[0])
    return msg


def send(settings: Settings, messages: list[EmailMessage], smtp_factory=None) -> None:
    problems = smtp_problems(settings)
    if problems:
        raise ReportError("Email não configurado: " + "; ".join(problems) + ".")
    from .trust import build_bundle
    ctx = ssl.create_default_context(cafile=build_bundle(settings))
    try:
        if smtp_factory is not None:
            server = smtp_factory(settings)
        elif settings.smtp_security == "ssl":
            server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=30, context=ctx)
        else:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30)
        with server:
            if settings.smtp_security == "starttls" and smtp_factory is None:
                server.starttls(context=ctx)
            if settings.smtp_user:
                server.login(settings.smtp_user, settings.smtp_password or "")
            for m in messages:
                server.send_message(m)
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        detail = str(exc).replace(settings.smtp_password or "\0", "***")
        raise ReportError(f"O servidor de email recusou ou não respondeu: {type(exc).__name__}: {detail}"[:500]) from exc

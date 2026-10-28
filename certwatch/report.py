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
from html.parser import HTMLParser
import io
import re
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy.orm import Session

from .config import Settings
from .db import as_utc, utcnow

PARTS = {"alertas": "Alertas", "reconciliacao": "Reconciliação com o Excel em anexo",
         "internet": "Certificados novos na internet, para aprovação"}
_EMAIL = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
MAX_TO = 20


from .fontes.email import EmailError, build_message, send, smtp_problems  # noqa: E402,F401

ReportError = EmailError        # o mesmo erro para o relatório e para o envio


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


def internet_rows(session: Session, settings: Settings, dias: int = 0, now: datetime | None = None) -> list[dict]:
    """Certificados encontrados na internet (CT) que não estão na CMDB, ainda válidos e não ignorados na triagem.
    dias > 0: só os encontrados pela primeira vez nos últimos N dias."""
    from .discovery import classify_ct
    now = now or utcnow()
    tz = ZoneInfo(settings.timezone)
    since = now - timedelta(days=dias) if dias > 0 else None
    out = []
    for r in classify_ct(session, settings, now):
        ct = r["ct"]
        if r["state"] == "na_cmdb" or r["expired"] or ct.triage == "ignorar":
            continue
        if since and as_utc(ct.first_seen) < since:
            continue
        names = list(ct.names or [])
        nome = ct.primary_name or (names[0] if names else "")
        crt = (ct.source_ids or {}).get("crtsh")
        out.append({
            "key": f"ct:{ct.id}", "id": ct.id, "nome": nome, "outros": [n for n in names if n != nome],
            "estado": r["state"], "emissor": ct.issuer_cn or "", "serie": (ct.serial_hex or "").upper(),
            "desde": as_utc(ct.not_before).astimezone(tz).date() if ct.not_before else None,
            "ate": as_utc(ct.not_after).astimezone(tz).date() if ct.not_after else None,
            "dias": r["days"], "no_servidor": "Sim" if r["live"] else "Não", "triagem": ct.triage,
            "visto": as_utc(ct.first_seen).astimezone(tz).date() if ct.first_seen else None,
            "cmdb": "; ".join(f"{c[0]} até {c[1]:%d/%m/%Y}" if c[1] else c[0] for c in r["cmdb"]),
            "link": f"https://crt.sh/?id={crt}" if crt and str(crt).isdigit() else f"https://crt.sh/?q={nome}",
        })
    out.sort(key=lambda x: (x["estado"] != "desconhecido", x["nome"]))
    return out


def select_rows(rows: list[dict], desde: int, ate: int, excluded: set[str] | None = None,
                internet: list[dict] | None = None) -> dict:
    excluded = excluded or set()
    window = [r for r in rows if desde <= r["dias"] <= ate]
    renewed = [r for r in rows if r["cmdb_atualizada"] == "Não"]
    pick = lambda xs: [r for r in xs if r["cn"] not in excluded]
    internet = internet or []
    return {"janela": pick(window), "renovados": pick(renewed),
            "todos_janela": window, "todos_renovados": renewed,
            "internet": [r for r in internet if r["key"] not in excluded], "todos_internet": internet}


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
    return "Bom dia" if now.hour < 13 else "Boa tarde"


# ------------------------------------------------------------------ texto dos emails (editável na página)
# Texto simples: {variáveis} são substituídas, **texto** fica a negrito e cada linha nova é uma quebra de linha.
DEFAULT_TEXTS = {
    "comum.saudacao": "{saudacao},",
    "comum.inicio": "",
    "comum.fim": "",
    "comum.fecho": "Cumprimentos,",
    "comum.assinatura": "{assinatura}",
    "alertas.assunto": "ALERTA | {n_alerta} certificado(s) a {alerta} dias ou menos da expiração",
    "alertas.assunto_sem_alerta": "Certificados a expirar {janela}",
    "alertas.alerta_titulo": "⚠ ALERTA — Certificados fora do prazo de renovação ({alerta} dias antes da sua expiração)",
    "alertas.alerta_texto": "Os certificados abaixo encontram-se a {alerta} dias ou menos da respetiva data de expiração "
                            "efetiva e devem ser acompanhados com prioridade:",
    "alertas.sem_alerta": "**Certificados fora do prazo de renovação ({alerta} dias antes da sua expiração):** "
                          "não foram identificados certificados nesta situação.",
    "alertas.internos": "Verificamos que {janela} os seguintes certificados internos têm data de expiração:",
    "alertas.externos": "Verificamos, também, que os seguintes certificados externos têm data de expiração {janela}:",
    "reconciliacao.assunto": "Reconciliação de certificados | {n_renovados} renovado(s) por refletir na CMDB",
    "reconciliacao.assunto_sem": "Reconciliação de certificados | CMDB coincide com os servidores",
    "reconciliacao.nota": "**Nota:** foram identificados {n_renovados} certificado(s) cuja validade apresentada pelo "
                          "servidor é posterior à registada na CMDB. Provável renovação ainda não refletida na CMDB:",
    "reconciliacao.sem": "**Reconciliação:** não foram identificados certificados com validade no servidor posterior "
                         "à registada na CMDB.",
    "reconciliacao.anexo": "Segue em anexo o ficheiro Excel com o detalhe da análise, incluindo a verificação dos servidores.",
    "internet.assunto": "Aprovação | {n_internet} certificado(s) novo(s) encontrado(s) na internet",
    "internet.assunto_sem": "Certificados encontrados na internet | nada novo",
    "internet.intro": "Foram encontrados na internet (registos públicos de Certificate Transparency), {periodo}, "
                      "**{n_internet} certificado(s)** emitido(s) para os domínios da organização que não constam da CMDB. "
                      "Pedimos à equipa de Sistemas que confirme, para cada um, se é conhecido e deve ser registado na CMDB, "
                      "indicando Aprovado ou Não aprovado na resposta a este email ou na coluna \"Aprovado\" do Excel em anexo.",
    "internet.desconhecidos": "Nomes que não existem na CMDB:",
    "internet.diferentes": "Nomes que já existem na CMDB, mas com outro certificado (outra data de fim):",
    "internet.sem": "**Certificados novos na internet:** {periodo} não foram encontrados certificados emitidos para os "
                    "domínios da organização que não constem da CMDB.",
    "internet.anexo": "Segue em anexo o ficheiro Excel com o detalhe de cada certificado.",
}
TEXT_GROUPS = {"comum": "Em todos os emails", "alertas": "Alertas", "reconciliacao": "Reconciliação",
               "internet": "Certificados novos na internet"}
TEXT_LABELS = {
    "comum.saudacao": "Saudação", "comum.inicio": "Texto a seguir à saudação (opcional)",
    "comum.fim": "Texto antes do fecho (opcional)", "comum.fecho": "Fecho", "comum.assinatura": "Assinatura",
    "alertas.assunto": "Assunto, quando há alertas", "alertas.assunto_sem_alerta": "Assunto, sem alertas",
    "alertas.alerta_titulo": "Título da caixa de alerta", "alertas.alerta_texto": "Texto da caixa de alerta",
    "alertas.sem_alerta": "Texto quando não há alertas", "alertas.internos": "Antes da tabela dos internos",
    "alertas.externos": "Antes da tabela dos externos",
    "reconciliacao.assunto": "Assunto, quando há renovados", "reconciliacao.assunto_sem": "Assunto, sem renovados",
    "reconciliacao.nota": "Antes da tabela dos renovados", "reconciliacao.sem": "Texto quando não há renovados",
    "reconciliacao.anexo": "Texto sobre o anexo",
    "internet.assunto": "Assunto, quando há certificados", "internet.assunto_sem": "Assunto, sem certificados",
    "internet.intro": "Introdução e pedido de aprovação", "internet.desconhecidos": "Antes da tabela dos nomes desconhecidos",
    "internet.diferentes": "Antes da tabela dos nomes já na CMDB", "internet.sem": "Texto quando não há certificados",
    "internet.anexo": "Texto sobre o anexo",
}
TEXT_VARS = {
    "saudacao": "Bom dia / Boa tarde, conforme a hora", "assinatura": "assinatura do .env (CERTWATCH_REPORT_SIGNATURE)",
    "janela": "\"nos próximos 90 dias\" ou \"entre 30 e 90 dias\"", "desde": "início do intervalo (dias)",
    "ate": "fim do intervalo (dias)", "alerta": "prazo de alerta (dias)", "n_alerta": "n.º de certificados em alerta",
    "n_internos": "n.º de internos no intervalo", "n_externos": "n.º de externos no intervalo",
    "n_renovados": "n.º de renovados por refletir na CMDB", "n_internet": "n.º de certificados novos na internet",
    "periodo": "\"nos últimos 30 dias\" ou \"até à data\"", "data": "data de hoje (DD/MM/AAAA)",
}
MAX_TEXT = 3000
_VAR = re.compile(r"\{(\w+)\}")


def texts_for(*layers: dict | None) -> dict:
    """Texto efetivo: o original, por cima o texto por omissão guardado e por cima o deste relatório."""
    out = dict(DEFAULT_TEXTS)
    for layer in layers:
        for k, v in (layer or {}).items():
            if k in DEFAULT_TEXTS and isinstance(v, str):
                out[k] = v
    return out


def text_context(sel: dict, desde: int, ate: int, alert_days: int, ct_dias: int, now: datetime, signature: str) -> dict:
    rel = sel["janela"]
    return {"saudacao": _greeting(now), "assinatura": signature or "Atalaia Cert",
            "janela": f"nos próximos {ate} dias" if desde <= 0 else f"entre {desde} e {ate} dias",
            "desde": desde, "ate": ate, "alerta": alert_days,
            "n_alerta": sum(1 for r in rel if 0 <= r["dias"] <= alert_days),
            "n_internos": sum(1 for r in rel if r["scope"] == "interno"),
            "n_externos": sum(1 for r in rel if r["scope"] != "interno"),
            "n_renovados": len(sel["renovados"]), "n_internet": len(sel.get("internet") or []),
            "periodo": f"nos últimos {ct_dias} dias" if ct_dias > 0 else "até à data", "data": now.strftime("%d/%m/%Y")}


def fill(template: str, ctx: dict) -> str:
    """Substitui {variável}; as desconhecidas ficam como estão."""
    return _VAR.sub(lambda m: str(ctx[m.group(1)]) if m.group(1) in ctx else m.group(0), template or "")


def _t(texts: dict, key: str, ctx: dict) -> str:
    """Texto de um bloco em HTML: escapado, **negrito** e quebras de linha."""
    out = _e(fill(texts.get(key, ""), ctx))
    out = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", out, flags=re.S)
    return out.replace("\r\n", "\n").replace("\n", "<br>")


def _p(texts: dict, key: str, ctx: dict) -> str:
    v = _t(texts, key, ctx)
    return f"<p>{v}</p>" if v.strip() else ""


def alerts_html(sel: dict, desde: int, ate: int, alert_days: int, texts: dict | None = None, ctx: dict | None = None) -> str:
    texts = texts or DEFAULT_TEXTS
    ctx = ctx or text_context(sel, desde, ate, alert_days, 0, utcnow(), "")
    rel = sorted(sel["janela"], key=lambda r: (r["dias"], r["cn"]))
    internos = [r for r in rel if r["scope"] == "interno"]
    externos = [r for r in rel if r["scope"] != "interno"]
    alerta = [r for r in rel if 0 <= r["dias"] <= alert_days]
    if alerta:
        box = ('<div style="border:2px solid #d97706;background:#fff7ed;padding:12px;margin:16px 0;">'
               f"<p><strong>{_t(texts, 'alertas.alerta_titulo', ctx)}</strong></p>"
               f"{_p(texts, 'alertas.alerta_texto', ctx)}{_table(alerta, True)}</div>")
    else:
        box = ('<div style="border:1px solid #bfbfbf;background:#f7f7f7;padding:10px;margin:16px 0;">'
               f"{_t(texts, 'alertas.sem_alerta', ctx)}</div>")
    return (f"{box}{_p(texts, 'alertas.internos', ctx)}{_table(internos)}"
            f"{_p(texts, 'alertas.externos', ctx)}{_table(externos)}")


def reconciliation_html(sel: dict, texts: dict | None = None, ctx: dict | None = None) -> str:
    texts = texts or DEFAULT_TEXTS
    ctx = ctx or text_context(sel, 0, 0, 0, 0, utcnow(), "")
    ren = sorted(sel["renovados"], key=lambda r: r["cn"])
    if ren:
        rows = "".join(f"<tr><td {_TD}>{_e(r['common_name'])}</td><td {_TD}>{_d(r['cmdb'])}</td><td {_TD}>{_d(r['servidor'])}</td>"
                       f"<td {_TD}>{_e(r['ticket']['alteracao'])}</td></tr>" for r in ren)
        table = ('<table style="border-collapse:collapse;font-family:Arial,sans-serif;font-size:14px;"><thead><tr>'
                 f"<th {_TH}>CommonName</th><th {_TH}>ValidTo na CMDB</th><th {_TH}>ValidTo no servidor</th><th {_TH}>Alteração</th>"
                 f"</tr></thead><tbody>{rows}</tbody></table>")
        note = f"{_p(texts, 'reconciliacao.nota', ctx)}{table}"
    else:
        note = _p(texts, "reconciliacao.sem", ctx)
    return note + _p(texts, "reconciliacao.anexo", ctx)


def internet_html(sel: dict, ct_dias: int, texts: dict | None = None, ctx: dict | None = None) -> str:
    texts = texts or DEFAULT_TEXTS
    ctx = ctx or text_context(sel, 0, 0, 0, ct_dias, utcnow(), "")
    rows = sel["internet"]
    if not rows:
        return _p(texts, "internet.sem", ctx)
    desconhecidos = [r for r in rows if r["estado"] == "desconhecido"]
    diferentes = [r for r in rows if r["estado"] != "desconhecido"]

    def table(data: list[dict], with_cmdb: bool) -> str:
        if not data:
            return "<p><em>Não foram identificados certificados nesta categoria.</em></p>"
        head = (f"<th {_TH}>Nome</th><th {_TH}>Outros nomes</th><th {_TH}>Emissor</th><th {_TH}>Válido até</th>"
                f"<th {_TH}>No servidor?</th>" + (f"<th {_TH}>Na CMDB</th>" if with_cmdb else ""))
        body = "".join(
            f"<tr><td {_TD}>{_e(r['nome'])}</td><td {_TD}>{_e(', '.join(r['outros'][:6]) + (' …' if len(r['outros']) > 6 else '') or '—')}</td>"
            f"<td {_TD}>{_e(r['emissor'])}</td><td {_TD}>{_d(r['ate'])}</td><td {_TD}>{_e(r['no_servidor'])}</td>"
            + (f"<td {_TD}>{_e(r['cmdb'])}</td>" if with_cmdb else "") + "</tr>" for r in data)
        return ('<table style="border-collapse:collapse;font-family:Arial,sans-serif;font-size:14px;">'
                f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>")

    return (f"{_p(texts, 'internet.intro', ctx)}"
            f"{_p(texts, 'internet.desconhecidos', ctx)}{table(desconhecidos, False)}"
            f"{_p(texts, 'internet.diferentes', ctx)}{table(diferentes, True)}"
            f"{_p(texts, 'internet.anexo', ctx)}")


def subject_for(part: str, sel: dict, desde: int, ate: int, alert_days: int, texts: dict | None = None,
                ct_dias: int = 0, now: datetime | None = None) -> str:
    texts = texts or DEFAULT_TEXTS
    ctx = text_context(sel, desde, ate, alert_days, ct_dias, now or utcnow(), "")
    if part == "internet":
        key = "internet.assunto" if ctx["n_internet"] else "internet.assunto_sem"
    elif part in ("alertas", "ambos"):
        key = "alertas.assunto" if ctx["n_alerta"] else "alertas.assunto_sem_alerta"
    else:
        key = "reconciliacao.assunto" if ctx["n_renovados"] else "reconciliacao.assunto_sem"
    # O assunto é uma só linha (nunca quebras de linha num cabeçalho de email)
    return re.sub(r"\s+", " ", fill(texts.get(key, ""), ctx)).strip()[:250] or "Certificados"


SECTIONS = ("inicio", "alertas", "reconciliacao", "internet", "fim")
PARTS = ("alertas", "reconciliacao", "internet")


def _parts(part: str | list[str]) -> list[str]:
    return {"ambos": ["alertas", "reconciliacao"]}.get(part, [part]) if isinstance(part, str) else list(part)


def email_sections(part: str | list[str], sel: dict, desde: int, ate: int, alert_days: int, signature: str, now: datetime,
                   ct_dias: int = 0, texts: dict | None = None) -> dict:
    """O email gerado, por secções: início (saudação), cada parte pedida e fim (fecho e assinatura)."""
    texts = texts or DEFAULT_TEXTS
    ctx = text_context(sel, desde, ate, alert_days, ct_dias, now, signature)
    out = {"inicio": _p(texts, "comum.saudacao", ctx) + _p(texts, "comum.inicio", ctx)}
    for p in _parts(part):
        if p == "alertas":
            out[p] = alerts_html(sel, desde, ate, alert_days, texts, ctx)
        elif p == "reconciliacao":
            out[p] = reconciliation_html(sel, texts, ctx)
        elif p == "internet":
            out[p] = internet_html(sel, ct_dias, texts, ctx)
    closing = "<br>".join(x for x in (_t(texts, "comum.fecho", ctx), _t(texts, "comum.assinatura", ctx)) if x.strip())
    out["fim"] = _p(texts, "comum.fim", ctx) + (f"<p>{closing}</p>" if closing else "")
    return out


def email_html(part: str | list[str], sel: dict, desde: int, ate: int, alert_days: int, signature: str, now: datetime,
               ct_dias: int = 0, texts: dict | None = None, edits: dict | None = None, markers: bool = False) -> str:
    """O email em HTML. `edits`: secções alteradas à mão na página (substituem as geradas).
    `markers`: marca cada secção (data-cw-part) para o editor da página."""
    body = ""
    for k, v in email_sections(part, sel, desde, ate, alert_days, signature, now, ct_dias, texts).items():
        if edits and isinstance(edits.get(k), str):
            v = sanitize_html(edits[k])
        body += f'<div data-cw-part="{k}">{v}</div>' if markers else v
    return f'<div style="font-family:Arial,sans-serif;font-size:14px;color:#222;">{body}</div>'


# ------------------------------------------------------------------ HTML editado na página: lista de permissões
MAX_HTML = 400_000
_ALLOWED_TAGS = {"p", "br", "div", "span", "strong", "b", "em", "i", "u", "table", "thead", "tbody", "tfoot", "tr", "th",
                 "td", "ul", "ol", "li", "h2", "h3", "h4", "hr"}
_VOID = {"br", "hr"}
_DROP_WITH_CONTENT = {"script", "style", "iframe", "object", "embed", "noscript", "template", "button", "svg", "math",
                      "head", "title", "textarea", "select", "form", "frameset", "noembed", "xmp"}
_STYLE_PROPS = {"border", "border-top", "border-bottom", "border-left", "border-right", "border-collapse", "border-color",
                "border-width", "border-style", "background", "background-color", "color", "padding", "padding-left",
                "padding-right", "padding-top", "padding-bottom", "margin", "margin-top", "margin-bottom", "font-family",
                "font-size", "font-weight", "font-style", "text-align", "text-decoration", "vertical-align", "white-space",
                "width", "line-height"}
_STYLE_VAL = re.compile(r"^[#a-zA-Z0-9\s.,%()'\"-]+$")


def _clean_style(style: str) -> str:
    out = []
    for decl in (style or "").split(";"):
        if ":" not in decl:
            continue
        prop, val = (x.strip() for x in decl.split(":", 1))
        prop = prop.lower()
        low = val.lower()
        if prop in _STYLE_PROPS and val and _STYLE_VAL.match(val) and "url" not in low and "expression" not in low:
            out.append(f"{prop}:{val}")
    return ";".join(out)


class _Sanitizer(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.stack: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in _DROP_WITH_CONTENT:
            self.skip += 1
            return
        if self.skip or tag not in _ALLOWED_TAGS:
            return
        a = ""
        for k, v in attrs:
            if k == "style":
                st = _clean_style(v or "")
                if st:
                    a += f' style="{html.escape(st)}"'
            elif k in ("colspan", "rowspan") and (v or "").isdigit() and 0 < int(v) < 100:
                a += f' {k}="{int(v)}"'
        self.out.append(f"<{tag}{a}>")
        if tag not in _VOID:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        if tag in _DROP_WITH_CONTENT:
            return
        self.handle_starttag(tag, attrs)
        if tag in _ALLOWED_TAGS and tag not in _VOID and not self.skip:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag in _DROP_WITH_CONTENT:
            self.skip = max(0, self.skip - 1)
            return
        if self.skip or tag not in self.stack:
            return
        while self.stack:
            t = self.stack.pop()
            self.out.append(f"</{t}>")
            if t == tag:
                break

    def handle_data(self, data):
        if not self.skip:
            self.out.append(html.escape(data, quote=False))

    def result(self) -> str:
        self.close()
        return "".join(self.out) + "".join(f"</{t}>" for t in reversed(self.stack))


def sanitize_html(fragment: str) -> str:
    """HTML editado na página → só etiquetas de texto e tabelas, estilos simples; sem scripts, links, imagens ou eventos."""
    p = _Sanitizer()
    p.feed((fragment or "")[:MAX_HTML])
    return p.result()


def clean_texts(form: dict) -> dict:
    """Textos vindos do formulário: só as chaves conhecidas, com tamanho limitado."""
    out = {}
    for k in DEFAULT_TEXTS:
        if k in form:
            v = str(form[k]).replace("\r\n", "\n")[:MAX_TEXT]
            if k.endswith(("assunto", "assunto_sem", "assunto_sem_alerta")):
                v = re.sub(r"\s+", " ", v).strip()
            out[k] = v
    return out


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


INTERNET_COLUMNS = ["Nome", "Outros_Nomes", "Situacao", "Emissor", "Numero_Serie", "Valido_De", "Valido_Ate",
                    "Dias_Para_Expirar", "Visto_No_Servidor", "Na_CMDB", "Triagem", "Encontrado_Em", "Link_crt_sh",
                    "Aprovado (Sim/Não)", "Observações"]
INTERNET_EXCEL = "Certificados_Internet.xlsx"


def internet_excel(sel: dict) -> bytes:
    from openpyxl import Workbook
    from openpyxl.cell import WriteOnlyCell
    from openpyxl.styles import Font, PatternFill
    from .discovery import CT_STATES, TRIAGE_LABELS
    wb = Workbook(write_only=True)
    ws = wb.create_sheet("Internet")
    head = []
    for c in INTERNET_COLUMNS:
        cell = WriteOnlyCell(ws, value=c)
        cell.font = Font(bold=True)
        cell.fill = PatternFill("solid", fgColor="FFFFF2CC" if c.startswith(("Aprovado", "Observ")) else "FFF2F2F2")
        head.append(cell)
    ws.append(head)
    for r in sel["internet"]:
        values = [r["nome"], ", ".join(r["outros"]), CT_STATES.get(r["estado"], r["estado"]), r["emissor"], r["serie"],
                  r["desde"], r["ate"], r["dias"], r["no_servidor"], r["cmdb"], TRIAGE_LABELS.get(r["triagem"], r["triagem"]),
                  r["visto"], r["link"], "", ""]
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


# O envio (SMTP) está em fontes/email.py; estes nomes continuam aqui para quem já os usa.

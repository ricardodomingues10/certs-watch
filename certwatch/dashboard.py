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


PHASE_ORDER = ("Log", "Classify", "FirstLineSupport", "Escalate", "Approve", "Plan", "Build", "Test", "Execute",
               "Implement", "Review", "Accept", "Validate")
MESES = ("janeiro", "fevereiro", "março", "abril", "maio", "junho", "julho", "agosto", "setembro", "outubro",
         "novembro", "dezembro")


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def deadline_buckets(inv: list[dict], snap: Snapshot, now: datetime) -> dict:
    """Certificados e APIs por prazo: expirado, até 7 dias, 8 a 20, 21 a 90 e mais de 90 (sem data fica de fora).
    Devolve também a posição de cada segmento numa barra de 0 a 1000 (SVG: a CSP não deixa usar style)."""
    days = [r["dias"] for r in inv if r["dias"] is not None]
    days += [days_left(a.expiry, now) for a in snap.apis if a.expiry is not None]
    defs = [("expirado", "expirado", "expirados", lambda d: d < 0), ("7", "até 7 dias", "até 7 dias", lambda d: 0 <= d <= 7),
            ("20", "8 a 20 dias", "8 a 20 dias", lambda d: 7 < d <= 20), ("90", "21 a 90 dias", "21 a 90 dias", lambda d: 20 < d <= 90),
            ("mais", "mais de 90 dias", "mais de 90 dias", lambda d: d > 90)]
    total = len(days)
    out, x = [], 0.0
    for key, one, many, test in defs:
        n = sum(1 for d in days if test(d))
        w = 1000 * n / total if total else 0
        out.append({"key": key, "label": one if n == 1 else many, "n": n, "x": round(x, 1), "w": round(max(w - 6, 0), 1) if n else 0})
        x += w
    return {"total": total, "segs": out}


def layer_summary(matrix: list) -> list[dict]:
    """Por camada de testes: quantos servidores falham, têm atenção, passam ou ainda não foram testados nela
    (o pior resultado dos testes dessa camada em cada servidor)."""
    from .checks import CHECK_BY_ID, LAYERS, STATUS_RANK
    out = []
    for lid, label, question in LAYERS:
        c = Counter()
        for row in matrix:
            worst = None
            for cid, res in row.results.items():
                cd = CHECK_BY_ID.get(cid)
                if cd and cd.layer == lid and res.status != "na" and (worst is None or STATUS_RANK[res.status] > STATUS_RANK[worst]):
                    worst = res.status
            c[worst or "na"] += 1
        state = "falha" if c["falha"] else "aviso" if c["aviso"] else "ok" if c["ok"] else "nt"
        text = (_plural(c["falha"], "falha", "falham") if c["falha"] else _plural(c["aviso"], "com atenção", "com atenção") if c["aviso"]
                else "todos passam" if c["ok"] and not c["nt"] else f"{c['ok']} passam" if c["ok"] else "por testar")
        first = next((cd.id for cd in CHECK_BY_ID.values() if cd.layer == lid), "")
        out.append({"id": lid, "label": label, "question": question, "state": state, "text": text,
                    "falha": c["falha"], "aviso": c["aviso"], "ok": c["ok"], "nt": c["nt"], "teste": first})
    return out


def open_by_phase(rows: list[dict]) -> list[dict]:
    """Pedidos abertos por fase do SMAX, pela ordem habitual das fases (as desconhecidas no fim)."""
    c = Counter((r["t"].phase or "sem fase") for r in rows if r["aberto"])
    order = {p.lower(): i for i, p in enumerate(PHASE_ORDER)}
    return [{"fase": f, "n": n} for f, n in sorted(c.items(), key=lambda kv: (order.get(kv[0].lower(), 99), kv[0]))]


def headline(k: dict, n_open_items: int) -> dict:
    """A frase do topo do Painel: o que pede atenção, por ordem de gravidade."""
    parts = []
    if k["expirados_em_uso"]:
        parts.append(_plural(k["expirados_em_uso"], "certificado expirado ainda em uso", "certificados expirados ainda em uso"))
    if n_open_items:
        parts.append(_plural(n_open_items, "pedido por abrir", "pedidos por abrir"))
    if k["criticos"]:
        parts.append(_plural(k["criticos"], "alerta crítico", "alertas críticos"))
    if k["parados"]:
        parts.append(_plural(k["parados"], "pedido parado", "pedidos parados"))
    if k.get("atrasados"):
        parts.append(_plural(k["atrasados"], "pedido com o certificado já expirado", "pedidos com o certificado já expirado"))
    if not parts:
        return {"partes": [], "fim": "Nada pede atenção agora: tudo o que expira em breve tem pedido em curso."}
    fim = "" if k["expirados_em_uso"] else "Nenhum certificado expirado continua em uso."
    return {"partes": parts, "fim": fim}


def _tone(d: int | None) -> str:
    if d is None:
        return "n"
    return "x" if d < 0 else "r" if d <= 7 else "a" if d <= 20 else "n"


def _when(d: int) -> str:
    if d < 0:
        return f"expirou há {-d} {'dia' if d == -1 else 'dias'}"
    return "hoje" if d == 0 else f"{d} {'dia' if d == 1 else 'dias'}"


def work_queue(items: list[dict], nis: dict, k: dict, stale: list[dict], tcounts: dict, nav: dict,
               stats: dict, fresh: list[dict], now: datetime, can_create: bool) -> dict:
    """O trabalho do Painel em três colunas, por urgência: hoje (expirado ou até 2 dias, alertas críticos), esta
    semana (até 7 dias, pedidos parados, CMDB e internet por rever) e este mês (o resto)."""
    lanes: dict[str, list[dict]] = {"hoje": [], "semana": [], "mes": []}

    def add(lane, quando, tom, titulo, detalhe, acao, href="", cn=None):
        lanes[lane].append({"quando": quando, "tom": tom, "titulo": titulo, "detalhe": detalhe, "acao": acao,
                            "href": href, "cn": cn})

    for r in nis["expirados_em_uso"]:
        add("hoje", _when(r["dias"]), "x", f"Substituir {r['cn']}", "Expirou e o servidor continua a apresentá-lo.",
            "Ver o certificado", f"/certificados/detalhe?cn={r['cn']}")
    if k["criticos"]:
        add("hoje", _plural(k["criticos"], "crítico", "críticos"), "r", f"Decidir sobre {_plural(k['criticos'], 'alerta crítico', 'alertas críticos')}",
            "Corrigir ou aceitar o risco, com justificação.", "Ver alertas", "/findings?sev=critica")
    if tcounts.get("atrasados"):
        n = tcounts["atrasados"]
        add("hoje", _plural(n, "pedido", "pedidos"), "x", "Pedidos com o certificado já expirado",
            "O pedido continua aberto e o certificado já expirou.", "Ver pedidos", "/pedidos?vista=atrasados")
    if k["nao_instalados"]:
        add("hoje", _plural(k["nao_instalados"], "certificado", "certificados"), "r", "Instalar certificados já renovados",
            "Há certificado novo, mas o servidor ainda apresenta o antigo.", "Ver quais", "/findings?tipo=RENOVACAO_NAO_INSTALADA")
    for it in items:
        d = it["dias"]
        lane = "hoje" if d <= 2 else "semana" if d <= 7 else "mes"
        outra = it["pedido"] and it["pedido"].get("state") == "outra_data" and it["pedido"].get("main")
        if it["tipo"] == "API":
            add(lane, _when(d), _tone(d), f"Renovar o segredo: {it['nome']}",
                f"{it['emissor'] or 'API'}; o pedido abre-se à mão no SMAX.", "Ver a API", it["url"])
        elif outra:
            m = it["pedido"]["main"]
            add(lane, _when(d), _tone(d), f"Pedido {m['id']} com outra data",
                f"O pedido refere outra data; {it['nome']} expira a {it['expira'].strftime('%d-%m-%Y') if it['expira'] else '—'}.",
                "Ver o pedido", f"/pedidos/smax/{m['id']}")
        else:
            add(lane, _when(d), _tone(d), f"Abrir pedido: {it['nome']}",
                f"Expira a {it['expira'].strftime('%d-%m-%Y') if it['expira'] else '—'}" + (f". Emissor {it['emissor']}." if it["emissor"] else "."),
                "Criar pedido" if can_create and it["criar"] else "Ver o certificado", it["url"], it["criar"] if can_create else None)
    for t in stale:
        lane = "semana" if t["cert_dias"] is None or t["cert_dias"] <= 30 else "mes"
        cert = f"{t['alvo']} expira em {t['cert_dias']} dias" if t["alvo"] and t["cert_dias"] is not None and t["cert_dias"] >= 0 else (t["alvo"] or "")
        quem = " · ".join(x for x in (t["grupo"], t["responsavel"]) if x)
        add(lane, f"parado {t['parado']} dias" if t["parado"] is not None else "parado", "a", f"Pedido {t['pedido']} sem movimento",
            "; ".join(x for x in (cert, quem) if x) or "Sem atualização nem comentários.", "Ver o pedido", f"/pedidos/smax/{t['pedido']}")
    if nav.get("reconc_dif"):
        n = nav["reconc_dif"]
        add("semana", _plural(n, "alteração", "alterações"), "n", f"Rever {_plural(n, 'alteração', 'alterações')} da CMDB",
            f"Comparação #{nav.get('reconc_run')}. Nada é escrito sem confirmar.", "Rever", f"/cmdb-final/{nav.get('reconc_run')}")
    if nav.get("ct_por_triar"):
        n = nav["ct_por_triar"]
        add("semana", f"{n} por triar", "n", "Triar certificados encontrados na internet",
            "Nomes da organização que a CMDB não conhece.", "Triar", "/descoberta")
    if tcounts.get("ja_renovado"):
        n = tcounts["ja_renovado"]
        add("mes", _plural(n, "pedido", "pedidos"), "n", "Fechar pedidos já renovados", "O certificado já foi renovado; o pedido pode fechar.",
            "Ver pedidos", "/pedidos?vista=ja_renovado")
    por_ver = stats["ep_total"] - stats["ep_verified"]
    if por_ver:
        add("mes", _plural(por_ver, "servidor", "servidores"), "n", "Verificar servidores ainda não verificados",
            "Ainda não passaram pelos testes.", "Ver servidores", "/endpoints")
    velhos = [f["fonte"] for f in fresh if f["velho"]]
    if velhos:
        add("mes", _plural(len(velhos), "fonte", "fontes"), "n", "Atualizar dados antigos",
            ", ".join(velhos) + " lidos há mais de 48 h.", "Ver execuções", "/jobs")

    def date_pt(d: datetime) -> str:
        return f"{d.day} de {MESES[d.month - 1]}"
    return {"lanes": [
        {"id": "hoje", "titulo": "Hoje", "sub": "urgente", "itens": lanes["hoje"]},
        {"id": "semana", "titulo": "Esta semana", "sub": f"até {date_pt(now + timedelta(days=7))}", "itens": lanes["semana"]},
        {"id": "mes", "titulo": "Este mês", "sub": f"até {date_pt(now + timedelta(days=30))}", "itens": lanes["mes"]},
    ], "total": sum(len(v) for v in lanes.values())}


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

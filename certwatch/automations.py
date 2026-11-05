"""Automatizações: o quê (uma ação com parâmetros) e quando (uma agenda), editáveis na página Sistema → Automatizações.

O worker vê a cada 15 s as automatizações ativas cuja próxima execução já passou, põe-nas na fila como um job
(«auto:<id>», que aparece em Execuções) e calcula a próxima. «Executar agora» põe na fila da mesma forma.

As ações que escrevem no SMAX ou na CMDB estão marcadas, só os administradores as criam ou editam, têm um limite
de alterações por execução e precisam de uma confirmação explícita ao gravar.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings
from .db import as_utc, session_scope, utcnow
from .models import AuditLog, Automation

log = logging.getLogger(__name__)

DAYS = ["segunda", "terça", "quarta", "quinta", "sexta", "sábado", "domingo"]
DAYS_PL = ["segundas", "terças", "quartas", "quintas", "sextas", "sábados", "domingos"]
SCHEDULES = {"diario": "Todos os dias", "uteis": "Dias úteis (segunda a sexta)", "semanal": "Em certos dias da semana",
             "mensal": "Uma vez por mês", "horas": "De N em N horas", "manual": "Só quando eu carregar em «Executar agora»"}
STEPS = {"ingest_cmdb": "Ler a CMDB", "ingest_apis": "Ler a lista de APIs", "ingest_smax": "Ler os pedidos do SMAX",
         "ingest_ct": "Procurar na internet (CT)", "scan": "Testar os servidores", "ssllabs": "Avaliação externa (SSL Labs)",
         "sites": "Verificar os sites públicos", "dominios": "Ler o registo dos domínios (RDAP)", "evaluate": "Reavaliar os alertas"}
REPORT_PARTS = {"alertas": "Alertas", "reconciliacao": "Reconciliação (com Excel)", "internet": "Certificados novos na internet (com Excel)",
                "sites": "Sites públicos e domínios (com Excel)"}


@dataclass
class Param:
    name: str
    label: str
    kind: str = "text"            # text | emails | int | select | multi | bool | textarea
    default: object = ""
    options: dict = field(default_factory=dict)
    help: str = ""
    lo: int = 0
    hi: int = 100000


@dataclass
class Action:
    key: str
    name: str
    group: str
    desc: str
    params: list[Param]
    writes: str = ""              # "" | "SMAX" | "CMDB": o que escreve sem revisão


ACTIONS: dict[str, Action] = {a.key: a for a in [
    Action("pipeline", "Executar tudo", "Ler e verificar",
           "Lê a CMDB, as APIs e o SMAX, procura na internet, testa os servidores, verifica os sites públicos e os domínios e reavalia os alertas.", []),
    Action("ler", "Ler e verificar só algumas partes", "Ler e verificar",
           "Escolha os passos: por exemplo ler o SMAX de hora a hora, ou verificar os sites públicos de manhã.",
           [Param("passos", "Passos", "multi", ["ingest_smax"], STEPS)]),
    Action("relatorio", "Enviar o relatório por email", "Enviar",
           "O mesmo relatório da página Relatório por email, com o texto por omissão guardado lá, para os destinatários indicados.",
           [Param("partes", "O que enviar", "multi", ["alertas"], REPORT_PARTS),
            Param("para", "Para", "emails", "", help="Vários endereços separados por vírgula."),
            Param("modo", "Se escolher mais do que uma parte", "select", "junto", {"junto": "Num só email", "separado": "Um email por parte"}),
            Param("desde", "Certificados que expiram de (dias)", "int", 0, lo=-365, hi=3650),
            Param("ate", "até (dias)", "int", 90, lo=0, hi=3650),
            Param("alerta", "Alerta a N dias ou menos", "int", 20, lo=0, hi=3650),
            Param("ct_dias", "Internet: certificados dos últimos N dias (0 = todos)", "int", 30, lo=0, hi=3650),
            Param("so_se_houver", "Só enviar se houver alguma coisa a reportar", "bool", True)]),
    Action("lembretes", "Enviar lembretes às pessoas dos pedidos", "Enviar",
           "Um email a cada pessoa responsável pelos pedidos dos certificados e segredos a expirar, com o link para responder «é meu» ou «passar para…». As respostas ficam para rever.",
           [Param("dias", "Certificados e segredos que expiram nos próximos (dias)", "int", 90, lo=1, hi=365),
            Param("intervalo", "Não repetir o lembrete do mesmo pedido antes de (dias)", "int", 7, lo=0, hi=365),
            Param("so_por_confirmar", "Só pedidos ainda não confirmados por quem os tem", "bool", True),
            Param("assunto", "Assunto", "text", "", help="Vazio = o assunto por omissão."),
            Param("intro", "Texto antes da tabela", "textarea", "", help="Vazio = o texto por omissão.")]),
    Action("reconciliar", "Reconciliar a CMDB", "Ler e verificar",
           "Gera uma reconciliação com as fontes (CA1, CA2, AVI, Azure, internet, renovações). Só compara: aplicar na UCMDB continua a ser à mão, a não ser com a ação seguinte.",
           [Param("fontes", "Fontes (nenhuma = todas)", "multi", [], {})]),
    Action("aplicar_cmdb", "Reconciliar e aplicar na UCMDB", "Escrever",
           "Gera a reconciliação e aplica na UCMDB as alterações incluídas por omissão. Se houver mais do que o limite, não aplica nada e avisa.",
           [Param("maximo", "Aplicar no máximo (alterações)", "int", 10, lo=1, hi=500)], writes="CMDB"),
    Action("abrir_pedidos", "Abrir pedidos pelas regras ativas", "Escrever",
           "Cria no SMAX os pedidos que as regras ativas abririam hoje (os de Pedidos SMAX → Regras). Se houver mais do que o limite, não cria nenhum e avisa.",
           [Param("maximo", "Criar no máximo (pedidos)", "int", 10, lo=1, hi=200)], writes="SMAX"),
    Action("fechar_renovados", "Fechar os pedidos de certificados já renovados", "Escrever",
           "Fecha no SMAX os pedidos abertos cujo certificado já foi renovado (o servidor já tem o novo), com um comentário.",
           [Param("maximo", "Fechar no máximo (pedidos)", "int", 10, lo=1, hi=200),
            Param("comentario", "Comentário no pedido", "textarea",
                  "Fechado automaticamente pelo Atalaia Cert: o certificado já foi renovado e está instalado.")], writes="SMAX"),
]}
GROUPS = ["Ler e verificar", "Enviar", "Escrever"]

TEMPLATES = [
    {"name": "Executar tudo de manhã", "action": "pipeline", "schedule": {"tipo": "diario", "hora": "06:15"}},
    {"name": "Ler o SMAX de hora a hora", "action": "ler", "params": {"passos": ["ingest_smax"]}, "schedule": {"tipo": "horas", "cada": 1, "minuto": 5}},
    {"name": "Relatório de alertas à segunda", "action": "relatorio", "params": {"partes": ["alertas", "reconciliacao"]},
     "schedule": {"tipo": "semanal", "dias": [0], "hora": "08:30"}},
    {"name": "Sites públicos todos os dias úteis", "action": "relatorio", "params": {"partes": ["sites"]},
     "schedule": {"tipo": "uteis", "hora": "09:00"}},
    {"name": "Lembretes às sextas", "action": "lembretes", "schedule": {"tipo": "semanal", "dias": [4], "hora": "10:00"}},
    {"name": "Reconciliação diária", "action": "reconciliar", "schedule": {"tipo": "diario", "hora": "07:00"}},
]


# ------------------------------------------------------------------ parâmetros e agenda
def default_params(action: str) -> dict:
    a = ACTIONS[action]
    return {p.name: (list(p.default) if isinstance(p.default, list) else p.default) for p in a.params}


def clean_params(action: str, form: dict, settings: Settings) -> tuple[dict, list[str]]:
    """Lê os parâmetros do formulário (form: nome -> valor ou lista). Devolve (parâmetros, erros)."""
    a = ACTIONS[action]
    out, errs = {}, []
    for p in a.params:
        raw = form.get(p.name)
        if p.kind == "multi":
            opts = options_for(p, settings)
            vals = [v for v in (raw if isinstance(raw, list) else ([raw] if raw else [])) if v in opts]
            out[p.name] = vals
        elif p.kind == "bool":
            out[p.name] = bool(raw)
        elif p.kind == "int":
            try:
                v = int(str(raw).strip())
            except (TypeError, ValueError):
                errs.append(f"{p.label}: tem de ser um número.")
                v = p.default
            if not p.lo <= v <= p.hi:
                errs.append(f"{p.label}: entre {p.lo} e {p.hi}.")
            out[p.name] = v
        elif p.kind == "select":
            v = str(raw or p.default)
            out[p.name] = v if v in p.options else p.default
        elif p.kind == "emails":
            v = str(raw or "").strip()
            out[p.name] = v[:1000]
            if v:
                from .report import ReportError, parse_recipients
                try:
                    parse_recipients(v, settings)
                except ReportError as exc:
                    errs.append(f"{p.label}: {exc}")
        else:
            out[p.name] = str(raw or "").strip()[:3000 if p.kind == "textarea" else 250]
    if action == "ler" and not out.get("passos"):
        errs.append("Escolha pelo menos um passo.")
    if action == "relatorio":
        if not out.get("partes"):
            errs.append("Escolha o que enviar.")
        if not out.get("para"):
            errs.append("Indique para quem enviar.")
        if out.get("desde", 0) > out.get("ate", 0):
            errs.append("O início do intervalo tem de ser menor ou igual ao fim.")
    return out, errs


def options_for(p: Param, settings: Settings) -> dict:
    if p.name == "fontes":
        from .cmdb_final import all_sources, source_name
        return {s: source_name(s) for s in all_sources(settings)}
    return p.options


def clean_schedule(form: dict) -> tuple[dict, list[str]]:
    tipo = str(form.get("tipo") or "manual")
    if tipo not in SCHEDULES:
        tipo = "manual"
    errs = []
    sch: dict = {"tipo": tipo}
    hora = str(form.get("hora") or "08:00").strip()
    try:
        hh, mm = (int(x) for x in hora.split(":")[:2])
        assert 0 <= hh <= 23 and 0 <= mm <= 59
        hora = f"{hh:02d}:{mm:02d}"
    except (ValueError, AssertionError):
        errs.append("A hora tem de ser HH:MM.")
        hora = "08:00"
    if tipo in ("diario", "uteis", "semanal", "mensal"):
        sch["hora"] = hora
    if tipo == "semanal":
        dias = form.get("dias") or []
        dias = sorted({int(d) for d in (dias if isinstance(dias, list) else [dias]) if str(d).isdigit() and 0 <= int(d) <= 6})
        if not dias:
            errs.append("Escolha pelo menos um dia da semana.")
        sch["dias"] = dias
    if tipo == "mensal":
        try:
            sch["dia"] = max(1, min(28, int(form.get("dia") or 1)))
        except ValueError:
            sch["dia"] = 1
    if tipo == "horas":
        try:
            sch["cada"] = max(1, min(24, int(form.get("cada") or 1)))
            sch["minuto"] = max(0, min(59, int(form.get("minuto") or 0)))
        except ValueError:
            errs.append("Indique de quantas em quantas horas.")
            sch.update(cada=1, minuto=0)
    return sch, errs


def next_run(sch: dict, after: datetime, tz: str) -> datetime | None:
    """A próxima execução (UTC) depois de `after`."""
    zone = ZoneInfo(tz)
    t = sch.get("tipo")
    if t == "manual" or t not in SCHEDULES:
        return None
    local = as_utc(after).astimezone(zone)
    if t == "horas":
        # a contagem recomeça à meia-noite: 00:MM, N:MM, 2N:MM…
        cada, minuto = int(sch.get("cada", 1)), int(sch.get("minuto", 0))
        for day in range(0, 3):
            d = (local + timedelta(days=day)).date()
            for h in range(0, 24, cada):
                c = datetime(d.year, d.month, d.day, h, minuto, tzinfo=zone)
                if c > local:
                    return c.astimezone(timezone.utc)
        return None
    hh, mm = (int(x) for x in str(sch.get("hora", "08:00")).split(":"))
    for day in range(0, 62):
        d = (local + timedelta(days=day)).date()
        c = datetime(d.year, d.month, d.day, hh, mm, tzinfo=zone)
        if c <= local:
            continue
        wd = c.weekday()
        if t == "uteis" and wd > 4:
            continue
        if t == "semanal" and wd not in (sch.get("dias") or []):
            continue
        if t == "mensal" and c.day != int(sch.get("dia", 1)):
            continue
        return c.astimezone(timezone.utc)
    return None


def describe_schedule(sch: dict) -> str:
    t = sch.get("tipo")
    if t == "diario":
        return f"Todos os dias às {sch.get('hora')}"
    if t == "uteis":
        return f"Dias úteis às {sch.get('hora')}"
    if t == "semanal":
        dias = [DAYS_PL[d] for d in sch.get("dias") or []]
        txt = dias[0] if len(dias) == 1 else ", ".join(dias[:-1]) + " e " + dias[-1] if dias else "—"
        return f"Às {txt} às {sch.get('hora')}"
    if t == "mensal":
        return f"No dia {sch.get('dia')} de cada mês às {sch.get('hora')}"
    if t == "horas":
        c = int(sch.get("cada", 1))
        return ("De hora a hora" if c == 1 else f"De {c} em {c} horas") + f", ao minuto {int(sch.get('minuto', 0)):02d}"
    return "Só à mão"


def describe_params(a: Automation, settings: Settings) -> str:
    act = ACTIONS.get(a.action)
    if act is None:
        return ""
    p = a.params or {}
    if a.action == "ler":
        return ", ".join(STEPS.get(x, x) for x in p.get("passos") or [])
    if a.action == "relatorio":
        return (", ".join(REPORT_PARTS.get(x, x).split(" (")[0] for x in p.get("partes") or []) + f" → {p.get('para') or '—'}"
                + (" · só se houver algo" if p.get("so_se_houver") else ""))
    if a.action == "lembretes":
        return f"próximos {p.get('dias', 90)} dias · não repetir antes de {p.get('intervalo', 7)} dias"
    if a.action == "reconciliar":
        return ", ".join(p.get("fontes") or []) or "todas as fontes"
    if a.action in ("aplicar_cmdb", "abrir_pedidos", "fechar_renovados"):
        return f"no máximo {p.get('maximo', 10)} por execução"
    return ""


def write_problem(action: str, settings: Settings) -> str:
    """O que falta para uma ação de escrita poder correr ("" = pode)."""
    a = ACTIONS[action]
    if a.writes == "CMDB":
        from .ucmdb_write import enabled_problem
        return enabled_problem(settings)
    if a.writes == "SMAX":
        from .conectores import ticket_connector, tickets_on
        if not tickets_on(settings):
            return "O SMAX não está ligado."
        if action == "fechar_renovados" and not (settings.smax_update_enabled and ticket_connector(settings).can("fase")):
            return "Fechar pedidos precisa de CERTWATCH_SMAX_UPDATE_ENABLED=true."
        if action == "abrir_pedidos":
            from .ticket_create import config_problems
            pr = config_problems(settings)
            return " ".join(pr)
    return ""


# ------------------------------------------------------------------ as ações
class Result(dict):
    """status: ok | aviso | erro | nada; texto: uma frase para a página; o resto é o detalhe."""


def _r(status: str, texto: str, **kw) -> Result:
    return Result(status=status, texto=texto, **kw)


def _steps_result(summary: dict) -> Result:
    errs = [k for k, v in summary.items() if isinstance(v, dict) and "erro" in v]
    txt = "; ".join(f"{STEPS.get(k, k)}: {v['erro'][:120]}" for k, v in summary.items() if isinstance(v, dict) and "erro" in v)
    return _r("aviso" if errs else "ok", txt or f"{len(summary)} passo(s) feito(s)", passos=summary)


def run_pipeline(settings: Settings, p: dict, actor: str) -> Result:
    from .jobs import _run
    return _steps_result(_run("pipeline", settings))


def run_ler(settings: Settings, p: dict, actor: str) -> Result:
    from .jobs import _run
    out = {}
    for step in p.get("passos") or []:
        if step not in STEPS:
            continue
        try:
            out.update(_run(step, settings))
        except Exception as exc:  # noqa: BLE001 - um passo não para os outros
            log.exception("Automatização: passo %s", step)
            out[step] = {"erro": f"{type(exc).__name__}: {str(exc)[:200]}"}
    return _steps_result(out)


def run_relatorio(settings: Settings, p: dict, actor: str) -> Result:
    from . import report as rp
    from .models import EmailReport, EmailTemplate
    partes = [x for x in p.get("partes") or [] if x in rp.PARTS]
    to = rp.parse_recipients(p.get("para") or "", settings)
    problems = rp.smtp_problems(settings)
    if problems:
        return _r("erro", "O email não está configurado: " + "; ".join(problems))
    desde, ate, alerta, ct = int(p.get("desde", 0)), int(p.get("ate", 90)), int(p.get("alerta", 20)), int(p.get("ct_dias", 30))
    with session_scope() as s:
        rows = rp.build_rows(s, settings)
        sel = rp.select_rows(rows, desde, ate, set(), rp.internet_rows(s, settings, ct), rp.sites_data(s, settings))
        t = s.scalar(select(EmailTemplate).where(EmailTemplate.key == "default"))
        texts = rp.texts_for(dict(t.textos or {}) if t else None)
    now = utcnow().astimezone(ZoneInfo(settings.timezone))
    ctx = rp.text_context(sel, desde, ate, alerta, ct, now, settings.report_signature)
    has = {"alertas": ctx["n_alerta"] > 0, "reconciliacao": ctx["n_renovados"] > 0, "internet": ctx["n_internet"] > 0,
           "sites": bool(ctx["n_sites_acao"] or ctx["n_cmdb_desat"] or ctx["n_pedidos_desat"] or ctx["n_dominios_alerta"])}
    if p.get("so_se_houver"):
        partes = [x for x in partes if has.get(x)]
        if not partes:
            return _r("nada", "Nada a reportar: não foi enviado nenhum email.")
    groups = [partes] if p.get("modo", "junto") == "junto" else [[x] for x in partes]
    msgs, subjects = [], []
    for g in groups:
        key = next(k for k in ("alertas", "reconciliacao", "internet", "sites") if k in g)
        subj = rp.subject_for(key, sel, desde, ate, alerta, texts, ct, now)
        att = []
        if "reconciliacao" in g:
            att.append((rp.excel_name(ate), rp.excel(sel, alerta)))
        if "internet" in g:
            att.append((rp.INTERNET_EXCEL, rp.internet_excel(sel)))
        if "sites" in g:
            att.append((rp.SITES_EXCEL, rp.sites_excel(sel)))
        msgs.append(rp.build_message(settings, to, subj, rp.email_html(g, sel, desde, ate, alerta, settings.report_signature,
                                                                         now, ct, texts), att))
        subjects.append(subj)
    ok, erro = True, ""
    try:
        rp.send(settings, msgs, SMTP_FACTORY)
    except rp.ReportError as exc:
        ok, erro = False, str(exc)
    with session_scope() as s:
        s.add(EmailReport(created_by=actor, desde=desde, ate=ate, alerta=alerta, ct_dias=ct, excluded=[],
                          sends=[{"em": utcnow().isoformat(), "por": actor, "para": to, "partes": partes,
                                  "modo": p.get("modo", "junto"), "assuntos": subjects, "ok": ok, "erro": erro}]))
    if not ok:
        return _r("erro", erro)
    return _r("ok", f"Enviado para {', '.join(to)}: {' | '.join(subjects)}", para=to, assuntos=subjects)


SMTP_FACTORY = None      # testes
SMAX_CLIENT = None       # testes


def run_lembretes(settings: Settings, p: dict, actor: str) -> Result:
    from . import reminders as rm
    from . import report as rp
    from .models import Reminder, ReminderLink
    problems = rp.smtp_problems(settings)
    if problems:
        return _r("erro", "O email não está configurado: " + "; ".join(problems))
    dias, intervalo = int(p.get("dias", 90)), int(p.get("intervalo", 7))
    now = utcnow()
    with session_scope() as s:
        rows = rm.rows(s, settings, dias)
    chosen = [r for r in rows if (r["pedido"] or {}).get("responsavel")
              and not (r["lembrete"] and now - as_utc(r["lembrete"]) < timedelta(days=intervalo))
              and not (p.get("so_por_confirmar", True) and r.get("confirmado"))]
    groups, _ = rm.group_by_person(chosen)
    if not groups:
        return _r("nada", "Nenhum pedido a lembrar (já lembrados há pouco, confirmados ou sem pessoa).")
    emails: dict = {}
    from .conectores import ticket_connector, tickets_on
    if tickets_on(settings) and ticket_connector(settings).kind == "smax":
        from .fontes.smax import SmaxError, person_emails
        try:
            emails = person_emails(settings, list(groups), SMAX_CLIENT)
        except SmaxError as exc:
            log.warning("Lembretes automáticos: emails do SMAX: %s", exc)
    sent, failed, skipped = [], [], []
    local = now.astimezone(ZoneInfo(settings.timezone))
    for name, items in groups.items():
        found = emails.get(name) or []
        dono = next(((x["dono"] or {}).get("email") for x in items
                     if (x["dono"] or {}).get("pessoa", "").strip().lower() == name.lower() and (x["dono"] or {}).get("email")), "")
        addr = found[0] if len(found) == 1 else dono
        if not addr:
            skipped.append(name + (" (homónimos no SMAX)" if len(found) > 1 else " (sem email)"))
            continue
        tickets = sorted({x["pedido"]["id"] for x in items})
        with session_scope() as s:
            rem = Reminder(sent_by=actor, person=name, tickets=tickets, items=rm.serial(items))
            s.add(rem)
            s.flush()
            rem_id = rem.id
        link_id, ok, erro = None, False, ""
        try:
            to = rp.parse_recipients(addr, settings)
            link = ""
            if settings.public_url:
                with session_scope() as s:
                    token = rm.create_link(s, settings, rem_id, name, to[0], items)
                    link_id = s.scalar(select(ReminderLink.id).where(ReminderLink.token_hash == rm.token_hash(token)))
                link = f"{settings.public_url}/r/{token}"
            msg = rp.build_message(settings, to, rm.subject(p.get("assunto") or rm.DEFAULT_SUBJECT, items),
                                   rm.email_html(name, items, p.get("intro") or rm.DEFAULT_INTRO, settings.report_signature,
                                                 local, link), [])
            rp.send(settings, [msg], SMTP_FACTORY)
            ok = True
            sent.append(name)
        except rp.ReportError as exc:
            to, erro = [addr], str(exc)
            failed.append(f"{name}: {erro[:120]}")
        with session_scope() as s:
            rem = s.get(Reminder, rem_id)
            rem.to, rem.ok, rem.erro = ", ".join(to), ok, erro[:500]
            if not ok and link_id:
                s.get(ReminderLink, link_id).revoked = True
            s.add(AuditLog(actor=actor, action="lembrete.enviar", target=name, details={"para": to, "pedidos": tickets, "ok": ok}))
    txt = f"{len(sent)} lembrete(s) enviado(s)"
    if skipped:
        txt += f"; sem email: {', '.join(skipped[:5])}"
    if failed:
        txt += f"; falharam: {'; '.join(failed[:3])}"
    if not settings.public_url:
        txt += " (sem CERTWATCH_PUBLIC_URL: os emails foram sem o link de resposta)"
    return _r("aviso" if failed or skipped else "ok", txt, enviados=sent, sem_email=skipped, falharam=failed)


def _reconcile(settings: Settings, p: dict, actor: str) -> tuple[int, Result | None]:
    from . import cmdb_final as cf
    from .models import FinalRun
    valid = cf.all_sources(settings)
    only = [x for x in (p.get("fontes") or []) if x in valid] or None
    with session_scope() as s:
        run_id = cf.start_run(s, actor, only).id
    cf.generate(run_id, settings, only=only)
    with session_scope() as s:
        run = s.get(FinalRun, run_id)
        status, err, summ = run.status, run.error, dict(run.summary or {})
        n = sum(1 for c in (run.changes or []) if c.get("incluir", True))
    if status == "erro":
        return run_id, _r("erro", f"Reconciliação #{run_id}: {err}", execucao=run_id)
    return run_id, _r("ok" if status == "pronto" else "aviso",
                      f"Reconciliação #{run_id}: {n} alteração(ões) por aplicar" + ("" if status == "pronto" else f" ({status})"),
                      execucao=run_id, alteracoes=n, estado=status, resumo={k: summ[k] for k in list(summ)[:12]})


def run_reconciliar(settings: Settings, p: dict, actor: str) -> Result:
    return _reconcile(settings, p, actor)[1]


def run_aplicar_cmdb(settings: Settings, p: dict, actor: str) -> Result:
    from . import ucmdb_write as uw
    from .models import FinalRun
    problem = uw.enabled_problem(settings)
    if problem:
        return _r("erro", problem)
    run_id, res = _reconcile(settings, p, actor)
    if res["status"] == "erro" or res.get("estado") != "pronto":
        return _r(res["status"] if res["status"] == "erro" else "aviso",
                  res["texto"] + " — nada aplicado (a reconciliação tem de ficar «pronta»).", execucao=run_id)
    maximo = int(p.get("maximo", 10))
    with session_scope() as s:
        run = s.get(FinalRun, run_id)
        keys = [c["chave"] for c in (run.changes or []) if c.get("incluir", True)]
        if not keys:
            return _r("nada", f"Reconciliação #{run_id}: nada a aplicar.", execucao=run_id)
        if len(keys) > maximo:
            return _r("aviso", f"Reconciliação #{run_id}: {len(keys)} alterações, mais do que o limite de {maximo}. "
                               "Nada aplicado: reveja em Atualizar a CMDB.", execucao=run_id)
        try:
            lote = uw.queue(s, run, keys, actor)
        except uw.WriteError as exc:
            return _r("erro", str(exc), execucao=run_id)
    uw.process(lote, settings)
    with session_scope() as s:
        from .models import UcmdbWrite
        ws = list(s.scalars(select(UcmdbWrite).where(UcmdbWrite.lote == lote)))
        ok = sum(1 for w in ws if w.estado in uw.DONE)
        bad = [f"{w.cn}: {w.detalhe[:80]}" for w in ws if w.estado == "erro"]
    return _r("aviso" if bad else "ok", f"Reconciliação #{run_id}: {ok} de {len(ws)} aplicada(s) na UCMDB"
              + (f"; erros: {'; '.join(bad[:3])}" if bad else ""), execucao=run_id, aplicadas=ok, erros=len(bad))


def run_abrir_pedidos(settings: Settings, p: dict, actor: str) -> Result:
    from . import dashboard as dsh
    from . import rules as rl
    from . import ticket_create as tc
    from .evaluator import load_snapshot
    from .insights import build_inventory
    problem = write_problem("abrir_pedidos", settings)
    if problem:
        return _r("erro", problem)
    now = utcnow()
    with session_scope() as s:
        snap = load_snapshot(s)
        inv = build_inventory(s, settings, now, snap)
        items = dsh.expiring_without_ticket(inv, snap, s, settings, now)
        inv_by = {r["cn"]: r for r in inv}
        cns = sorted({m["criar"] for r in rl.rules(s) if r.enabled for m in rl.matches(r, items, inv_by) if m["criar"]})
    if not cns:
        return _r("nada", "As regras ativas não abririam nenhum pedido hoje.")
    maximo = int(p.get("maximo", 10))
    if len(cns) > maximo:
        return _r("aviso", f"As regras abririam {len(cns)} pedidos, mais do que o limite de {maximo}. Nenhum criado: reveja em Regras.")
    with session_scope() as s:
        batch = tc.create_batch(s, cns, actor, settings)
        bid = batch.id
    try:
        tc.start(bid, actor, settings)
    except tc.TicketError as exc:
        return _r("erro", f"Lote {bid}: {exc} (abra o lote em Pedidos SMAX → Lotes para completar).", lote=bid)
    out = tc.execute(bid, actor, settings) or {}
    if out.get("erro"):
        return _r("erro", f"Lote {bid}: {out['erro']}", lote=bid)
    return _r("ok", f"Lote {bid}: {out.get('criados', len(cns))} pedido(s) criado(s).", lote=bid, resumo=out)


def run_fechar_renovados(settings: Settings, p: dict, actor: str) -> Result:
    from .fontes.smax import SmaxError, change_phase
    from .insights import build_inventory
    from .models import SmaxTicket
    from .tickets import ticket_list
    problem = write_problem("fechar_renovados", settings)
    if problem:
        return _r("erro", problem)
    with session_scope() as s:
        inv = build_inventory(s, settings, utcnow())
        rows, _ = ticket_list(s, settings, "ja_renovado", inventory=inv)
        ids = [r["t"].id for r in rows]
    if not ids:
        return _r("nada", "Nenhum pedido aberto com o certificado já renovado.")
    maximo = int(p.get("maximo", 10))
    if len(ids) > maximo:
        return _r("aviso", f"{len(ids)} pedidos por fechar, mais do que o limite de {maximo}. Nenhum fechado: reveja em Pedidos SMAX.")
    done, bad = [], []
    for tid in ids:
        try:
            res = change_phase(settings, tid, "fechar", str(p.get("comentario") or "")[:2000])
        except SmaxError as exc:
            bad.append(f"{tid}: {str(exc)[:100]}")
            continue
        with session_scope() as s:
            t = s.get(SmaxTicket, tid)
            if t is not None and res.get("pedido"):
                t.phase, t.last_update = res["pedido"]["phase"], res["pedido"]["last_update"]
            s.add(AuditLog(actor=actor, action="pedido.fechar", target=tid, details={"ok": res["ok"], "motivo": res["motivo"]}))
        (done if res["ok"] else bad).append(tid if res["ok"] else f"{tid}: {res['motivo'][:100]}")
    return _r("aviso" if bad else "ok", f"{len(done)} pedido(s) fechado(s)" + (f"; falharam: {'; '.join(bad[:3])}" if bad else ""),
              fechados=done, falharam=bad)


RUNNERS = {"pipeline": run_pipeline, "ler": run_ler, "relatorio": run_relatorio, "lembretes": run_lembretes,
           "reconciliar": run_reconciliar, "aplicar_cmdb": run_aplicar_cmdb, "abrir_pedidos": run_abrir_pedidos,
           "fechar_renovados": run_fechar_renovados}


def execute(automation_id: int, settings: Settings) -> dict:
    """Corre uma automatização (chamado pelo job «auto:<id>»). Guarda o resultado e devolve o resumo do job."""
    with session_scope() as s:
        a = s.get(Automation, automation_id)
        if a is None:
            return {"erro": f"automatização {automation_id} já não existe"}
        action, params, name = a.action, dict(a.params or {}), a.name
    actor = f"automação «{name}»"
    try:
        if ACTIONS[action].writes:
            problem = write_problem(action, settings)
            if problem:
                raise RuntimeError(problem)
        res = RUNNERS[action](settings, params, actor)
    except Exception as exc:  # noqa: BLE001
        log.exception("Automatização %s", automation_id)
        res = _r("erro", f"{type(exc).__name__}: {str(exc)[:300]}")
    with session_scope() as s:
        a = s.get(Automation, automation_id)
        if a is not None:
            a.last_run_at, a.last_status, a.last_summary = utcnow(), res["status"], dict(res)
        s.add(AuditLog(actor=actor, action="automacao.executar", target=name,
                       details={"id": automation_id, "estado": res["status"], "texto": res["texto"][:300]}))
    out = {"automacao": {"id": automation_id, "nome": name, "estado": res["status"], "texto": res["texto"]}}
    if res["status"] == "erro":
        out["automacao"]["erro"] = res["texto"]
    return out


# ------------------------------------------------------------------ agenda (chamado pelo worker)
def due(settings: Settings, now: datetime | None = None) -> list[int]:
    """Põe na fila as automatizações cuja hora chegou e calcula a próxima. Devolve os ids postos na fila."""
    from .jobs import enqueue
    now = now or utcnow()
    out = []
    with session_scope() as s:
        for a in s.scalars(select(Automation).where(Automation.enabled.is_(True))):
            if a.next_run_at is None:
                a.next_run_at = next_run(a.schedule or {}, now, settings.timezone)
                continue
            if as_utc(a.next_run_at) <= now:
                out.append(a.id)
                a.next_run_at = next_run(a.schedule or {}, now, settings.timezone)
    for aid in out:
        enqueue(f"auto:{aid}", "agendador")
    return out


def pipeline_automated(session: Session) -> bool:
    """Há uma automatização ativa a «Executar tudo»? Então o horário fixo do .env deixa de valer."""
    return session.scalar(select(Automation.id).where(Automation.enabled.is_(True), Automation.action == "pipeline").limit(1)) is not None


def seed(session: Session, settings: Settings, actor: str = "sistema") -> None:
    """Na primeira vez: a execução diária do .env passa a ser uma automatização (igual, editável)."""
    if session.scalar(select(Automation.id).limit(1)) is not None:
        return
    sch = {"tipo": "diario", "hora": settings.pipeline_daily_at}
    session.add(Automation(name="Executar tudo de manhã", action="pipeline", params={}, schedule=sch, enabled=True,
                           next_run_at=next_run(sch, utcnow(), settings.timezone), created_by=actor, updated_by=actor))
    session.flush()

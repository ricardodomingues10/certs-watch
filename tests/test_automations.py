"""Automatizações: agenda, formulário, execução pelo worker, relatório e lembretes automáticos, limites de escrita."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from certwatch import automations as au
from certwatch.db import session_scope, utcnow
from certwatch.jobs import execute_job_run
from certwatch.models import Automation, EmailReport, JobRun, Reminder
from tests.test_dashboard import setup
from tests.test_reminders import FakeSmax
from tests.test_report import FakeSMTP

AUTH = ("admin", "teste-admin-123")
TZ = "Europe/Lisbon"


def test_next_run_and_describe():
    now = datetime(2026, 11, 5, 18, 50, tzinfo=timezone.utc)            # quinta-feira
    assert au.next_run({"tipo": "diario", "hora": "06:15"}, now, TZ) == datetime(2026, 11, 6, 6, 15, tzinfo=timezone.utc)
    assert au.next_run({"tipo": "diario", "hora": "19:00"}, now, TZ) == datetime(2026, 11, 5, 19, 0, tzinfo=timezone.utc)
    fri = datetime(2026, 11, 6, 9, 0, tzinfo=timezone.utc)
    assert au.next_run({"tipo": "uteis", "hora": "08:30"}, fri, TZ) == datetime(2026, 11, 9, 8, 30, tzinfo=timezone.utc)
    assert au.next_run({"tipo": "semanal", "dias": [0, 3], "hora": "09:00"}, now, TZ) == datetime(2026, 11, 9, 9, 0, tzinfo=timezone.utc)
    assert au.next_run({"tipo": "mensal", "dia": 1, "hora": "07:00"}, now, TZ) == datetime(2026, 12, 1, 7, 0, tzinfo=timezone.utc)
    assert au.next_run({"tipo": "horas", "cada": 4, "minuto": 5}, now, TZ) == datetime(2026, 11, 5, 20, 5, tzinfo=timezone.utc)
    assert au.next_run({"tipo": "horas", "cada": 6, "minuto": 0}, datetime(2026, 11, 5, 23, 30, tzinfo=timezone.utc), TZ) == \
        datetime(2026, 11, 6, 0, 0, tzinfo=timezone.utc)
    summer = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)             # hora de verão: 06:15 em Lisboa = 05:15 UTC
    assert au.next_run({"tipo": "diario", "hora": "06:15"}, summer, TZ) == datetime(2026, 7, 2, 5, 15, tzinfo=timezone.utc)
    assert au.next_run({"tipo": "manual"}, now, TZ) is None
    assert au.describe_schedule({"tipo": "semanal", "dias": [0, 3, 4], "hora": "09:00"}) == "Às segundas, quintas e sextas às 09:00"
    assert au.describe_schedule({"tipo": "horas", "cada": 1, "minuto": 5}) == "De hora a hora, ao minuto 05"


def test_clean_params_and_schedule(env):
    st = replace(env, report_allowed_domains=["exemplo.pt"])
    p, e = au.clean_params("relatorio", {"partes": ["alertas", "inventada"], "para": "x@gmail.com", "desde": "30", "ate": "10",
                                         "alerta": "20", "ct_dias": "30", "modo": "junto"}, st)
    assert p["partes"] == ["alertas"] and any("só são permitidos" in x for x in e) and any("início" in x for x in e)
    p, e = au.clean_params("ler", {"passos": []}, st)
    assert e == ["Escolha pelo menos um passo."]
    sch, e = au.clean_schedule({"tipo": "semanal", "hora": "25:00", "dias": []})
    assert "A hora tem de ser HH:MM." in e and "Escolha pelo menos um dia da semana." in e
    sch, e = au.clean_schedule({"tipo": "horas", "cada": "99", "minuto": "7"})
    assert sch == {"tipo": "horas", "cada": 24, "minuto": 7} and not e


@pytest.fixture()
def st(env):
    s = setup(env)
    return replace(s, smax_user="svc", smax_password="pw", smtp_host="smtp.exemplo.pt", smtp_from="atalaia@exemplo.pt",
                   smtp_security="none", report_allowed_domains=["exemplo.pt"], public_url="https://atalaia.exemplo.pt")


def _run_pending(st):
    with session_scope() as s:
        ids = list(s.scalars(select(JobRun.id).where(JobRun.status == "pending")))
    for jid in ids:
        execute_job_run(jid, st)
    return ids


def test_page_create_run_report(st, monkeypatch):
    from certwatch.web import app as webapp
    monkeypatch.setattr(webapp, "get_settings", lambda: st)
    monkeypatch.setattr(au, "SMTP_FACTORY", FakeSMTP)
    FakeSMTP.sent = []
    with TestClient(webapp.app) as c:
        page = c.get("/automacoes", auth=AUTH).text
        assert "Executar tudo de manhã" in page and "Todos os dias às" in page          # o horário do .env, agora editável
        assert "Relatório de alertas à segunda" in page                                   # modelos
        form = c.get("/automacoes/nova?modelo=2", auth=AUTH).text
        assert 'name="partes" value="alertas" checked' in form and 'value="semanal"' in form
        # os dias da semana da agenda não se confundem com o parâmetro «dias» dos lembretes
        r = c.post("/automacoes", data={"csrf": c.cookies["cw_csrf"], "acao": "lembretes", "nome": "L", "dias": "90",
                                        "intervalo": "7", "ag_tipo": "semanal", "ag_hora": "10:00", "ag_dias": ["4"]},
                   auth=AUTH, follow_redirects=False)
        assert r.status_code == 303
        with session_scope() as s:
            lx = s.scalar(select(Automation).where(Automation.name == "L"))
            assert lx.params["dias"] == 90 and lx.schedule["dias"] == [4] and not lx.enabled
        token = c.cookies["cw_csrf"]
        bad = c.post("/automacoes", data={"csrf": token, "acao": "relatorio", "nome": "Semanal", "partes": ["alertas"],
                                          "para": "", "desde": "0", "ate": "90", "alerta": "20", "ct_dias": "30",
                                          "ag_tipo": "semanal", "ag_hora": "08:30", "ag_dias": ["0"], "ativa": "1"}, auth=AUTH)
        assert bad.status_code == 400 and "Indique para quem enviar." in bad.text
        r = c.post("/automacoes", data={"csrf": token, "acao": "relatorio", "nome": "Semanal", "partes": ["alertas"],
                                        "para": "equipa@exemplo.pt", "modo": "junto", "desde": "0", "ate": "90", "alerta": "20",
                                        "ct_dias": "30", "ag_tipo": "semanal", "ag_hora": "08:30", "ag_dias": ["0"], "ativa": "1"},
                   auth=AUTH, follow_redirects=False)
        assert r.status_code == 303 and "Pr%C3%B3xima" in r.headers["location"]
        with session_scope() as s:
            a = s.scalar(select(Automation).where(Automation.name == "Semanal"))
            aid = a.id
            assert a.enabled and a.schedule == {"tipo": "semanal", "hora": "08:30", "dias": [0]}
            assert as_local_weekday(a.next_run_at) == 0
        page = c.get("/automacoes", auth=AUTH).text
        assert "Às segundas às 08:30" in page and "Alertas → equipa@exemplo.pt" in page
        # executar agora: vai para a fila do worker
        c.post(f"/automacoes/{aid}/executar", data={"csrf": token}, auth=AUTH)
        assert _run_pending(st)
        with session_scope() as s:
            a = s.get(Automation, aid)
            assert a.last_status == "ok" and "Enviado para equipa@exemplo.pt" in a.last_summary["texto"]
            rep = s.scalar(select(EmailReport).where(EmailReport.created_by == "automação «Semanal»"))
            assert rep is not None and rep.sends[0]["ok"]
        msgs = [m for m in FakeSMTP.sent if not isinstance(m, tuple)]
        assert len(msgs) == 1 and msgs[0]["To"] == "equipa@exemplo.pt"
        assert "correu bem" in c.get("/automacoes", auth=AUTH).text
        assert "Automatização «Semanal»" in c.get("/jobs", auth=AUTH).text
        # editar, desligar, duplicar, apagar
        assert 'value="Semanal"' in c.get(f"/automacoes/{aid}", auth=AUTH).text
        c.post(f"/automacoes/{aid}/desativar", data={"csrf": token}, auth=AUTH)
        c.post(f"/automacoes/{aid}/duplicar", data={"csrf": token}, auth=AUTH)
        with session_scope() as s:
            assert not s.get(Automation, aid).enabled and s.get(Automation, aid).next_run_at is None
            assert s.scalar(select(Automation).where(Automation.name == "Semanal (cópia)")) is not None
        c.post(f"/automacoes/{aid}/apagar", data={"csrf": token}, auth=AUTH)
        with session_scope() as s:
            assert s.get(Automation, aid) is None


def as_local_weekday(dt):
    from zoneinfo import ZoneInfo
    from certwatch.db import as_utc
    return as_utc(dt).astimezone(ZoneInfo(TZ)).weekday()


def test_only_if_something_and_due(st, monkeypatch):
    monkeypatch.setattr(au, "SMTP_FACTORY", FakeSMTP)
    FakeSMTP.sent = []
    with session_scope() as s:
        s.add(Automation(name="Internet", action="relatorio", enabled=True, schedule={"tipo": "diario", "hora": "08:00"},
                         params={**au.default_params("relatorio"), "partes": ["internet"], "para": "a@exemplo.pt", "so_se_houver": True},
                         next_run_at=utcnow() - timedelta(minutes=1)))
        s.add(Automation(name="Futura", action="pipeline", enabled=True, schedule={"tipo": "diario", "hora": "08:00"},
                         next_run_at=utcnow() + timedelta(hours=3)))
    queued = au.due(st)
    assert len(queued) == 1
    with session_scope() as s:
        a = s.scalar(select(Automation).where(Automation.name == "Internet"))
        assert a.next_run_at is not None and a.next_run_at > utcnow().replace(tzinfo=a.next_run_at.tzinfo)
    _run_pending(st)
    with session_scope() as s:
        a = s.scalar(select(Automation).where(Automation.name == "Internet"))
        assert a.last_status == "nada" and "Nada a reportar" in a.last_summary["texto"]
    assert not FakeSMTP.sent


def test_reminders_automation(st, monkeypatch):
    fake = FakeSmax()
    monkeypatch.setattr(au, "SMTP_FACTORY", FakeSMTP)
    monkeypatch.setattr(au, "SMAX_CLIENT", fake.client())
    FakeSMTP.sent = []
    with session_scope() as s:
        s.add(Automation(name="Lembretes", action="lembretes", enabled=False, schedule={"tipo": "manual"},
                         params=au.default_params("lembretes")))
    with session_scope() as s:
        aid = s.scalar(select(Automation.id).where(Automation.name == "Lembretes"))
    out = au.execute(aid, st)
    assert out["automacao"]["estado"] == "ok" and "1 lembrete(s) enviado(s)" in out["automacao"]["texto"]
    msg = [m for m in FakeSMTP.sent if not isinstance(m, tuple)][0]
    assert msg["To"] == "ana@exemplo.pt" and "https://atalaia.exemplo.pt/r/" in msg.get_body(("html",)).get_content()
    # não repete dentro do intervalo
    out = au.execute(aid, st)
    assert out["automacao"]["estado"] == "nada"
    with session_scope() as s:
        assert len(list(s.scalars(select(Reminder)))) == 1


def test_write_actions_guarded(st, monkeypatch):
    from certwatch.web import app as webapp
    monkeypatch.setattr(webapp, "get_settings", lambda: st)
    with session_scope() as s:
        s.add(Automation(name="Fechar", action="fechar_renovados", enabled=False, schedule={"tipo": "manual"},
                         params=au.default_params("fechar_renovados")))
    with session_scope() as s:
        aid = s.scalar(select(Automation.id).where(Automation.name == "Fechar"))
    out = au.execute(aid, st)                                  # sem CERTWATCH_SMAX_UPDATE_ENABLED
    assert out["automacao"]["estado"] == "erro" and "CERTWATCH_SMAX_UPDATE_ENABLED" in out["automacao"]["texto"]
    out = au.execute(aid, replace(st, smax_update_enabled=True))   # nenhum pedido já renovado nos dados de teste
    assert out["automacao"]["estado"] in ("nada", "ok")
    with TestClient(webapp.app) as c:
        c.get("/automacoes", auth=AUTH)
        r = c.post("/automacoes", data={"csrf": c.cookies["cw_csrf"], "acao": "fechar_renovados", "nome": "F2", "maximo": "5",
                                        "comentario": "x", "ag_tipo": "diario", "ag_hora": "07:00", "ativa": "1"}, auth=AUTH)
        assert r.status_code == 400 and "Confirme que esta automatização pode escrever no SMAX" in r.text
        r = c.post("/automacoes", data={"csrf": c.cookies["cw_csrf"], "acao": "fechar_renovados", "nome": "F2", "maximo": "5",
                                        "comentario": "x", "ag_tipo": "diario", "ag_hora": "07:00", "ativa": "1", "confirmo_escrita": "1"},
                   auth=AUTH, follow_redirects=False)
        assert r.status_code == 303
        assert "escreve no SMAX" in c.get("/automacoes", auth=AUTH).text


def test_worker_env_schedule_yields_to_automations(env):
    from certwatch import worker
    assert worker._env_schedule_on()
    with session_scope() as s:
        au.seed(s, env)
    assert not worker._env_schedule_on()
    with session_scope() as s:
        a = s.scalar(select(Automation))
        assert a.action == "pipeline" and a.schedule == {"tipo": "diario", "hora": env.pipeline_daily_at} and a.enabled
        assert au.pipeline_automated(s)
        au.seed(s, env)                                        # só da primeira vez
        assert len(list(s.scalars(select(Automation)))) == 1

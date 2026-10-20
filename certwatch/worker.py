"""Worker: agenda o pipeline diário e executa os jobs pedidos pela interface."""
from __future__ import annotations

import logging
import signal
import time
from datetime import datetime, time as dtime
from zoneinfo import ZoneInfo

from sqlalchemy import select

from .config import get_settings
from .db import init_db, session_scope, utcnow
from .jobs import enqueue, execute_job_run
from .models import JobRun

log = logging.getLogger("certwatch.worker")
POLL_SECONDS = 15
_stop = False


def _handle_stop(*_):
    global _stop
    _stop = True


def _recover_interrupted() -> None:
    with session_scope() as s:
        for jr in s.scalars(select(JobRun).where(JobRun.status == "running")):
            jr.status, jr.finished_at = "error", utcnow()
            jr.summary = {"erro": "interrompido (reinício do worker)"}


def _schedule_due(tz: ZoneInfo, daily_at: str) -> bool:
    hh, mm = (int(x) for x in daily_at.split(":"))
    now_local = datetime.now(tz)
    if now_local.time() < dtime(hh, mm):
        return False
    start_local = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
    with session_scope() as s:
        exists = s.scalar(
            select(JobRun.id).where(
                JobRun.job == "pipeline",
                JobRun.requested_by == "agendador",
                JobRun.requested_at >= start_local,
            ).limit(1)
        )
    return exists is None


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)

    settings = get_settings()
    init_db()
    _recover_interrupted()
    tz = ZoneInfo(settings.timezone)
    log.info("Worker iniciado; pipeline diário às %s (%s)", settings.pipeline_daily_at, settings.timezone)

    while not _stop:
        try:
            if _schedule_due(tz, settings.pipeline_daily_at):
                jid = enqueue("pipeline", "agendador")
                log.info("Pipeline agendado (job %s)", jid)

            with session_scope() as s:
                pending = list(s.scalars(select(JobRun.id).where(JobRun.status == "pending").order_by(JobRun.id)))
            for jid in pending:
                if _stop:
                    break
                log.info("A executar job %s", jid)
                execute_job_run(jid, settings)
        except Exception:
            log.exception("Erro no ciclo do worker")
        for _ in range(POLL_SECONDS):
            if _stop:
                break
            time.sleep(1)
    log.info("Worker terminado")


if __name__ == "__main__":
    main()

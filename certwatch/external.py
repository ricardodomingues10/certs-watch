"""Avaliação externa (Qualys SSL Labs) dos nomes públicos do inventário."""
from __future__ import annotations

import logging
import time
from datetime import timedelta
from typing import Callable

import httpx
from sqlalchemy import select

from .collectors import ssllabs
from .config import Settings
from .db import as_utc, session_scope, utcnow
from .insights import build_inventory
from .models import SslLabsResult
from .normalize import is_valid_hostname

log = logging.getLogger(__name__)


def external_targets(settings: Settings) -> list[str]:
    """Nomes externos (não wildcard, não IP) ainda sem avaliação recente, os mais antigos primeiro."""
    now = utcnow()
    with session_scope() as s:
        rows = build_inventory(s, settings, now)
        done = {r.host: r for r in s.scalars(select(SslLabsResult))}
    fresh_after = now - timedelta(days=settings.ssllabs_max_age_days)
    hosts = []
    for r in rows:
        h = r["cn"]
        if r["scope"] != "externo" or r["kind"] != "host" or not is_valid_hostname(h):
            continue
        if any(h.endswith(sfx) for sfx in settings.internal_suffixes):
            continue
        prev = done.get(h)
        if prev is not None and prev.status in ("READY", "ERROR") and as_utc(prev.checked_at) > fresh_after:
            continue
        hosts.append((as_utc(prev.checked_at) if prev else None, h))
    hosts.sort(key=lambda x: (x[0] is not None, x[0] or now, x[1]))
    return [h for _, h in hosts][: settings.ssllabs_max_hosts]


def _save(result: dict) -> None:
    with session_scope() as s:
        row = s.scalar(select(SslLabsResult).where(SslLabsResult.host == result["host"]))
        if row is None:
            row = SslLabsResult(host=result["host"])
            s.add(row)
        if result["status"] == "TIMEOUT" and row.status == "READY":
            return  # mantém a última nota válida
        row.status, row.status_message = result["status"], result["status_message"][:500]
        row.grade, row.has_warnings = result["grade"], result["has_warnings"]
        row.endpoints, row.test_time, row.checked_at = result["endpoints"], result["test_time"], utcnow()


def run_ssllabs(settings: Settings, client: httpx.Client | None = None,
                sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> dict:
    if not settings.ssllabs_email:
        return {"aviso": "CERTWATCH_SSLLABS_EMAIL não definido"}
    targets = external_targets(settings)
    deadline = clock() + settings.ssllabs_budget_min * 60
    own = client is None
    client = client or ssllabs.client(settings)
    out = {"alvos": len(targets), "avaliados": 0, "notas": {}, "pendentes": 0}
    try:
        for host in targets:
            if clock() > deadline:
                out["pendentes"] += 1
                continue
            try:
                res = ssllabs.assess(client, host, settings.ssllabs_email, deadline=deadline, sleep=sleep, clock=clock)
            except ssllabs.SslLabsUnavailable as exc:
                out["aviso"] = str(exc)
                break
            except (ssllabs.SslLabsError, httpx.HTTPError, ValueError) as exc:
                log.warning("SSL Labs %s: %s", host, exc)
                if "não registado" in str(exc):
                    out["erro"] = str(exc)
                    break
                res = {"host": host, "status": "ERROR", "status_message": str(exc)[:500], "grade": "",
                       "has_warnings": False, "endpoints": [], "test_time": None}
            _save(res)
            if res["status"] == "TIMEOUT":
                out["pendentes"] += 1
            else:
                out["avaliados"] += 1
                out["notas"][host] = res["grade"] or res["status"]
            sleep(1)  # newAssessmentCoolOff
    finally:
        if own:
            client.close()
    return out

"""Avaliação externa com a API v4 do Qualys SSL Labs (https://api.ssllabs.com/api/v4).

- Exige registo prévio com um email da organização (não aceita Gmail, Hotmail...): ver `cli ssllabs-register`.
- O email vai no cabeçalho HTTP `email` de cada pedido.
- Só avalia nomes acessíveis a partir da internet; os testes correm nos servidores da Qualys.
- Termos: uso gratuito para testar a própria infraestrutura; uso comercial só com autorização da Qualys.
- Boas práticas da documentação: resultados em cache (fromCache + maxAge), um nome de cada vez,
  sondagem a cada 5 s até IN_PROGRESS e a cada 10 s depois, nunca repetir startNew.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Callable

import httpx

from ..config import Settings
from ..trust import build_bundle

log = logging.getLogger(__name__)
API = "https://api.ssllabs.com/api/v4"
USER_AGENT = "certwatch/0.4 (certificate monitoring for the domain owner)"
GOOD_GRADES = ("A+", "A", "A-")
GRADE_ORDER = ("A+", "A", "A-", "B", "C", "D", "E", "F", "M", "T")   # do melhor para o pior


class SslLabsError(RuntimeError):
    pass


class SslLabsUnavailable(SslLabsError):
    """Serviço sobrecarregado ou em manutenção (529/503): parar e tentar noutro dia."""


def client(settings: Settings) -> httpx.Client:
    import ssl
    ctx = ssl.create_default_context(cafile=build_bundle(settings))
    return httpx.Client(base_url=API, verify=ctx, timeout=httpx.Timeout(30.0, read=60.0),
                        headers={"User-Agent": USER_AGENT}, trust_env=True)


def register(c: httpx.Client, first_name: str, last_name: str, email: str, organization: str) -> dict:
    r = c.post("/register", json={"firstName": first_name, "lastName": last_name, "email": email,
                                  "organization": organization})
    try:
        data = r.json()
    except ValueError:
        data = {"status": "failure", "message": r.text[:300]}
    if r.status_code != 200 or str(data.get("status", "")).lower() != "success":
        raise SslLabsError(f"Registo recusado (HTTP {r.status_code}): {data.get('message') or data}")
    return data


def _get(c: httpx.Client, email: str, params: dict) -> dict:
    r = c.get("/analyze", params=params, headers={"email": email})
    if r.status_code == 441:
        raise SslLabsError("Email não registado no SSL Labs: correr `python -m certwatch.cli ssllabs-register`")
    if r.status_code in (503, 529):
        raise SslLabsUnavailable(f"SSL Labs indisponível ou sobrecarregado (HTTP {r.status_code})")
    if r.status_code == 429:
        raise SslLabsError("SSL Labs: demasiados pedidos (HTTP 429)")
    if r.status_code == 400:
        raise SslLabsError(f"SSL Labs recusou o pedido: {r.text[:200]}")
    if r.status_code != 200:
        raise SslLabsError(f"SSL Labs respondeu HTTP {r.status_code}")
    return r.json() or {}


def worst_grade(grades: list[str]) -> str:
    known = [g for g in grades if g in GRADE_ORDER]
    return max(known, key=GRADE_ORDER.index) if known else ""


def summarize(host: str, data: dict) -> dict:
    eps = []
    for e in data.get("endpoints") or []:
        eps.append({"ip": e.get("ipAddress"), "grade": e.get("grade") or "",
                    "grade_sem_confianca": e.get("gradeTrustIgnored") or "", "avisos": bool(e.get("hasWarnings")),
                    "estado": e.get("statusMessage") or ""})
    tt = data.get("testTime")
    return {
        "host": host,
        "status": data.get("status") or "",
        "status_message": data.get("statusMessage") or "",
        "grade": worst_grade([e["grade"] for e in eps]),
        "has_warnings": any(e["avisos"] for e in eps),
        "endpoints": eps,
        "test_time": datetime.fromtimestamp(tt / 1000, tz=timezone.utc) if isinstance(tt, (int, float)) and tt else None,
    }


def assess(c: httpx.Client, host: str, email: str, max_age_hours: int = 24, deadline: float | None = None,
           sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> dict:
    """Pede o resultado em cache (até max_age_hours) ou inicia uma avaliação, e espera que termine."""
    params = {"host": host, "publish": "off", "all": "done", "fromCache": "on", "maxAge": str(max_age_hours)}
    data = _get(c, email, params)
    poll = {"host": host, "publish": "off", "all": "done"}
    while data.get("status") not in ("READY", "ERROR"):
        if deadline is not None and clock() > deadline:
            return {"host": host, "status": "TIMEOUT", "status_message": "avaliação ainda a decorrer; continua na próxima execução",
                    "grade": "", "has_warnings": False, "endpoints": [], "test_time": None}
        sleep(10 if data.get("status") == "IN_PROGRESS" else 5)
        data = _get(c, email, poll)
    return summarize(host, data)


def report_url(host: str) -> str:
    return f"https://www.ssllabs.com/ssltest/analyze.html?d={host}&hideResults=on"

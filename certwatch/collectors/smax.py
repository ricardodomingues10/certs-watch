"""Leitura de tickets (changes) do SMAX, só de leitura.

  POST {base}/auth/authentication-endpoint/authenticate/login?TENANTID={tenant}  {"Login", "Password"}
       -> o corpo da resposta é o token
  GET  {base}/rest/{tenant}/ems/{entidade}?filter=...&layout=...&size=&skip=
       com o cookie "LWSSO_COOKIE_KEY={token}; TENANTID={tenant}"

Os dados do certificado vêm nos campos personalizados de UserOptions
(complexTypeProperties[0].properties): endpoint, data de expiração (em ms), ambiente e tipo.
Os nomes desses campos são configuráveis (CERTWATCH_SMAX_FIELD_*).
"""
from __future__ import annotations

import json
import logging
import re
import ssl
from datetime import datetime, timezone

import httpx

from ..config import Settings
from ..trust import build_bundle

log = logging.getLogger(__name__)
PAGE_SIZE = 500
LAYOUT = ("Id,DisplayLabel,PhaseId,Priority,UserOptions,LastUpdateTime,ScheduledStartTime,ScheduledEndTime,"
          "OwnedByGroup,OwnedByGroup.Name,OwnedByPerson,OwnedByPerson.Name")
LAYOUT_EXTRA = ",AffectsServiceComponent"      # Application ID dos pedidos (para sugerir valores ao criar)
_ENV_CODES = {"NAME1_C": "DEV", "NAME2_C": "TST", "NAME3_C": "SIT", "NAME4_C": "UAT", "NAME5_C": "PRE", "NAME6_C": "PRD"}


class SmaxError(RuntimeError):
    pass


def configured(settings: Settings) -> bool:
    return bool(settings.smax_url and settings.smax_tenant and settings.smax_user and settings.smax_password)


def client(settings: Settings) -> httpx.Client:
    verify: ssl.SSLContext | bool = ssl.create_default_context(cafile=build_bundle(settings))
    if not settings.smax_verify_tls:
        verify = False
    return httpx.Client(base_url=settings.smax_url.rstrip("/"), verify=verify,
                        timeout=httpx.Timeout(30.0, read=120.0), headers={"User-Agent": "certwatch"})


def ticket_url(settings: Settings, ticket_id: str) -> str:
    try:
        return settings.smax_ticket_url.format(base=settings.smax_url.rstrip("/"), tenant=settings.smax_tenant,
                                               entity=settings.smax_entity, id=ticket_id)
    except (KeyError, IndexError, ValueError):
        return ""


def norm_endpoint(value) -> str:
    s = str(value or "").replace(" ", " ").strip().lower()
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
    s = s.split("/")[0]
    s = re.sub(r":\d+$", "", s)
    return s.rstrip(".")


def norm_env(value) -> str:
    if isinstance(value, list):
        value = value[0] if value else ""
    s = str(value or "").strip().upper()
    if s in _ENV_CODES:
        return _ENV_CODES[s]
    for key, out in (("PRD", "PRD"), ("PRODU", "PRD"), ("PPRD", "PRE"), ("PRE", "PRE"), ("UAT", "UAT"),
                     ("SIT", "SIT"), ("TST", "TST"), ("TEST", "TST"), ("DEV", "DEV")):
        if key in s:
            return out
    return s


def _ms(value) -> datetime | None:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None
    return datetime.fromtimestamp(v / 1000 if v > 100_000_000_000 else v, tz=timezone.utc)


def _user_options(raw) -> dict:
    try:
        parsed = json.loads(raw) if isinstance(raw, str) else (raw or {})
        ctp = parsed.get("complexTypeProperties") or []
        return (ctp[0] or {}).get("properties") or {} if ctp else {}
    except (ValueError, AttributeError, TypeError):
        return {}


def _reason(r: httpx.Response) -> str:
    """Motivo devolvido pelo SMAX numa resposta de erro (texto curto, sem HTML)."""
    try:
        data = r.json()
        if isinstance(data, dict):
            for k in ("message", "error_description", "errorMessage", "error", "msg"):
                if data.get(k):
                    return str(data[k])[:300]
        return str(data)[:300]
    except ValueError:
        text = re.sub(r"<[^>]+>", " ", r.text or "")
        return re.sub(r"\s+", " ", text).strip()[:300]


def login(c: httpx.Client, settings: Settings) -> str:
    try:
        r = c.post("/auth/authentication-endpoint/authenticate/login", params={"TENANTID": settings.smax_tenant},
                   json={"Login": settings.smax_user, "Password": settings.smax_password})
    except httpx.HTTPError as exc:
        raise SmaxError(f"Erro de comunicação com o SMAX: {exc}") from exc
    if r.status_code != 200:
        reason = _reason(r).replace(settings.smax_password or "\0", "***")
        hint = (" Possíveis causas: utilizador ou password errados, conta bloqueada, ou a conta não é um "
                "utilizador de integração no SMAX (as contas com SSO não fazem login pela API).") if r.status_code in (401, 403, 500) else ""
        raise SmaxError(f"Autenticação no SMAX falhou: HTTP {r.status_code}"
                        f"{' — resposta do SMAX: ' + reason if reason else ''}.{hint}")
    token = r.text.strip().strip('"')
    if not token or len(token) < 20 or " " in token:
        raise SmaxError("Autenticação no SMAX sem token na resposta")
    return token


def parse_entity(e: dict, settings: Settings) -> dict | None:
    p = e.get("properties") or {}
    rp = e.get("related_properties") or {}
    user = _user_options(p.get("UserOptions"))
    f = settings.smax_fields
    endpoint = norm_endpoint(user.get(f["endpoint"]))
    if not p.get("Id"):
        return None
    return {
        "id": str(p.get("Id")),
        "display_label": str(p.get("DisplayLabel") or "")[:512],
        "endpoint": endpoint[:253],
        "environment": norm_env(user.get(f["env"]) or user.get(f["env"].replace("_c", "Lista_c")))[:32],
        "cert_expiry": _ms(user.get(f["expiry"])),
        "cert_type": str(user.get(f["type"]) or "")[:128],
        "phase": str(p.get("PhaseId") or "")[:64],
        "priority": str(p.get("Priority") or "")[:64],
        "owner_group": str(((rp.get("OwnedByGroup") or {}).get("Name")) or "")[:256],
        "owner_person": str(((rp.get("OwnedByPerson") or {}).get("Name")) or "")[:256],
        "last_update": _ms(p.get("LastUpdateTime")),
        "scheduled_end": _ms(p.get("ScheduledEndTime")),
        "service_component": str(p.get("AffectsServiceComponent") or "")[:64],
    }


def fetch_tickets(settings: Settings, c: httpx.Client | None = None) -> list[dict]:
    if not configured(settings):
        raise SmaxError("SMAX não configurado (CERTWATCH_SMAX_URL, CERTWATCH_SMAX_TENANT e segredos smax_user/smax_password)")
    own = c is None
    c = c or client(settings)
    try:
        token = login(c, settings)
        headers = {"Cookie": f"LWSSO_COOKIE_KEY={token}; TENANTID={settings.smax_tenant}", "Accept": "application/json"}
        out: list[dict] = []
        skip = 0
        layout = LAYOUT + LAYOUT_EXTRA
        while skip < settings.smax_max_tickets:
            params = {"layout": layout, "meta": "totalCount", "order": "Id desc", "size": str(PAGE_SIZE), "skip": str(skip)}
            if settings.smax_filter:
                params["filter"] = settings.smax_filter
            try:
                r = c.get(f"/rest/{settings.smax_tenant}/ems/{settings.smax_entity}", params=params, headers=headers)
            except httpx.HTTPError as exc:
                raise SmaxError(f"Erro de comunicação com o SMAX: {exc}") from exc
            if r.status_code == 400 and skip == 0 and layout != LAYOUT:
                layout = LAYOUT   # campo extra não aceite nesta instalação: continuar sem ele
                continue
            if r.status_code != 200:
                raise SmaxError(f"Consulta de {settings.smax_entity} no SMAX falhou: HTTP {r.status_code}"
                                f" — {_reason(r)}")
            data = r.json() or {}
            ents = data.get("entities") or []
            for e in ents:
                t = parse_entity(e, settings)
                if t:
                    out.append(t)
            total = (data.get("meta") or {}).get("total_count")
            skip += len(ents)
            if len(ents) < PAGE_SIZE or (isinstance(total, int) and skip >= total):
                break
        return out
    finally:
        if own:
            c.close()

"""Coletor UCMDB via REST API (/rest-api/authenticate + /rest-api/topology).

Certificados: só se extraem os campos confiáveis (common_name, valid_to, issuer, issuer_name).
APIs: deteção automática dos campos de nome, URL e validade, com filtro de dados sensíveis.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

import httpx

from ..config import Settings
from ..normalize import norm_host, parse_iso
from ..trust import ssl_context_for_api

log = logging.getLogger(__name__)


class UcmdbError(RuntimeError):
    pass


class UcmdbSession:
    """Sessão autenticada na REST API da UCMDB (um token para várias chamadas)."""

    def __init__(self, settings: Settings, client: httpx.Client | None = None):
        if not settings.ucmdb_url:
            raise UcmdbError("Defina CERTWATCH_UCMDB_URL no ficheiro .env")
        if not settings.ucmdb_user or not settings.ucmdb_password:
            raise UcmdbError("Credenciais UCMDB em falta (segredos ucmdb_user / ucmdb_password)")
        self.settings = settings
        self.own = client is None
        self.client = client or httpx.Client(
            base_url=settings.ucmdb_url.rstrip("/") + "/rest-api",
            verify=ssl_context_for_api(settings),
            timeout=httpx.Timeout(30.0, read=180.0),
        )
        self.headers: dict[str, str] = {}

    def __enter__(self) -> "UcmdbSession":
        try:
            r = self.client.post("/authenticate", json={
                "username": self.settings.ucmdb_user,
                "password": self.settings.ucmdb_password,
                "clientContext": self.settings.ucmdb_client_context,
            })
        except httpx.HTTPError as exc:
            self.close()
            raise UcmdbError(f"Erro de comunicação com a UCMDB: {exc}") from exc
        if r.status_code != 200:
            self.close()
            raise UcmdbError(f"Autenticação UCMDB falhou: HTTP {r.status_code}")
        token = (r.json() or {}).get("token")
        if not token:
            self.close()
            raise UcmdbError("Autenticação UCMDB sem token na resposta")
        self.headers = {"Authorization": f"Bearer {token}"}
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        if self.own:
            self.client.close()

    def _request(self, method: str, path: str, what: str, **kw) -> httpx.Response:
        try:
            r = self.client.request(method, path, headers={**self.headers, **kw.pop("headers", {})}, **kw)
        except httpx.HTTPError as exc:
            raise UcmdbError(f"Erro de comunicação com a UCMDB: {exc}") from exc
        if r.status_code != 200:
            detail = ""
            try:
                detail = str((r.json() or {}).get("error") or "")[:200]
            except ValueError:
                pass
            raise UcmdbError(f"{what} falhou: HTTP {r.status_code}{': ' + detail if detail else ''}")
        return r

    def _result(self, data, what: str) -> list[dict]:
        """Lê o resultado de uma consulta, incluindo resultados divididos em blocos (queryResultId)."""
        if not isinstance(data, dict):
            raise UcmdbError(f"Resposta inesperada da UCMDB em {what}")
        if data.get("queryResultId"):
            qid, n = data["queryResultId"], int(data.get("numberOfChunks") or 0)
            cis: list[dict] = []
            for i in range(1, n + 1):
                part = self._request("GET", f"/topology/result/{qid}/{i}", f"{what} (bloco {i})").json() or {}
                cis += list(part.get("cis") or [])
            try:
                self.client.delete(f"/topology/result/{qid}", headers=self.headers)
            except httpx.HTTPError:
                pass
            return cis
        if "cis" not in data:
            raise UcmdbError(f"Resposta inesperada da UCMDB em {what} (sem 'cis')")
        extra = set(data) - {"cis", "relations"}
        if extra:
            log.warning("Resposta UCMDB com chaves adicionais: %s", sorted(extra))
        return list(data.get("cis") or [])

    def topology(self, tql: str) -> list[dict]:
        """Executa um TQL guardado na UCMDB, pelo nome."""
        r = self._request("POST", "/topology", f"Execução do TQL '{tql}'", content=tql.encode("utf-8"),
                          headers={"Content-Type": "application/json"})
        return self._result(r.json(), f"TQL '{tql}'")

    def topology_query(self, ci_type: str, layout: list[str], ids: list[str] | None = None) -> list[dict]:
        """Consulta ad-hoc (POST /topologyQuery) que escolhe os atributos devolvidos, sem mexer no TQL."""
        body = {"nodes": [{"type": ci_type, "queryIdentifier": "ci", "visible": True, "includeSubtypes": True,
                           "layout": layout, "attributeConditions": [], "ids": ids or [], "linkConditions": []}],
                "relations": []}
        r = self._request("POST", "/topologyQuery", "Consulta ad-hoc (topologyQuery)", json=body)
        return self._result(r.json(), "topologyQuery")

    def ci(self, ucmdb_id: str) -> dict:
        """Todas as propriedades de um CI (GET /dataModel/ci/{id})."""
        return self._request("GET", f"/dataModel/ci/{ucmdb_id}", f"Leitura do CI {ucmdb_id}").json() or {}


def fetch_topology(settings: Settings, tql: str, client: httpx.Client | None = None) -> list[dict]:
    """Autentica e executa um TQL pelo nome. Devolve a lista de CIs."""
    if not tql:
        raise UcmdbError("Defina o nome do TQL no ficheiro .env")
    with UcmdbSession(settings, client) as s:
        return s.topology(tql)


def fetch_certificates(settings: Settings, client: httpx.Client | None = None) -> list[dict]:
    out: list[dict] = []
    for ci in fetch_topology(settings, settings.ucmdb_tql, client):
        props = ci.get("properties") or {}
        out.append({
            "ucmdb_id": str(ci.get("ucmdbId") or ""),
            "global_id": props.get("global_id") or ci.get("globalId"),
            "common_name": (props.get("common_name") or "").strip(),
            "valid_to": props.get("valid_to"),
            "issuer": (props.get("issuer") or "").strip(),
            "issuer_name": (props.get("issuer_name") or "").strip(),
        })
    return out


# ------------------------------------------------------------------ APIs
# A lista de APIs da CMDB ("API secrets") descreve sobretudo segredos de aplicações (ex.: client secrets de
# App Registrations do Azure AD): nome, aplicação, data de expiração, "expirado?", localização e data de
# registo. Pode haver ou não um URL. Os nomes internos dos atributos variam de CMDB para CMDB, por isso
# são detetados pelo nome e pelo conteúdo; os do .env (CERTWATCH_APIS_FIELD_*) têm prioridade.

# Nomes de atributos que podem conter segredos.
SENSITIVE_KEY = re.compile(r"secret|password|passwd|pwd|token|credential|private|api_?key|client_?key|cert_?key|hash|salt", re.I)
# ...mas um atributo como "secret_location" ou "secret_expiration_date" descreve o segredo, não o contém.
DESCRIPTOR_KEY = re.compile(r"locali[sz]|location|local$|tipo|type|status|estado|expir|valid|name|nome|label|aplica|"
                            r"application|owner|respons|regist|create|date|data", re.I)
DATE_KEY = re.compile(r"expir|valid|validade|end_?date|data_?fim|termin|until|not_?after|renova", re.I)
EXPIRY_STRONG = re.compile(r"expir|end_?date|data_?fim|not_?after", re.I)
REGISTERED_KEY = re.compile(r"regist|create|criad|insert|discover", re.I)
# Atributos técnicos da UCMDB (data_allow_auto_discovery, root_class...). "data_" também é "data" em português:
# data_expiracao, data_de_validade... não são técnicos (ver _internal).
INTERNAL_KEY = re.compile(r"^(data_|root_|last_|create|tenant|calculated_|global_id$|user_label$)", re.I)


def _internal(k: str) -> bool:
    return bool(INTERNAL_KEY.search(k)) and not (k.lower().startswith("data_") and DATE_KEY.search(k[5:]))
URL_KEY = re.compile(r"url|uri|endpoint|host|link|address|endereco", re.I)
NAME_KEYS = ("display_label", "name", "label", "user_label")
APP_KEY = re.compile(r"aplica|application|^app(_|$)|sistema|servico|service", re.I)
LOCATION_KEY = re.compile(r"locali[sz]|location|^local$|origem|plataforma|platform", re.I)
EXTRA_KEY = re.compile(r"ambiente|environment|owner|respons|descr|fornecedor|vendor|tipo|type|status|estado|grupo|group", re.I)
_URLISH = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:/.*)?$", re.I)
_TRUE = {"true", "1", "yes", "sim", "y", "s"}
_FALSE = {"false", "0", "no", "nao", "não", "n"}
_LISBON = ZoneInfo("Europe/Lisbon")


def _parse_date(value, tz: ZoneInfo = _LISBON) -> datetime | None:
    """ISO, epoch (ms ou s), DD-MM-AAAA[ HH:MM[:SS]] e DD/MM/AAAA (nunca troca dia e mês)."""
    if isinstance(value, bool) or value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        if value > 100_000_000_000:          # epoch em milissegundos
            return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
        if value > 1_000_000_000:            # epoch em segundos
            return datetime.fromtimestamp(value, tz=timezone.utc)
        return None
    if not isinstance(value, str):
        return None
    s = value.strip()
    if re.fullmatch(r"\d{12,14}", s):
        return _parse_date(int(s), tz)
    d = parse_iso(s) if re.match(r"^\d{4}-\d{2}-\d{2}", s) else None
    if d is None:
        from ..reconcile import parse_date   # import tardio: evita ciclo
        d = parse_date(s, tz) if re.match(r"^\d{1,2}[/.\-]\d{1,2}[/.\-]\d{4}", s) else None
    return d


def _is_date(value) -> bool:
    return _parse_date(value) is not None


def _as_bool(value) -> bool | None:
    if isinstance(value, bool):
        return value
    s = str(value or "").strip().lower()
    return True if s in _TRUE else (False if s in _FALSE else None)


def _looks_secret(value) -> bool:
    """Texto sem espaços, comprido e com mistura de caracteres: tratado como possível segredo."""
    if not isinstance(value, str):
        return False
    s = value.strip()
    if len(s) < 16 or " " in s or _URLISH.match(s) or _is_date(s):
        return False
    classes = sum(bool(re.search(p, s)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    return classes >= 3 or len(s) >= 32


def safe_properties(props: dict) -> dict:
    """Remove tudo o que possa ser segredo. Um atributo com nome sensível só passa se o nome o descrever
    (data, tipo, localização, estado...) e o valor for uma data, um booleano ou um texto curto legível."""
    out = {}
    for k, v in (props or {}).items():
        if isinstance(v, str) and len(v) > 300:
            continue
        if SENSITIVE_KEY.search(k):
            if not DESCRIPTOR_KEY.search(k):
                continue
            if not (_is_date(v) or isinstance(v, bool) or _as_bool(v) is not None
                    or (isinstance(v, str) and len(v) <= 120 and not _looks_secret(v))):
                continue
        out[k] = v
    return out


def detect_api_fields(cis: list[dict], settings: Settings) -> dict[str, str | None]:
    """Escolhe os atributos de cada campo. Os valores do .env têm prioridade."""
    keys: dict[str, list] = {}
    for ci in cis:
        for k, v in safe_properties(ci.get("properties") or {}).items():
            if v not in (None, ""):
                keys.setdefault(k, []).append(v)

    def best(cands, score):
        ranked = sorted(((score(k, vals), k) for k, vals in keys.items() if k in cands), reverse=True)
        return ranked[0][1] if ranked and ranked[0][0] > 0 else None

    bools = {k for k, vals in keys.items() if vals and all(_as_bool(v) is not None for v in vals)}
    dates = {k for k, vals in keys.items() if k not in bools and any(_is_date(v) for v in vals)}

    expired = best({k for k in bools if re.search(r"expir", k, re.I)}, lambda k, v: len(v))
    registered = best({k for k in dates if REGISTERED_KEY.search(k)},
                      lambda k, v: sum(1 for x in v if _is_date(x)) + (0.5 if re.search(r"regist", k, re.I) else 0))
    expiry = best({k for k in dates if DATE_KEY.search(k) and not _internal(k) and k != registered},
                  lambda k, v: sum(1 for x in v if _is_date(x)) + (len(v) if EXPIRY_STRONG.search(k) else 0))
    url = best({k for k in keys if URL_KEY.search(k) and not _internal(k)},
               lambda k, v: sum(1 for x in v if isinstance(x, str) and _URLISH.match(x.strip())))
    name = next((k for k in NAME_KEYS if k in keys), None)
    taken = {name, url, expiry, expired, registered}
    app = best({k for k in keys if APP_KEY.search(k) and k not in taken and k not in bools and k not in dates},
               lambda k, v: len(v))
    location = best({k for k in keys if LOCATION_KEY.search(k) and k not in taken | {app} and k not in bools},
                    lambda k, v: len(v))
    return {
        "nome": settings.apis_field_name or name,
        "aplicacao": settings.apis_field_app or app,
        "validade": settings.apis_field_expiry or expiry,
        "expirado": settings.apis_field_expired or expired,
        "localizacao": settings.apis_field_location or location,
        "registo": settings.apis_field_registered or registered,
        "url": settings.apis_field_url or url,
    }


def parse_api_url(value: str | None) -> tuple[str, str, int | None]:
    """Devolve (esquema, host, porta). Aceita URL completo ou só host[:porta]."""
    s = (value or "").strip()
    if not s or " " in s:
        return "", "", None
    if "://" not in s:
        s = "https://" + s
        implicit = True
    else:
        implicit = False
    try:
        parts = urlsplit(s)
        port = parts.port
    except ValueError:
        return "", "", None
    scheme = "" if implicit else (parts.scheme or "").lower()
    return scheme, norm_host(parts.hostname or ""), port


MAX_CI_LOOKUPS = 5000
PROBE_CIS = 15                 # CIs lidos para saber que atributos existem
# Atributos técnicos da UCMDB que não interessam (mas create_time interessa: é a data de registo)
_SKIP_LAYOUT = re.compile(r"^(root_|data_|calculated_|tenant|global_id$|last_|track_|monitored_by|ucmdb_id$)", re.I)


def _layout_from(props: dict) -> list[str]:
    """Atributos a pedir na consulta ad-hoc: os não sensíveis, sem os técnicos da UCMDB."""
    keys = [k for k in safe_properties(props)
            if not _SKIP_LAYOUT.search(k) or REGISTERED_KEY.search(k)
            or (k.lower().startswith("data_") and DATE_KEY.search(k[5:]))]
    return sorted(set(keys) | {"display_label"})


def _merge(cis: list[dict], extra: dict[str, dict]) -> list[dict]:
    out = []
    for ci in cis:
        props = {**(extra.get(str(ci.get("ucmdbId"))) or {}), **{k: v for k, v in (ci.get("properties") or {}).items()
                                                                 if v not in (None, "")}}
        out.append({**ci, "properties": props})
    return out


def enrich_cis(session: UcmdbSession, cis: list[dict], mode: str = "auto") -> tuple[list[dict], str, list[str]]:
    """Quando o layout do TQL não traz os atributos, vai buscá-los à REST API sem mexer no TQL:
    1) lê um CI (GET /dataModel/ci/{id}) para saber que atributos existem;
    2) pede esses atributos para todos os CIs numa só consulta ad-hoc (POST /topologyQuery);
    3) se a consulta ad-hoc não for permitida, lê CI a CI.
    Devolve (cis, método, avisos)."""
    notes: list[str] = []
    if mode == "off" or not cis:
        return cis, "tql", notes
    ids = [str(c.get("ucmdbId")) for c in cis if c.get("ucmdbId")]
    if mode in ("auto", "query"):
        try:
            # os atributos sem valor não vêm no CI: junta os de vários CIs para não perder nenhum
            probe, seen_props = None, {}
            for uid in ids[:PROBE_CIS]:
                try:
                    one = session.ci(uid)
                except UcmdbError:
                    continue
                probe = probe or one
                for k, v in (one.get("properties") or {}).items():
                    if v not in (None, "") or k not in seen_props:
                        seen_props[k] = v
            if probe is None:
                raise UcmdbError("Não foi possível ler nenhum CI")
            layout = _layout_from(seen_props)
            ci_type = str(cis[0].get("type") or probe.get("type") or "")
            got = session.topology_query(ci_type, layout, ids)
            extra = {str(c.get("ucmdbId")): safe_properties(c.get("properties") or {}) for c in got}
            if any(len(v) > 1 for v in extra.values()):
                return _merge(cis, extra), "topologyQuery", notes
            notes.append("topologyQuery não devolveu atributos")
        except UcmdbError as exc:
            notes.append(str(exc))
            log.warning("Consulta ad-hoc falhou, a ler CI a CI: %s", exc)
        if mode == "query":
            return cis, "tql", notes
    extra: dict[str, dict] = {}
    for uid in ids[:MAX_CI_LOOKUPS]:
        try:
            extra[uid] = safe_properties((session.ci(uid).get("properties") or {}))
        except UcmdbError as exc:
            notes.append(str(exc))
            if len(notes) > 5:
                break
    if extra:
        return _merge(cis, extra), "ci", notes
    return cis, "tql", notes


def fetch_apis(settings: Settings, client: httpx.Client | None = None) -> tuple[list[dict], dict]:
    if not settings.ucmdb_tql_apis:
        raise UcmdbError("CERTWATCH_UCMDB_TQL_APIS não definido")
    with UcmdbSession(settings, client) as s:
        cis = s.topology(settings.ucmdb_tql_apis)
        method, notes = "tql", []
        fields = detect_api_fields(cis, settings)
        if not fields.get("validade") and settings.apis_enrich != "off":
            cis, method, notes = enrich_cis(s, cis, settings.apis_enrich)
    records, fields = parse_apis(cis, settings)
    fields = {**fields, "metodo": method}
    if notes:
        fields["avisos"] = notes[:5]
    return records, fields


def parse_apis(cis: list[dict], settings: Settings) -> tuple[list[dict], dict]:
    fields = detect_api_fields(cis, settings)
    tz = ZoneInfo(settings.timezone)
    get = lambda props, f: props.get(fields[f]) if fields.get(f) else None
    out = []
    for ci in cis:
        props = safe_properties(ci.get("properties") or {})
        raw_url = get(props, "url")
        scheme, host, port = parse_api_url(raw_url if isinstance(raw_url, str) and _URLISH.match(raw_url.strip()) else None)
        name = get(props, "nome")
        out.append({
            "ucmdb_id": str(ci.get("ucmdbId") or ""),
            "name": str(name or ci.get("displayLabel") or "").strip()[:512],
            "application": str(get(props, "aplicacao") or "").strip()[:512],
            "location": str(get(props, "localizacao") or "").strip()[:512],
            "cmdb_expired": _as_bool(get(props, "expirado")),
            "registered_at": _parse_date(get(props, "registo"), tz),
            "url": str(raw_url or "").strip()[:1024] if host else "",
            "scheme": scheme,
            "host": host,
            "port": port,
            "expiry": _parse_date(get(props, "validade"), tz),
            "extra": {k: v for k, v in props.items()
                      if EXTRA_KEY.search(k) and not _internal(k) and isinstance(v, (str, int, bool))
                      and k not in fields.values()},
        })
    return out, fields


def describe_tql(settings: Settings, tql: str, client: httpx.Client | None = None) -> dict:
    """Resumo de um TQL para configuração: atributos, tipos e exemplos não sensíveis. Para o TQL das APIs,
    se o layout só trouxer o nome, mostra também o que se obtém pela REST API (topologyQuery / CI a CI)."""
    method, notes = "tql", []
    with UcmdbSession(settings, client) as s:
        cis = s.topology(tql)
        if tql == settings.ucmdb_tql_apis and cis and not detect_api_fields(cis, settings).get("validade"):
            cis, method, notes = enrich_cis(s, cis, "auto" if settings.apis_enrich == "off" else settings.apis_enrich)
    out = _describe(cis, settings)
    out = {"tql": tql, **out, "metodo": method}
    if notes:
        out["avisos"] = notes[:5]
    return out


def _describe(cis: list[dict], settings: Settings) -> dict:
    keys: dict[str, dict] = {}
    for ci in cis:
        for k, v in (ci.get("properties") or {}).items():
            info = keys.setdefault(k, {"tipo": type(v).__name__, "preenchido": 0, "exemplo": None})
            if v not in (None, "", []):
                info["preenchido"] += 1
                if info["exemplo"] is None:
                    if SENSITIVE_KEY.search(k) and not (DATE_KEY.search(k) and _is_date(v)):
                        info["exemplo"] = "(oculto: nome sensível)"
                    elif _is_date(v) or isinstance(v, (bool, int, float)):
                        info["exemplo"] = v
                    elif isinstance(v, str) and _URLISH.match(v.strip()):
                        _, host, port = parse_api_url(v)
                        info["exemplo"] = f"(URL/host com {len(host)} caracteres{', porta ' + str(port) if port else ''})"
                    else:
                        info["exemplo"] = f"(texto, {len(str(v))} caracteres)"
    return {"total_cis": len(cis), "tipos_ci": sorted({str(c.get('type')) for c in cis}),
            "atributos": keys, "campos_detetados": detect_api_fields(cis, settings) if cis else {}}

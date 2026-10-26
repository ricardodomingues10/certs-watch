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

import base64
import binascii
import hashlib
import html as _html
import json
import logging
import re
import ssl
from datetime import datetime, timezone
from urllib.parse import unquote, urlsplit

import httpx

from ..config import Settings
from ..trust import build_bundle

log = logging.getLogger(__name__)
PAGE_SIZE = 500
LAYOUT = ("Id,DisplayLabel,PhaseId,Priority,UserOptions,LastUpdateTime,ScheduledStartTime,ScheduledEndTime,"
          "OwnedByGroup,OwnedByGroup.Name,OwnedByPerson,OwnedByPerson.Name")
LAYOUT_EXTRA = ",AffectsServiceComponent,EmsCreationTime"   # Application ID (sugestões ao criar) e data de criação
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
                        timeout=httpx.Timeout(30.0, read=120.0), headers={"User-Agent": "AtalaiaCert"})


def ticket_url(settings: Settings, ticket_id: str) -> str:
    try:
        return settings.smax_ticket_url.format(base=settings.smax_url.rstrip("/"), tenant=settings.smax_tenant,
                                               entity=settings.smax_entity, id=ticket_id)
    except (KeyError, IndexError, ValueError):
        return ""


def discussions_url(settings: Settings, ticket_id: str) -> str:
    try:
        return settings.smax_discussions_url.format(base=settings.smax_url.rstrip("/"), tenant=settings.smax_tenant,
                                                    entity=settings.smax_entity, id=ticket_id)
    except (KeyError, IndexError, ValueError):
        return ""


def _text(html_body) -> str:
    import html as _html
    s = re.sub(r"<(br|/p|/div|/li)\s*/?>", "\n", str(html_body or ""), flags=re.I)
    s = _html.unescape(re.sub(r"<[^>]+>", "", s))
    return re.sub(r"\n{3,}", "\n\n", re.sub(r"[ \t\u00a0]+", " ", s)).strip()


# ------------------------------------------------------------------ imagens e anexos dos comentários
MAX_FILE = 10 * 1024 * 1024
_IMG = re.compile(r"<img\b[^>]*?\bsrc\s*=\s*([\'\"])(.*?)\1", re.I | re.S)
_DATA = re.compile(r"^data:([\w.+-]+/[\w.+-]+)?(;[\w=.+-]+)*;base64,(.*)$", re.I | re.S)
_SAFE_ID = re.compile(r"^(?!\.+$)[A-Za-z0-9_.-]{1,128}$")
# Só se pedem ao SMAX caminhos de ficheiros (repositório de imagens e anexos), nunca outras APIs
_FILE_PATH = re.compile(r"^/rest/[^/]+/(frs|ces/attachment)/", re.I)
IMAGE_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp"}


def sniff(data: bytes) -> str:
    """Tipo pelo conteúdo (não pelo que o servidor diz): só estes tipos de imagem são mostrados na página."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data[:2] == b"BM":
        return "image/bmp"
    if data.startswith(b"%PDF-"):
        return "application/pdf"
    return "application/octet-stream"


def comment_files(body, attachment_ids) -> list[dict]:
    """Imagens no corpo do comentário (<img src>) e anexos (AttachmentIds) de um comentário."""
    out, seen = [], set()
    for m in _IMG.finditer(str(body or "")):
        src = _html.unescape(m.group(2)).strip()
        key = src if not src.lower().startswith("data:") else "data:" + hashlib.sha256(src.encode()).hexdigest()
        if src and key not in seen:
            seen.add(key)
            out.append({"kind": "imagem", "ref": key, "src": src})
    for aid in attachment_ids or []:
        aid = str(aid).strip()
        if _SAFE_ID.match(aid) and f"anexo:{aid}" not in seen:
            seen.add(f"anexo:{aid}")
            out.append({"kind": "anexo", "ref": f"anexo:{aid}", "src": aid})
    return out[:30]


def _smax_path(settings: Settings, src: str) -> str | None:
    """Caminho no próprio SMAX para um src de imagem; None se apontar para outro servidor (nunca é pedido)."""
    if src.startswith("//"):
        return None
    u = urlsplit(src)
    base = urlsplit(settings.smax_url)
    if u.scheme or u.netloc:
        if u.scheme not in ("https", "http") or (u.hostname or "").lower() != (base.hostname or "").lower():
            return None
        if (u.port or (443 if u.scheme == "https" else 80)) != (base.port or (443 if base.scheme == "https" else 80)):
            return None
    if not u.path.startswith("/") or ".." in u.path or not _FILE_PATH.match(u.path):
        return None
    return u.path + (f"?{u.query}" if u.query else "")


def _filename(r: httpx.Response, fallback: str) -> str:
    cd = r.headers.get("content-disposition", "")
    m = re.search(r"filename\*=(?:UTF-8'')?([^;]+)", cd, re.I) or re.search(r'filename="?([^";]+)"?', cd, re.I)
    name = unquote(m.group(1).strip()) if m else fallback
    return re.sub(r"[^\w .()-]", "_", name)[:200] or fallback


def download_file(c: httpx.Client, headers: dict, settings: Settings, f: dict) -> dict:
    """Descarrega uma imagem ou anexo de um comentário. Devolve {name, mime, data} ou {error}."""
    src = f["src"]
    if f["kind"] == "imagem" and src.lower().startswith("data:"):
        m = _DATA.match(src)
        if not m:
            return {"error": "imagem embebida num formato não suportado"}
        try:
            data = base64.b64decode(re.sub(r"\s+", "", m.group(3)), validate=True)
        except (binascii.Error, ValueError):
            return {"error": "imagem embebida inválida"}
        if len(data) > MAX_FILE:
            return {"error": "imagem demasiado grande"}
        return {"name": "imagem", "mime": sniff(data), "data": data}
    path = (f"/rest/{settings.smax_tenant}/ces/attachment/{src}" if f["kind"] == "anexo"
            else _smax_path(settings, src))
    if path is None:
        return {"error": "imagem fora do repositório de ficheiros do SMAX (não é descarregada)"}
    try:
        with c.stream("GET", path, headers={**headers, "Accept": "*/*"}) as r:
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}"}
            if int(r.headers.get("content-length") or 0) > MAX_FILE:
                return {"error": "ficheiro demasiado grande"}
            buf = bytearray()
            for chunk in r.iter_bytes():
                buf += chunk
                if len(buf) > MAX_FILE:
                    return {"error": "ficheiro demasiado grande"}
            data = bytes(buf)
            name = _filename(r, "anexo" if f["kind"] == "anexo" else "imagem")
    except httpx.HTTPError as exc:
        return {"error": f"erro de comunicação: {exc}"[:200]}
    mime = sniff(data)
    if f["kind"] == "imagem" and mime not in IMAGE_TYPES:
        return {"error": "a resposta não é uma imagem"}
    return {"name": name, "mime": mime, "data": data}


def fetch_comments(settings: Settings, ticket_ids: list[str], c: httpx.Client | None = None,
                   known_files: set[tuple[str, str]] | None = None) -> tuple[list[dict], dict]:
    """Comentários dos pedidos indicados (GET /rest/{tenant}/collaboration/comments/{entidade}/{id}).
    Ignora os comentários do sistema. Traz também as imagens e anexos que ainda não estão guardados
    (known_files = {(id do comentário, ref)}). Devolve (comentários, resumo)."""
    own = c is None
    c = c or client(settings)
    out: list[dict] = []
    errors = 0
    known_files = known_files or set()
    try:
        token = login(c, settings)
        headers = {"Cookie": f"LWSSO_COOKIE_KEY={token}; TENANTID={settings.smax_tenant}", "Accept": "application/json"}
        for tid in ticket_ids[: settings.smax_comments_max]:
            try:
                r = c.get(f"/rest/{settings.smax_tenant}/collaboration/comments/{settings.smax_entity}/{tid}", headers=headers)
            except httpx.HTTPError:
                r = None
            if r is None or r.status_code != 200:
                errors += 1
                if errors >= 5 and not out:
                    break   # o endpoint não está acessível para esta conta: não insistir
                continue
            try:
                data = r.json()
            except ValueError:
                continue
            for x in data if isinstance(data, list) else (data or {}).get("comments", []) or []:
                if not isinstance(x, dict) or x.get("IsSystem") or not x.get("Id"):
                    continue
                out.append({"id": str(x["Id"])[:64], "ticket_id": str(tid), "created_at": _ms(x.get("CreateTime")),
                            "author_id": str(((x.get("Submitter") or {}).get("UserId")) or "")[:64],
                            "body": _text(x.get("Body"))[:4000], "privacy": str(x.get("PrivacyType") or "")[:32],
                            "origin": str(x.get("CommentFrom") or "")[:32], "author": "",
                            "files": comment_files(x.get("Body"), x.get("AttachmentIds"))})
        # Imagens e anexos (só os novos; no máximo smax_files_max por leitura)
        budget, got, failed = settings.smax_files_max, 0, 0
        for x in out:
            for f in x["files"]:
                if (x["id"], f["ref"]) in known_files:
                    f["existing"] = True
                    continue
                if budget <= 0:
                    f["skipped"] = True
                    continue
                budget -= 1
                f.update(download_file(c, headers, settings, f))
                got += 0 if f.get("error") else 1
                failed += 1 if f.get("error") else 0
        # Nomes de quem comentou
        names: dict[str, str] = {}
        for uid in list({x["author_id"] for x in out if x["author_id"]})[:150]:
            try:
                r = c.get(f"/rest/{settings.smax_tenant}/ems/Person/{uid}", params={"layout": "Name"}, headers=headers)
                data = r.json() if r.status_code == 200 else {}
            except (httpx.HTTPError, ValueError):
                data = {}
            ents = data.get("entities") if isinstance(data, dict) else None
            props = (ents[0] if ents else data if isinstance(data, dict) else {}).get("properties") or {}
            if props.get("Name"):
                names[uid] = str(props["Name"])[:256]
        for x in out:
            x["author"] = names.get(x["author_id"], "")
        return out, {"pedidos": min(len(ticket_ids), settings.smax_comments_max), "comentarios": len(out), "erros": errors,
                     "ficheiros_novos": got, "ficheiros_com_erro": failed}
    finally:
        if own:
            c.close()


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
        "created": _ms(p.get("EmsCreationTime")),
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


# ------------------------------------------------------------------ escrita: fechar / reabrir / comentar
def _auth_headers(token: str, settings: Settings) -> dict:
    return {"Cookie": f"LWSSO_COOKIE_KEY={token}; TENANTID={settings.smax_tenant}", "Accept": "application/json"}


def fetch_ticket(c: httpx.Client, headers: dict, settings: Settings, ticket_id: str) -> dict | None:
    """Um pedido, lido de novo (para confirmar o que mudou)."""
    for layout in (LAYOUT + LAYOUT_EXTRA, LAYOUT):
        try:
            r = c.get(f"/rest/{settings.smax_tenant}/ems/{settings.smax_entity}/{ticket_id}",
                      params={"layout": layout}, headers=headers)
        except httpx.HTTPError:
            return None
        if r.status_code == 400 and layout != LAYOUT:
            continue
        if r.status_code != 200:
            return None
        try:
            data = r.json() or {}
        except ValueError:
            return None
        ents = data.get("entities") if isinstance(data, dict) else None
        return parse_entity(ents[0], settings) if ents else None
    return None


def update_ticket(c: httpx.Client, headers: dict, settings: Settings, ticket_id: str, fields: dict) -> tuple[str, str]:
    """bulk UPDATE de um pedido. Devolve (estado, motivo): ok | falhou | indeterminado."""
    body = {"entities": [{"entity_type": settings.smax_entity, "properties": {"Id": str(ticket_id), **fields}}],
            "operation": "UPDATE"}
    try:
        r = c.post(f"/rest/{settings.smax_tenant}/ems/bulk", json=body, headers={**headers, "Content-Type": "application/json"})
    except httpx.HTTPError as exc:
        return "indeterminado", f"Erro de comunicação com o SMAX: {exc}"[:300]
    try:
        data = r.json()
    except ValueError:
        data = None
    results = data.get("entity_result_list") if isinstance(data, dict) else None
    first = results[0] if isinstance(results, list) and results else None
    if 200 <= r.status_code < 300 and isinstance(first, dict) and first.get("completion_status") == "OK":
        return "ok", ""
    reason = ""
    if isinstance(first, dict):
        err = first.get("errorDetails") or first.get("error") or {}
        reason = str((err.get("message") or err.get("errorMessage") or err) if isinstance(err, dict) else err)[:300]
    if not reason:
        reason = _reason(r)
    status = "indeterminado" if r.status_code >= 500 or first is None else "falhou"
    return status, f"HTTP {r.status_code}: {reason}"[:400]


def add_comment(c: httpx.Client, headers: dict, settings: Settings, ticket_id: str, text: str) -> tuple[bool, str]:
    """Comentário de texto num pedido (POST /collaboration/comments/{entidade}/{id})."""
    body_html = "".join(f"<p>{_html.escape(line)}</p>" for line in text.strip().splitlines() if line.strip())
    body = {"IsSystem": False, "Body": body_html, "PrivacyType": settings.smax_comment_privacy, "AttachmentIds": [],
            "CommentFrom": "Agent", "CommentTo": "Agent", "FunctionalPurpose": "StatusUpdate", "Media": "UI",
            "ActualInterface": "API"}
    try:
        r = c.post(f"/rest/{settings.smax_tenant}/collaboration/comments/{settings.smax_entity}/{ticket_id}",
                   json=body, headers={**headers, "Content-Type": "application/json"})
    except httpx.HTTPError as exc:
        return False, f"Erro de comunicação: {exc}"[:300]
    if 200 <= r.status_code < 300:
        return True, ""
    return False, f"HTTP {r.status_code}: {_reason(r)}"[:300]


def change_phase(settings: Settings, ticket_id: str, action: str, comment: str = "",
                 c: httpx.Client | None = None) -> dict:
    """Fecha ou reabre um pedido. O comentário é escrito antes de fechar (um pedido fechado pode não aceitar
    comentários) e depois de reabrir. No fim o pedido é lido de novo para confirmar a fase."""
    if action not in ("fechar", "reabrir"):
        raise SmaxError("Ação inválida")
    fields = settings.smax_close_fields if action == "fechar" else settings.smax_reopen_fields
    own = c is None
    c = c or client(settings)
    try:
        headers = _auth_headers(login(c, settings), settings)
        before = fetch_ticket(c, headers, settings, ticket_id)
        if before is None:
            raise SmaxError(f"O pedido {ticket_id} não foi encontrado no SMAX (ou a conta não o pode ler).")
        out = {"fase_antes": before["phase"], "comentario": None}
        if comment and action == "fechar":
            out["comentario"] = add_comment(c, headers, settings, ticket_id, comment)
        status, reason = update_ticket(c, headers, settings, ticket_id, fields)
        if comment and action == "reabrir" and status == "ok":
            out["comentario"] = add_comment(c, headers, settings, ticket_id, comment)
        after = fetch_ticket(c, headers, settings, ticket_id)
        out.update({"estado": status, "motivo": reason, "pedido": after, "fase_depois": after["phase"] if after else None})
        want = str(fields.get("PhaseId") or "")
        out["ok"] = bool(after) and (not want or (after["phase"] or "").lower() == want.lower())
        if status == "ok" and not out["ok"]:
            out["motivo"] = (f"O SMAX aceitou o pedido, mas a fase ficou "
                             f"{(after or {}).get('phase') or 'desconhecida'} (esperada {want}).")
        return out
    finally:
        if own:
            c.close()

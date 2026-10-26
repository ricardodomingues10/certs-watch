"""Coletor AVI (NSX Advanced Load Balancer) pela REST API: certificados SSL dos virtual services e das CAs.

Faz o mesmo que o script PowerShell de exportação (login, páginas de /api/sslkeyandcertificate, logout) e
produz um CSV com as mesmas colunas, para ser lido pelo mesmo leitor do ficheiro do AVI.

Segurança:
- só leitura (GET); pede só os campos necessários e descarta tudo o resto em memória (nunca a chave privada);
- a verificação TLS do controlador está sempre ligada (CA do controlador em trust/), ao contrário do script;
- credenciais só nos ficheiros de segredo avi_user / avi_password; nunca em logs nem na página.
"""
from __future__ import annotations

import csv
import io
import logging
import re
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from ..config import Settings

log = logging.getLogger(__name__)

# As colunas do CSV do script de exportação (a mesma ordem e os mesmos nomes)
AVI_COLUMNS = ["Nome", "Subject_CommonName", "Validity_NotBefore", "Validity_NotAfter", "SerialNumber",
               "Issuer_CommonName", "SubjectAlternativeName"]
FIELDS = "name,certificate,type"
MAX_PAGES = 500


class AviError(RuntimeError):
    pass


@dataclass
class AviResult:
    vs: list[dict] = field(default_factory=list)      # certificados dos virtual services (a fonte AVI)
    ca: list[dict] = field(default_factory=list)      # raízes e intermédios
    pedidos: int = 0
    segundos: float = 0.0
    avisos: list[str] = field(default_factory=list)


def configured(settings: Settings) -> str:
    """Devolve o que falta configurar ("" = pronto)."""
    if not settings.avi_url:
        return "Defina CERTWATCH_AVI_URL no .env (endereço do controlador AVI)."
    from ..config import UNREADABLE_SECRETS
    bad = sorted({"avi_user", "avi_password"} & UNREADABLE_SECRETS)
    if bad:
        files = " ".join(f"secrets/{b}" for b in bad)
        return (f"O certwatch não consegue ler {files}: o dono tem de ser o UID 10001. No servidor: "
                f"sudo chown 10001:10001 {files} && sudo chmod 400 {files}, e docker compose up -d.")
    if not settings.avi_user or not settings.avi_password:
        return "Faltam as credenciais do AVI nos ficheiros de segredo secrets/avi_user e secrets/avi_password."
    return ""


def serial_hex(value) -> str:
    """Como o script (ConvertTo-Hex): decimal -> hexadecimal em minúsculas, sem zeros à esquerda.
    Se já vier em hexadecimal (com ou sem ':'), fica em minúsculas sem separadores."""
    s = str(value or "").strip()
    if not s:
        return ""
    if s.isdigit():
        return format(int(s), "x")
    h = re.sub(r"[\s:]", "", s)
    return h.lower() if re.fullmatch(r"[0-9a-fA-F]+", h) else s


def to_row(item: dict) -> dict:
    """Um objeto sslkeyandcertificate -> uma linha com as colunas do script (só campos públicos do certificado)."""
    cert = item.get("certificate") or {}
    subject = cert.get("subject") or {}
    issuer = cert.get("issuer") or {}
    sans = cert.get("subject_alt_names") or []
    return {
        "Nome": item.get("name") or "",
        "Subject_CommonName": subject.get("common_name", "") if subject else "[sem Subject]",
        "Validity_NotBefore": cert.get("not_before", "") if cert else "[sem Validade]",
        "Validity_NotAfter": cert.get("not_after", "") if cert else "[sem Validade]",
        "SerialNumber": serial_hex(cert.get("serial_number")) if cert.get("serial_number") else "[Sem Serial Number]",
        "Issuer_CommonName": issuer.get("common_name", "") if issuer else "[Sem Issuer]",
        "SubjectAlternativeName": "; ".join(str(x) for x in sans) if sans else "[sem SAN]",
    }


def to_csv(rows: list[dict]) -> bytes:
    """CSV como o do script (todas as colunas entre aspas), em UTF-8 com BOM."""
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=AVI_COLUMNS, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    w.writeheader()
    for r in rows:
        w.writerow({k: r.get(k, "") for k in AVI_COLUMNS})
    return buf.getvalue().encode("utf-8-sig")


def _verify(settings: Settings) -> ssl.SSLContext | bool:
    if not settings.avi_verify_tls:
        return False
    from ..trust import build_bundle
    return ssl.create_default_context(cafile=build_bundle(settings))


def _explain(exc: Exception, url: str) -> str:
    text = str(exc)
    if "CERTIFICATE_VERIFY_FAILED" in text or "certificate verify failed" in text:
        return (f"O certificado do controlador AVI ({url}) não é reconhecido. Coloque a raiz (e o intermédio) da CA "
                "que o emitiu na pasta trust/ do certwatch e reinicie. A verificação não é desligada.")
    if isinstance(exc, httpx.ConnectTimeout):
        return (f"A ligação ao controlador AVI ({url}) não abriu em 10 s: normalmente é a firewall entre este "
                "servidor e o AVI (porta 443). Use \"Diagnosticar a ligação\" para ver em que passo para.")
    if isinstance(exc, httpx.ReadTimeout):
        return (f"O controlador AVI ({url}) aceitou a ligação mas não respondeu em 60 s. "
                "Use \"Diagnosticar a ligação\" para ver em que passo para.")
    if isinstance(exc, httpx.ConnectError):
        return f"Não foi possível ligar ao controlador AVI ({url}): {text[:200]}. Confirme o endereço e a firewall."
    return f"Erro de comunicação com o AVI: {text[:300]}"


class AviSession:
    def __init__(self, settings: Settings, client: httpx.Client | None = None):
        problem = configured(settings)
        if problem:
            raise AviError(problem)
        self.settings = settings
        self.base = settings.avi_url.rstrip("/")
        self.headers = {"X-Avi-Tenant": settings.avi_tenant or "admin", "Accept": "application/json"}
        if settings.avi_version:
            self.headers["X-Avi-Version"] = settings.avi_version
        # trust_env=False: o AVI é interno, nunca vai pelo proxy de internet (HTTPS_PROXY do .env)
        self.client = client or httpx.Client(base_url=self.base, verify=_verify(settings), trust_env=False,
                                             timeout=httpx.Timeout(60.0, connect=10.0), follow_redirects=False)
        self.requests = 0

    def __enter__(self) -> "AviSession":
        try:
            r = self.client.post("/login", json={"username": self.settings.avi_user, "password": self.settings.avi_password},
                                 headers={"Accept": "application/json"})
        except httpx.HTTPError as exc:
            self.client.close()
            raise AviError(_explain(exc, self.base)) from None
        self.requests += 1
        if r.status_code in (401, 403):
            self.client.close()
            raise AviError(f"O AVI recusou as credenciais (HTTP {r.status_code}). Confirme secrets/avi_user e "
                           "secrets/avi_password e se a conta está ativa.")
        if r.status_code != 200:
            self.client.close()
            raise AviError(f"Login no AVI falhou: HTTP {r.status_code}.")
        return self

    def __exit__(self, *exc) -> None:
        try:
            csrf = self.client.cookies.get("csrftoken")
            self.client.post("/logout", headers={**self.headers, **({"X-CSRFToken": csrf} if csrf else {}),
                                                 "Referer": self.base + "/"})
        except httpx.HTTPError:
            pass
        finally:
            self.client.close()

    def collection(self, endpoint: str) -> list[dict]:
        """Todas as páginas de uma coleção (ex.: /api/sslkeyandcertificate?type=...), como o script."""
        parts = urlsplit(endpoint)
        base_params = dict(parse_qsl(parts.query, keep_blank_values=True))
        base_params.setdefault("page_size", str(self.settings.avi_page_size))
        base_params.setdefault("fields", FIELDS)
        out: list[dict] = []
        for page in range(1, MAX_PAGES + 1):
            params = {**base_params, "page": str(page)}
            path = urlunsplit(("", "", parts.path, urlencode(params), ""))
            try:
                r = self.client.get(path, headers=self.headers)
            except httpx.HTTPError as exc:
                raise AviError(_explain(exc, self.base)) from None
            self.requests += 1
            if r.status_code == 401:
                raise AviError("A sessão no AVI expirou ou não foi aceite (HTTP 401).")
            if r.status_code == 403:
                raise AviError(f"A conta do AVI não tem permissão para ler {parts.path} no tenant "
                               f"{self.headers['X-Avi-Tenant']} (HTTP 403). Precisa de leitura em SSL/TLS Certificates.")
            if r.status_code != 200:
                raise AviError(f"{parts.path}: HTTP {r.status_code}.")
            data = r.json() or {}
            for item in data.get("results") or []:
                # só o nome e o certificado (público): tudo o resto, incluindo a chave, é descartado aqui
                out.append({"name": item.get("name"), "type": item.get("type"),
                            "certificate": {k: v for k, v in (item.get("certificate") or {}).items()
                                            if k in ("subject", "issuer", "not_before", "not_after", "serial_number",
                                                     "subject_alt_names")}})
            if not data.get("next"):
                return out
        raise AviError(f"{parts.path}: mais de {MAX_PAGES} páginas; aumente CERTWATCH_AVI_PAGE_SIZE.")


def fetch(settings: Settings, client: httpx.Client | None = None, with_ca: bool = True) -> AviResult:
    t0 = time.monotonic()
    res = AviResult()
    with AviSession(settings, client) as s:
        res.vs = [to_row(x) for x in s.collection(settings.avi_endpoint)]
        if with_ca and settings.avi_endpoint_ca:
            try:
                res.ca = [to_row(x) for x in s.collection(settings.avi_endpoint_ca)]
            except AviError as exc:
                res.avisos.append(f"CAs não lidas: {exc}")
        res.pedidos = s.requests
    res.segundos = round(time.monotonic() - t0, 1)
    return res


def diagnose(settings: Settings, timeout: float = 10.0) -> list[dict]:
    """Passo a passo até ao AVI: DNS, TCP, TLS, login. Para no primeiro que falha e diz o que fazer.
    Não usa o proxy. Não envia a password para nenhum lado a não ser o login do próprio AVI."""
    import socket
    from urllib.parse import urlsplit as _split
    steps: list[dict] = []

    def add(passo, ok, detalhe, fazer=""):
        steps.append({"passo": passo, "ok": ok, "detalhe": detalhe, "fazer": fazer})
        return ok

    u = _split(settings.avi_url or "")
    host, port = u.hostname or "", u.port or 443
    if not host:
        add("Endereço", False, "CERTWATCH_AVI_URL não definido ou inválido", "Defina CERTWATCH_AVI_URL=https://<controlador> no .env.")
        return steps
    try:
        ips = sorted({a[4][0] for a in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
        add("DNS", True, f"{host} → {', '.join(ips)}")
    except socket.gaierror as exc:
        add("DNS", False, f"{host} não resolve: {exc}", "Confirme o nome do controlador, ou use o IP em CERTWATCH_AVI_URL.")
        return steps
    t0 = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (TimeoutError, socket.timeout):
        add("Ligação TCP", False, f"{host}:{port} não respondeu em {timeout:.0f} s",
            f"A firewall está a bloquear (ou o controlador não escuta em {port}). Peça a abertura deste servidor "
            f"para {', '.join(ips)} na porta TCP {port}.")
        return steps
    except OSError as exc:
        add("Ligação TCP", False, f"{host}:{port}: {exc}",
            "Ligação recusada ou sem rota: confirme o endereço, a porta e a firewall.")
        return steps
    add("Ligação TCP", True, f"{host}:{port} aberta em {round((time.monotonic() - t0) * 1000)} ms "
                             f"(a partir de {sock.getsockname()[0]})")
    try:
        ctx = _verify(settings)
        if ctx is False:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            sock = None
            add("TLS", True, f"{tls.version()}, certificado do controlador " +
                ("verificado" if settings.avi_verify_tls else "NÃO verificado (CERTWATCH_AVI_VERIFY_TLS=false)"))
    except ssl.SSLCertVerificationError as exc:
        add("TLS", False, f"certificado do controlador não reconhecido: {exc.verify_message}",
            "Coloque a raiz (e o intermédio) da CA que emitiu o certificado do controlador na pasta trust/ "
            "e reinicie (docker compose up -d).")
        return steps
    except (ssl.SSLError, OSError) as exc:
        add("TLS", False, f"o handshake falhou: {exc}", "Confirme que o endereço é o do controlador (https).")
        return steps
    finally:
        if sock is not None:
            sock.close()
    problem = configured(settings)
    if problem:
        add("Login", False, "credenciais em falta", problem)
        return steps
    try:
        with AviSession(settings) as s:
            add("Login", True, f"sessão aberta no tenant {s.headers['X-Avi-Tenant']}")
            try:
                r = s.client.get(urlunsplit(("", "", urlsplit(settings.avi_endpoint).path,
                                             urlencode({**dict(parse_qsl(urlsplit(settings.avi_endpoint).query)),
                                                        "page_size": "1", "fields": "name"}), "")), headers=s.headers)
                if r.status_code == 200:
                    add("Leitura", True, f"{settings.avi_endpoint}: {(r.json() or {}).get('count', '?')} certificados")
                else:
                    add("Leitura", False, f"{settings.avi_endpoint}: HTTP {r.status_code}",
                        "A conta precisa de leitura em SSL/TLS Certificates neste tenant; confirme também o endpoint.")
            except httpx.HTTPError as exc:
                add("Leitura", False, _explain(exc, s.base))
    except AviError as exc:
        add("Login", False, str(exc))
    return steps

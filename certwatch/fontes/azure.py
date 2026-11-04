"""Fonte: Microsoft Entra ID (Azure AD), as App Registrations e os seus segredos e certificados.

Duas formas, com o mesmo resultado:
- por ficheiro: a exportação (EnterpriseApplication;AppRegistration;AppId;CredentialType;KeyId;StartDate;EndDate;Status)
  posta em import/azure*.csv ou carregada em Atualizar a CMDB; a leitura está em azure_rec.read_azure;
- pela API (Microsoft Graph): uma App Registration própria do Atalaia, com a permissão de aplicação
  Application.Read.All (só leitura, com consentimento de administrador) e um client secret. Produz um CSV com as mesmas
  colunas da exportação, lido pelo mesmo leitor.

Segurança:
- o client secret só existe no ficheiro de segredo secrets/azure_client_secret; nunca em logs, páginas ou na base de dados;
- só GET no Graph, só os campos necessários ($select); o "hint" dos segredos e o conteúdo dos certificados são
  descartados em memória (o Graph nunca devolve o valor de um segredo);
- o token só é enviado para o endereço do Graph configurado: um @odata.nextLink para outro sítio é recusado;
- a verificação TLS está sempre ligada; sai pelo HTTPS_PROXY do .env, se houver (o Graph está na internet).
"""
from __future__ import annotations

import csv
import io
import re
import ssl
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

import httpx

from ..config import Settings

COLUMNS = ["EnterpriseApplication", "AppRegistration", "AppId", "CredentialType", "KeyId", "StartDate", "EndDate", "Status"]
SCOPE = "/.default"
MAX_PAGES = 200
APPS = "/v1.0/applications"
SPS = "/v1.0/servicePrincipals"

FONTE = {
    "id": "azure", "nome": "Azure (App Registrations)", "tipo": "API REST (Microsoft Graph) ou ficheiro",
    "estado": "em uso (API ou ficheiro)",
    "para": "Segredos e certificados das App Registrations, com a data de fim, comparados com a lista de APIs da CMDB.",
    "config": ["CERTWATCH_AZURE_TENANT_ID", "CERTWATCH_AZURE_CLIENT_ID", "secrets/azure_client_secret",
               "CERTWATCH_AZURE_SOURCE", "HTTPS_PROXY", "CERTWATCH_IMPORT_DIR (azure*)"],
    "chamadas": [
        {"metodo": "Ficheiro", "endereco": "import/azure*.csv", "para": "exportação das App Registrations", "acesso": "leitura", "estado": "em uso (sem API)", "onde": "azure_rec.py · read_azure"},
        {"metodo": "POST", "endereco": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token", "para": "token da aplicação (client credentials, client secret)", "acesso": "leitura", "estado": "em uso", "onde": "fontes/azure.py · GraphSession"},
        {"metodo": "GET", "endereco": "https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials", "para": "segredos e certificados de cada App Registration (paginado)", "acesso": "leitura", "estado": "em uso", "onde": "fontes/azure.py · fetch"},
        {"metodo": "GET", "endereco": "https://graph.microsoft.com/v1.0/servicePrincipals?$select=appId,displayName", "para": "o nome da Enterprise Application (paginado)", "acesso": "leitura", "estado": "em uso", "onde": "fontes/azure.py · fetch"},
    ],
}

# Códigos AADSTS mais comuns no pedido do token, com o que fazer
AADSTS = {
    "7000215": "O client secret não é válido. No portal, em Certificates & secrets, copia-se o «Value» (só aparece quando "
               "é criado), não o «Secret ID». Crie um novo e ponha o valor em secrets/azure_client_secret.",
    "7000222": "O client secret expirou. Crie um novo em Certificates & secrets e ponha o valor em secrets/azure_client_secret.",
    "700016": "A aplicação (CERTWATCH_AZURE_CLIENT_ID) não existe neste tenant. Confirme o «Application (client) ID» e o tenant.",
    "90002": "O tenant (CERTWATCH_AZURE_TENANT_ID) não foi encontrado. Use o «Directory (tenant) ID» da página Overview.",
    "900023": "O tenant (CERTWATCH_AZURE_TENANT_ID) não é válido. Use o «Directory (tenant) ID» (um GUID).",
    "700027": "A assinatura do pedido não foi aceite. Confirme o client secret.",
    "53003": "Uma política de Acesso Condicional bloqueou o token. Peça uma exceção para esta aplicação (identidade de carga de trabalho).",
}


class AzureError(RuntimeError):
    pass


@dataclass
class AzureResult:
    rows: list[dict] = field(default_factory=list)       # linhas no formato da exportação
    apps: int = 0
    sem_credenciais: int = 0
    pedidos: int = 0
    segundos: float = 0.0
    avisos: list[str] = field(default_factory=list)
    proprio: list[dict] = field(default_factory=list)    # os segredos da própria aplicação do Atalaia


def configured(settings: Settings) -> str:
    """O que falta configurar ("" = pronto)."""
    if not settings.azure_tenant_id or not settings.azure_client_id:
        return "Defina CERTWATCH_AZURE_TENANT_ID e CERTWATCH_AZURE_CLIENT_ID no .env (página Overview da App Registration)."
    from ..config import UNREADABLE_SECRETS
    if "azure_client_secret" in UNREADABLE_SECRETS:
        return ("O Atalaia Cert não consegue ler secrets/azure_client_secret: o dono tem de ser o UID 10001. No servidor: "
                "sudo chown 10001:10001 secrets/azure_client_secret && sudo chmod 400 secrets/azure_client_secret, "
                "e docker compose up -d.")
    if not settings.azure_client_secret:
        return "Falta o client secret no ficheiro de segredo secrets/azure_client_secret."
    return ""


def estado(settings) -> tuple[bool, str]:
    falta = configured(settings)
    if falta:
        return False, "por ficheiro (API por configurar)"
    return True, {"api": "API", "auto": "API (ficheiro se falhar)"}.get(settings.azure_source,
                                                                         "API configurada; a reconciliação usa o ficheiro")


def _verify(settings: Settings) -> ssl.SSLContext:
    from ..trust import build_bundle
    return ssl.create_default_context(cafile=build_bundle(settings))


def _proxy_host() -> str:
    import os
    p = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""
    return urlsplit(p).hostname or "" if p else ""      # só o nome: um proxy com credenciais não aparece


def _explain(exc: Exception, url: str) -> str:
    text = str(exc)
    if "CERTIFICATE_VERIFY_FAILED" in text or "certificate verify failed" in text:
        return (f"O certificado de {url} não é reconhecido. Se o proxy inspeciona o TLS, ponha a CA do proxy na pasta "
                "trust/ e reinicie. A verificação não é desligada.")
    if isinstance(exc, httpx.ProxyError):
        return f"O proxy recusou ou não respondeu ao pedido para {url}: {text[:200]}. Confirme HTTPS_PROXY e se o proxy deixa passar este endereço."
    if isinstance(exc, httpx.ConnectTimeout):
        return (f"A ligação a {url} não abriu em 10 s. O Microsoft Graph está na internet: este servidor precisa de sair "
                "diretamente ou por proxy (HTTPS_PROXY no .env). Use \"Diagnosticar a ligação\".")
    if isinstance(exc, httpx.ConnectError):
        return f"Não foi possível ligar a {url}: {text[:200]}. Confirme a saída para a internet ou o HTTPS_PROXY."
    if isinstance(exc, httpx.ReadTimeout):
        return f"{url} não respondeu em 60 s."
    return f"Erro de comunicação com {url}: {text[:300]}"


def _graph_error(r: httpx.Response) -> tuple[str, str]:
    try:
        e = (r.json() or {}).get("error") or {}
        return str(e.get("code") or ""), str(e.get("message") or "")[:200]
    except ValueError:
        return "", ""


class GraphSession:
    """Um token de aplicação e GETs paginados ao Microsoft Graph."""

    def __init__(self, settings: Settings, client: httpx.Client | None = None):
        problem = configured(settings)
        if problem:
            raise AzureError(problem)
        self.settings = settings
        self.graph = settings.azure_graph_url.rstrip("/")
        # trust_env=True: o Graph está na internet; sai pelo HTTPS_PROXY / NO_PROXY do .env, se houver
        self.client = client or httpx.Client(verify=_verify(settings), trust_env=True, follow_redirects=False,
                                             timeout=httpx.Timeout(60.0, connect=10.0))
        self.requests = 0
        self.token = ""

    def __enter__(self) -> "GraphSession":
        st = self.settings
        url = f"{st.azure_login_url.rstrip('/')}/{st.azure_tenant_id}/oauth2/v2.0/token"
        try:
            r = self.client.post(url, data={"client_id": st.azure_client_id, "client_secret": st.azure_client_secret,
                                            "scope": self.graph + SCOPE, "grant_type": "client_credentials"},
                                 headers={"Accept": "application/json"})
        except httpx.HTTPError as exc:
            self.client.close()
            raise AzureError(_explain(exc, st.azure_login_url)) from None
        self.requests += 1
        if r.status_code != 200:
            self.client.close()
            try:
                body = r.json() or {}
            except ValueError:
                body = {}
            codes = [str(c) for c in body.get("error_codes") or []]
            hint = next((AADSTS[c] for c in codes if c in AADSTS), "")
            code = f"AADSTS{codes[0]}" if codes else (body.get("error") or f"HTTP {r.status_code}")
            # a descrição do Entra não leva o segredo; mesmo assim só se mostra o código e a explicação
            raise AzureError(f"O Entra ID recusou o pedido do token ({code}). " + (hint or "Confirme o tenant, o client ID e o client secret."))
        self.token = (r.json() or {}).get("access_token") or ""
        if not self.token:
            self.client.close()
            raise AzureError("O Entra ID respondeu sem token.")
        return self

    def __exit__(self, *exc) -> None:
        self.token = ""
        self.client.close()

    def _get(self, url: str, params: dict | None = None) -> dict:
        if not url.startswith(self.graph + "/"):
            raise AzureError(f"O Graph indicou uma página seguinte fora de {self.graph}; o pedido foi recusado.")
        for attempt in range(4):
            try:
                r = self.client.get(url, params=params, headers={"Authorization": f"Bearer {self.token}",
                                                                 "Accept": "application/json"})
            except httpx.HTTPError as exc:
                raise AzureError(_explain(exc, self.graph)) from None
            self.requests += 1
            if r.status_code in (429, 503, 504) and attempt < 3:
                try:
                    wait = min(float(r.headers.get("Retry-After", "5")), 30.0)
                except ValueError:
                    wait = 5.0
                time.sleep(wait)
                continue
            break
        path = urlsplit(url).path
        if r.status_code == 200:
            return r.json() or {}
        code, msg = _graph_error(r)
        if r.status_code == 401:
            raise AzureError(f"O Graph não aceitou o token ({code or 'HTTP 401'}). Confirme o tenant e a aplicação.")
        if r.status_code == 403:
            raise AzureError(f"A aplicação não tem permissão para ler {path} ({code or 'HTTP 403'}). Precisa da permissão "
                             "de APLICAÇÃO Application.Read.All no Microsoft Graph, com «Grant admin consent».")
        if r.status_code == 429:
            raise AzureError("O Graph pediu para abrandar (HTTP 429) várias vezes seguidas. Tente daqui a uns minutos.")
        raise AzureError(f"{path}: HTTP {r.status_code}{' ' + code if code else ''}.")

    def collection(self, path: str, params: dict) -> list[dict]:
        out: list[dict] = []
        url, p = self.graph + path, params
        for _ in range(MAX_PAGES):
            data = self._get(url, p)
            out.extend(data.get("value") or [])
            url, p = data.get("@odata.nextLink"), None
            if not url:
                return out
        raise AzureError(f"{path}: mais de {MAX_PAGES} páginas.")


_FRAC = re.compile(r"(\.\d{1,6})\d*")


def parse_graph_dt(v) -> datetime | None:
    if not v:
        return None
    s = _FRAC.sub(r"\1", str(v).replace("Z", "+00:00"))
    try:
        d = datetime.fromisoformat(s)
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def to_rows(apps: list[dict], sps: dict[str, str], now: datetime, tz: str) -> list[dict]:
    """As App Registrations do Graph -> uma linha por credencial, como a exportação (datas em hora local)."""
    zone = ZoneInfo(tz)
    fmt = lambda d: d.astimezone(zone).strftime("%d/%m/%Y %H:%M:%S") if d else ""  # noqa: E731
    out = []
    for a in apps:
        name = a.get("displayName") or ""
        ent = sps.get(a.get("appId") or "") or name
        creds = [("Secret", c) for c in a.get("passwordCredentials") or []] + \
                [("Certificate", c) for c in a.get("keyCredentials") or []]
        for kind, c in creds:
            start, end = parse_graph_dt(c.get("startDateTime")), parse_graph_dt(c.get("endDateTime"))
            out.append({"EnterpriseApplication": ent, "AppRegistration": name, "AppId": a.get("appId") or "",
                        "CredentialType": kind, "KeyId": c.get("keyId") or "", "StartDate": fmt(start),
                        "EndDate": fmt(end), "Status": "Expired" if end and end < now else "Valid"})
    out.sort(key=lambda r: (r["AppRegistration"].lower(), r["CredentialType"], r["KeyId"]))
    return out


def to_csv(rows: list[dict]) -> bytes:
    """CSV como a exportação (separador ;, tudo entre aspas), em UTF-8 com BOM."""
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=COLUMNS, delimiter=";", quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    w.writeheader()
    for r in rows:
        w.writerow({k: r.get(k, "") for k in COLUMNS})
    return buf.getvalue().encode("utf-8-sig")


def fetch(settings: Settings, client: httpx.Client | None = None, now: datetime | None = None) -> AzureResult:
    t0 = time.monotonic()
    now = now or datetime.now(timezone.utc)
    res = AzureResult()
    with GraphSession(settings, client) as g:
        raw = g.collection(APPS, {"$select": "id,appId,displayName,passwordCredentials,keyCredentials", "$top": "999"})
        # só o que interessa: as datas e o KeyId de cada credencial (o hint e o conteúdo do certificado saem aqui)
        keep = ("keyId", "startDateTime", "endDateTime")
        apps = [{"appId": a.get("appId"), "displayName": a.get("displayName"),
                 "passwordCredentials": [{k: c.get(k) for k in keep} for c in a.get("passwordCredentials") or []],
                 "keyCredentials": [{k: c.get(k) for k in keep} for c in a.get("keyCredentials") or []]} for a in raw]
        sps: dict[str, str] = {}
        try:
            for sp in g.collection(SPS, {"$select": "appId,displayName", "$top": "999"}):
                if sp.get("appId"):
                    sps[sp["appId"]] = sp.get("displayName") or ""
        except AzureError as exc:
            res.avisos.append(f"Nomes das Enterprise Applications não lidos ({exc}); foi usado o nome da App Registration.")
        res.pedidos = g.requests
    res.apps = len(apps)
    res.sem_credenciais = sum(1 for a in apps if not a["passwordCredentials"] and not a["keyCredentials"])
    res.rows = to_rows(apps, sps, now, settings.timezone)
    res.proprio = [r for r in res.rows if r["AppId"].lower() == settings.azure_client_id.lower()]
    res.segundos = round(time.monotonic() - t0, 1)
    return res


def diagnose(settings: Settings, client: httpx.Client | None = None) -> list[dict]:
    """Passo a passo até ao Graph: configuração, saída (direta ou proxy), token, leitura das aplicações e dos service
    principals. Para no primeiro que falha e diz o que fazer. O segredo só vai para o endereço do token."""
    steps: list[dict] = []

    def add(passo, ok, detalhe, fazer=""):
        steps.append({"passo": passo, "ok": ok, "detalhe": detalhe, "fazer": fazer})
        return ok

    problem = configured(settings)
    if not add("Configuração", not problem, "tenant, client ID e client secret definidos" if not problem else "em falta", problem):
        return steps
    proxy = _proxy_host()
    add("Saída para a internet", True, f"pelo proxy {proxy}" if proxy else "direta (sem HTTPS_PROXY no .env)",
        "" if proxy else "Se a rede só sai por proxy, defina HTTPS_PROXY no .env.")
    try:
        with GraphSession(settings, client) as g:
            add("Token", True, f"token de aplicação obtido em {settings.azure_login_url}")
            for label, path, sel in (("Ler as App Registrations", APPS, "id"), ("Ler as Enterprise Applications", SPS, "appId")):
                try:
                    data = g._get(g.graph + path, {"$select": sel, "$top": "1"})
                    add(label, True, f"{path}: ok ({len(data.get('value') or [])} na primeira página de 1)")
                except AzureError as exc:
                    add(label, False, str(exc), "Em API permissions: Microsoft Graph → Application permissions → "
                                                "Application.Read.All → Grant admin consent.")
                    break
    except AzureError as exc:
        add("Token", False, str(exc))
    return steps


def read(data: bytes, filename: str, today: date):
    from ..azure_rec import read_azure
    return read_azure(data, filename, today)

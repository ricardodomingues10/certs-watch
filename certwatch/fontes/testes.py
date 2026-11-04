"""«Testar a ligação» de cada fonte, na página Sistema → Fontes e ligações.

Cada teste faz o mínimo para provar que a fonte responde (só leitura; o email liga-se e autentica-se mas não envia
nada) e devolve passos: {"passo", "ok", "detalhe", "fazer"}. Para no primeiro que falha. Nunca mostra segredos.
"""
from __future__ import annotations

import time

import httpx

from ..config import Settings

TIMEOUT = 15.0


def _step(passo, ok, detalhe, fazer=""):
    return {"passo": passo, "ok": ok, "detalhe": detalhe, "fazer": fazer}


def _http(url: str, ok_codes=(200,)) -> dict:
    t0 = time.monotonic()
    try:
        with httpx.Client(timeout=TIMEOUT, trust_env=True, follow_redirects=True) as c:
            r = c.get(url, headers={"Accept": "application/json"})
    except httpx.HTTPError as exc:
        return _step("Ligação", False, f"{url}: {type(exc).__name__}: {str(exc)[:160]}",
                     "Confirme a saída para a internet deste servidor (direta ou HTTPS_PROXY) e a firewall.")
    ms = round((time.monotonic() - t0) * 1000)
    if r.status_code in ok_codes:
        return _step("Ligação", True, f"{url}: HTTP {r.status_code} em {ms} ms")
    return _step("Ligação", False, f"{url}: HTTP {r.status_code}", "O serviço respondeu com erro: tente mais tarde.")


def _connector(settings: Settings, role: str) -> list[dict]:
    from ..conectores import active
    conn = active(settings, role)
    if conn.kind == "nenhum":
        return [_step("Configuração", False, f"{conn.label}: desligado", "Escolha o tipo em Configurar.")]
    if not conn.configured():
        return [_step("Configuração", False, f"{conn.label}: falta {', '.join(conn.missing())}", "Preencha em Configurar.")]
    try:
        res = conn.test()
    except Exception as exc:  # um conector mal configurado não estraga a página
        return [_step("Ligação", False, f"{conn.label}: {type(exc).__name__}: {str(exc)[:200]}")]
    total = f" · {res.total} registos" if res.total is not None else ""
    return [_step("Configuração", True, conn.label), _step("Leitura", res.ok, f"{res.message}{total}")]


def test_ucmdb(settings: Settings) -> list[dict]:
    return _connector(settings, "cmdb")


def test_smax(settings: Settings) -> list[dict]:
    return _connector(settings, "tickets")


def test_avi(settings: Settings) -> list[dict]:
    from . import avi
    return avi.diagnose(settings)


def test_azure(settings: Settings) -> list[dict]:
    from . import azure
    return azure.diagnose(settings)


def test_ct(settings: Settings) -> list[dict]:
    if not settings.ct_domains:
        return [_step("Configuração", False, "sem domínios", "Defina CERTWATCH_CT_DOMAINS no .env.")]
    return [_step("Configuração", True, ", ".join(settings.ct_domains[:4])),
            _http(f"https://crt.sh/?q={settings.ct_domains[0]}&output=json&exclude=expired", (200, 502, 503))]


def test_servidores(settings: Settings) -> list[dict]:
    from sqlalchemy import select

    from ..db import session_scope
    from ..models import Endpoint
    from ..trust import build_bundle
    from .servidores import scan_endpoint
    with session_scope() as s:
        ep = s.scalar(select(Endpoint).where(Endpoint.enabled.is_(True)).order_by(Endpoint.id).limit(1))
        host, port = (ep.host, ep.port) if ep else ("", 0)
    if not host:
        return [_step("Servidores", False, "ainda não há servidores para testar", "Importe a CMDB primeiro.")]
    out = scan_endpoint(host, port, build_bundle(settings), settings.scan_timeout)
    ok = out.status == "ok"
    return [_step(f"TLS a {host}:{port}", ok,
                  f"{out.tls_version}, {out.resolved_ip}, {out.duration_ms:.0f} ms" if ok else f"{out.status}: {out.error}",
                  "" if ok else "Confirme o DNS e a firewall entre este servidor e o servidor testado.")]


def test_dns(settings: Settings) -> list[dict]:
    from . import dns
    name = (settings.domains or settings.ct_domains or ["example.com"])[0]
    inside = dns.resolve_internal(name)
    steps = [{**_step(f"DNS interno: {name}", bool(inside.ips), ", ".join(inside.ips) or inside.erro), "seguir": True}]
    outside = dns.resolve_public(name, settings.public_dns_urls)
    steps.append(_step(f"DNS público: {name}", bool(outside.ips) or outside.inexistente,
                       (f"{outside.resolvedor}: " + (", ".join(outside.ips) or outside.erro)) if not outside.erro or outside.inexistente
                       else outside.erro,
                       "" if outside.ips or outside.inexistente else "O servidor precisa de chegar a cloudflare-dns.com ou dns.google (HTTPS)."))
    return steps


def test_rdap(settings: Settings) -> list[dict]:
    from . import rdap
    if not settings.domains:
        return [_step("Configuração", False, "sem domínios", "Defina CERTWATCH_DOMAINS (ou CERTWATCH_CT_DOMAINS) no .env.")]
    try:
        with httpx.Client(timeout=TIMEOUT, trust_env=True, follow_redirects=True) as c:
            servers = rdap.bootstrap(c, settings.rdap_bootstrap_url)
            steps = [_step("Lista da IANA", True, f"{len(servers)} terminações com RDAP")]
            info = rdap.lookup(settings.domains[0], servers, c)
    except rdap.RdapError as exc:
        return [_step("RDAP", False, str(exc), "Confirme a saída para a internet (data.iana.org e o servidor RDAP do domínio).")]
    exp = info["expires"].date().isoformat() if info["expires"] else "o registo não indica"
    return steps + [_step(f"Registo de {settings.domains[0]}", True, f"{info['servidor']} · expira {exp} · {info['registrar'] or 'registrar ?'}")]


def test_ssllabs(settings: Settings) -> list[dict]:
    return [_http("https://api.ssllabs.com/api/v3/info")]


def test_email(settings: Settings) -> list[dict]:
    from .email import EmailError, send, smtp_problems
    p = smtp_problems(settings)
    if p:
        return [_step("Configuração", False, "; ".join(p), "Defina CERTWATCH_SMTP_* no .env.")]
    try:
        send(settings, [])            # liga, cifra e autentica, sem enviar nada
    except EmailError as exc:
        return [_step("Servidor de email", False, str(exc))]
    return [_step("Servidor de email", True, f"{settings.smtp_host}:{settings.smtp_port}: ligação e autenticação ok (nada enviado)")]


TESTS = {"ucmdb": test_ucmdb, "smax": test_smax, "avi": test_avi, "azure": test_azure, "ct": test_ct,
         "servidores": test_servidores, "dns": test_dns, "rdap": test_rdap, "ssllabs": test_ssllabs, "email": test_email}
# Onde se configura cada fonte (páginas de detalhe, fora do menu)
CONFIG = {"ucmdb": [("/ligacoes#cmdb", "Escolher a CMDB"), ("/cmdb-final/permissoes", "Permissões da UCMDB")],
          "smax": [("/ligacoes#tickets", "Escolher o sistema de tickets")],
          "avi": [("/cmdb-final/avi", "AVI pela API")], "azure": [("/cmdb-final/azure", "Azure pela API")],
          "ct": [("/descoberta", "Na internet")], "servidores": [("/endpoints", "Servidores")],
          "dns": [("/sites-publicos", "Sites públicos")], "rdap": [("/sites-publicos#dominios", "Domínios")],
          "email": [("/relatorio", "Relatório por email")], "teams": [("/donos", "Canais das equipas")]}


def run(source: str, settings: Settings) -> list[dict]:
    fn = TESTS.get(source)
    if fn is None:
        return [_step("Teste", False, "esta fonte não tem teste de ligação (é por ficheiro ou ainda está planeada)")]
    try:
        steps = fn(settings)
    except Exception as exc:
        steps = [_step("Teste", False, f"{type(exc).__name__}: {str(exc)[:200]}")]
    out = []
    for st in steps:                  # para no primeiro que falha
        out.append(st)
        if not st["ok"] and not st.get("seguir"):
            break
    return out
TEST_OVERRIDE = None     # testes: substitui run(fonte, settings)

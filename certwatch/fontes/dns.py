"""Fonte: DNS interno (o resolvedor do servidor) e DNS público (DNS-over-HTTPS).

- interno: a resolução normal do sistema (getaddrinfo), a que o Atalaia sempre usou para ligar aos servidores;
- público: DNS-over-HTTPS (JSON) num resolvedor público (Cloudflare, e o da Google se o primeiro falhar). É o que a
  internet vê: com DNS diferente dentro e fora, o mesmo nome pode apontar para outro sítio. Usado em Sites públicos.
Planeado: os registos CAA de cada domínio (que autoridades podem emitir certificados para ele).
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field

import httpx

FONTE = {
    "id": "dns", "nome": "DNS (interno e público)", "tipo": "DNS e DNS-over-HTTPS", "estado": "em uso; CAA planeado",
    "para": "Resolver os nomes como os vê este servidor (DNS interno) e como os vê a internet (DNS público), "
            "para comparar o certificado servido dentro e fora.",
    "config": ["resolvedor DNS do servidor", "CERTWATCH_PUBLIC_DNS (resolvedores DNS-over-HTTPS)", "HTTPS_PROXY (se houver)"],
    "chamadas": [
        {"metodo": "DNS", "endereco": "A/AAAA {nome} (resolvedor do servidor)", "para": "para onde o nome aponta dentro da rede", "acesso": "leitura", "estado": "em uso", "onde": "fontes/dns.py · resolve_internal"},
        {"metodo": "GET", "endereco": "https://cloudflare-dns.com/dns-query?name={nome}&type=A|AAAA", "para": "para onde o nome aponta na internet (DNS público)", "acesso": "leitura", "estado": "em uso", "onde": "fontes/dns.py · resolve_public"},
        {"metodo": "GET", "endereco": "https://dns.google/resolve?name={nome}&type=A|AAAA", "para": "o mesmo, se o primeiro resolvedor falhar", "acesso": "leitura", "estado": "em uso", "onde": "fontes/dns.py · resolve_public"},
        {"metodo": "GET", "endereco": "DNS-over-HTTPS CAA {domínio} (e cada nível acima)", "para": "que autoridades podem emitir para o domínio", "acesso": "leitura", "estado": "planeado", "onde": "—"},
    ],
}

# Sinais de CDN / balanceadores globais no CNAME: muitos nós, cada um com o seu certificado; testa-se uma amostra
CDN_SUFFIXES = (".cloudflare.net", ".cdn.cloudflare.net", ".akamaiedge.net", ".edgekey.net", ".edgesuite.net",
                ".akamai.net", ".cloudfront.net", ".azureedge.net", ".azurefd.net", ".fastly.net", ".fastlylb.net",
                ".incapdns.net", ".impervadns.net", ".cdn77.org", ".llnwd.net", ".stackpathdns.com", ".b-cdn.net")


def estado(settings) -> tuple[bool, str]:
    urls = getattr(settings, "public_dns_urls", []) or []
    return True, "resolução do sistema" + (f"; DNS público por {urlhost(urls[0])}" if urls else "")


def urlhost(url: str) -> str:
    from urllib.parse import urlsplit
    return urlsplit(url).hostname or url


@dataclass
class Resolution:
    ips: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    erro: str = ""
    inexistente: bool = False           # o nome não existe neste DNS (NXDOMAIN / sem registos)
    resolvedor: str = ""

    @property
    def cdn(self) -> str:
        for c in self.cnames:
            c = c.rstrip(".").lower()
            for s in CDN_SUFFIXES:
                if c.endswith(s):
                    return s.lstrip(".")
        return ""


def _sort_ips(ips) -> list[str]:
    def key(x):
        a = ipaddress.ip_address(x)
        return (a.version, int(a))
    return sorted(set(ips), key=key)


def resolve_internal(name: str) -> Resolution:
    try:
        infos = socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return Resolution(erro=f"DNS interno: {exc}", inexistente=exc.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)),
                          resolvedor="interno")
    return Resolution(ips=_sort_ips(i[4][0] for i in infos), resolvedor="interno")


def resolve_public(name: str, urls: list[str], client: httpx.Client | None = None, timeout: float = 8.0) -> Resolution:
    """A e AAAA por DNS-over-HTTPS (formato JSON). Tenta cada resolvedor pela ordem até um responder."""
    if not urls:
        return Resolution(erro="sem resolvedor público configurado (CERTWATCH_PUBLIC_DNS)")
    own = client is None
    c = client or httpx.Client(timeout=timeout, trust_env=True, follow_redirects=False)
    last = ""
    try:
        for url in urls:
            res = Resolution(resolvedor=urlhost(url))
            try:
                statuses = []
                for qtype in ("A", "AAAA"):
                    r = c.get(url, params={"name": name, "type": qtype}, headers={"Accept": "application/dns-json"})
                    if r.status_code != 200:
                        raise httpx.HTTPStatusError(f"HTTP {r.status_code}", request=r.request, response=r)
                    data = r.json()
                    statuses.append(data.get("Status"))
                    for a in data.get("Answer") or []:
                        t, v = a.get("type"), str(a.get("data") or "").strip()
                        if t == 5 and v and v not in res.cnames:
                            res.cnames.append(v.rstrip("."))
                        elif t in (1, 28) and v:
                            try:
                                ipaddress.ip_address(v)
                                res.ips.append(v)
                            except ValueError:
                                pass
                res.ips = _sort_ips(res.ips)
                if not res.ips:
                    res.inexistente = True
                    res.erro = "não existe no DNS público" if 3 in statuses else "sem endereços no DNS público"
                return res
            except (httpx.HTTPError, ValueError) as exc:
                last = f"{urlhost(url)}: {str(exc)[:120]}"
        return Resolution(erro=f"DNS público indisponível ({last})")
    finally:
        if own:
            c.close()


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_unspecified

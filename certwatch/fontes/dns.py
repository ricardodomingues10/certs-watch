"""Fonte: DNS interno (o resolvedor do servidor) e DNS público (DNS-over-HTTPS).

- interno: a resolução normal do sistema (getaddrinfo), a que o Atalaia sempre usou para ligar aos servidores;
- público: DNS-over-HTTPS (JSON) num resolvedor público (Cloudflare, e o da Google se o primeiro falhar). É o que a
  internet vê: com DNS diferente dentro e fora, o mesmo nome pode apontar para outro sítio. Usado em Sites públicos.
Também os registos CAA de cada domínio (que autoridades podem emitir certificados para ele).
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field

import httpx

FONTE = {
    "id": "dns", "nome": "DNS (interno e público)", "tipo": "DNS e DNS-over-HTTPS", "estado": "em uso",
    "para": "Resolver os nomes como os vê este servidor (DNS interno) e como os vê a internet (DNS público), "
            "para comparar o certificado servido dentro e fora.",
    "config": ["resolvedor DNS do servidor", "CERTWATCH_PUBLIC_DNS (resolvedores DNS-over-HTTPS)", "HTTPS_PROXY (se houver)"],
    "chamadas": [
        {"metodo": "DNS", "endereco": "A/AAAA {nome} (resolvedor do servidor)", "para": "para onde o nome aponta dentro da rede", "acesso": "leitura", "estado": "em uso", "onde": "fontes/dns.py · resolve_internal"},
        {"metodo": "GET", "endereco": "https://cloudflare-dns.com/dns-query?name={nome}&type=A|AAAA", "para": "para onde o nome aponta na internet (DNS público)", "acesso": "leitura", "estado": "em uso", "onde": "fontes/dns.py · resolve_public"},
        {"metodo": "GET", "endereco": "https://dns.google/resolve?name={nome}&type=A|AAAA", "para": "o mesmo, se o primeiro resolvedor falhar", "acesso": "leitura", "estado": "em uso", "onde": "fontes/dns.py · resolve_public"},
        {"metodo": "GET", "endereco": "DNS-over-HTTPS CAA {domínio} (e cada nível acima)", "para": "que autoridades podem emitir para o domínio", "acesso": "leitura", "estado": "em uso", "onde": "fontes/dns.py · caa_lookup"},
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


# ------------------------------------------------------------------ CAA (RFC 8659): que CAs podem emitir para o domínio
@dataclass
class CaaResult:
    zona: str = ""                                   # nome onde os registos foram encontrados ("" = não há em lado nenhum)
    registos: list = field(default_factory=list)     # [(flags, tag, valor)]
    erro: str = ""
    resolvedor: str = ""


def _parse_caa(data: str) -> tuple[int, str, str] | None:
    """Uma linha de resposta: `0 issue "ca.exemplo"` ou o formato genérico `\\# <n> <hex>` (RFC 3597)."""
    data = (data or "").strip()
    if data.startswith("\\#"):
        try:
            raw = bytes.fromhex("".join(data.split()[2:]))
            n = raw[1]
            return raw[0], raw[2:2 + n].decode("ascii").lower(), raw[2 + n:].decode("utf-8", "replace").strip()
        except (ValueError, IndexError):
            return None
    parts = data.split(None, 2)
    if len(parts) < 3 or not parts[0].isdigit():
        return None
    return int(parts[0]), parts[1].lower(), parts[2].strip().strip('"').strip()


def caa_lookup(name: str, urls: list[str], client: httpx.Client | None = None, timeout: float = 8.0,
               cache: dict | None = None) -> CaaResult:
    """Procura os registos CAA do nome e, se não houver, do domínio acima, até ao domínio de dois níveis. Vale o
    primeiro nome que tiver registos. "Não há" (registos vazios, sem erro) é diferente de "não se sabe" (erro)."""
    if not urls:
        return CaaResult(erro="sem resolvedor público configurado (CERTWATCH_PUBLIC_DNS)")
    labels = [x for x in name.strip().lower().rstrip(".").lstrip("*").lstrip(".").split(".") if x]
    if len(labels) < 2:
        return CaaResult(erro="não é um nome de domínio")
    cache = cache if cache is not None else {}
    own = client is None
    c = client or httpx.Client(timeout=timeout, trust_env=True, follow_redirects=False)
    try:
        for i in range(0, len(labels) - 1):
            zone = ".".join(labels[i:])
            if zone not in cache:
                cache[zone] = _caa_at(zone, urls, c)
            recs = cache[zone]
            if isinstance(recs, str):
                return CaaResult(erro=recs)
            if recs:
                return CaaResult(zona=zone, registos=list(recs), resolvedor=urlhost(urls[0]))
        return CaaResult(resolvedor=urlhost(urls[0]))
    finally:
        if own:
            c.close()


def _caa_at(zone: str, urls: list[str], c: httpx.Client):
    """Registos CAA exatamente neste nome: lista (pode ser vazia) ou uma frase de erro."""
    last = ""
    for url in urls:
        try:
            r = c.get(url, params={"name": zone, "type": "CAA"}, headers={"Accept": "application/dns-json"})
            if r.status_code != 200:
                raise httpx.HTTPStatusError(f"HTTP {r.status_code}", request=r.request, response=r)
            data = r.json()
            status = data.get("Status")
            if status not in (0, 3):                 # 2 = SERVFAIL, 5 = REFUSED…: não se sabe
                raise ValueError(f"o DNS respondeu com erro {status}")
            out = []
            for a in data.get("Answer") or []:
                if a.get("type") == 257:
                    rec = _parse_caa(str(a.get("data") or ""))
                    if rec:
                        out.append(rec)
            return out
        except (httpx.HTTPError, ValueError) as exc:
            last = f"{urlhost(url)}: {str(exc)[:120]}"
    return f"DNS público indisponível ({last})"


def caa_evaluate(registos: list, issuer_ids: set[str], wildcard: bool) -> tuple[str, str]:
    """(veredicto, frase). Veredictos: autorizada | nao_autorizada | sem_restricao | ca_desconhecida.
    Para um certificado wildcard manda o `issuewild`, se existir; senão, e para os outros, manda o `issue`."""
    known = {"issue", "issuewild", "iodef", "issuemail", "issuevmc", "contactemail", "contactphone"}
    critical = [t for f, t, _ in registos if f & 128 and t not in known]
    if critical:
        return "nao_autorizada", f"o domínio tem uma regra obrigatória que não se conhece ({critical[0]}): nenhuma CA devia emitir"
    issue = [v for _, t, v in registos if t == "issue"]
    wild = [v for _, t, v in registos if t == "issuewild"]
    relevant = wild if (wildcard and wild) else issue
    if not relevant:
        return "sem_restricao", "o domínio tem registos CAA mas nenhum limita quem pode emitir este tipo de certificado"
    allowed = sorted({v.split(";", 1)[0].strip().lower().rstrip(".") for v in relevant} - {""})
    if not allowed:
        return "nao_autorizada", "o domínio proíbe a emissão por qualquer CA"
    if not issuer_ids:
        return "ca_desconhecida", "o domínio só autoriza " + ", ".join(allowed) + "; não se sabe o identificador CAA desta CA"
    if set(allowed) & {i.lower() for i in issuer_ids}:
        return "autorizada", "a CA deste certificado está autorizada (" + ", ".join(sorted(set(allowed) & issuer_ids)) + ")"
    return "nao_autorizada", "o domínio só autoriza " + ", ".join(allowed)

"""HSTS (Strict-Transport-Security, RFC 6797): o site diz ao browser para nunca mais o abrir sem cifra?

Sem este cabeçalho, quem escreve o endereço sem "https://" faz o primeiro pedido em claro, e alguém na mesma rede
(um wifi público) pode intercetá-lo e manter a pessoa numa cópia sem cifra do site. Com o cabeçalho, o browser
lembra-se durante `max-age` segundos de que aquele site só se abre por HTTPS, e recusa avisos de certificado.

Aqui faz-se um pedido GET à raiz do site por HTTPS e lê-se o cabeçalho da primeira resposta (mesmo que seja um
redirecionamento: não se segue). O certificado não é validado neste pedido, porque isso já é outro teste.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import httpx

FONTE = {
    "id": "hsts", "nome": "Cabeçalhos dos sites (HSTS)", "tipo": "HTTPS", "estado": "em uso",
    "para": "Ver se cada site web obriga o browser a usar sempre HTTPS (Strict-Transport-Security).",
    "config": ["CERTWATCH_HSTS", "CERTWATCH_HSTS_MIN_AGE", "CERTWATCH_HSTS_PORTS"],
    "chamadas": [
        {"metodo": "GET", "endereco": "https://{servidor}:{porta}/", "para": "ler o cabeçalho Strict-Transport-Security da primeira resposta", "acesso": "leitura", "estado": "em uso", "onde": "fontes/hsts.py · fetch"},
    ],
}


def estado(settings) -> tuple[bool, str]:
    on = getattr(settings, "hsts", True)
    ports = ", ".join(str(p) for p in getattr(settings, "hsts_ports", (443,)))
    return on, f"portas web: {ports}" if on else "desligado (CERTWATCH_HSTS=false)"


@dataclass
class Hsts:
    max_age: int | None = None
    include_subdomains: bool = False
    preload: bool = False
    valido: bool = False
    erro: str = ""


@dataclass
class HstsFetch:
    status: str                       # presente | ausente | invalido | nao_http | erro
    cabecalho: str = ""
    http_status: int | None = None
    erro: str = ""
    hsts: Hsts = field(default_factory=Hsts)

    def as_dict(self) -> dict:
        d = {"cabecalho": self.cabecalho[:300], "http_status": self.http_status, "erro": self.erro,
             "max_age": self.hsts.max_age, "include_subdomains": self.hsts.include_subdomains, "preload": self.hsts.preload}
        return {k: v for k, v in d.items() if v not in (None, "", False)}


def parse(header: str) -> Hsts:
    """Lê o cabeçalho como um browser: nomes sem distinção de maiúsculas, max-age obrigatório, diretiva repetida
    invalida tudo, diretivas desconhecidas ignoram-se."""
    out = Hsts()
    seen: set[str] = set()
    for part in (header or "").split(";"):
        part = part.strip()
        if not part:
            continue
        name, _, value = part.partition("=")
        name, value = name.strip().lower(), value.strip().strip('"').strip()
        if name in seen:
            return Hsts(erro=f"diretiva repetida: {name}")
        seen.add(name)
        if name == "max-age":
            if not value.isdigit():
                return Hsts(include_subdomains="includesubdomains" in seen, erro="max-age não é um número")
            out.max_age = int(value)
        elif name == "includesubdomains":
            out.include_subdomains = True
        elif name == "preload":
            out.preload = True
    if out.max_age is None:
        out.erro = "falta o max-age"
        return out
    out.valido = True
    return out


def fetch(host: str, port: int, client: httpx.Client | None = None, timeout: float = 8.0) -> HstsFetch:
    own = client is None
    c = client or new_client(timeout)
    target = f"[{host}]" if ":" in host else host
    try:
        r = c.get(f"https://{target}:{port}/", headers={"Accept": "text/html,*/*;q=0.5"}, follow_redirects=False)
        headers = r.headers.get_list("strict-transport-security")
        if not headers:
            return HstsFetch("ausente", http_status=r.status_code)
        first = headers[0]                                   # vários cabeçalhos: o browser usa o primeiro
        h = parse(first)
        return HstsFetch("presente" if h.valido else "invalido", cabecalho=first, http_status=r.status_code, erro=h.erro, hsts=h)
    except (httpx.RemoteProtocolError, httpx.LocalProtocolError, httpx.DecodingError) as exc:
        return HstsFetch("nao_http", erro=str(exc)[:160])       # responde TLS mas não fala HTTP (LDAPS, base de dados…)
    except httpx.HTTPError as exc:
        return HstsFetch("erro", erro=f"{type(exc).__name__}: {str(exc)[:120]}")
    finally:
        if own:
            c.close()


def new_client(timeout: float = 8.0) -> httpx.Client:
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE                     # o certificado é avaliado pelos outros testes
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return httpx.Client(verify=ctx, timeout=timeout, follow_redirects=False, trust_env=False,
                        headers={"User-Agent": "AtalaiaCert-hsts/1"})

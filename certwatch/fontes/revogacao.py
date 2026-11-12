"""Revogação: o certificado ainda vale, ou a CA anulou-o antes do fim do prazo?

Um certificado revogado continua com as datas certas e a cadeia certa: só a CA sabe que já não vale (chave roubada,
certificado substituído, serviço fechado). Há duas formas de lhe perguntar, e os endereços vêm escritos no próprio
certificado:

  1) OCSP: pergunta-se à CA por este certificado e ela responde bom, revogado ou desconhecido;
  2) CRL: descarrega-se a lista de todos os revogados dessa CA e procura-se o número de série.

Tenta-se o OCSP primeiro e a CRL quando ele não existe ou não responde (o Let's Encrypt, por exemplo, só tem CRL).

Nada do que vem da rede é aceite sem prova:
  - a resposta OCSP tem de vir assinada pelo emissor, ou por um respondedor que o emissor autorizou para isso
    (certificado emitido por ele, com o uso "OCSP Signing", dentro do prazo);
  - a CRL tem de vir assinada pelo emissor;
  - ambas têm de estar dentro do seu prazo (uma resposta "bom" de há um mês não prova nada) e ser sobre este certificado.
Quem chama só deve pedir a verificação para cadeias já confiáveis: os endereços vêm do certificado, e um servidor
qualquer podia escrever lá o que quisesse. Só se contactam endereços http(s), sem seguir redirecionamentos.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID

FONTE = {
    "id": "revogacao", "nome": "Revogação (OCSP e CRL das CAs)", "tipo": "HTTP", "estado": "em uso",
    "para": "Perguntar à CA de cada certificado servido se ele foi revogado antes do fim do prazo.",
    "config": ["CERTWATCH_REVOCATION", "CERTWATCH_CRL_MAX_MB"],
    "chamadas": [
        {"metodo": "POST", "endereco": "{endereço OCSP escrito no certificado}", "para": "estado deste certificado: bom, revogado ou desconhecido", "acesso": "leitura", "estado": "em uso", "onde": "fontes/revogacao.py · check_ocsp"},
        {"metodo": "GET", "endereco": "{endereço da CRL escrito no certificado}", "para": "lista de revogados da CA, quando não há OCSP ou ele não responde", "acesso": "leitura", "estado": "em uso", "onde": "fontes/revogacao.py · check_crl"},
    ],
}

SKEW = timedelta(minutes=10)                 # relógios desacertados
NO_NEXT_UPDATE_MAX = timedelta(days=7)       # resposta sem "válida até": aceita-se durante uma semana
MAX_OCSP_BYTES = 128 * 1024
REASONS = {
    "unspecified": "sem motivo indicado", "keyCompromise": "chave comprometida", "cACompromise": "CA comprometida",
    "affiliationChanged": "mudança de entidade", "superseded": "substituído por outro",
    "cessationOfOperation": "serviço terminado", "certificateHold": "suspenso", "privilegeWithdrawn": "privilégio retirado",
    "aACompromise": "autoridade de atributos comprometida", "removeFromCRL": "retirado da lista",
}


def estado(settings) -> tuple[bool, str]:
    on = getattr(settings, "revocation", True)
    return on, "OCSP e CRL, só para cadeias confiáveis" if on else "desligada (CERTWATCH_REVOCATION=false)"


@dataclass
class Revocation:
    status: str                    # bom | revogado | desconhecido | sem_info | erro
    metodo: str = ""               # ocsp | crl
    detalhe: str = ""
    url: str = ""
    revogado_em: str | None = None
    motivo: str = ""
    produzido_em: str | None = None
    valido_ate: str | None = None

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v not in (None, "")}


class _Refused(Exception):
    """A resposta existe mas não pode ser aceite (assinatura, prazo, outro certificado, formato)."""


def _iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).isoformat() if dt else None


def _reason(flag) -> str:
    return REASONS.get(getattr(flag, "value", ""), "") if flag is not None else ""


def safe_url(url: str) -> bool:
    """Só http(s), com servidor e sem utilizador:palavra-passe. ldap://, file:// e afins nunca se contactam."""
    try:
        u = urlsplit(url)
    except ValueError:
        return False
    return u.scheme in ("http", "https") and bool(u.hostname) and u.username is None and u.password is None


def pointers(cert: x509.Certificate) -> tuple[list[str], list[str], int]:
    """(endereços OCSP, endereços de CRL, quantos endereços foram postos de parte por não serem http)."""
    ocsp_urls, crl_urls, skipped = [], [], 0
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        for d in aia:
            if d.access_method == AuthorityInformationAccessOID.OCSP and isinstance(d.access_location, x509.UniformResourceIdentifier):
                if safe_url(d.access_location.value):
                    ocsp_urls.append(d.access_location.value)
                else:
                    skipped += 1
    except x509.ExtensionNotFound:
        pass
    try:
        cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        for dp in cdp:
            for n in dp.full_name or []:
                if isinstance(n, x509.UniformResourceIdentifier):
                    if safe_url(n.value):
                        crl_urls.append(n.value)
                    else:
                        skipped += 1
    except x509.ExtensionNotFound:
        pass
    return ocsp_urls, crl_urls, skipped


def _verify(pk, signature: bytes, data: bytes, hash_alg) -> None:
    if isinstance(pk, rsa.RSAPublicKey):
        pk.verify(signature, data, padding.PKCS1v15(), hash_alg)
    elif isinstance(pk, ec.EllipticCurvePublicKey):
        pk.verify(signature, data, ec.ECDSA(hash_alg))
    elif isinstance(pk, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        pk.verify(signature, data)
    else:
        raise InvalidSignature("tipo de chave não suportado")


def _signed_by(resp, pk) -> bool:
    try:
        _verify(pk, resp.signature, resp.tbs_response_bytes, resp.signature_hash_algorithm)
        return True
    except (InvalidSignature, UnsupportedAlgorithm, ValueError, TypeError):
        return False


def _authorized_responder(c: x509.Certificate, issuer: x509.Certificate, now: datetime) -> bool:
    """Um respondedor delegado: emitido diretamente pelo emissor, com o uso OCSP Signing, dentro do prazo."""
    try:
        c.verify_directly_issued_by(issuer)
        eku = c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except (InvalidSignature, ValueError, TypeError, x509.ExtensionNotFound, UnsupportedAlgorithm):
        return False
    return ExtendedKeyUsageOID.OCSP_SIGNING in eku and c.not_valid_before_utc - SKEW <= now <= c.not_valid_after_utc + SKEW


def _check_window(this_update: datetime | None, next_update: datetime | None, now: datetime, what: str) -> None:
    if this_update is None or this_update - SKEW > now:
        raise _Refused(f"{what} com data no futuro")
    limit = next_update if next_update is not None else this_update + NO_NEXT_UPDATE_MAX
    if limit + SKEW < now:
        raise _Refused(f"{what} fora do prazo (valia até {limit.date().isoformat()})")


def check_ocsp(cert: x509.Certificate, issuer: x509.Certificate, url: str, client: httpx.Client, now: datetime) -> Revocation:
    req = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1()).build()   # SHA-1 aqui só identifica a CA
    r = client.post(url, content=req.public_bytes(serialization.Encoding.DER),
                    headers={"Content-Type": "application/ocsp-request", "Accept": "application/ocsp-response"},
                    follow_redirects=False)
    if r.status_code != 200:
        raise _Refused(f"HTTP {r.status_code}")
    if len(r.content) > MAX_OCSP_BYTES:
        raise _Refused("resposta grande demais")
    try:
        resp = ocsp.load_der_ocsp_response(r.content)
    except ValueError:
        raise _Refused("a resposta não é OCSP") from None
    if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise _Refused(f"o respondedor recusou ({resp.response_status.name.lower()})")
    try:
        if resp.serial_number != cert.serial_number or resp.issuer_key_hash != _as_response_hash(req, resp, cert, issuer):
            raise _Refused("a resposta é sobre outro certificado")
        signers = [issuer.public_key()] + [c.public_key() for c in resp.certificates if _authorized_responder(c, issuer, now)]
        if not any(_signed_by(resp, pk) for pk in signers):
            raise _Refused("assinatura da resposta não é do emissor nem de um respondedor autorizado por ele")
        _check_window(resp.this_update_utc, resp.next_update_utc, now, "resposta")
        base = dict(metodo="ocsp", url=url, produzido_em=_iso(resp.this_update_utc), valido_ate=_iso(resp.next_update_utc))
        st = resp.certificate_status
        if st == ocsp.OCSPCertStatus.GOOD:
            return Revocation("bom", detalhe="a CA confirma que não foi revogado", **base)
        if st == ocsp.OCSPCertStatus.REVOKED:
            return Revocation("revogado", detalhe="a CA diz que foi revogado", revogado_em=_iso(resp.revocation_time_utc),
                              motivo=_reason(resp.revocation_reason), **base)
        return Revocation("desconhecido", detalhe="a CA diz que não conhece este certificado", **base)
    except ValueError as exc:                      # resposta com várias entradas ou campos em falta
        raise _Refused(f"resposta OCSP inesperada ({str(exc)[:80]})") from None


def _as_response_hash(req, resp, cert, issuer) -> bytes:
    """O hash da chave do emissor, no algoritmo que a resposta usou (pode não ser o do pedido)."""
    if isinstance(resp.hash_algorithm, hashes.SHA1):
        return req.issuer_key_hash
    alt = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, resp.hash_algorithm).build()
    return alt.issuer_key_hash


def _download(client: httpx.Client, url: str, max_bytes: int) -> bytes:
    with client.stream("GET", url, follow_redirects=False) as r:
        if r.status_code != 200:
            raise _Refused(f"HTTP {r.status_code}")
        buf = bytearray()
        for chunk in r.iter_bytes():
            buf += chunk
            if len(buf) > max_bytes:
                raise _Refused(f"lista grande demais (mais de {max_bytes // 1024} KB)")
        return bytes(buf)


def _load_crl(url: str, issuer: x509.Certificate, client: httpx.Client, now: datetime, max_bytes: int):
    raw = _download(client, url, max_bytes)
    try:
        crl = x509.load_pem_x509_crl(raw) if raw.lstrip().startswith(b"-----BEGIN") else x509.load_der_x509_crl(raw)
    except ValueError:
        raise _Refused("o que veio não é uma CRL") from None
    try:
        good = crl.issuer == issuer.subject and crl.is_signature_valid(issuer.public_key())
    except (InvalidSignature, UnsupportedAlgorithm, ValueError, TypeError):
        good = False
    if not good:
        raise _Refused("assinatura da lista não é do emissor")
    _check_window(crl.last_update_utc, crl.next_update_utc, now, "lista")
    return crl


def check_crl(cert: x509.Certificate, issuer: x509.Certificate, url: str, client: httpx.Client, now: datetime,
              cache: dict | None = None, max_bytes: int = 20_000_000) -> Revocation:
    cache = cache if cache is not None else {}
    key = (url, issuer.fingerprint(hashes.SHA256()))
    if key not in cache:                           # a mesma lista serve todos os certificados dessa CA nesta execução
        try:
            cache[key] = _load_crl(url, issuer, client, now, max_bytes)
        except (_Refused, httpx.HTTPError) as exc:
            cache[key] = exc
    crl = cache[key]
    if isinstance(crl, Exception):
        raise crl
    base = dict(metodo="crl", url=url, produzido_em=_iso(crl.last_update_utc), valido_ate=_iso(crl.next_update_utc))
    hit = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    if hit is None:
        return Revocation("bom", detalhe="não está na lista de revogados da CA", **base)
    try:
        reason = _reason(hit.extensions.get_extension_for_class(x509.CRLReason).value.reason)
    except x509.ExtensionNotFound:
        reason = ""
    return Revocation("revogado", detalhe="está na lista de revogados da CA", revogado_em=_iso(hit.revocation_date_utc),
                      motivo=reason, **base)


def _why(exc: Exception) -> str:
    if isinstance(exc, _Refused):
        return str(exc)
    if isinstance(exc, httpx.TimeoutException):
        return "sem resposta a tempo"
    return f"sem ligação ({type(exc).__name__})"


def check(cert_pem: str, issuer_pem: str, client: httpx.Client, now: datetime | None = None, cache: dict | None = None,
          max_crl_bytes: int = 20_000_000) -> Revocation:
    """Estado de revogação de um certificado. Nunca devolve "bom" sem uma resposta assinada e dentro do prazo."""
    now = now or datetime.now(timezone.utc)
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        issuer = x509.load_pem_x509_certificate(issuer_pem.encode()) if issuer_pem else None
    except ValueError:
        return Revocation("erro", detalhe="certificado ilegível")
    if issuer is None:
        return Revocation("erro", detalhe="falta o certificado do emissor (o servidor não envia a cadeia completa)")
    try:
        cert.verify_directly_issued_by(issuer)
    except (InvalidSignature, ValueError, TypeError, UnsupportedAlgorithm):
        return Revocation("erro", detalhe="o certificado do emissor na cadeia não é o que assinou este certificado")
    ocsp_urls, crl_urls, skipped = pointers(cert)
    if not ocsp_urls and not crl_urls:
        extra = f" (tem {skipped} endereço(s) que não são http, por exemplo ldap, e esses não se consultam)" if skipped else ""
        return Revocation("sem_info", detalhe="o certificado não indica onde confirmar a revogação por http" + extra)
    problems, unknown = [], None
    for url in ocsp_urls:
        try:
            res = check_ocsp(cert, issuer, url, client, now)
        except (_Refused, httpx.HTTPError) as exc:
            problems.append(f"OCSP {urlsplit(url).hostname}: {_why(exc)}")
            continue
        if res.status in ("bom", "revogado"):
            return res
        unknown = res
    for url in crl_urls:
        try:
            return check_crl(cert, issuer, url, client, now, cache, max_crl_bytes)
        except (_Refused, httpx.HTTPError) as exc:
            problems.append(f"CRL {urlsplit(url).hostname}: {_why(exc)}")
    if unknown is not None:
        return unknown
    return Revocation("erro", detalhe="; ".join(problems)[:500])


def new_client(timeout: float = 10.0) -> httpx.Client:
    return httpx.Client(timeout=timeout, follow_redirects=False, trust_env=True,
                        headers={"User-Agent": "AtalaiaCert-revogacao/1"})

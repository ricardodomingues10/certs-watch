"""Proteções à volta do certificado: revogação (OCSP/CRL), CAA do domínio, HSTS e chaves reutilizadas.

`run` vai à rede (com limites) e guarda um resultado por certificado, por nome e por servidor em `posture_results`.
`Context` junta esses resultados ao que já se sabe de cada servidor e entrega-os aos testes (checks.py), que não
tocam na rede nem na base de dados. A reutilização de chaves não precisa de rede: sai dos certificados já vistos.

Regras para não criar ruído nem falsos descansos:
  - o que não se conseguiu verificar nunca aparece como "passou";
  - um resultado com mais de CERTWATCH_POSTURE_MAX_AGE_DAYS dias deixa de contar (fica "não testado");
  - a revogação só se pergunta para cadeias já confiáveis (os endereços vêm escritos no certificado).
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .classify import scope_of
from .normalize import classify
from .config import Settings
from .db import as_utc, utcnow
from .models import Certificate, PostureResult
from .normalize import norm_issuer

log = logging.getLogger(__name__)

# Identificadores CAA das CAs públicas mais comuns: (texto no emissor, em minúsculas) → domínios que a CA aceita
# num registo `issue`. Acrescenta-se com CERTWATCH_CAA_ISSUERS ("texto=dominio1|dominio2; outro=dominio").
CAA_ISSUERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (r"let'?s encrypt|isrg", ("letsencrypt.org",)),
    (r"digicert|geotrust|rapidssl|thawte|encryption everywhere|quovadis", ("digicert.com", "digicert.ne.jp", "geotrust.com", "rapidssl.com", "thawte.com", "symantec.com", "quovadisglobal.com")),
    (r"sectigo|comodo|usertrust|zerossl|gandi|trust-?provider", ("sectigo.com", "comodoca.com", "comodo.com", "usertrust.com", "trust-provider.com")),
    (r"globalsign|alphassl", ("globalsign.com",)),
    (r"google trust services|\bgts\b", ("pki.goog",)),
    (r"amazon", ("amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com", "aws.amazon.com")),
    (r"go ?daddy|starfield", ("godaddy.com", "starfieldtech.com")),
    (r"entrust|affirmtrust", ("entrust.net", "affirmtrust.com")),
    (r"microsoft", ("microsoft.com",)),
    (r"ssl\.com|ssl corp", ("ssl.com",)),
    (r"buypass", ("buypass.com",)),
    (r"certum|asseco", ("certum.pl", "certum.eu")),
    (r"harica|hellenic academic", ("harica.gr",)),
    (r"actalis", ("actalis.it",)),
    (r"identrust", ("identrust.com",)),
    (r"swisssign", ("swisssign.com",)),
    (r"multicert", ("multicert.com",)),
    (r"digitalsign", ("digitalsign.pt",)),
    (r"cloudflare", ("cloudflare.com", "digicert.com", "letsencrypt.org", "pki.goog", "ssl.com", "comodoca.com")),
)


def caa_ids(issuer_dn: str, extra: tuple = ()) -> set[str]:
    """Os identificadores CAA da CA que emitiu, a partir do nome do emissor. Vazio = CA que não se conhece."""
    text = (issuer_dn or "").lower()
    out: set[str] = set()
    for needle, ids in extra:
        if needle and needle.lower() in text:
            out.update(i.lower() for i in ids)
    for pattern, ids in CAA_ISSUERS:
        if re.search(pattern, text):
            out.update(ids)
    return out


def _names(cert) -> set[str]:
    return {n.lower() for n in (cert.sans_dns or []) if n} | ({cert.subject_cn.lower()} if cert.subject_cn else set())


def _covers(pattern: str, name: str) -> bool:
    if pattern == name:
        return True
    return pattern.startswith("*.") and name.count(".") == pattern.count(".") and name.endswith(pattern[1:])


def names_overlap(a: set[str], b: set[str]) -> bool:
    """Dois certificados são do mesmo serviço se partilham um nome (contando com wildcards)."""
    return any(_covers(x, y) or _covers(y, x) for x in a for y in b)


def matched_by_wildcard(host: str, cert) -> bool:
    names = _names(cert)
    return host.lower() not in names and any(n.startswith("*.") and _covers(n, host.lower()) for n in names)


# ------------------------------------------------------------------ ler o que está guardado e entregar aos testes
@dataclass
class Context:
    settings: Settings
    now: datetime
    results: dict = field(default_factory=dict)          # (kind, key) -> PostureResult
    reuse: dict = field(default_factory=dict)            # sha256 da folha -> {"partilhada": [...], "anterior": {...}}
    ran: bool = False                                    # já houve alguma verificação?

    def _fresh(self, kind: str, key: str):
        r = self.results.get((kind, key))
        if r is None:
            return None
        if self.now - as_utc(r.checked_at) > timedelta(days=self.settings.posture_max_age_days):
            return None
        return {"status": r.status, "em": as_utc(r.checked_at), **(r.data or {})}

    def for_ep(self, ep, sr, leaf) -> dict:
        """O que os testes precisam de saber sobre este servidor (só dados, nada de rede)."""
        s = self.settings
        out = {"ran": self.ran, "revogacao": None, "caa": None, "hsts": None, "chave": None,
               "revogacao_on": s.revocation, "caa_on": s.caa, "hsts_on": s.hsts,
               "web": ep.port in s.hsts_ports, "externo": False, "ca_interna": False, "wildcard": False, "caa_ids": set()}
        if leaf is None:
            return out
        issuer_norm = norm_issuer(leaf.issuer_cn)
        kind = classify(ep.host)
        out["externo"] = kind != "ip" and scope_of(ep.host, kind, s, issuer_norm=issuer_norm,
                                                   resolved_ip=sr.resolved_ip if sr else "") == "externo"
        out["ca_interna"] = bool(issuer_norm and any(p in issuer_norm for p in s.internal_issuer_patterns)) or \
            bool(leaf.self_issued)
        out["wildcard"] = matched_by_wildcard(ep.host, leaf)
        out["caa_ids"] = caa_ids(leaf.issuer_dn, s.caa_issuers)
        out["revogacao"] = self._fresh("revogacao", leaf.sha256)
        out["caa"] = self._fresh("caa", ep.host.lower())
        out["hsts"] = self._fresh("hsts", str(ep.id))
        out["chave"] = self.reuse.get(leaf.sha256, {})
        return out


def key_reuse(session: Session, snap) -> dict:
    """Para cada certificado servido agora: a sua chave pública aparece noutro certificado?

    - "partilhada": outro certificado servido agora, de um serviço diferente (nenhum nome em comum), com a mesma chave.
      Quem obtiver a chave de um dos servidores consegue fazer-se passar pelo outro.
    - "anterior": um certificado mais antigo do mesmo serviço com a mesma chave: foi renovado sem gerar chave nova, por
      isso uma cópia antiga da chave (uma cópia de segurança, um servidor abatido) continua a servir.
    O mesmo certificado instalado em vários servidores não conta: é um certificado, não dois.
    """
    served: dict[str, list] = defaultdict(list)          # sha256 -> ["host:porta"]
    leaves: dict[str, Certificate] = {}
    for ep in snap.endpoints:
        sr = snap.scan_for(ep)
        leaf = snap.leaf_for(sr)
        if not ep.enabled or sr is None or sr.status != "ok" or leaf is None or leaf.is_ca or not leaf.spki_sha256:
            continue
        served[leaf.sha256].append(f"{ep.host}:{ep.port}")
        leaves[leaf.sha256] = leaf
    if not leaves:
        return {}
    by_key: dict[str, list[Certificate]] = defaultdict(list)
    spkis = {c.spki_sha256 for c in leaves.values()}
    for c in session.scalars(select(Certificate).where(Certificate.spki_sha256.in_(spkis), Certificate.is_ca.is_(False))):
        by_key[c.spki_sha256].append(c)
    out: dict[str, dict] = {}
    for sha, leaf in leaves.items():
        mine, shared, previous = _names(leaf), [], None
        for other in by_key.get(leaf.spki_sha256, []):
            if other.sha256 == sha:
                continue
            same_service = names_overlap(mine, _names(other))
            if not same_service and other.sha256 in served:
                shared.append({"cn": other.subject_cn or (other.sans_dns or ["?"])[0], "onde": sorted(served[other.sha256])[:5],
                               "sha256": other.sha256})
            elif same_service and other.not_before and leaf.not_before and as_utc(other.not_before) < as_utc(leaf.not_before):
                if previous is None or as_utc(other.not_before) > as_utc(previous.not_before):
                    previous = other
        out[sha] = {"partilhada": sorted(shared, key=lambda x: x["cn"]),
                    "anterior": {"sha256": previous.sha256, "de": as_utc(previous.not_before).date().isoformat(),
                                 "ate": as_utc(previous.not_after).date().isoformat() if previous.not_after else ""} if previous else None}
    return out


def load(session: Session, settings: Settings, snap, now: datetime | None = None) -> Context:
    rows = list(session.scalars(select(PostureResult)))
    return Context(settings=settings, now=now or utcnow(), results={(r.kind, r.key): r for r in rows},
                   reuse=key_reuse(session, snap), ran=bool(rows))


# ------------------------------------------------------------------ ir à rede e guardar
def _save(session: Session, kind: str, key: str, status: str, data: dict, now: datetime) -> None:
    row = session.get(PostureResult, (kind, key[:255]))
    if row is None:
        row = PostureResult(kind=kind, key=key[:255])
        session.add(row)
    row.status, row.data, row.checked_at = status[:24], data, now


def _issuer_pem(session: Session, sr, leaf) -> str:
    """O certificado do emissor: o seguinte na cadeia que o servidor enviou ou, se não veio, um já visto com a
    chave que o certificado indica (Authority Key Identifier)."""
    chain = sr.chain or []
    if len(chain) > 1 and chain[1].get("sha256"):
        c = session.get(Certificate, chain[1]["sha256"])
        if c is not None and c.pem:
            return c.pem
    if leaf.aki:
        c = session.scalars(select(Certificate).where(Certificate.ski == leaf.aki, Certificate.is_ca.is_(True))).first()
        if c is not None and c.pem:
            return c.pem
    return ""


def run(session: Session, settings: Settings, snap=None, clients: dict | None = None) -> dict:
    """Corre as três verificações de rede para tudo o que está a ser servido e guarda os resultados."""
    from .evaluator import load_snapshot
    from .fontes import dns as fdns
    from .fontes import hsts as fhsts
    from .fontes import revogacao as frev
    snap = snap or load_snapshot(session)
    clients = clients or {}
    now = utcnow()
    out: dict = {}
    live = []
    for ep in snap.endpoints:
        sr = snap.scan_for(ep)
        leaf = snap.leaf_for(sr)
        if ep.enabled and sr is not None and sr.status == "ok" and leaf is not None:
            live.append((ep, sr, leaf))

    # 1) Revogação: uma pergunta por certificado (o mesmo certificado em dez servidores pergunta-se uma vez)
    if settings.revocation:
        todo: dict[str, tuple] = {}
        counts: dict[str, int] = defaultdict(int)
        for ep, sr, leaf in live:
            if leaf.sha256 in todo:
                continue
            if leaf.self_issued:
                todo[leaf.sha256] = ("autoassinado", None)
            elif as_utc(leaf.not_after) <= now:
                todo[leaf.sha256] = ("expirado", None)             # já não vale; as CAs até o retiram das listas
            elif not sr.verify_ok:
                todo[leaf.sha256] = ("nao_confiavel", None)        # cadeia sem confiança: os endereços não merecem crédito
            else:
                todo[leaf.sha256] = ("", (leaf.pem, _issuer_pem(session, sr, leaf)))
        work = {sha: args for sha, (st, args) in todo.items() if not st}
        client = clients.get("revogacao") or frev.new_client(settings.scan_timeout + 4)
        cache: dict = {}
        try:
            with ThreadPoolExecutor(max_workers=max(1, min(8, settings.scan_workers))) as pool:
                futs = {sha: pool.submit(frev.check, a[0], a[1], client, now, cache, settings.crl_max_mb * 1024 * 1024)
                        for sha, a in work.items()}
                done = {}
                for sha, f in futs.items():
                    try:
                        done[sha] = f.result()
                    except Exception as exc:                        # uma resposta estranha não pára as outras
                        log.warning("Revogação de %s falhou: %s", sha[:12], exc)
                        done[sha] = frev.Revocation("erro", detalhe=f"erro inesperado ({type(exc).__name__})")
        finally:
            if "revogacao" not in clients:
                client.close()
        for sha, (st, _) in todo.items():
            if st:
                _save(session, "revogacao", sha, st, {}, now)
                counts[st] += 1
            else:
                r = done[sha]
                _save(session, "revogacao", sha, r.status, {k: v for k, v in r.as_dict().items() if k != "status"}, now)
                counts[r.status] += 1
        out["revogacao"] = dict(counts)

    # 2) CAA: uma pergunta por nome externo (os domínios acima ficam em memória para os nomes seguintes)
    if settings.caa:
        ctx = Context(settings=settings, now=now)
        hosts = sorted({ep.host.lower() for ep, sr, leaf in live if ctx.for_ep(ep, sr, leaf)["externo"]})
        client = clients.get("caa")
        own = client is None
        if own:
            import httpx
            client = httpx.Client(timeout=settings.scan_timeout, trust_env=True, follow_redirects=False)
        counts = defaultdict(int)
        cache = {}
        try:
            for h in hosts:
                r = fdns.caa_lookup(h, list(settings.public_dns_urls), client, cache=cache)
                st = "erro" if r.erro else ("com_registos" if r.registos else "sem_registos")
                _save(session, "caa", h, st, {"zona": r.zona, "registos": [list(x) for x in r.registos], "erro": r.erro}, now)
                counts[st] += 1
        finally:
            if own:
                client.close()
        out["caa"] = dict(counts)

    # 3) HSTS: um pedido por servidor web
    if settings.hsts:
        targets = [ep for ep, _, _ in live if ep.port in settings.hsts_ports]
        client = clients.get("hsts") or fhsts.new_client(settings.scan_timeout)
        counts = defaultdict(int)
        try:
            with ThreadPoolExecutor(max_workers=max(1, settings.scan_workers)) as pool:
                futs = {ep.id: pool.submit(fhsts.fetch, ep.host, ep.port, client) for ep in targets}
                for eid, f in futs.items():
                    try:
                        r = f.result()
                    except Exception as exc:
                        log.warning("HSTS do servidor %s falhou: %s", eid, exc)
                        r = fhsts.HstsFetch("erro", erro=f"erro inesperado ({type(exc).__name__})")
                    _save(session, "hsts", str(eid), r.status, r.as_dict(), now)
                    counts[r.status] += 1
        finally:
            if "hsts" not in clients:
                client.close()
        out["hsts"] = dict(counts)

    # limpeza: resultados de certificados e servidores que já não existem
    session.flush()
    keep = {("revogacao", leaf.sha256) for _, _, leaf in live} | {("caa", ep.host.lower()) for ep, _, _ in live} | \
           {("hsts", str(ep.id)) for ep, _, _ in live}
    old = now - timedelta(days=max(30, settings.posture_max_age_days * 4))
    for row in list(session.scalars(select(PostureResult))):
        if (row.kind, row.key) not in keep and as_utc(row.checked_at) < old:
            session.delete(row)
    session.flush()
    return out

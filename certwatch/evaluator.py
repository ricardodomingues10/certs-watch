"""Motor de regras.

Cruza a CMDB (CN, ValidTo, Issuer) com o que os endpoints servem de facto e produz
findings com identificador estável. Findings que deixam de se verificar são
resolvidos automaticamente; aceitações expiradas voltam a "aberto".
"""
from __future__ import annotations

import hashlib
import math
from collections import defaultdict
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings
from .db import as_utc, utcnow
from .models import Certificate, CmdbRecord, Endpoint, Finding, ScanResult
from .normalize import hostname_matches, norm_issuer

SEVERITIES = ("info", "baixa", "media", "alta", "critica")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

WEAK_HASHES = {"md2", "md5", "sha1"}
LEGACY_TLS = {"SSLv3", "TLSv1", "TLSv1.1"}

# Códigos OpenSSL X509_V_ERR_*
X509_CERT_HAS_EXPIRED = 10
X509_DEPTH_ZERO_SELF_SIGNED = 18

FINDING_TYPES = {
    "EXPIRACAO": "Certificado a expirar ou expirado",
    "CMDB_REGISTO_EXPIRADO": "Registo expirado há muito tempo ainda ativo na CMDB",
    "RENOVACAO_NAO_INSTALADA": "A CMDB tem uma data posterior à do certificado servido",
    "RENOVADO_NAO_REFLETIDO": "O endpoint serve um certificado mais recente do que o da CMDB",
    "ISSUER_DIVERGENTE": "O emissor servido não corresponde a nenhum emissor registado na CMDB",
    "CHAIN_INVALIDA": "Cadeia de certificação inválida ou incompleta",
    "VALIDACAO_INCOMPLETA": "Não foi possível validar a cadeia (falha no handshake verificado)",
    "HOSTNAME_MISMATCH": "O certificado não cobre o nome do endpoint",
    "SELF_SIGNED": "Certificado autoassinado",
    "CRIPTO_FRACA": "Algoritmo de assinatura ou chave fracos",
    "TLS_LEGADO": "Protocolo TLS obsoleto negociado",
    "INALCANCAVEL": "Endpoint sem resposta TLS em verificações consecutivas",
    "WILDCARD_SEM_ENDPOINT": "Certificado wildcard sem endpoints conhecidos para verificar",
}


def finding_id(ftype: str, key: str) -> str:
    return hashlib.sha1(f"{ftype}|{key}".encode("utf-8")).hexdigest()


def days_left(not_after: datetime, now: datetime) -> int:
    return math.floor((as_utc(not_after) - now).total_seconds() / 86400)


def expiry_severity(days: int, pct_left: float | None, settings: Settings) -> str | None:
    t = settings.expiry_thresholds
    if days < 0 or days <= t["critica"]:
        sev = "critica"
    elif days <= t["alta"]:
        sev = "alta"
    elif days <= t["media"]:
        sev = "media"
    elif days <= t["baixa"]:
        sev = "baixa"
    else:
        sev = None
    if pct_left is not None and pct_left <= settings.lifetime_warn_pct:
        if sev is None or SEV_RANK[sev] < SEV_RANK["media"]:
            sev = "media"
    return sev


class _Collector:
    def __init__(self) -> None:
        self.items: dict[str, dict] = {}

    def add(self, ftype: str, severity: str, subject: str, key: str, cn_norm: str = "",
            endpoint_id: int | None = None, **details) -> None:
        fid = finding_id(ftype, key)
        self.items[fid] = {
            "type": ftype,
            "severity": severity,
            "subject": subject[:600],
            "cn_norm": cn_norm,
            "endpoint_id": endpoint_id,
            "details": {k: v for k, v in details.items() if v is not None},
        }


def _iso(dt: datetime | None) -> str | None:
    return as_utc(dt).isoformat() if dt else None


def _evaluate_live(c: _Collector, ep: Endpoint, sr: ScanResult, leaf: Certificate,
                   latest_by_issuer: dict[str, CmdbRecord], settings: Settings, now: datetime) -> str | None:
    """Regras sobre o certificado servido. Devolve o issuer_norm da CMDB que corresponde, se algum."""
    subj = f"{ep.host}:{ep.port}"
    key = f"ep:{ep.id}"
    na, nb = as_utc(leaf.not_after), as_utc(leaf.not_before)
    dl = days_left(na, now)
    total = (na - nb).total_seconds() if nb else 0
    pct = max(0.0, (na - now).total_seconds() / total) if total > 0 else None

    sev = expiry_severity(dl, pct, settings)
    if sev:
        c.add("EXPIRACAO", sev, subj, key, ep.expected_cn_norm, ep.id,
              fonte="live", dias=dl, expira_em=_iso(na), vida_restante_pct=round(pct * 100, 1) if pct is not None else None,
              emissor=leaf.issuer_cn, serial=leaf.serial_hex, sha256=leaf.sha256)

    names = leaf.sans_dns or ([leaf.subject_cn] if leaf.subject_cn else [])
    if not hostname_matches(ep.host, names, leaf.sans_ip):
        c.add("HOSTNAME_MISMATCH", "media", subj, key, ep.expected_cn_norm, ep.id,
              nomes_no_certificado=names[:20] + leaf.sans_ip[:5])

    if leaf.self_issued:
        c.add("SELF_SIGNED", "media", subj, key, ep.expected_cn_norm, ep.id, subject_dn=leaf.subject_dn)
    elif sr.verify_ok is False:
        intermediate_expired = any(
            not x.get("self_issued") and x.get("not_after") and as_utc(datetime.fromisoformat(x["not_after"])) < now
            for x in (sr.chain or [])[1:]
        )
        only_leaf_expired = sr.verify_code == X509_CERT_HAS_EXPIRED and na < now and not intermediate_expired
        if not only_leaf_expired and sr.verify_code != X509_DEPTH_ZERO_SELF_SIGNED:
            c.add("CHAIN_INVALIDA", "media", subj, key, ep.expected_cn_norm, ep.id,
                  codigo=sr.verify_code, motivo=sr.verify_message,
                  cadeia=[f"{x.get('subject_cn')} ← {x.get('issuer_cn')}" for x in (sr.chain or [])])
    elif sr.verify_ok is None:
        c.add("VALIDACAO_INCOMPLETA", "baixa", subj, key, ep.expected_cn_norm, ep.id, erro=sr.error)

    weak, leaf_weak = [], False
    if leaf.sig_hash in WEAK_HASHES:
        weak.append(f"assinatura {leaf.sig_hash.upper()}")
        leaf_weak = True
    if (leaf.key_type == "RSA" and (leaf.key_bits or 0) < 2048) or leaf.key_type == "DSA" or \
       (leaf.key_type == "EC" and (leaf.key_bits or 0) < 256):
        weak.append(f"chave {leaf.key_type} {leaf.key_bits}")
        leaf_weak = True
    for x in (sr.chain or [])[1:]:
        if not x.get("self_issued") and x.get("sig_hash") in WEAK_HASHES:
            weak.append(f"intermédio '{x.get('subject_cn')}' assinado com {x['sig_hash'].upper()}")
    if weak:
        c.add("CRIPTO_FRACA", "alta" if leaf_weak else "media", subj, key, ep.expected_cn_norm, ep.id, problemas=weak)

    if sr.tls_version in LEGACY_TLS:
        c.add("TLS_LEGADO", "media", subj, key, ep.expected_cn_norm, ep.id, protocolo=sr.tls_version)

    li = norm_issuer(leaf.issuer_cn)
    rec = latest_by_issuer.get(li)
    if not latest_by_issuer:
        return None
    if rec is None:
        c.add("ISSUER_DIVERGENTE", "media", subj, key, ep.expected_cn_norm, ep.id,
              emissor_servido=leaf.issuer_cn,
              emissores_cmdb=sorted({r.issuer_name or r.issuer for r in latest_by_issuer.values()}))
        return None
    if rec.valid_to:
        diff = (na.date() - as_utc(rec.valid_to).date()).days
        if diff > 1:
            c.add("RENOVADO_NAO_REFLETIDO", "baixa", subj, key, ep.expected_cn_norm, ep.id,
                  validade_servida=_iso(na), validade_cmdb=_iso(rec.valid_to), ucmdb_id=rec.ucmdb_id)
        elif diff < -1:
            c.add("RENOVACAO_NAO_INSTALADA", "alta", subj, key, ep.expected_cn_norm, ep.id,
                  validade_servida=_iso(na), validade_cmdb=_iso(rec.valid_to), ucmdb_id=rec.ucmdb_id)
    return li


def collect_findings(session: Session, settings: Settings, now: datetime) -> dict[str, dict]:
    c = _Collector()

    records = list(session.scalars(select(CmdbRecord).where(CmdbRecord.active.is_(True))))
    by_cn: dict[str, list[CmdbRecord]] = defaultdict(list)
    for r in records:
        by_cn[r.cn_norm].append(r)

    endpoints = list(session.scalars(select(Endpoint).where(Endpoint.enabled.is_(True))))
    ep_by_cn: dict[str, list[Endpoint]] = defaultdict(list)
    for e in endpoints:
        ep_by_cn[e.expected_cn_norm].append(e)

    scan_ids = [e.last_scan_id for e in endpoints if e.last_scan_id]
    scans = {s.id: s for s in session.scalars(select(ScanResult).where(ScanResult.id.in_(scan_ids)))} if scan_ids else {}
    leaf_ids = {s.leaf_sha256 for s in scans.values() if s.leaf_sha256}
    certs = {x.sha256: x for x in session.scalars(select(Certificate).where(Certificate.sha256.in_(leaf_ids)))} if leaf_ids else {}

    # Endpoints manuais cujo CN esperado não existe na CMDB também são avaliados
    for cn in set(ep_by_cn) - set(by_cn):
        by_cn[cn] = []

    for cn, recs in by_cn.items():
        latest_by_issuer: dict[str, CmdbRecord] = {}
        for r in recs:
            cur = latest_by_issuer.get(r.issuer_norm)
            if cur is None or (r.valid_to and (cur.valid_to is None or as_utc(r.valid_to) > as_utc(cur.valid_to))):
                latest_by_issuer[r.issuer_norm] = r

        kind = recs[0].kind if recs else "host"
        eps = ep_by_cn.get(cn, [])
        if kind == "wildcard" and not eps:
            c.add("WILDCARD_SEM_ENDPOINT", "info", cn, f"cn:{cn}", cn,
                  sugestao="Adicionar endpoints manuais que sirvam este wildcard")

        matched: set[str] = set()
        for ep in eps:
            sr = scans.get(ep.last_scan_id) if ep.last_scan_id else None
            if sr is None:
                continue
            leaf = certs.get(sr.leaf_sha256) if sr.leaf_sha256 else None
            if sr.status != "ok" or leaf is None:
                if ep.consecutive_failures >= settings.unreachable_after:
                    c.add("INALCANCAVEL", "baixa", f"{ep.host}:{ep.port}", f"ep:{ep.id}", cn, ep.id,
                          estado=sr.status, erro=sr.error, falhas_consecutivas=ep.consecutive_failures)
                continue
            li = _evaluate_live(c, ep, sr, leaf, latest_by_issuer, settings, now)
            if li is not None:
                matched.add(li)

        # Expiração pela CMDB para os emissores que nenhum endpoint confirmou
        for li, rec in latest_by_issuer.items():
            if li in matched or rec.valid_to is None:
                continue
            dl = days_left(rec.valid_to, now)
            label = rec.issuer_name or rec.issuer or "(sem emissor)"
            if dl < -30:
                c.add("CMDB_REGISTO_EXPIRADO", "baixa", f"{rec.common_name} ({label})", f"cmdb:{cn}|{li}", cn,
                      dias=dl, expira_em=_iso(rec.valid_to), ucmdb_id=rec.ucmdb_id)
                continue
            sev = expiry_severity(dl, None, settings)
            if sev:
                c.add("EXPIRACAO", sev, f"{rec.common_name} ({label})", f"cmdb:{cn}|{li}", cn,
                      fonte="cmdb", dias=dl, expira_em=_iso(rec.valid_to), emissor=label, ucmdb_id=rec.ucmdb_id)
    return c.items


def evaluate(session: Session, settings: Settings, now: datetime | None = None) -> dict:
    now = now or utcnow()
    current = collect_findings(session, settings, now)
    existing = {f.id: f for f in session.scalars(select(Finding))}
    new = reopened = resolved = 0

    for fid, data in current.items():
        f = existing.get(fid)
        if f is None:
            session.add(Finding(id=fid, status="aberto", first_seen=now, last_seen=now, **data))
            new += 1
            continue
        f.severity, f.subject, f.details = data["severity"], data["subject"], data["details"]
        f.cn_norm, f.endpoint_id, f.last_seen = data["cn_norm"], data["endpoint_id"], now
        if f.status == "resolvido":
            f.status, f.resolved_at = "aberto", None
            reopened += 1
        elif f.status == "aceite" and f.accepted_until and as_utc(f.accepted_until) < now:
            f.status = "aberto"
            reopened += 1

    for fid, f in existing.items():
        if fid not in current and f.status in ("aberto", "aceite"):
            f.status, f.resolved_at = "resolvido", now
            resolved += 1

    by_sev: dict[str, int] = {}
    for d in current.values():
        by_sev[d["severity"]] = by_sev.get(d["severity"], 0) + 1
    return {"ativos": len(current), "novos": new, "reabertos": reopened, "resolvidos": resolved, "por_severidade": by_sev}

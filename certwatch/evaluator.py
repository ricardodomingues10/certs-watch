"""Motor de regras.

Cruza a CMDB (CN, ValidTo, Issuer) e a lista de APIs com o que os endpoints servem de facto
e produz findings com identificador estável. Os testes por endpoint vêm de checks.py.
Findings que deixam de se verificar são resolvidos automaticamente; aceitações expiradas
voltam a "aberto".
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .classify import is_auto_renew
from .checks import days_left, evaluate_endpoint, expiry_severity  # noqa: F401  (reexportados)
from .config import Settings
from .db import as_utc, utcnow
from .models import ApiRecord, Certificate, CmdbRecord, Endpoint, Finding, ScanResult, SslLabsResult

SEVERITIES = ("info", "baixa", "media", "alta", "critica")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

FINDING_TYPES = {
    "EXPIRACAO": "Certificado a expirar ou expirado",
    "CMDB_REGISTO_EXPIRADO": "Registo expirado há muito tempo ainda ativo na CMDB",
    "RENOVACAO_NAO_INSTALADA": "Renovado na CMDB mas não instalado no servidor",
    "RENOVADO_NAO_REFLETIDO": "Servidor com certificado mais recente do que a CMDB",
    "ISSUER_DIVERGENTE": "Emissor diferente do registado na CMDB",
    "NAO_REGISTADO_CMDB": "Certificado em uso que não consta da CMDB",
    "CHAIN_INVALIDA": "Cadeia de certificação inválida ou incompleta",
    "VALIDACAO_INCOMPLETA": "Não foi possível validar a cadeia",
    "HOSTNAME_MISMATCH": "O certificado não cobre o nome do servidor",
    "SELF_SIGNED": "Certificado autoassinado",
    "CRIPTO_FRACA": "Algoritmo de assinatura ou chave fracos",
    "TLS_LEGADO": "Protocolo TLS obsoleto",
    "INALCANCAVEL": "Servidor sem resposta em verificações seguidas",
    "WILDCARD_SEM_ENDPOINT": "Wildcard sem servidores conhecidos para verificar",
    "API_EXPIRACAO": "Segredo de API a expirar (lista de APIs da CMDB)",
    "API_REGISTO_EXPIRADO": "Segredo de API expirado há mais de 30 dias ainda na lista",
    "SSLLABS_NOTA": "Nota baixa na avaliação externa do SSL Labs",
    "API_SEM_TLS": "API publicada sem TLS (http://)",
}

# Teste da aba "Testes" a que cada tipo de finding corresponde (para mostrar como corrigir)
FINDING_CHECK = {
    "EXPIRACAO": "validade.prazo", "RENOVACAO_NAO_INSTALADA": "inventario.data",
    "RENOVADO_NAO_REFLETIDO": "inventario.data", "ISSUER_DIVERGENTE": "inventario.emissor",
    "NAO_REGISTADO_CMDB": "inventario.registo", "CHAIN_INVALIDA": "cadeia.confianca",
    "VALIDACAO_INCOMPLETA": "cadeia.confianca", "HOSTNAME_MISMATCH": "identidade.nome",
    "SELF_SIGNED": "cadeia.autoassinado", "CRIPTO_FRACA": "cripto.assinatura", "TLS_LEGADO": "tls.protocolo",
    "INALCANCAVEL": "rede.porta",
}


def finding_id(ftype: str, key: str) -> str:
    return hashlib.sha1(f"{ftype}|{key}".encode("utf-8")).hexdigest()


def _iso(dt: datetime | None) -> str | None:
    return as_utc(dt).isoformat() if dt else None


@dataclass
class Snapshot:
    """Estado atual carregado da base de dados, partilhado pelo motor de regras e pela interface."""

    records: list[CmdbRecord] = field(default_factory=list)
    by_cn: dict[str, list[CmdbRecord]] = field(default_factory=dict)
    endpoints: list[Endpoint] = field(default_factory=list)
    ep_by_cn: dict[str, list[Endpoint]] = field(default_factory=dict)
    scans: dict[int, ScanResult] = field(default_factory=dict)
    certs: dict[str, Certificate] = field(default_factory=dict)
    apis: list[ApiRecord] = field(default_factory=list)

    def latest_by_issuer(self, cn: str) -> dict[str, CmdbRecord]:
        out: dict[str, CmdbRecord] = {}
        for r in self.by_cn.get(cn, []):
            cur = out.get(r.issuer_norm)
            if cur is None or (r.valid_to and (cur.valid_to is None or as_utc(r.valid_to) > as_utc(cur.valid_to))):
                out[r.issuer_norm] = r
        return out

    def scan_for(self, ep: Endpoint) -> ScanResult | None:
        return self.scans.get(ep.last_scan_id) if ep.last_scan_id else None

    def leaf_for(self, sr: ScanResult | None) -> Certificate | None:
        return self.certs.get(sr.leaf_sha256) if sr and sr.leaf_sha256 else None


def load_snapshot(session: Session, include_disabled: bool = False) -> Snapshot:
    snap = Snapshot()
    snap.records = list(session.scalars(select(CmdbRecord).where(CmdbRecord.active.is_(True))))
    by_cn: dict[str, list[CmdbRecord]] = defaultdict(list)
    for r in snap.records:
        by_cn[r.cn_norm].append(r)
    snap.by_cn = dict(by_cn)
    stmt = select(Endpoint) if include_disabled else select(Endpoint).where(Endpoint.enabled.is_(True))
    snap.endpoints = list(session.scalars(stmt))
    ep_by_cn: dict[str, list[Endpoint]] = defaultdict(list)
    for e in snap.endpoints:
        if e.enabled:
            ep_by_cn[e.expected_cn_norm].append(e)
    snap.ep_by_cn = dict(ep_by_cn)
    ids = [e.last_scan_id for e in snap.endpoints if e.last_scan_id]
    if ids:
        snap.scans = {s.id: s for s in session.scalars(select(ScanResult).where(ScanResult.id.in_(ids)))}
    leafs = {s.leaf_sha256 for s in snap.scans.values() if s.leaf_sha256}
    if leafs:
        snap.certs = {c.sha256: c for c in session.scalars(select(Certificate).where(Certificate.sha256.in_(leafs)))}
    snap.apis = list(session.scalars(select(ApiRecord).where(ApiRecord.active.is_(True))))
    return snap


class _Collector:
    def __init__(self) -> None:
        self.items: dict[str, dict] = {}

    def add(self, ftype: str, severity: str, subject: str, key: str, cn_norm: str = "",
            endpoint_id: int | None = None, **details) -> None:
        self.items[finding_id(ftype, key)] = {
            "type": ftype, "severity": severity, "subject": subject[:600], "cn_norm": cn_norm,
            "endpoint_id": endpoint_id, "details": {k: v for k, v in details.items() if v is not None},
        }


def collect_findings(session: Session, settings: Settings, now: datetime) -> dict[str, dict]:
    c = _Collector()
    snap = load_snapshot(session)

    all_cns = set(snap.by_cn) | set(snap.ep_by_cn)
    for cn in all_cns:
        recs = snap.by_cn.get(cn, [])
        latest = snap.latest_by_issuer(cn)
        kind = recs[0].kind if recs else "host"
        eps = snap.ep_by_cn.get(cn, [])
        if kind == "wildcard" and not eps:
            c.add("WILDCARD_SEM_ENDPOINT", "info", cn, f"cn:{cn}", cn,
                  sugestao="Adicionar em Servidores os servidores que usam este wildcard")

        matched: set[str] = set()
        for ep in eps:
            sr = snap.scan_for(ep)
            if sr is None:
                continue
            ev = evaluate_endpoint(ep, sr, snap.leaf_for(sr), latest, settings, now)
            for ftype, sev, details in ev.findings:
                c.add(ftype, sev, f"{ep.host}:{ep.port}", f"ep:{ep.id}", cn, ep.id, **details)
            if ev.matched_issuer is not None:
                matched.add(ev.matched_issuer)

        # Expiração pela CMDB para os emissores que nenhum endpoint confirmou
        for li, rec in latest.items():
            if li in matched or rec.valid_to is None:
                continue
            dl = days_left(rec.valid_to, now)
            label = rec.issuer_name or rec.issuer or "(sem emissor)"
            if dl < -30:
                c.add("CMDB_REGISTO_EXPIRADO", "baixa", f"{rec.common_name} ({label})", f"cmdb:{cn}|{li}", cn,
                      dias=dl, expira_em=_iso(rec.valid_to), ucmdb_id=rec.ucmdb_id)
                continue
            auto = is_auto_renew(settings, rec.issuer, rec.issuer_name)
            sev = expiry_severity(dl, None, settings, auto_renew=auto)
            if sev:
                c.add("EXPIRACAO", sev, f"{rec.common_name} ({label})", f"cmdb:{cn}|{li}", cn,
                      fonte="cmdb", dias=dl, expira_em=_iso(rec.valid_to), emissor=label, ucmdb_id=rec.ucmdb_id,
                      renovacao_automatica=auto or None)

    # Lista de APIs
    for api in snap.apis:
        subj = api.name or api.url or api.ucmdb_id
        if api.scheme == "http":
            c.add("API_SEM_TLS", "alta", subj, f"api:{api.ucmdb_id}", api.host, url=api.url)
        if api.expiry is not None:
            dl = days_left(api.expiry, now)
            extra = dict(aplicacao=api.application or None, localizacao=api.location or None,
                         url=api.url or None, ucmdb_id=api.ucmdb_id)
            if dl < -30:
                # Segredo antigo: já não é um risco de interrupção, é limpeza (no Azure e na CMDB)
                c.add("API_REGISTO_EXPIRADO", "baixa", subj, f"api:{api.ucmdb_id}", api.host,
                      dias=dl, expira_em=_iso(api.expiry), **extra)
                continue
            sev = expiry_severity(dl, None, settings)
            if sev:
                c.add("API_EXPIRACAO", sev, subj, f"api:{api.ucmdb_id}", api.host,
                      dias=dl, expira_em=_iso(api.expiry), **extra)
    # Avaliação externa SSL Labs
    for r in session.scalars(select(SslLabsResult).where(SslLabsResult.status == "READY")):
        sev = SSLLABS_SEVERITY.get(r.grade)
        if sev:
            c.add("SSLLABS_NOTA", sev, f"{r.host}: nota {r.grade}", f"ssllabs:{r.host}", r.host,
                  nota=r.grade, avaliado_em=_iso(r.test_time),
                  ips={e.get("ip"): e.get("grade") for e in (r.endpoints or [])},
                  relatorio=f"https://www.ssllabs.com/ssltest/analyze.html?d={r.host}&hideResults=on")
    return c.items


# Notas A+, A e A- não geram alerta. T = certificado não confiável; M = nome não corresponde.
SSLLABS_SEVERITY = {"B": "media", "C": "alta", "D": "alta", "E": "alta", "F": "alta", "T": "alta", "M": "media"}


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

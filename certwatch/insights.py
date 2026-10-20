"""Vistas agregadas para a interface: inventário legível, matriz de testes, painel e árvore PKI."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from sqlalchemy import select
from sqlalchemy.orm import Session

from .checks import CHECKS, FALHA, STATUS_RANK, days_left, evaluate_endpoint
from .classify import cert_type, scope_of
from .config import Settings
from .db import as_utc
from .evaluator import FINDING_TYPES, SEV_RANK, Snapshot, load_snapshot
from .models import Certificate, CmdbRecord, Endpoint, Finding, ScanResult
from .normalize import classify, norm_issuer
from .scanner import summarize

_MIN_DT = datetime.min.replace(tzinfo=timezone.utc)

STATE_LABELS = {"falha": "Falha", "aviso": "Atenção", "ok": "OK", "pendente": "Por verificar", "cmdb": "Só CMDB"}


def _state_from(findings: list[Finding], live_ok: bool, scannable: bool) -> str:
    worst = max((SEV_RANK[f.severity] for f in findings), default=-1)
    if worst >= SEV_RANK["alta"]:
        return "falha"
    if worst >= SEV_RANK["baixa"]:
        return "aviso"
    if live_ok:
        return "ok"
    return "pendente" if scannable else "cmdb"


def _summary(findings: list[Finding], days: int | None, live_ok: bool) -> str:
    if findings:
        f = max(findings, key=lambda x: SEV_RANK[x.severity])
        if f.type == "EXPIRACAO" and days is not None:
            return f"Expirou há {-days} dias" if days < 0 else f"Expira em {days} dias"
        return FINDING_TYPES.get(f.type, f.type)
    if live_ok:
        return "Todos os testes passaram"
    return "Sem verificação live"


# ------------------------------------------------------------------ inventário
def build_inventory(session: Session, settings: Settings, now: datetime, snap: Snapshot | None = None) -> list[dict]:
    snap = snap or load_snapshot(session)
    open_f: dict[str, list[Finding]] = defaultdict(list)
    for f in session.scalars(select(Finding).where(Finding.status == "aberto")):
        open_f[f.cn_norm].append(f)
    api_by_host: dict[str, list] = defaultdict(list)
    for a in snap.apis:
        if a.host:
            api_by_host[a.host].append(a)

    rows = []
    for cn in sorted(set(snap.by_cn) | set(snap.ep_by_cn)):
        recs = snap.by_cn.get(cn, [])
        latest = max(recs, key=lambda r: as_utc(r.valid_to) or _MIN_DT) if recs else None
        kind = latest.kind if latest else classify(cn)
        live_cert, live_scan, statuses = None, None, []
        for ep in snap.ep_by_cn.get(cn, []):
            sr = snap.scan_for(ep)
            if sr is None:
                continue
            statuses.append(sr.status)
            leaf = snap.leaf_for(sr)
            if sr.status == "ok" and leaf is not None:
                live_cert, live_scan = leaf, sr
                break
        effective = live_cert.not_after if live_cert else (latest.valid_to if latest else None)
        days = days_left(effective, now) if effective else None
        issuer_norm = norm_issuer(live_cert.issuer_cn) if live_cert else (latest.issuer_norm if latest else "")
        ctype = cert_type(cn, kind, is_api=cn in api_by_host, issuer_norm=issuer_norm,
                          common_name=latest.common_name if latest else cn)
        scope = scope_of(cn, kind, settings, issuer_norm=issuer_norm,
                         resolved_ip=live_scan.resolved_ip if live_scan else "")
        fl = open_f.get(cn, [])
        scannable = kind in ("host", "ip") or bool(snap.ep_by_cn.get(cn))
        state = _state_from(fl, live_cert is not None, scannable)
        rows.append({
            "cn": cn,
            "common_name": latest.common_name if latest else cn,
            "kind": kind,
            "type": ctype,
            "scope": scope,
            "state": state,
            "summary": _summary(fl, days, live_cert is not None),
            "issuers": sorted({r.issuer_name or r.issuer for r in recs if (r.issuer_name or r.issuer)}),
            "registos": len(recs),
            "in_cmdb": bool(recs),
            "apis": [a.name for a in api_by_host.get(cn, [])],
            "cmdb_valid_to": latest.valid_to if latest else None,
            "live_status": "ok" if live_cert else (statuses[0] if statuses else None),
            "live_not_after": live_cert.not_after if live_cert else None,
            "live_issuer": live_cert.issuer_cn if live_cert else None,
            "live_sha256": live_cert.sha256 if live_cert else None,
            "dias": days,
            "fonte_data": "live" if live_cert else ("cmdb" if latest else "—"),
            "findings": len(fl),
            "max_sev": max((f.severity for f in fl), key=lambda x: SEV_RANK[x], default=None),
        })
    rows.sort(key=lambda r: (r["dias"] is None, r["dias"] if r["dias"] is not None else 0, r["cn"]))
    return rows


# ------------------------------------------------------------------ matriz de testes
@dataclass
class EndpointChecks:
    ep: Endpoint
    scan: ScanResult | None
    leaf: Certificate | None
    results: dict
    worst: str
    type: str
    scope: str


def check_matrix(session: Session, settings: Settings, now: datetime, snap: Snapshot | None = None) -> list[EndpointChecks]:
    snap = snap or load_snapshot(session)
    api_hosts = {a.host for a in snap.apis if a.host}
    out = []
    for ep in snap.endpoints:
        if not ep.enabled:
            continue
        sr = snap.scan_for(ep)
        leaf = snap.leaf_for(sr)
        ev = evaluate_endpoint(ep, sr, leaf, snap.latest_by_issuer(ep.expected_cn_norm), settings, now)
        recs = snap.by_cn.get(ep.expected_cn_norm, [])
        kind = recs[0].kind if recs else classify(ep.expected_cn_norm)
        issuer_norm = norm_issuer(leaf.issuer_cn) if leaf else ""
        out.append(EndpointChecks(
            ep=ep, scan=sr, leaf=leaf, results=ev.results, worst=ev.worst(),
            type=cert_type(ep.expected_cn_norm, kind, is_api=ep.expected_cn_norm in api_hosts, issuer_norm=issuer_norm),
            scope=scope_of(ep.expected_cn_norm, kind, settings, issuer_norm=issuer_norm,
                           resolved_ip=sr.resolved_ip if sr else ""),
        ))
    out.sort(key=lambda r: (-STATUS_RANK[r.worst], r.ep.host, r.ep.port))
    return out


def check_totals(matrix: list[EndpointChecks]) -> dict[str, Counter]:
    totals: dict[str, Counter] = {c.id: Counter() for c in CHECKS}
    for row in matrix:
        for cid, res in row.results.items():
            totals[cid][res.status] += 1
    return totals


# ------------------------------------------------------------------ painel
def dashboard_stats(inventory: list[dict], matrix: list[EndpointChecks], now: datetime) -> dict:
    by_state = Counter(r["state"] for r in inventory)
    by_type = Counter(r["type"] for r in inventory)
    by_scope = Counter(r["scope"] for r in inventory)
    type_state: dict[str, Counter] = defaultdict(Counter)
    for r in inventory:
        type_state[r["type"]][r["state"]] += 1
    issuers = Counter((r["live_issuer"] or (r["issuers"][0] if r["issuers"] else "(sem emissor)")) for r in inventory)

    buckets = {"expirados": 0, "7": 0, "20": 0, "30": 0, "90": 0}
    for r in inventory:
        d = r["dias"]
        if d is None:
            continue
        if d < 0:
            buckets["expirados"] += 1
        elif d <= 7:
            buckets["7"] += 1
        elif d <= 20:
            buckets["20"] += 1
        elif d <= 30:
            buckets["30"] += 1
        elif d <= 90:
            buckets["90"] += 1

    # Expirações por mês nos próximos 12 meses
    months = []
    y, m = now.year, now.month
    for _ in range(12):
        months.append((y, m))
        m += 1
        if m > 12:
            y, m = y + 1, 1
    per_month = Counter()
    for r in inventory:
        when = r["live_not_after"] or r["cmdb_valid_to"]
        if when is None:
            continue
        w = as_utc(when)
        if (w.year, w.month) in months:
            per_month[(w.year, w.month)] += 1
    timeline = [{"ano": y, "mes": m, "total": per_month.get((y, m), 0)} for y, m in months]

    ep_total = len(matrix)
    ep_verified = sum(1 for r in matrix if r.scan is not None)
    ep_tls_ok = sum(1 for r in matrix if r.leaf is not None)
    ep_failing = sum(1 for r in matrix if r.worst == FALHA)
    return {
        "total": len(inventory), "by_state": by_state, "by_type": by_type, "by_scope": by_scope,
        "type_state": type_state, "issuers": issuers.most_common(8), "buckets": buckets, "timeline": timeline,
        "ep_total": ep_total, "ep_verified": ep_verified, "ep_tls_ok": ep_tls_ok, "ep_failing": ep_failing,
        "check_totals": check_totals(matrix),
    }


# ------------------------------------------------------------------ árvore PKI
@dataclass
class Node:
    key: str
    cert: Certificate | dict | None
    subject_cn: str
    subject_dn: str
    issuer_dn: str
    not_after: datetime | None
    is_ca: bool
    origin: str  # observado | trust | virtual
    children: list["Node"] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    cmdb_count: int = 0

    @property
    def leaf_count(self) -> int:
        return sum(1 for c in self.children if not c.is_ca)

    @property
    def total_below(self) -> int:
        return sum(1 + c.total_below for c in self.children)


@lru_cache(maxsize=4)
def _trust_roots(trust_dir: str, system_bundle: str) -> tuple[dict, ...]:
    """Certificados do trust store (sistema + raízes internas), para completar o topo da árvore."""
    pems: list[bytes] = []
    for path in [Path(system_bundle)] + sorted(p for p in Path(trust_dir).glob("*") if p.is_file()):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        pems += re.findall(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", data, re.S)
    out = []
    for pem in pems:
        try:
            out.append(summarize(x509.load_pem_x509_certificate(pem).public_bytes(Encoding.DER)))
        except Exception:
            continue
    return tuple(out)


def build_tree(session: Session, settings: Settings) -> list[Node]:
    certs = list(session.scalars(select(Certificate)))
    nodes: dict[str, Node] = {}
    for c in certs:
        nodes[c.sha256] = Node(c.sha256, c, c.subject_cn, c.subject_dn, c.issuer_dn, c.not_after, c.is_ca, "observado")

    by_ski: dict[str, list[Node]] = defaultdict(list)
    by_dn: dict[str, list[Node]] = defaultdict(list)
    for n in nodes.values():
        if n.is_ca:
            if n.cert.ski:
                by_ski[n.cert.ski].append(n)
            by_dn[n.subject_dn].append(n)

    # Raízes do trust store que são emissoras de algum certificado observado
    needed_dns = {n.issuer_dn for n in nodes.values()} - set(by_dn)
    if needed_dns:
        for s in _trust_roots(str(settings.trust_dir), str(settings.system_ca_bundle)):
            if s["subject_dn"] in needed_dns and s["sha256"] not in nodes:
                n = Node(s["sha256"], s, s["subject_cn"], s["subject_dn"], s["issuer_dn"], s["not_after"], True, "trust")
                nodes[n.key] = n
                by_dn[n.subject_dn].append(n)
                if s.get("ski"):
                    by_ski[s["ski"]].append(n)

    def parent_of(n: Node) -> Node | None:
        if n.subject_dn == n.issuer_dn:
            return None
        aki = n.cert.aki if isinstance(n.cert, Certificate) else (n.cert or {}).get("aki", "")
        cands = by_ski.get(aki, []) if aki else []
        cands = [c for c in cands if c.key != n.key] or [c for c in by_dn.get(n.issuer_dn, []) if c.key != n.key]
        if not cands:
            return None
        return max(cands, key=lambda c: as_utc(c.not_after) or _MIN_DT)

    roots: dict[str, Node] = {}
    for n in list(nodes.values()):
        p = parent_of(n)
        if p is None and n.subject_dn != n.issuer_dn:
            vkey = "virtual:" + n.issuer_dn
            p = roots.get(vkey) or nodes.get(vkey)
            if p is None:
                cn = re.search(r"CN=([^,]+)", n.issuer_dn)
                p = Node(vkey, None, cn.group(1) if cn else n.issuer_dn, n.issuer_dn, "", None, True, "virtual")
                nodes[vkey] = p
                roots[vkey] = p
        if p is None:
            roots[n.key] = n
        else:
            p.children.append(n)

    # Endpoints que servem cada certificado (última verificação) e registos CMDB por emissor
    eps = {e.id: e for e in session.scalars(select(Endpoint).where(Endpoint.enabled.is_(True)))}
    last_ids = [e.last_scan_id for e in eps.values() if e.last_scan_id]
    if last_ids:
        for sr in session.scalars(select(ScanResult).where(ScanResult.id.in_(last_ids))):
            if sr.leaf_sha256 in nodes:
                e = eps.get(sr.endpoint_id)
                if e:
                    nodes[sr.leaf_sha256].endpoints.append(f"{e.host}:{e.port}")
    cmdb_issuers = Counter(r.issuer_norm for r in session.scalars(select(CmdbRecord).where(CmdbRecord.active.is_(True))))
    for n in nodes.values():
        if n.is_ca:
            n.cmdb_count = cmdb_issuers.get(norm_issuer(n.subject_cn), 0)

    def sort_rec(n: Node) -> None:
        n.children.sort(key=lambda c: (not c.is_ca, as_utc(c.not_after) or _MIN_DT, c.subject_cn))
        for ch in n.children:
            sort_rec(ch)

    out = sorted(roots.values(), key=lambda n: (-n.total_below, n.subject_cn))
    for r in out:
        sort_rec(r)
    return out


def ancestry(session: Session, settings: Settings, sha256: str) -> tuple[list[Node], Node | None]:
    """Cadeia ascendente (raiz primeiro) e o nó do certificado pedido."""
    roots = build_tree(session, settings)
    path: list[Node] = []

    def walk(n: Node, trail: list[Node]) -> bool:
        if n.key == sha256:
            path.extend(trail + [n])
            return True
        return any(walk(c, trail + [n]) for c in n.children)

    for r in roots:
        if walk(r, []):
            break
    return path[:-1], (path[-1] if path else None)

"""Sites públicos: o certificado que cada nome externo serve, em cada IP, visto de dentro e de fora, lado a lado com a
CMDB e com o pedido do SMAX.

Para cada nome:
1. resolve-se no DNS interno (o do servidor) e no DNS público (DNS-over-HTTPS): com DNS diferente dentro e fora, o
   mesmo nome pode apontar para sítios diferentes;
2. liga-se a cada IP (até CERTWATCH_SITES_MAX_IPS por visão; numa CDN só uma amostra), sempre com o nome no SNI,
   e lê-se o certificado: um nó esquecido com o certificado antigo aparece aqui;
3. compara-se: os nós entre si, dentro com fora, o certificado servido com a CMDB e com o pedido aberto.

Só leitura: nada é escrito na CMDB nem no SMAX.
"""
from __future__ import annotations

import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings
from .db import as_utc, utcnow
from .models import SiteCheck

log = logging.getLogger(__name__)

# Estados, do mais grave para o menos grave. O estado do site é o mais grave das suas marcas.
STATES = {
    "sem_resposta": ("Sem resposta", "Nenhum IP respondeu com um certificado (ou o nome não resolve).", "x"),
    "expirado": ("Expirado", "Há um IP a servir um certificado já expirado.", "x"),
    "fora_diferente": ("Dentro ≠ fora", "A internet vê um certificado diferente do que se vê de dentro da rede.", "r"),
    "nos_diferentes": ("Nós diferentes", "Os IPs do mesmo nome servem certificados diferentes (um nó esquecido?).", "r"),
    "renovado_nao_instalado": ("Renovado mas não instalado", "A CMDB tem uma data mais recente do que a servida: falta instalar.", "r"),
    "cmdb_desatualizada": ("CMDB desatualizada", "O servidor já tem um certificado mais recente do que o da CMDB.", "a"),
    "pedido_desatualizado": ("Pedido desatualizado", "Há um pedido aberto para um certificado que já foi renovado (pode fechar).", "a"),
    "sem_cmdb": ("Não está na CMDB", "O nome é servido mas não tem certificado registado na CMDB.", "a"),
    "so_interno": ("Só no DNS interno", "O nome não existe no DNS público: não é visto da internet.", "n"),
    "ok": ("Tudo certo", "O servidor, a CMDB e o pedido estão de acordo.", "ok"),
}
ORDER = list(STATES)
PROBLEMS = [k for k in ORDER if STATES[k][2] in ("x", "r", "a")]
NOTES = {
    "fora_indisponivel": "Os IPs públicos não respondem a partir deste servidor (a firewall não deixa voltar a entrar "
                         "pelo IP público): a visão de fora não foi possível.",
    "dns_publico_falhou": "O DNS público não respondeu: só a visão de dentro.",
    "cdn": "Servido por uma CDN: testada só uma amostra dos nós, e certificados diferentes entre nós são normais.",
    "sem_ipv6": "Há endereços IPv6 que este servidor não consegue testar (sem IPv6).",
}


def _day(v, tz: ZoneInfo):
    if v is None:
        return None
    if isinstance(v, str):
        v = datetime.fromisoformat(v)
    return as_utc(v).astimezone(tz).date()


def _iso(v):
    return as_utc(v).isoformat() if isinstance(v, datetime) else v


def public_names(inventory: list[dict], settings: Settings) -> list[dict]:
    """Os nomes externos do inventário que se podem testar (sem wildcards nem IPs), mais CERTWATCH_SITES_EXTRA."""
    out = {r["cn"]: r for r in inventory if r["scope"] == "externo" and r["kind"] == "host"}
    by = {r["cn"]: r for r in inventory}
    for n in settings.sites_extra:
        out.setdefault(n, by.get(n) or {"cn": n, "common_name": n, "cmdb_valid_to": None, "in_cmdb": False,
                                         "smax": None, "dono": None})
    return [out[k] for k in sorted(out)]


# ------------------------------------------------------------------ teste de um nome
def probe(name: str, settings: Settings, cafile: str, resolve_internal, resolve_public, scan) -> dict:
    """Resolve (dentro e fora) e liga a cada IP. Devolve os nós e as resoluções (ainda sem comparar)."""
    from .fontes.servidores import summarize
    inside = resolve_internal(name)
    outside = resolve_public(name) if settings.sites_external else None
    cdn = (outside.cdn if outside else "") or ""
    limit = 2 if cdn else settings.sites_max_ips
    views: dict[str, set] = {}
    for ip in inside.ips[:limit]:
        views.setdefault(ip, set()).add("dentro")
    if outside:
        for ip in outside.ips[:limit]:
            views.setdefault(ip, set()).add("fora")
    nodes = []
    for ip in sorted(views, key=lambda x: (ipaddress.ip_address(x).version, int(ipaddress.ip_address(x)))):
        out = scan(name, 443, cafile, settings.scan_timeout, connect_to=ip)
        node = {"ip": ip, "vistas": sorted(views[ip]), "status": out.status, "erro": out.error[:200],
                "verificado": out.verify_ok, "tls": out.tls_version}
        if out.status == "ok" and out.chain_der:
            s = summarize(out.chain_der[0])
            names = [n.lower() for n in (s["sans_dns"] or [])] or [s["subject_cn"].lower()]
            node.update(sha256=s["sha256"], not_after=_iso(s["not_after"]), serial=s["serial_hex"], emissor=s["issuer_cn"],
                        cn=s["subject_cn"], nome_ok=any(n == name or (n.startswith("*.") and name.split(".", 1)[-1] == n[2:])
                                                         for n in names))
        elif ipaddress.ip_address(ip).version == 6 and out.status == "unreachable" and \
                any(x in out.error.lower() for x in ("network is unreachable", "no route", "cannot assign")):
            node["status"] = "sem_ipv6"
        nodes.append(node)
    return {"nodes": nodes, "cdn": cdn,
            "dentro": {"ips": inside.ips, "erro": inside.erro, "inexistente": inside.inexistente},
            "fora": ({"ips": outside.ips, "cnames": outside.cnames, "erro": outside.erro, "inexistente": outside.inexistente,
                      "resolvedor": outside.resolvedor} if outside else None)}


def evaluate(name: str, probed: dict, row: dict | None, now: datetime, tz: str) -> dict:
    """Compara os nós entre si, dentro com fora, e o servido com a CMDB e com o pedido. Função pura."""
    zone = ZoneInfo(tz)
    row = row or {}
    nodes = probed["nodes"]
    ok = [n for n in nodes if n["status"] == "ok" and n.get("sha256")]
    fora_info = probed.get("fora")
    flags, notes = [], []
    if fora_info and fora_info.get("erro") and not fora_info.get("inexistente"):
        notes.append("dns_publico_falhou")
    if probed.get("cdn"):
        notes.append("cdn")
    if any(n["status"] == "sem_ipv6" for n in nodes):
        notes.append("sem_ipv6")
    so_interno = bool(fora_info and fora_info.get("inexistente"))
    in_view = lambda v: [n for n in ok if v in n["vistas"]]  # noqa: E731
    dentro, fora = in_view("dentro"), in_view("fora")
    fora_ips = [n for n in nodes if "fora" in n["vistas"]]
    if fora_ips and not fora and dentro:
        notes.append("fora_indisponivel")
    public_view = fora or dentro                 # o que a internet vê, se se conseguiu ver; senão o de dentro
    if not ok:
        flags.append("sem_resposta")
    else:
        if any(_day(n["not_after"], zone) < now.astimezone(zone).date() for n in ok):
            flags.append("expirado")
        if dentro and fora and not ({n["sha256"] for n in dentro} & {n["sha256"] for n in fora}):
            flags.append("fora_diferente")
        if not probed.get("cdn") and any(len({n["sha256"] for n in view}) > 1 for view in (dentro, fora) if view):
            flags.append("nos_diferentes")
    served_max = max(public_view, key=lambda n: n["not_after"]) if public_view else None
    served_min = min(public_view, key=lambda n: n["not_after"]) if public_view else None
    cmdb_day = _day(row.get("cmdb_valid_to"), zone)
    if served_max:
        smax_day, smin_day = _day(served_max["not_after"], zone), _day(served_min["not_after"], zone)
        if not row.get("in_cmdb"):
            flags.append("sem_cmdb")
        elif cmdb_day:
            if (cmdb_day - smin_day).days > 1:
                flags.append("renovado_nao_instalado")
            if (smax_day - cmdb_day).days > 1:
                flags.append("cmdb_desatualizada")
    smax = row.get("smax") or {}
    abertos = [t for t in smax.get("open") or []]
    desatualizados = []
    if served_max:
        smax_day = _day(served_max["not_after"], zone)
        for t in abertos:
            exp = _day(t.get("expira"), zone)
            if exp and (smax_day - exp).days > 1:
                desatualizados.append(t["id"])
    if desatualizados:
        flags.append("pedido_desatualizado")
    if so_interno:
        flags.append("so_interno")
    estado = next((k for k in ORDER if k in flags), "ok")
    main = smax.get("main") or None
    dono = row.get("dono") or {}
    return {
        "name": name, "estado": estado, "flags": [k for k in ORDER if k in flags], "notas": notes,
        "nos": nodes, "cdn": probed.get("cdn") or "", "dentro": probed["dentro"], "fora": fora_info,
        "servido": ({k: served_max.get(k) for k in ("not_after", "serial", "emissor", "cn", "sha256", "nome_ok")}
                    if served_max else None),
        "servido_min": served_min.get("not_after") if served_min else None,
        "dias": ((_day(served_min["not_after"], zone) - now.astimezone(zone).date()).days if served_min else None),
        "dias_max": ((_day(served_max["not_after"], zone) - now.astimezone(zone).date()).days if served_max else None),
        "cmdb": {"valid_to": _iso(row.get("cmdb_valid_to")), "in_cmdb": bool(row.get("in_cmdb"))},
        "pedido": ({"id": main["id"], "url": main.get("url"), "fase": main.get("fase"), "aberto": main.get("aberto"),
                    "expira": _iso(main.get("expira"))} if main else None),
        "pedidos_abertos": [{"id": t["id"], "url": t.get("url"), "fase": t.get("fase"), "expira": _iso(t.get("expira"))}
                            for t in abertos],
        "pedidos_desatualizados": desatualizados,
        "dono": dono.get("equipa") or "", "common_name": row.get("common_name") or name,
    }


# ------------------------------------------------------------------ execução
def run(session: Session, settings: Settings, inventory: list[dict] | None = None, now: datetime | None = None,
        resolve_internal=None, resolve_public=None, scan=None, client: httpx.Client | None = None) -> dict:
    """Testa todos os sites públicos e guarda o último resultado de cada um."""
    from .fontes import dns
    from .fontes.servidores import scan_endpoint
    from .insights import build_inventory
    from .trust import build_bundle
    now = now or utcnow()
    inventory = inventory if inventory is not None else build_inventory(session, settings, now)
    rows = public_names(inventory, settings)
    own = client is None and resolve_public is None
    http = client or (httpx.Client(timeout=8.0, trust_env=True, follow_redirects=False) if resolve_public is None else None)
    ri = resolve_internal or dns.resolve_internal
    rp = resolve_public or (lambda n: dns.resolve_public(n, settings.public_dns_urls, http))
    sc = scan or scan_endpoint
    cafile = build_bundle(settings)
    try:
        def one(r):
            try:
                return evaluate(r["cn"], probe(r["cn"], settings, cafile, ri, rp, sc), r, now, settings.timezone)
            except Exception as exc:  # um nome com problemas não para os outros
                log.exception("Sites públicos: %s", r["cn"])
                return {"name": r["cn"], "estado": "sem_resposta", "flags": ["sem_resposta"], "notas": [], "nos": [],
                        "erro": f"{type(exc).__name__}: {str(exc)[:200]}", "common_name": r.get("common_name") or r["cn"]}
        with ThreadPoolExecutor(max_workers=max(1, min(settings.scan_workers, 16))) as ex:
            results = list(ex.map(one, rows))
    finally:
        if own and http is not None:
            http.close()
    existing = {c.name: c for c in session.scalars(select(SiteCheck))}
    for res in results:
        c = existing.pop(res["name"], None)
        if c is None:
            c = SiteCheck(name=res["name"])
            session.add(c)
        c.checked_at, c.estado, c.data = now, res["estado"], res
    for c in existing.values():           # nomes que deixaram de ser públicos
        session.delete(c)
    session.flush()
    counts: dict[str, int] = {}
    for r in results:
        counts[r["estado"]] = counts.get(r["estado"], 0) + 1
    return {"sites": len(results), "problemas": sum(v for k, v in counts.items() if k in PROBLEMS), **counts}


def latest(session: Session) -> list[dict]:
    """Os resultados guardados, do mais grave para o menos grave."""
    rows = []
    for c in session.scalars(select(SiteCheck)):
        rows.append({**(c.data or {}), "estado": c.estado, "checked_at": as_utc(c.checked_at)})
    rows.sort(key=lambda r: (ORDER.index(r["estado"]) if r["estado"] in ORDER else 99,
                             r.get("dias") if r.get("dias") is not None else 99999, r["name"]))
    return rows


def summary(rows: list[dict]) -> dict:
    counts = {k: 0 for k in ORDER}
    for r in rows:
        counts[r["estado"]] = counts.get(r["estado"], 0) + 1
    last = max((r["checked_at"] for r in rows), default=None)
    return {"total": len(rows), "counts": counts, "problemas": sum(counts[k] for k in PROBLEMS), "quando": last,
            "antigo": bool(last and utcnow() - last > timedelta(hours=36))}

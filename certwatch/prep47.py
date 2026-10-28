"""Preparar os 47 dias: o que muda com a redução da validade dos certificados públicos (CA/Browser Forum, ballot SC-081)
e quanto trabalho de renovação isso traz a cada equipa.

  até 14-03-2026   398 dias de validade máxima; validação do domínio reutilizável 398 dias
  15-03-2026       200 dias; validação 200 dias
  15-03-2027       100 dias; validação 100 dias
  15-03-2029        47 dias; validação 10 dias

Só afeta certificados de autoridades públicas (as que os navegadores reconhecem). Os das CAs internas (CA1, CA2) seguem
as regras da própria organização. Os de renovação automática (ACME, ex.: Let's Encrypt) já se renovam sozinhos.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import date

from .config import Settings
from .normalize import norm_issuer

PHASES = [
    {"desde": date(2015, 1, 1), "dias": 398, "validacao": 398, "nome": "até março de 2026"},
    {"desde": date(2026, 3, 15), "dias": 200, "validacao": 200, "nome": "15 de março de 2026"},
    {"desde": date(2027, 3, 15), "dias": 100, "validacao": 100, "nome": "15 de março de 2027"},
    {"desde": date(2029, 3, 15), "dias": 47, "validacao": 10, "nome": "15 de março de 2029"},
]
CLASSES = {"manual": "CA pública, renovação manual", "auto": "Renovação automática", "interna": "CA interna",
           "desconhecida": "Emissor desconhecido"}


def renewals_per_year(max_days: int) -> float:
    return round(365 / max_days, 1)


def phase_for(today: date) -> int:
    return max(i for i, p in enumerate(PHASES) if p["desde"] <= today)


def classify(r: dict, internal: set[str]) -> str:
    issuer = r["live_issuer"] or (r["issuers"][0] if r["issuers"] else "")
    if not issuer:
        return "desconhecida"
    if norm_issuer(issuer) in internal:
        return "interna"
    return "auto" if r["renovacao"] == "auto" else "manual"


def analyse(inv: list[dict], settings: Settings, today: date, hours_per_renewal: float = 2.0) -> dict:
    internal = {norm_issuer(v) for v in settings.import_issuers.values() if v}
    cur = phase_for(today)
    nxt = PHASES[cur + 1] if cur + 1 < len(PHASES) else None
    rows, by_class = [], defaultdict(int)
    for r in inv:
        c = classify(r, internal)
        by_class[c] += 1
        if c == "manual":
            rows.append({**r, "classe": c})
    future = [p for p in PHASES[1:]]
    per_year = {p["dias"]: renewals_per_year(p["dias"]) for p in future}
    teams: dict[str, dict] = {}
    for r in rows:
        d = r.get("dono") or {}
        key = d.get("equipa") or "Sem dono"
        t = teams.setdefault(key, {"equipa": key, "equipa_id": d.get("equipa_id"), "n": 0})
        t["n"] += 1
    for t in teams.values():
        t["renov"] = {p["dias"]: round(t["n"] * per_year[p["dias"]]) for p in future}
        t["horas"] = round(t["n"] * per_year[47] * hours_per_renewal)
    n = len(rows)
    longer = [r for r in rows if r.get("vida_dias") and nxt and r["vida_dias"] > nxt["dias"]]
    public_total = by_class["manual"] + by_class["auto"]
    return {
        "phases": [{**p, "renov": renewals_per_year(p["dias"]), "atual": i == cur, "passada": i < cur} for i, p in enumerate(PHASES)],
        "atual": PHASES[cur], "proxima": nxt, "dias_ate": (nxt["desde"] - today).days if nxt else None,
        "classes": {k: by_class.get(k, 0) for k in CLASSES}, "manual": sorted(rows, key=lambda r: (r["dias"] is None, r["dias"] or 0)),
        "n_manual": n, "renov_total": {p["dias"]: round(n * per_year[p["dias"]]) for p in future},
        "horas_2029": round(n * per_year[47] * hours_per_renewal), "horas_hoje": round(n * per_year[200] * hours_per_renewal),
        "equipas": sorted(teams.values(), key=lambda t: (-t["n"], t["equipa"])), "mais_longos": longer,
        "sem_dono": sum(1 for r in rows if not r.get("dono")),
        "pct_auto": round(100 * by_class["auto"] / public_total) if public_total else None,
        "horas_renovacao": hours_per_renewal,
    }

"""Regras para abrir pedidos sozinho.

Uma regra diz quando um certificado (ou API) deve ter um pedido de renovação aberto: quando faltam N dias ou menos,
para que tipo, âmbito, renovação, emissor e equipa dona, e com que grupo do SMAX.

Nesta versão nenhuma regra abre pedidos sozinha. Uma regra ativa aparece no Painel e em Regras com os pedidos que
abriria hoje, e alguém confirma (o rascunho dos pedidos abre como em "Criar pedidos para os selecionados").
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Team, TicketRule

KINDS = {"certificado": "Certificados", "api": "APIs e segredos", "todos": "Certificados e APIs"}
SCOPES = {"todos": "Internos e externos", "externo": "Só externos (acessíveis da internet)", "interno": "Só internos"}
RENEWALS = {"manual": "Só renovação manual", "todos": "Manual e automática"}

TEMPLATES = [
    {"name": "Externos de renovação manual a 30 dias", "days": 30, "kind": "certificado", "scope": "externo", "renewal": "manual"},
    {"name": "Internos a 20 dias", "days": 20, "kind": "certificado", "scope": "interno", "renewal": "manual"},
    {"name": "Segredos de APIs a 30 dias", "days": 30, "kind": "api", "scope": "todos", "renewal": "todos"},
]


def rules(session: Session) -> list[TicketRule]:
    return list(session.scalars(select(TicketRule).order_by(TicketRule.enabled.desc(), TicketRule.days, TicketRule.id)))


def describe(r: TicketRule, teams: dict[int, Team]) -> str:
    parts = [f"faltam {r.days} dias ou menos", KINDS.get(r.kind, r.kind).lower()]
    if r.scope != "todos":
        parts.append(SCOPES[r.scope].lower().replace("só ", ""))
    if r.renewal == "manual":
        parts.append("renovação manual")
    if r.issuer_contains:
        parts.append(f"emissor com «{r.issuer_contains}»")
    if r.team_id and r.team_id in teams:
        parts.append(f"da equipa {teams[r.team_id].name}")
    return ", ".join(parts)


def matches(r: TicketRule, items: list[dict], inv_by_cn: dict[str, dict]) -> list[dict]:
    """Os pedidos que a regra abriria hoje: dos que expiram sem pedido em curso (os do Painel)."""
    out = []
    for it in items:
        if it["dias"] > r.days:
            continue
        is_api = it["tipo"] == "API"
        if (r.kind == "certificado" and is_api) or (r.kind == "api" and not is_api):
            continue
        row = inv_by_cn.get(it["criar"] or "") if not is_api else None
        if r.scope != "todos" and (row is None or row["scope"] != r.scope):
            continue
        if r.renewal == "manual" and it["auto"]:
            continue
        if r.issuer_contains and r.issuer_contains.lower() not in (it["emissor"] or "").lower():
            continue
        dono = (row or {}).get("dono") or {}
        if r.team_id and dono.get("equipa_id") != r.team_id:
            continue
        out.append({**it, "dono": dono or None})
    return out


def group_for(r: TicketRule, match: dict, teams: dict[int, Team]) -> str:
    """O grupo do SMAX que o pedido teria: o da regra, senão o da equipa dona, senão o do rascunho por omissão."""
    if r.smax_group:
        return r.smax_group
    d = match.get("dono") or {}
    t = teams.get(d.get("equipa_id")) if d.get("equipa_id") else None
    return (t.smax_group if t and t.smax_group else "") or "o grupo por omissão do rascunho"

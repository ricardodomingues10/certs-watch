"""Fonte: Microsoft Teams, para avisar o dono de um certificado no canal da equipa.

Planeado: não há avisos automáticos. Quando forem ligados, cada equipa tem um "Workflow" do Teams (ou um Incoming
Webhook) com um endereço próprio. Esse endereço dá para escrever no canal, por isso é um segredo: fica no ficheiro
secrets/teams_webhooks (JSON {"chave da equipa": "https://…"}), nunca na base de dados nem nas páginas. Em Donos, cada
equipa diz só a chave e se ela existe no ficheiro.
"""
from __future__ import annotations

import json
from pathlib import Path

FONTE = {
    "id": "teams", "nome": "Microsoft Teams (avisos aos donos)", "tipo": "Webhook", "estado": "planeado",
    "para": "Avisar no canal da equipa dona quando um certificado se aproxima do fim ou não tem pedido.",
    "config": ["secrets/teams_webhooks (JSON: chave da equipa → endereço do Workflow)"],
    "chamadas": [
        {"metodo": "POST", "endereco": "{endereço do Workflow da equipa} · Adaptive Card", "para": "mensagem no canal da equipa", "acesso": "envio", "estado": "planeado", "onde": "fontes/teams.py · post_card (sem uso automático)"},
    ],
}
SECRET = Path("/run/secrets/teams_webhooks")


def webhooks() -> dict[str, str]:
    """As chaves configuradas no ficheiro de segredo (os endereços não saem daqui)."""
    try:
        data = json.loads(SECRET.read_text(encoding="utf-8")) if SECRET.is_file() else {}
        return {str(k): str(v) for k, v in data.items() if str(v).startswith("https://")}
    except (OSError, ValueError):
        return {}


def estado(settings) -> tuple[bool, str]:
    n = len(webhooks())
    return (n > 0), (f"{n} equipa(s) com endereço" if n else "sem endereços em secrets/teams_webhooks")


def card(title: str, text: str, url: str = "") -> dict:
    """Mensagem (Adaptive Card) no formato que os Workflows do Teams aceitam."""
    body = [{"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "wrap": True},
            {"type": "TextBlock", "text": text, "wrap": True}]
    actions = [{"type": "Action.OpenUrl", "title": "Abrir no Atalaia Cert", "url": url}] if url else []
    return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {
        "type": "AdaptiveCard", "version": "1.4", "body": body, "actions": actions}}]}


def post_card(key: str, title: str, text: str, url: str = "", client=None) -> None:
    """Envia uma mensagem para o canal de uma equipa. Ainda não é chamado por nada automaticamente."""
    import httpx
    hook = webhooks().get(key)
    if not hook:
        raise ValueError(f"Sem endereço do Teams para a equipa {key!r} em secrets/teams_webhooks")
    c = client or httpx.Client(timeout=15)
    r = c.post(hook, json=card(title, text, url))
    if r.status_code >= 300:
        raise RuntimeError(f"O Teams respondeu HTTP {r.status_code}")

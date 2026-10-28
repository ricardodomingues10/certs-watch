"""Fonte: DNS público e interno.

Hoje: só a resolução dos nomes dos servidores (em fontes/servidores.py, pelo resolvedor do sistema).
Planeado: os registos CAA de cada domínio (que autoridades podem emitir certificados para ele) e alertas quando mudam
ou quando aparece na Certificate Transparency um certificado de uma autoridade que o CAA não autoriza. A biblioteca
padrão do Python não pergunta registos CAA: é preciso o dnspython (pip) ou um resolvedor DNS-over-HTTPS autorizado.
"""
from __future__ import annotations

FONTE = {
    "id": "dns", "nome": "DNS (resolução e CAA)", "tipo": "DNS", "estado": "resolução em uso; CAA planeado",
    "para": "Resolver os nomes dos servidores; no futuro, ler os registos CAA dos domínios.",
    "config": ["resolvedor DNS do servidor", "CERTWATCH_CT_DOMAINS (domínios a vigiar)"],
    "chamadas": [
        {"metodo": "DNS", "endereco": "A/AAAA {servidor}", "para": "o nome existe e para onde aponta", "acesso": "leitura", "estado": "em uso", "onde": "fontes/servidores.py"},
        {"metodo": "DNS", "endereco": "CAA {domínio} (e cada nível acima)", "para": "que autoridades podem emitir para o domínio", "acesso": "leitura", "estado": "planeado", "onde": "—"},
    ],
}


def estado(settings) -> tuple[bool, str]:
    return True, "resolução do sistema"

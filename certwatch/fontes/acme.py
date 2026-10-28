"""Fonte: ACME (o protocolo da Let's Encrypt, que DigiCert e Sectigo também aceitam), para renovar automaticamente.

Planeado. Com os certificados públicos a durar 200 dias (2026), 100 (2027) e 47 (2029), renovar à mão deixa de ser
sustentável. Um cliente ACME pede o certificado à autoridade, prova o domínio (registo DNS ou ficheiro HTTP) e devolve-o
para instalar (no AVI, IIS, Azure Key Vault, …). O ARI (RFC 9773) diz a cada certificado quando renovar.
"""
from __future__ import annotations

FONTE = {
    "id": "acme", "nome": "ACME (renovação automática)", "tipo": "API REST (ACME)", "estado": "planeado",
    "para": "Pedir e renovar certificados públicos sem intervenção, à hora que a autoridade recomenda (ARI).",
    "config": ["conta ACME / EAB da autoridade (segredo)", "credenciais do DNS para o desafio dns-01 (segredo)"],
    "chamadas": [
        {"metodo": "GET", "endereco": "{autoridade}/directory", "para": "os endereços do serviço ACME", "acesso": "leitura", "estado": "planeado", "onde": "—"},
        {"metodo": "POST", "endereco": "newAccount · newOrder · challenge · finalize (JWS)", "para": "pedir o certificado e provar o domínio", "acesso": "escrita", "estado": "planeado", "onde": "—"},
        {"metodo": "GET", "endereco": "{autoridade}/renewalInfo/{id do certificado}", "para": "quando renovar (ARI, RFC 9773)", "acesso": "leitura", "estado": "planeado", "onde": "—"},
    ],
}


def estado(settings) -> tuple[bool, str]:
    return False, "por implementar"

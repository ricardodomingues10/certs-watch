"""Fonte: Microsoft Entra ID (Azure AD), as App Registrations e os seus segredos e certificados.

Hoje: por ficheiro. A exportação (EnterpriseApplication;AppRegistration;AppId;CredentialType;KeyId;StartDate;EndDate;Status)
é posta em import/azure*.csv ou carregada em Atualizar a CMDB; a leitura está em azure_rec.read_azure.

Por API (planeado): Microsoft Graph com uma App Registration própria do Atalaia, permissão de aplicação
Application.Read.All (só leitura) e autenticação por certificado (client credentials; a chave privada num ficheiro de
segredo, nunca na base de dados). Devolve o mesmo que a exportação: cada segredo e certificado com a data de fim.
"""
from __future__ import annotations

from datetime import date

FONTE = {
    "id": "azure", "nome": "Azure (App Registrations)", "tipo": "Ficheiro", "estado": "em uso por ficheiro; API planeada",
    "para": "Segredos e certificados das App Registrations, com a data de fim, comparados com a lista de APIs da CMDB.",
    "config": ["CERTWATCH_IMPORT_DIR (azure*)"],
    "chamadas": [
        {"metodo": "Ficheiro", "endereco": "import/azure*.csv", "para": "exportação das App Registrations", "acesso": "leitura", "estado": "em uso", "onde": "azure_rec.py · read_azure"},
        {"metodo": "POST", "endereco": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token", "para": "token por certificado (client credentials)", "acesso": "leitura", "estado": "planeado", "onde": "—"},
        {"metodo": "GET", "endereco": "https://graph.microsoft.com/v1.0/applications?$select=appId,displayName,passwordCredentials,keyCredentials", "para": "segredos e certificados de cada App Registration (paginado)", "acesso": "leitura", "estado": "planeado", "onde": "—"},
        {"metodo": "GET", "endereco": "https://graph.microsoft.com/v1.0/servicePrincipals?$select=appId,displayName", "para": "o nome da Enterprise Application", "acesso": "leitura", "estado": "planeado", "onde": "—"},
    ],
}


def estado(settings) -> tuple[bool, str]:
    return True, "por ficheiro"


def read(data: bytes, filename: str, today: date):
    from ..azure_rec import read_azure
    return read_azure(data, filename, today)

"""Fonte: as autoridades de certificação internas (CA1 e CA2, Microsoft AD CS).

Hoje: por ficheiro. A exportação da base de dados de cada CA (certutil, CSV em UTF-16, ou Excel) é posta na diretoria
import/ com o nome a começar por ca1 ou ca2, ou carregada em Atualizar a CMDB. A leitura está em cmdb_final.read_source
(colunas Issued Common Name, Certificate Expiration Date, Serial Number, Request Disposition).

Por API (planeado, ver FONTE["chamadas"]): o AD CS não tem uma API REST de inventário. Os caminhos possíveis são:
  1. Um script agendado na própria CA (certutil -view ... csv) que deixa o ficheiro numa partilha lida pelo Atalaia
     (não muda nada aqui, só deixa de ser preciso exportar à mão).
  2. PowerShell remoto (WinRM sobre HTTPS, porta 5986) com uma conta só de leitura na CA, a ler a base de dados
     (ICertView / módulo PSPKI) e a devolver JSON.
  3. Os registos de auditoria da CA enviados para o SIEM, lidos de lá.
"""
from __future__ import annotations

from datetime import date

FONTE = {
    "id": "ca", "nome": "CAs internas (CA1, CA2 · AD CS)", "tipo": "Ficheiro", "estado": "em uso por ficheiro; API planeada",
    "para": "Os certificados emitidos pelas CAs internas: nome, validade, série e estado do pedido.",
    "config": ["CERTWATCH_IMPORT_DIR (ca1*, ca2*)", "CERTWATCH_IMPORT_ISSUERS", "CERTWATCH_FINAL_SOURCES"],
    "chamadas": [
        {"metodo": "Ficheiro", "endereco": "import/ca1*.csv · import/ca2*.csv (ou .xlsx)", "para": "exportação certutil de cada CA", "acesso": "leitura", "estado": "em uso", "onde": "cmdb_final.py · read_source"},
        {"metodo": "Ficheiro", "endereco": "partilha de rede com o CSV gerado por um script agendado na CA", "para": "deixar de exportar à mão", "acesso": "leitura", "estado": "planeado", "onde": "—"},
        {"metodo": "WinRM", "endereco": "https://{ca}:5986/wsman · ICertView", "para": "ler a base de dados da CA diretamente (conta só de leitura)", "acesso": "leitura", "estado": "planeado", "onde": "—"},
    ],
}


def estado(settings) -> tuple[bool, str]:
    return True, "por ficheiro (" + ", ".join(s for s in settings.final_sources if s.startswith("CA")) + ")"


def read(source: str, filename: str, data: bytes, today: date):
    """Lê uma exportação de uma CA (o mesmo que Atualizar a CMDB usa)."""
    from ..cmdb_final import read_source
    return read_source(source, filename, data, today)

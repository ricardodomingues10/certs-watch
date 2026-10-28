"""Fontes: cada sistema com que o Atalaia Cert fala tem o seu ficheiro aqui.

Cada módulo declara FONTE (o que faz, como, a configuração e cada chamada: método, endereço, para quê, se é leitura ou
escrita, se está em uso ou planeada e onde está o código) e estado(settings) (ligada ou não, e porquê). A página
Sistema → Fontes e chamadas mostra tudo isto.

  ucmdb.py       UCMDB (API REST)                  smax.py      SMAX (API REST)
  avi.py         AVI (API REST ou ficheiro)        ca.py        CAs internas CA1/CA2 (ficheiro; API planeada)
  azure.py       Azure App Registrations (ficheiro; Graph planeado)
  ct.py          Certificate Transparency          ssllabs.py   SSL Labs
  servidores.py  ligação TLS direta aos servidores email.py     servidor de email (SMTP)
  teams.py       Microsoft Teams (planeado)        dns.py       DNS (resolução; CAA planeado)
  acme.py        ACME, renovação automática (planeado)
"""
from __future__ import annotations

from importlib import import_module

ORDER = ("ucmdb", "smax", "avi", "ca", "azure", "ct", "servidores", "ssllabs", "email", "teams", "dns", "acme")


def all_sources(settings) -> list[dict]:
    """Todas as fontes, com as chamadas e se estão ligadas nesta instalação."""
    out = []
    for name in ORDER:
        mod = import_module(f"{__name__}.{name}")
        f = dict(mod.FONTE)
        try:
            ok, detail = mod.estado(settings)
        except Exception as exc:                         # uma fonte mal configurada não estraga a página
            ok, detail = False, f"erro ao ver o estado: {type(exc).__name__}"
        f.update(ligada=ok, detalhe=detail, modulo=f"certwatch/fontes/{name}.py")
        out.append(f)
    return out

"""Configuração da aplicação.

Valores não sensíveis vêm de variáveis de ambiente (CERTWATCH_*).
Segredos vêm de ficheiros (/run/secrets/<nome> ou <VAR>_FILE); a variável
de ambiente direta só é aceite como último recurso (útil em testes).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote


def _env(name: str, default: str | None = None) -> str | None:
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def _secret(name: str, env_var: str) -> str | None:
    candidates = []
    if _env(f"{env_var}_FILE"):
        candidates.append(Path(_env(f"{env_var}_FILE")))
    candidates.append(Path("/run/secrets") / name)
    for p in candidates:
        try:
            if p.is_file():
                return p.read_text(encoding="utf-8").strip()
        except PermissionError as exc:
            raise RuntimeError(f"Sem permissão para ler o segredo {p}") from exc
    return _env(env_var)


def _str_list(value: str | None) -> list[str]:
    """Lista separada por vírgulas, ponto e vírgula ou espaços; minúsculas, sem repetidos."""
    out: list[str] = []
    for x in re.split(r"[,;\s]+", value or ""):
        x = x.strip().lower()
        if x and x not in out:
            out.append(x)
    return out


def _pattern_list(value: str | None) -> list[str]:
    """Expressões regulares separadas por ';' (a vírgula pode fazer parte de uma expressão)."""
    return [x.strip() for x in (value or "").split(";") if x.strip()]


def _kv_map(value: str | None) -> dict[str, str]:
    """'CA1=Nome A;CA2=Nome B' -> {'CA1': 'Nome A', 'CA2': 'Nome B'}"""
    out = {}
    for part in (value or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            if k.strip():
                out[k.strip().upper()] = v.strip()
    return out


def _int_list(value: str) -> list[int]:
    return sorted({int(x) for x in value.split(",") if x.strip()})


DEFAULT_IMPORT_SOURCES = "CA1=ca1;CA2=ca2;AVI=avi;AZURE=azure"

# Let's Encrypt: pelo nome da organização ou pelo CN das intermédias (R3, R10, R11, E5, E6, YR1...),
# que é muitas vezes o único texto que fica no campo Issuer da CMDB.
DEFAULT_AUTO_RENEW = r"let'?s ?encrypt;\bisrg\b;^(cn=)?[re]\d{1,2}$;^(cn=)?y[re]\d{1,2}$"


@dataclass(frozen=True)
class Settings:
    # Base de dados
    database_url: str

    # UCMDB
    ucmdb_url: str
    ucmdb_tql: str
    ucmdb_user: str | None
    ucmdb_password: str | None
    ucmdb_client_context: int
    ucmdb_min_cis: int
    ucmdb_verify_tls: bool

    # Lista de APIs na UCMDB (opcional)
    ucmdb_tql_apis: str
    apis_min: int
    apis_field_name: str
    apis_field_url: str
    apis_field_expiry: str
    apis_field_app: str
    apis_field_location: str
    apis_field_expired: str
    apis_field_registered: str
    apis_enrich: str          # auto | query | ci | off
    apis_file: str            # prefixo do ficheiro de exportação na diretoria de importação

    # Descoberta na internet (Certificate Transparency)
    ct_domains: list[str]
    ct_sources: list[str]
    ct_include_expired_days: int
    certspotter_api_key: str | None
    ctlogs_api_key: str | None

    # Avaliação externa Qualys SSL Labs (opcional; exige registo com email da organização)
    ssllabs_email: str
    ssllabs_max_hosts: int
    ssllabs_max_age_days: int
    ssllabs_budget_min: int

    # Reconciliação com ficheiros de exportação
    import_dir: Path
    import_sources: dict[str, str]
    import_issuers: dict[str, str]

    # Classificação interno / externo
    internal_suffixes: list[str]
    internal_issuer_patterns: list[str]

    # Confiança TLS
    trust_dir: Path
    system_ca_bundle: Path

    # Scanner
    scan_default_port: int
    scan_allowed_ports: list[int]
    scan_timeout: float
    scan_workers: int
    unreachable_after: int

    # Regras
    expiry_thresholds: dict[str, int] = field(default_factory=dict)
    lifetime_warn_pct: float = 0.2
    # Renovação automática (ACME / Let's Encrypt): emissores reconhecidos e prazo a partir do qual se alerta
    auto_renew_issuers: list[str] = field(default_factory=list)
    auto_renew_alert_days: int = 20

    # Agendamento
    pipeline_daily_at: str = "06:15"
    timezone: str = "Europe/Lisbon"

    # Interface web
    admin_user: str = "admin"
    admin_password: str | None = None
    cookie_secure: bool = False

    @staticmethod
    def from_env() -> "Settings":
        db_url = _env("CERTWATCH_DATABASE_URL")
        if not db_url:
            user = _env("CERTWATCH_DB_USER", "certwatch")
            pwd = _secret("db_password", "CERTWATCH_DB_PASSWORD") or ""
            host = _env("CERTWATCH_DB_HOST", "127.0.0.1")
            port = _env("CERTWATCH_DB_PORT", "55432")
            name = _env("CERTWATCH_DB_NAME", "certwatch")
            db_url = f"postgresql+psycopg://{quote(user)}:{quote(pwd)}@{host}:{port}/{quote(name)}"

        return Settings(
            database_url=db_url,
            ucmdb_url=_env("CERTWATCH_UCMDB_URL", ""),
            ucmdb_tql=_env("CERTWATCH_UCMDB_TQL", ""),
            ucmdb_user=_secret("ucmdb_user", "CERTWATCH_UCMDB_USER"),
            ucmdb_password=_secret("ucmdb_password", "CERTWATCH_UCMDB_PASSWORD"),
            ucmdb_client_context=int(_env("CERTWATCH_UCMDB_CLIENT_CONTEXT", "1")),
            ucmdb_min_cis=int(_env("CERTWATCH_UCMDB_MIN_CIS", "300")),
            ucmdb_verify_tls=_env("CERTWATCH_UCMDB_VERIFY_TLS", "true").lower() != "false",
            ucmdb_tql_apis=_env("CERTWATCH_UCMDB_TQL_APIS", ""),
            apis_min=int(_env("CERTWATCH_APIS_MIN", "1")),
            apis_field_name=_env("CERTWATCH_APIS_FIELD_NAME", ""),
            apis_field_url=_env("CERTWATCH_APIS_FIELD_URL", ""),
            apis_field_expiry=_env("CERTWATCH_APIS_FIELD_EXPIRY", ""),
            apis_field_app=_env("CERTWATCH_APIS_FIELD_APP", ""),
            apis_field_location=_env("CERTWATCH_APIS_FIELD_LOCATION", ""),
            apis_field_expired=_env("CERTWATCH_APIS_FIELD_EXPIRED", ""),
            apis_field_registered=_env("CERTWATCH_APIS_FIELD_REGISTERED", ""),
            apis_enrich=(_env("CERTWATCH_APIS_ENRICH", "auto") or "auto").lower(),
            apis_file=(_env("CERTWATCH_APIS_FILE", "api-cmdb") or "").lower(),
            ct_domains=_str_list(_env("CERTWATCH_CT_DOMAINS", "")),
            ct_sources=_str_list(_env("CERTWATCH_CT_SOURCES", "crtsh,certspotter,ctlogs")),
            ct_include_expired_days=int(_env("CERTWATCH_CT_INCLUDE_EXPIRED_DAYS", "0")),
            certspotter_api_key=_secret("certspotter_api_key", "CERTWATCH_CERTSPOTTER_API_KEY"),
            ctlogs_api_key=_secret("ctlogs_api_key", "CERTWATCH_CTLOGS_API_KEY"),
            ssllabs_email=_env("CERTWATCH_SSLLABS_EMAIL", ""),
            ssllabs_max_hosts=int(_env("CERTWATCH_SSLLABS_MAX_HOSTS", "25")),
            ssllabs_max_age_days=int(_env("CERTWATCH_SSLLABS_MAX_AGE_DAYS", "7")),
            ssllabs_budget_min=int(_env("CERTWATCH_SSLLABS_BUDGET_MIN", "30")),
            import_dir=Path(_env("CERTWATCH_IMPORT_DIR", "/app/import")),
            # As fontes do .env juntam-se às de origem (um .env antigo sem AZURE continua a reconhecer azure*)
            import_sources={**_kv_map(DEFAULT_IMPORT_SOURCES), **_kv_map(_env("CERTWATCH_IMPORT_SOURCES", ""))},
            import_issuers=_kv_map(_env("CERTWATCH_IMPORT_ISSUERS", "")),
            internal_suffixes=_str_list(_env("CERTWATCH_INTERNAL_SUFFIXES", ".local,.lan,.internal,.intranet,.corp")),
            internal_issuer_patterns=_str_list(_env("CERTWATCH_INTERNAL_ISSUER_PATTERNS", "internal,interna")),
            trust_dir=Path(_env("CERTWATCH_TRUST_DIR", "/app/trust")),
            system_ca_bundle=Path(_env("CERTWATCH_SYSTEM_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt")),
            scan_default_port=int(_env("CERTWATCH_SCAN_DEFAULT_PORT", "443")),
            scan_allowed_ports=_int_list(_env("CERTWATCH_SCAN_ALLOWED_PORTS", "443,465,636,993,995,4443,5986,8443,9443")),
            scan_timeout=float(_env("CERTWATCH_SCAN_TIMEOUT", "8")),
            scan_workers=int(_env("CERTWATCH_SCAN_WORKERS", "16")),
            unreachable_after=int(_env("CERTWATCH_UNREACHABLE_AFTER", "2")),
            expiry_thresholds={
                "critica": int(_env("CERTWATCH_EXPIRY_CRITICA", "7")),
                "alta": int(_env("CERTWATCH_EXPIRY_ALTA", "20")),
                "media": int(_env("CERTWATCH_EXPIRY_MEDIA", "30")),
                "baixa": int(_env("CERTWATCH_EXPIRY_BAIXA", "90")),
            },
            lifetime_warn_pct=float(_env("CERTWATCH_LIFETIME_WARN_PCT", "0.2")),
            auto_renew_issuers=_pattern_list(_env("CERTWATCH_AUTO_RENEW_ISSUERS", DEFAULT_AUTO_RENEW)),
            auto_renew_alert_days=int(_env("CERTWATCH_AUTO_RENEW_ALERT_DAYS", "20")),
            pipeline_daily_at=_env("CERTWATCH_PIPELINE_DAILY_AT", "06:15"),
            timezone=_env("CERTWATCH_TIMEZONE", "Europe/Lisbon"),
            admin_user=_env("CERTWATCH_ADMIN_USER", "admin"),
            admin_password=_secret("admin_password", "CERTWATCH_ADMIN_PASSWORD"),
            cookie_secure=_env("CERTWATCH_COOKIE_SECURE", "false").lower() == "true",
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.from_env()

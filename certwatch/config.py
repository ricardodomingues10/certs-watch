"""Configuração da aplicação.

Valores não sensíveis vêm de variáveis de ambiente (CERTWATCH_*).
Segredos vêm de ficheiros (/run/secrets/<nome> ou <VAR>_FILE); a variável
de ambiente direta só é aceite como último recurso (útil em testes).
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote


def _env(name: str, default: str | None = None) -> str | None:
    v = os.environ.get(name)
    return v if v not in (None, "") else default


# Segredos opcionais que existem mas não se conseguem ler (ex.: dono errado): a aplicação arranca na mesma e a
# funcionalidade diz o que corrigir. Os obrigatórios (base de dados, admin) continuam a impedir o arranque.
UNREADABLE_SECRETS: set[str] = set()


def _secret(name: str, env_var: str, required: bool = False) -> str | None:
    candidates = []
    if _env(f"{env_var}_FILE"):
        candidates.append(Path(_env(f"{env_var}_FILE")))
    candidates.append(Path("/run/secrets") / name)
    for p in candidates:
        try:
            if p.is_file():
                UNREADABLE_SECRETS.discard(name)
                return p.read_text(encoding="utf-8").strip()
        except PermissionError as exc:
            if required:
                raise RuntimeError(f"Sem permissão para ler o segredo {p} (dono deve ser o UID 10001: "
                                   f"sudo chown 10001:10001 secrets/{name} && sudo chmod 400 secrets/{name})") from exc
            if name not in UNREADABLE_SECRETS:
                logging.getLogger(__name__).error(
                    "Sem permissão para ler o segredo %s: sudo chown 10001:10001 secrets/%s && sudo chmod 400 secrets/%s",
                    p, name, name)
            UNREADABLE_SECRETS.add(name)
            return None
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


def _attr_map(value: str | None) -> dict[str, str]:
    """'SGSI=Sim;scml_status_key=1' -> {'SGSI': 'Sim', 'scml_status_key': '1'} (nomes de atributos: mantém maiúsculas)"""
    out = {}
    for part in (value or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            if k.strip():
                out[k.strip()] = v.strip()
    return out


def _kv_map(value: str | None) -> dict[str, str]:
    """'CA1=Nome A;CA2=Nome B' -> {'CA1': 'Nome A', 'CA2': 'Nome B'}"""
    out = {}
    for part in (value or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            if k.strip():
                out[k.strip().upper()] = v.strip()
    return out


def _json_fields(value: str | None, name: str) -> dict:
    """Campos de um pedido em JSON ({"PhaseId": "Close", ...}); só nomes simples e valores simples."""
    import json
    try:
        data = json.loads(value or "{}")
    except ValueError as exc:
        raise RuntimeError(f"{name} não é JSON válido: {exc}") from exc
    if not isinstance(data, dict) or not all(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", str(k)) for k in data) \
            or not all(isinstance(v, (str, int, float, bool)) for v in data.values()):
        raise RuntimeError(f"{name}: use um objeto JSON simples, por exemplo {{\"PhaseId\": \"Close\"}}")
    return data


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
    ct_scan: bool
    ct_scan_max: int
    certspotter_api_key: str | None
    ctlogs_api_key: str | None

    # SMAX (só leitura de tickets)
    smax_url: str
    smax_tenant: str
    smax_user: str | None
    smax_password: str | None
    smax_entity: str
    smax_filter: str
    smax_fields: dict[str, str]
    smax_closed_phases: list[str]
    smax_ticket_url: str
    smax_verify_tls: bool
    smax_max_tickets: int
    smax_comments: bool
    smax_comments_max: int
    smax_discussions_url: str
    # SMAX: criação de pedidos (desligada por omissão)
    smax_create_enabled: bool
    smax_change_model: str
    smax_service: str
    smax_data_domains: list[str]
    smax_default_app_id: str
    smax_default_responsible: str
    smax_env_codes: dict[str, str]
    smax_type_options: list[str]
    smax_create_max: int
    smax_description_sign: str

    # Avaliação externa Qualys SSL Labs (opcional; exige registo com email da organização)
    ssllabs_email: str
    ssllabs_max_hosts: int
    ssllabs_max_age_days: int
    ssllabs_budget_min: int

    # Reconciliação com ficheiros de exportação
    import_dir: Path
    import_sources: dict[str, str]
    import_issuers: dict[str, str]
    apis_create_defaults: dict[str, str]   # atributos fixos ao criar uma API (os obrigatórios que faltem)

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
    # AVI pela REST API (alternativa ao ficheiro avi* em import/)
    avi_url: str = ""
    avi_tenant: str = "admin"
    avi_endpoint: str = "/api/sslkeyandcertificate?type=SSL_CERTIFICATE_TYPE_VIRTUALSERVICE"
    avi_endpoint_ca: str = "/api/sslkeyandcertificate?type=SSL_CERTIFICATE_TYPE_CA"
    avi_user: str | None = None
    avi_password: str | None = None
    avi_verify_tls: bool = True
    avi_version: str = ""
    avi_page_size: int = 100
    client_name: str = ""              # nome do cliente mostrado na interface (ex.: Santa Casa da Misericórdia de Lisboa)
    branding_dir: Path = Path("/app/branding")   # logo do cliente: logo.svg, logo.png ou logo.webp
    logo_style: str = "original"       # original (transparente, como é) | claro (branco, para fundos escuros) | placa
    logo_animation: str = "sempre"     # animação da vigia: sempre | auto (para se o sistema pedir menos movimento) | parado
    ui_palette: str = "consola"         # tema por omissão: consola | assinatura | relatorio
    dash_expiry_days: int = 20          # painel: "expiram sem pedido" nos próximos N dias
    dash_stale_days: int = 10           # painel: pedido aberto sem movimento há N dias = parado
    avi_source: str = "ficheiro"        # ficheiro | api | auto (API, e o ficheiro se a API falhar)
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

    # Escrever na UCMDB pela REST API (criar e atualizar certificados em vez do certs_update.csv)
    ucmdb_write: bool = False
    ucmdb_cert_type: str = "digital_certificate"
    smax_files_max: int = 200                      # imagens/anexos novos descarregados por leitura do SMAX
    # Fechar / reabrir pedidos no SMAX (bulk UPDATE). Os campos dependem do modelo de change.
    smax_update_enabled: bool = False
    smax_close_fields: dict = field(default_factory=lambda: {"PhaseId": "Close"})
    smax_reopen_fields: dict = field(default_factory=lambda: {"PhaseId": "Execute"})
    smax_comment_privacy: str = "INTERNAL"

    # Relatório por email
    smtp_host: str = ""
    smtp_port: int = 25
    smtp_security: str = "starttls"               # starttls | ssl | none
    smtp_from: str = ""
    smtp_user: str = ""
    smtp_password: str | None = None
    report_to: list[str] = field(default_factory=list)
    report_allowed_domains: list[str] = field(default_factory=list)
    report_signature: str = "Atalaia Cert"
    report_window_days: int = 90
    report_alert_days: int = 20

    # CMDB final (CMDB_Final.xlsx e certs_update*.csv)
    final_sources: list[str] = field(default_factory=lambda: ["CA1", "CA2", "AVI"])
    final_ct: bool = True                          # incluir os certificados encontrados na internet
    final_enrich: str = "auto"                     # auto | query | ci | off
    final_header_prefix: str = "[Digital Certificate] : "
    final_description: str = "Changed with n8n"
    final_live_marker: str = "Validado via TLS"
    final_live_max_age_h: int = 24
    final_columns_file: str = "cmdb-colunas"
    final_keep_runs: int = 20

    @staticmethod
    def from_env() -> "Settings":
        db_url = _env("CERTWATCH_DATABASE_URL")
        if not db_url:
            user = _env("CERTWATCH_DB_USER", "certwatch")
            pwd = _secret("db_password", "CERTWATCH_DB_PASSWORD", required=True) or ""
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
            ct_scan=_env("CERTWATCH_CT_SCAN", "true").lower() != "false",
            ct_scan_max=int(_env("CERTWATCH_CT_SCAN_MAX", "500")),
            certspotter_api_key=_secret("certspotter_api_key", "CERTWATCH_CERTSPOTTER_API_KEY"),
            ctlogs_api_key=_secret("ctlogs_api_key", "CERTWATCH_CTLOGS_API_KEY"),
            smax_url=_env("CERTWATCH_SMAX_URL", ""),
            smax_tenant=_env("CERTWATCH_SMAX_TENANT", ""),
            smax_user=_secret("smax_user", "CERTWATCH_SMAX_USER"),
            smax_password=_secret("smax_password", "CERTWATCH_SMAX_PASSWORD"),
            smax_entity=_env("CERTWATCH_SMAX_ENTITY", "Change"),
            smax_filter=_env("CERTWATCH_SMAX_FILTER", ""),
            smax_fields={
                "endpoint": _env("CERTWATCH_SMAX_FIELD_ENDPOINT", "Endpoint_c"),
                "expiry": _env("CERTWATCH_SMAX_FIELD_EXPIRY", "DataExpiracao_c"),
                "env": _env("CERTWATCH_SMAX_FIELD_ENV", "Ambiente_c"),
                "type": _env("CERTWATCH_SMAX_FIELD_TYPE", "TipoCertificado_c"),
            },
            smax_closed_phases=_str_list(_env("CERTWATCH_SMAX_CLOSED_PHASES", "Close,Closed,Abandon,Abandoned,Done")),
            smax_ticket_url=_env("CERTWATCH_SMAX_TICKET_URL", "{base}/saw/{entity}/{id}/general?TENANTID={tenant}"),
            smax_verify_tls=_env("CERTWATCH_SMAX_VERIFY_TLS", "true").lower() != "false",
            smax_max_tickets=int(_env("CERTWATCH_SMAX_MAX_TICKETS", "20000")),
            smax_comments=_env("CERTWATCH_SMAX_COMMENTS", "true").lower() != "false",
            smax_comments_max=int(_env("CERTWATCH_SMAX_COMMENTS_MAX", "300")),
            smax_discussions_url=_env("CERTWATCH_SMAX_DISCUSSIONS_URL", "{base}/saw/{entity}/{id}/discussions?TENANTID={tenant}"),
            smax_create_enabled=_env("CERTWATCH_SMAX_CREATE_ENABLED", "false").lower() == "true",
            smax_change_model=_env("CERTWATCH_SMAX_CHANGE_MODEL", ""),
            smax_service=_env("CERTWATCH_SMAX_SERVICE", ""),
            smax_data_domains=[x.strip() for x in (_env("CERTWATCH_SMAX_DATA_DOMAINS", "") or "").split(",") if x.strip()],
            smax_default_app_id=_env("CERTWATCH_SMAX_DEFAULT_APP_ID", ""),
            smax_default_responsible=_env("CERTWATCH_SMAX_DEFAULT_RESPONSIBLE", ""),
            smax_env_codes=_kv_map(_env("CERTWATCH_SMAX_ENV_CODES",
                                        "DEV=Name1_c;TST=Name2_c;SIT=Name3_c;UAT=Name4_c;PRE=Name5_c;PPRD=Name5_c;PRD=Name6_c")),
            smax_type_options=[x.strip() for x in (_env("CERTWATCH_SMAX_TYPE_OPTIONS", "Interno;Externo") or "").split(";") if x.strip()],
            smax_create_max=int(_env("CERTWATCH_SMAX_CREATE_MAX", "50")),
            smax_description_sign=_env("CERTWATCH_SMAX_DESCRIPTION_SIGN", "Obrigada"),
            ssllabs_email=_env("CERTWATCH_SSLLABS_EMAIL", ""),
            ssllabs_max_hosts=int(_env("CERTWATCH_SSLLABS_MAX_HOSTS", "25")),
            ssllabs_max_age_days=int(_env("CERTWATCH_SSLLABS_MAX_AGE_DAYS", "7")),
            ssllabs_budget_min=int(_env("CERTWATCH_SSLLABS_BUDGET_MIN", "30")),
            import_dir=Path(_env("CERTWATCH_IMPORT_DIR", "/app/import")),
            # As fontes do .env juntam-se às de origem (um .env antigo sem AZURE continua a reconhecer azure*)
            import_sources={**_kv_map(DEFAULT_IMPORT_SOURCES), **_kv_map(_env("CERTWATCH_IMPORT_SOURCES", ""))},
            import_issuers=_kv_map(_env("CERTWATCH_IMPORT_ISSUERS", "")),
            apis_create_defaults=_attr_map(_env("CERTWATCH_APIS_CREATE_DEFAULTS", "")),
            avi_url=_env("CERTWATCH_AVI_URL", ""),
            avi_tenant=_env("CERTWATCH_AVI_TENANT", "admin"),
            avi_endpoint=_env("CERTWATCH_AVI_ENDPOINT", "/api/sslkeyandcertificate?type=SSL_CERTIFICATE_TYPE_VIRTUALSERVICE"),
            avi_endpoint_ca=_env("CERTWATCH_AVI_ENDPOINT_CA", "/api/sslkeyandcertificate?type=SSL_CERTIFICATE_TYPE_CA"),
            avi_user=_secret("avi_user", "CERTWATCH_AVI_USER"),
            avi_password=_secret("avi_password", "CERTWATCH_AVI_PASSWORD"),
            avi_verify_tls=_env("CERTWATCH_AVI_VERIFY_TLS", "true").lower() != "false",
            avi_version=_env("CERTWATCH_AVI_VERSION", ""),
            avi_page_size=int(_env("CERTWATCH_AVI_PAGE_SIZE", "100")),
            avi_source=(_env("CERTWATCH_AVI_SOURCE", "ficheiro") or "ficheiro").lower(),
            ui_palette=(_env("CERTWATCH_UI_PALETTE", "consola") or "consola").lower(),
            client_name=_env("CERTWATCH_CLIENT_NAME", ""),
            branding_dir=Path(_env("CERTWATCH_BRANDING_DIR", "/app/branding")),
            logo_style=(_env("CERTWATCH_LOGO_STYLE", "original") or "original").lower(),
            logo_animation=(_env("CERTWATCH_LOGO_ANIMATION", "sempre") or "sempre").lower(),
            dash_expiry_days=int(_env("CERTWATCH_DASH_EXPIRY_DAYS", "20")),
            dash_stale_days=int(_env("CERTWATCH_DASH_STALE_DAYS", "10")),
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
            admin_password=_secret("admin_password", "CERTWATCH_ADMIN_PASSWORD", required=True),
            cookie_secure=_env("CERTWATCH_COOKIE_SECURE", "false").lower() == "true",
            ucmdb_write=_env("CERTWATCH_UCMDB_WRITE", "false").lower() == "true",
            ucmdb_cert_type=_env("CERTWATCH_UCMDB_CERT_TYPE", "digital_certificate"),
            smax_files_max=int(_env("CERTWATCH_SMAX_FILES_MAX", "200")),
            smax_update_enabled=_env("CERTWATCH_SMAX_UPDATE_ENABLED",
                                     _env("CERTWATCH_SMAX_CREATE_ENABLED", "false")).lower() == "true",
            smax_close_fields=_json_fields(_env("CERTWATCH_SMAX_CLOSE_FIELDS", '{"PhaseId": "Close"}'), "CERTWATCH_SMAX_CLOSE_FIELDS"),
            smax_reopen_fields=_json_fields(_env("CERTWATCH_SMAX_REOPEN_FIELDS", '{"PhaseId": "Execute"}'), "CERTWATCH_SMAX_REOPEN_FIELDS"),
            smax_comment_privacy=_env("CERTWATCH_SMAX_COMMENT_PRIVACY", "INTERNAL").upper(),
            smtp_host=_env("CERTWATCH_SMTP_HOST", ""),
            smtp_port=int(_env("CERTWATCH_SMTP_PORT", "25")),
            smtp_security=_env("CERTWATCH_SMTP_SECURITY", "starttls").lower(),
            smtp_from=_env("CERTWATCH_SMTP_FROM", ""),
            smtp_user=_env("CERTWATCH_SMTP_USER", ""),
            smtp_password=_secret("smtp_password", "CERTWATCH_SMTP_PASSWORD"),
            report_to=_str_list(_env("CERTWATCH_REPORT_TO", "")),
            report_allowed_domains=_str_list(_env("CERTWATCH_REPORT_ALLOWED_DOMAINS", "")),
            report_signature=_env("CERTWATCH_REPORT_SIGNATURE", "Atalaia Cert"),
            report_window_days=int(_env("CERTWATCH_REPORT_WINDOW_DAYS", "90")),
            report_alert_days=int(_env("CERTWATCH_REPORT_ALERT_DAYS", "20")),
            final_sources=[x.upper() for x in _str_list(_env("CERTWATCH_FINAL_SOURCES", "CA1,CA2,AVI"))],
            final_ct=_env("CERTWATCH_FINAL_CT", "true").lower() != "false",
            final_enrich=_env("CERTWATCH_FINAL_ENRICH", "auto").lower(),
            final_header_prefix=_env("CERTWATCH_FINAL_HEADER_PREFIX", "[Digital Certificate] : "),
            final_description=_env("CERTWATCH_FINAL_DESCRIPTION", "Changed with n8n"),
            final_live_marker=_env("CERTWATCH_FINAL_LIVE_MARKER", "Validado via TLS"),
            final_live_max_age_h=int(_env("CERTWATCH_FINAL_LIVE_MAX_AGE_H", "24")),
            final_columns_file=_env("CERTWATCH_FINAL_COLUMNS_FILE", "cmdb-colunas").lower(),
            final_keep_runs=int(_env("CERTWATCH_FINAL_KEEP_RUNS", "20")),
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.from_env()

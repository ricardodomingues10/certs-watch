"""Modelo de dados.

Regra de confiança: da CMDB só se usam CommonName, ValidTo e Issuer/IssuerName.
Tudo o que é técnico (serial, fingerprint, SANs, algoritmos) vem do scan live.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, utcnow


class CmdbRecord(Base):
    """Um CI digital_certificate tal como existe na UCMDB (campos confiáveis apenas)."""

    __tablename__ = "cmdb_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ucmdb_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    global_id: Mapped[str | None] = mapped_column(String(64))
    common_name: Mapped[str] = mapped_column(String(512))
    cn_norm: Mapped[str] = mapped_column(String(512), index=True)
    kind: Mapped[str] = mapped_column(String(16))  # host | wildcard | ip | other
    issuer: Mapped[str] = mapped_column(String(512), default="")
    issuer_name: Mapped[str] = mapped_column(String(512), default="")
    issuer_norm: Mapped[str] = mapped_column(String(512), default="", index=True)
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Endpoint(Base):
    """Alvo de scan host:porta e o CN que é esperado servir."""

    __tablename__ = "endpoints"
    __table_args__ = (UniqueConstraint("host", "port", name="uq_endpoint_host_port"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host: Mapped[str] = mapped_column(String(253), index=True)
    port: Mapped[int] = mapped_column(Integer, default=443)
    expected_cn_norm: Mapped[str] = mapped_column(String(512), index=True)
    source: Mapped[str] = mapped_column(String(16), default="cmdb")  # cmdb | manual
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    note: Mapped[str] = mapped_column(String(512), default="")
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    last_scan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Certificate(Base):
    """Certificado X.509 efetivamente observado (identidade = SHA-256 do DER)."""

    __tablename__ = "certificates"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    subject_cn: Mapped[str] = mapped_column(String(512), default="")
    subject_dn: Mapped[str] = mapped_column(Text, default="")
    issuer_cn: Mapped[str] = mapped_column(String(512), default="")
    issuer_dn: Mapped[str] = mapped_column(Text, default="")
    serial_hex: Mapped[str] = mapped_column(String(128), default="", index=True)
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sans_dns: Mapped[list] = mapped_column(JSON, default=list)
    sans_ip: Mapped[list] = mapped_column(JSON, default=list)
    sig_hash: Mapped[str] = mapped_column(String(64), default="")
    key_type: Mapped[str] = mapped_column(String(16), default="")
    key_bits: Mapped[int | None] = mapped_column(Integer, nullable=True)
    spki_sha256: Mapped[str] = mapped_column(String(64), default="", index=True)
    ski: Mapped[str] = mapped_column(String(64), default="", index=True)   # Subject Key Identifier
    aki: Mapped[str] = mapped_column(String(64), default="", index=True)   # Authority Key Identifier
    is_ca: Mapped[bool] = mapped_column(Boolean, default=False)
    self_issued: Mapped[bool] = mapped_column(Boolean, default=False)
    pem: Mapped[str] = mapped_column(Text, default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"), index=True)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    status: Mapped[str] = mapped_column(String(24))  # ok | dns_error | unreachable | tls_error
    error: Mapped[str] = mapped_column(Text, default="")
    tls_version: Mapped[str] = mapped_column(String(16), default="")
    cipher: Mapped[str] = mapped_column(String(128), default="")
    resolved_ip: Mapped[str] = mapped_column(String(64), default="")
    verify_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    verify_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    verify_message: Mapped[str] = mapped_column(Text, default="")
    leaf_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    chain: Mapped[list] = mapped_column(JSON, default=list)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)


class ApiRecord(Base):
    """Uma API da lista da UCMDB. Só se guardam campos não sensíveis."""

    __tablename__ = "api_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ucmdb_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(512), default="")
    application: Mapped[str] = mapped_column(String(512), default="")
    location: Mapped[str] = mapped_column(String(512), default="")       # ex.: "AzureAD - App Registration - Client Secret"
    cmdb_expired: Mapped[bool | None] = mapped_column(Boolean, nullable=True)   # campo "Expirado?" da CMDB
    registered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    url: Mapped[str] = mapped_column(String(1024), default="")
    scheme: Mapped[str] = mapped_column(String(16), default="")
    host: Mapped[str] = mapped_column(String(253), default="", index=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    expiry: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    extra: Mapped[dict] = mapped_column(JSON, default=dict)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CtCert(Base):
    """Certificado encontrado nos registos públicos de Certificate Transparency."""

    __tablename__ = "ct_certs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key_serial: Mapped[str] = mapped_column(String(200), default="", index=True)   # emissor|serial
    key_time: Mapped[str] = mapped_column(String(200), default="", index=True)     # emissor|notBefore|notAfter
    domain: Mapped[str] = mapped_column(String(253), default="", index=True)
    names: Mapped[list] = mapped_column(JSON, default=list)
    primary_name: Mapped[str] = mapped_column(String(253), default="", index=True)
    issuer_cn: Mapped[str] = mapped_column(String(512), default="")
    issuer_dn: Mapped[str] = mapped_column(Text, default="")
    serial_hex: Mapped[str] = mapped_column(String(128), default="")
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    sources: Mapped[list] = mapped_column(JSON, default=list)
    source_ids: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    triage: Mapped[str] = mapped_column(String(16), default="por_triar", index=True)  # por_triar | adicionar | ignorar | investigar
    triage_by: Mapped[str] = mapped_column(String(128), default="")
    triage_note: Mapped[str] = mapped_column(Text, default="")
    triage_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ImportFile(Base):
    """Ficheiro de exportação (CA1, CA2, AVI…) lido da diretoria de importação."""

    __tablename__ = "import_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(512))
    source: Mapped[str] = mapped_column(String(32), index=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size: Mapped[int] = mapped_column(Integer, default=0)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    status: Mapped[str] = mapped_column(String(16), default="ok")  # ok | erro
    rows_total: Mapped[int] = mapped_column(Integer, default=0)
    rows_ok: Mapped[int] = mapped_column(Integer, default=0)
    columns: Mapped[dict] = mapped_column(JSON, default=dict)
    problems: Mapped[list] = mapped_column(JSON, default=list)
    is_current: Mapped[bool] = mapped_column(Boolean, default=True, index=True)


class ImportRecord(Base):
    __tablename__ = "import_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    file_id: Mapped[int] = mapped_column(ForeignKey("import_files.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(32), index=True)
    row_no: Mapped[int] = mapped_column(Integer, default=0)
    common_name: Mapped[str] = mapped_column(String(512), default="")
    cn_norm: Mapped[str] = mapped_column(String(512), default="", index=True)
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    serial: Mapped[str] = mapped_column(String(128), default="")
    issuer: Mapped[str] = mapped_column(String(512), default="")
    san: Mapped[str] = mapped_column(Text, default="")
    extra: Mapped[dict] = mapped_column(JSON, default=dict)


class Finding(Base):
    """Problema detetado. O id é estável (hash de tipo + alvo) para não duplicar."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    type: Mapped[str] = mapped_column(String(48), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    subject: Mapped[str] = mapped_column(String(600))
    cn_norm: Mapped[str] = mapped_column(String(512), default="", index=True)
    endpoint_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="aberto", index=True)  # aberto | aceite | resolvido
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    accepted_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    accepted_by: Mapped[str] = mapped_column(String(128), default="")
    accept_reason: Mapped[str] = mapped_column(Text, default="")


class JobRun(Base):
    __tablename__ = "job_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job: Mapped[str] = mapped_column(String(32), index=True)
    requested_by: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)  # pending | running | ok | error
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(600), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class SslLabsResult(Base):
    """Última avaliação externa do Qualys SSL Labs para um nome público."""

    __tablename__ = "ssllabs_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host: Mapped[str] = mapped_column(String(253), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="")
    status_message: Mapped[str] = mapped_column(String(512), default="")
    grade: Mapped[str] = mapped_column(String(8), default="")          # pior nota entre os IPs do nome
    has_warnings: Mapped[bool] = mapped_column(Boolean, default=False)
    endpoints: Mapped[list] = mapped_column(JSON, default=list)
    test_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

"""Modelo de dados.

Regra de confiança: da CMDB só se usam CommonName, ValidTo e Issuer/IssuerName.
Tudo o que é técnico (serial, fingerprint, SANs, algoritmos) vem do scan live.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, LargeBinary, String, Text, UniqueConstraint
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


class SmaxTicket(Base):
    """Ticket do SMAX (change de certificado), copiado na última leitura."""

    __tablename__ = "smax_tickets"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_label: Mapped[str] = mapped_column(String(512), default="")
    endpoint: Mapped[str] = mapped_column(String(253), default="", index=True)   # nome normalizado
    environment: Mapped[str] = mapped_column(String(32), default="")
    cert_expiry: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cert_type: Mapped[str] = mapped_column(String(128), default="")
    phase: Mapped[str] = mapped_column(String(64), default="")
    priority: Mapped[str] = mapped_column(String(64), default="")
    owner_group: Mapped[str] = mapped_column(String(256), default="")
    owner_person: Mapped[str] = mapped_column(String(256), default="")
    last_update: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scheduled_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    service_component: Mapped[str] = mapped_column(String(64), default="")    # AffectsServiceComponent (Application ID)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TicketBatch(Base):
    """Lote de pedidos SMAX a criar: rascunho -> a_criar -> concluido | interrompido (ou cancelado)."""

    __tablename__ = "ticket_batches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(16), default="rascunho", index=True)
    confirmed_by: Mapped[str] = mapped_column(String(128), default="")
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    note: Mapped[str] = mapped_column(String(600), default="")


class TicketDraft(Base):
    """Um pedido de um lote: dados do certificado, campos pedidos ao utilizador e resultado da criação."""

    __tablename__ = "ticket_drafts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    batch_id: Mapped[int] = mapped_column(ForeignKey("ticket_batches.id", ondelete="CASCADE"), index=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    cn: Mapped[str] = mapped_column(String(253), index=True)
    name: Mapped[str] = mapped_column(String(253), default="")
    expiry: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expiry_source: Mapped[str] = mapped_column(String(16), default="")
    issuer: Mapped[str] = mapped_column(String(512), default="")
    scope: Mapped[str] = mapped_column(String(16), default="")
    include: Mapped[bool] = mapped_column(Boolean, default=True)
    override_duplicate: Mapped[bool] = mapped_column(Boolean, default=False)
    ambiente: Mapped[str] = mapped_column(String(16), default="")
    tipo: Mapped[str] = mapped_column(String(64), default="")
    app_id: Mapped[str] = mapped_column(String(32), default="")
    responsavel: Mapped[str] = mapped_column(String(128), default="")
    localizacao: Mapped[str] = mapped_column(String(256), default="")
    prefill: Mapped[dict] = mapped_column(JSON, default=dict)      # de onde veio cada valor sugerido
    via: Mapped[list | None] = mapped_column(JSON, default=list, nullable=True)     # nomes selecionados que levaram a este certificado
    sites: Mapped[list | None] = mapped_column(JSON, default=list, nullable=True)   # sites onde o certificado está instalado
    warnings: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16), default="pendente")
    ticket_id: Mapped[str] = mapped_column(String(64), default="")
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    done_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SmaxComment(Base):
    """Comentário de um pedido do SMAX (só comentários de pessoas; os do sistema são ignorados)."""

    __tablename__ = "smax_comments"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    ticket_id: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    author_id: Mapped[str] = mapped_column(String(64), default="")
    author: Mapped[str] = mapped_column(String(256), default="")
    body: Mapped[str] = mapped_column(Text, default="")
    privacy: Mapped[str] = mapped_column(String(32), default="")
    origin: Mapped[str] = mapped_column(String(32), default="")



class SmaxFile(Base):
    """Imagem ou anexo de um comentário do SMAX (ex.: print de uma renovação), guardado para ver na aplicação."""

    __tablename__ = "smax_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    comment_id: Mapped[str] = mapped_column(String(64), index=True)
    ticket_id: Mapped[str] = mapped_column(String(64), index=True)
    ref: Mapped[str] = mapped_column(String(1024), default="")
    kind: Mapped[str] = mapped_column(String(16), default="imagem")      # imagem | anexo
    name: Mapped[str] = mapped_column(String(255), default="")
    mime: Mapped[str] = mapped_column(String(64), default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), default="")
    data: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True, deferred=True)
    error: Mapped[str] = mapped_column(String(300), default="")
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)



class Renewal(Base):
    """Renovação de um certificado registada no certwatch (a partir do servidor, do ficheiro do certificado ou à
    mão a partir de um print). Entra como fonte na atualização da CMDB."""

    __tablename__ = "renewals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ticket_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    cn: Mapped[str] = mapped_column(String(253), index=True)
    valid_to: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    serial: Mapped[str] = mapped_column(String(128), default="")
    issuer: Mapped[str] = mapped_column(String(512), default="")
    san: Mapped[str] = mapped_column(Text, default="")
    origin: Mapped[str] = mapped_column(String(16), default="manual")    # servidor | ficheiro | manual
    cert_sha256: Mapped[str] = mapped_column(String(64), default="")
    note: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)


class TicketStep(Base):
    """Passo do percurso de renovação confirmado à mão (ex.: instalado num servidor que o certwatch não vê)."""

    __tablename__ = "ticket_steps"
    __table_args__ = (UniqueConstraint("ticket_id", "step", name="uq_ticket_step"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ticket_id: Mapped[str] = mapped_column(String(64), index=True)
    step: Mapped[str] = mapped_column(String(32))
    by: Mapped[str] = mapped_column(String(128), default="")
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    note: Mapped[str] = mapped_column(Text, default="")


# ------------------------------------------------------------------ CMDB final (CMDB_Final.xlsx e certs_update)
class FinalInput(Base):
    """Ficheiro de uma fonte (CA1, CA2, AVI...) carregado pela interface. Também guarda ficheiros CMDB_Final
    carregados só para comparação (source = "CMDB_FINAL")."""

    __tablename__ = "final_inputs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(Integer, default=0)
    data: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True, deferred=True)
    uploaded_by: Mapped[str] = mapped_column(String(128), default="")
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class FinalRun(Base):
    """Uma geração dos ficheiros: CMDB lida pela API + fontes -> CMDB_Final.xlsx, certs_update.csv e
    certs_update_sem_cabecalho.csv."""

    __tablename__ = "final_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    created_by: Mapped[str] = mapped_column(String(128), default="")
    # a_gerar | pronto | bloqueado (CSV recusados pelas validações) | erro
    status: Mapped[str] = mapped_column(String(16), default="a_gerar", index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str] = mapped_column(Text, default="")
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    inputs: Mapped[dict] = mapped_column(JSON, default=dict)
    columns: Mapped[dict] = mapped_column(JSON, default=dict)
    changes: Mapped[list] = mapped_column(JSON, default=list)
    problems: Mapped[list] = mapped_column(JSON, default=list)     # relatório de erros das fontes e da CMDB
    live: Mapped[list] = mapped_column(JSON, default=list)         # regressões e decisão da verificação TLS
    validation: Mapped[list] = mapped_column(JSON, default=list)   # motivos de bloqueio dos CSV
    xlsx: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True, deferred=True)
    csv: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True, deferred=True)
    csv_sem: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True, deferred=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    published_by: Mapped[str] = mapped_column(String(128), default="")
    # CMDB reconstruída (JSON comprimido) para refazer os ficheiros quando se muda a seleção
    state: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True, deferred=True)


class FinalDecision(Base):
    """Escolha de incluir ou não uma alteração nos ficheiros finais. Fica para as gerações seguintes
    (a mesma alteração = mesmo CommonName e mesma nova data de expiração)."""

    __tablename__ = "final_decisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(300), unique=True, index=True)
    include: Mapped[bool] = mapped_column(Boolean, default=True)
    by: Mapped[str] = mapped_column(String(128), default="")
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FinalPublish(Base):
    """Publicação de ficheiros de uma geração na pasta de rede, com cópia do que lá estava antes."""

    __tablename__ = "final_publishes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("final_runs.id", ondelete="CASCADE"), index=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    by: Mapped[str] = mapped_column(String(128), default="")
    folder: Mapped[str] = mapped_column(String(512), default="")
    ok: Mapped[bool] = mapped_column(Boolean, default=False)
    result: Mapped[list] = mapped_column(JSON, default=list)


class FinalPublishFile(Base):
    __tablename__ = "final_publish_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    publish_id: Mapped[int] = mapped_column(ForeignKey("final_publishes.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64), default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    ok: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str] = mapped_column(Text, default="")
    previous: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True, deferred=True)
    previous_sha256: Mapped[str] = mapped_column(String(64), default="")
    previous_mtime: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EmailReport(Base):
    """Relatório por email preparado na página: janela, prazo de alerta, certificados retirados e envios feitos."""

    __tablename__ = "email_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_by: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    desde: Mapped[int] = mapped_column(Integer, default=0)
    ate: Mapped[int] = mapped_column(Integer, default=90)
    alerta: Mapped[int] = mapped_column(Integer, default=20)
    ct_dias: Mapped[int] = mapped_column(Integer, default=30)     # internet: encontrados nos últimos N dias (0 = todos)
    excluded: Mapped[list] = mapped_column(JSON, default=list)
    sends: Mapped[list] = mapped_column(JSON, default=list)
    textos: Mapped[dict | None] = mapped_column(JSON, nullable=True)     # texto alterado só neste relatório
    # emails editados à mão na página: {"secoes": {secção: html}, "assuntos": {parte: assunto}, "por", "em"}
    editados: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class EmailTemplate(Base):
    """Texto dos emails guardado como modelo para os próximos relatórios (só o que difere do original)."""

    __tablename__ = "email_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(32), unique=True, default="default")
    textos: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_by: Mapped[str] = mapped_column(String(128), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class UcmdbWrite(Base):
    """Cada certificado criado ou atualizado na UCMDB pela REST API (a partir de uma geração ou editado à mão)."""

    __tablename__ = "ucmdb_writes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)   # geração (None = edição à mão)
    chave: Mapped[int | None] = mapped_column(Integer, nullable=True)                # alteração da geração
    lote: Mapped[str] = mapped_column(String(32), default="", index=True)
    acao: Mapped[str] = mapped_column(String(16))              # criar | atualizar
    cn: Mapped[str] = mapped_column(String(512), default="")
    ucmdb_id: Mapped[str] = mapped_column(String(64), default="")
    estado: Mapped[str] = mapped_column(String(16), default="pendente", index=True)   # pendente|a_aplicar|ok|aviso|erro|ignorado
    enviado: Mapped[dict] = mapped_column(JSON, default=dict)    # atributo -> valor enviado
    antes: Mapped[dict] = mapped_column(JSON, default=dict)      # atributo -> valor na UCMDB antes
    resposta: Mapped[dict] = mapped_column(JSON, default=dict)   # addedCis/updatedCis/ignoredCis/removedCis
    verificado: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    detalhe: Mapped[str] = mapped_column(Text, default="")
    por: Mapped[str] = mapped_column(String(128), default="")
    pedido_em: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    feito_em: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


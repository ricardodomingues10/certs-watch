"""Ligação à base de dados, sessões e locks entre processos."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from functools import lru_cache
from typing import Iterator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


class JobBusy(RuntimeError):
    """Já existe um job em execução noutro processo."""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(dt: datetime | None) -> datetime | None:
    """Garante datetime com timezone UTC (SQLite devolve datetimes naive)."""
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    url = get_settings().database_url
    kwargs = {"pool_pre_ping": True, "future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(url, **kwargs)


@lru_cache(maxsize=1)
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


@contextmanager
def session_scope() -> Iterator[Session]:
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# Chaves de advisory lock (PostgreSQL)
LOCK_INIT_DB = 7_100_001
LOCK_PIPELINE = 7_100_002


@contextmanager
def advisory_lock(key: int, wait: bool = False) -> Iterator[None]:
    """Lock entre processos. Usa uma ligação dedicada durante todo o bloco."""
    engine = get_engine()
    if engine.dialect.name != "postgresql":
        yield
        return
    with engine.connect() as conn:
        if wait:
            conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": key})
        else:
            got = conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": key}).scalar()
            if not got:
                raise JobBusy("Já existe um job em execução")
        try:
            yield
        finally:
            conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": key})
            conn.commit()


# Colunas acrescentadas depois da v0.1 (bases de dados já existentes não as têm)
_ADDED_COLUMNS = [
    ("certificates", "ski", "VARCHAR(64) NOT NULL DEFAULT ''"),
    ("certificates", "aki", "VARCHAR(64) NOT NULL DEFAULT ''"),
    ("scan_results", "resolved_ip", "VARCHAR(64) NOT NULL DEFAULT ''"),
    ("api_records", "application", "VARCHAR(512) NOT NULL DEFAULT ''"),
    ("api_records", "location", "VARCHAR(512) NOT NULL DEFAULT ''"),
    ("api_records", "cmdb_expired", "BOOLEAN"),
    ("api_records", "registered_at", "TIMESTAMP WITH TIME ZONE"),
    ("smax_tickets", "service_component", "VARCHAR(64) NOT NULL DEFAULT ''"),
    ("ticket_drafts", "via", "JSON"),
    ("ticket_drafts", "sites", "JSON"),
    ("final_runs", "state", "BYTEA"),
    ("email_reports", "ct_dias", "INTEGER NOT NULL DEFAULT 30"),
    ("email_reports", "textos", "JSON"),
]


_ADDED_INDEXES = [
    "CREATE INDEX IF NOT EXISTS ix_certificates_ski ON certificates (ski)",
    "CREATE INDEX IF NOT EXISTS ix_certificates_aki ON certificates (aki)",
]


def _migrate(engine: Engine) -> None:
    insp = inspect(engine)
    with engine.begin() as conn:
        for table, column, ddl in _ADDED_COLUMNS:
            if table in insp.get_table_names() and column not in {c["name"] for c in insp.get_columns(table)}:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
        for ddl in _ADDED_INDEXES:
            conn.execute(text(ddl))


def init_db() -> None:
    from . import models  # noqa: F401  (regista as tabelas)

    with advisory_lock(LOCK_INIT_DB, wait=True):
        engine = get_engine()
        Base.metadata.create_all(engine)
        _migrate(engine)

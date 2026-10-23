"""CMDB final: a lógica do workflow n8n "Reconciliação de Certificados", dentro do certwatch.

1. A CMDB vem da REST API da UCMDB (TQL dos certificados), com todos os atributos: se o layout do TQL só tiver
   alguns, os restantes são pedidos à REST API. Os atributos passam a colunas com os cabeçalhos do export da
   CMDB ("[Digital Certificate] : CommonName"...).
2. CA1, CA2 e AVI (ficheiros da diretoria de importação ou carregados na página) são normalizados e filtrados:
   sem CommonName, data ilegível ou vazia, pedido não emitido ou já expirado -> relatório de erros.
3. Cada certificado das fontes é procurado na CMDB pelo CommonName (com Name -> Display Label -> Hostname como
   alternativa) e pela data de expiração ao DIA. Os que não coincidem são alterações.
4. Fonte com data ANTERIOR à da CMDB = regressão suspeita: decide o certificado apresentado pelo servidor (443).
   Sem resposta, ou wildcard, a CMDB fica como está.
5. A CMDB é reconstruída: CommonName existente -> atualiza ValidTo/SerialNumber (e o emissor, se validado no
   servidor); CommonName novo -> linha nova com Global Id = x.
6. Saídas: CMDB_Final.xlsx (verde novo, amarelo alterado, vermelho expirado), certs_update.csv (só o delta,
   com cabeçalho e aspas) e certs_update_sem_cabecalho.csv. Separador |, CRLF, UTF-8 sem BOM.

Diferenças deliberadas em relação ao workflow (para não estragar a CMDB):
- uma data vazia na fonte é descartada e aparece no relatório de erros (no workflow contava como data 0 e
  caía na verificação no servidor por "regressão");
- ValidTo e SerialNumber só contam como alterados se mudarem de facto (mesmo dia / mesmo número de série
  escrito de outra forma não é alteração);
- a verificação no servidor usa o scan do certwatch (ou uma ligação TLS na hora) em vez do OpenSSL;
- emissor ou série em falta: procurados nas outras fontes e nos certificados já vistos pelo certwatch; um
  certificado novo sem emissor fica com Issuer/IssuerName "Por verificar" e, se vier da internet sem série, com
  SerialNumber x1, x2... (regra da equipa, numerado para a chave não se repetir), em vez de bloquear os CSV; dos ficheiros sem série, fica fora dos CSV por
  omissão (IssuerName + SerialNumber é a chave primária na CMDB);
- numa linha existente, uma fonte sem série não apaga a série que está na CMDB.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import logging
import re
import threading
import unicodedata
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from zoneinfo import ZoneInfo

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .config import Settings
from .db import as_utc, session_scope, utcnow
from .models import (ApiRecord, Certificate, CtCert, Endpoint, FinalDecision, FinalInput,
                     FinalRun, ScanResult)
from .normalize import norm_issuer, norm_serial
from .reconcile import ALLOWED_EXT, _fix_mojibake, map_columns, norm_header, read_table_bytes, source_for

log = logging.getLogger(__name__)

AZURE_SOURCE = "AZURE"         # exportação das App Registrations do Azure (segredos e certificados), opcional
INTERNET = "INTERNET"          # fonte: certificados encontrados na internet (Certificate Transparency)
RENOVACAO = "RENOVACAO"        # fonte: renovações registadas nos pedidos (servidor, ficheiro ou à mão)
SOURCE_LABELS = {INTERNET: "Internet (CT)", RENOVACAO: "Renovação registada"}

FILES = {"xlsx": "CMDB_Final.xlsx", "csv": "certs_update.csv", "csv_sem": "certs_update_sem_cabecalho.csv"}
FILE_LABELS = {"xlsx": "CMDB final (Excel, todas as linhas)", "csv": "Atualização UCMDB (com cabeçalho)",
               "csv_sem": "Atualização UCMDB (sem cabeçalho)"}

# Colunas do certs_update.csv (ordem fixa para a integração UCMDB) e base da ordem do CMDB_Final.xlsx
OUTPUT_COLUMNS = [
    "Display Label", "ValidTo", "Aplicação", "Localização", "Responsabilidade de instalação",
    "Certificate Status", "Certificado Gerido", "Ambiente", "Name", "CommonName", "Issuer", "IssuerName",
    "SerialNumber", "Certificate Type", "IsSelfSigned", "Global Id", "Link para a Documentação",
    "Subject Alternative Names", "Organization", "Version", "Type", "Subject", "CreateOn", "Hostname",
    "Description", "OrganizationUnit",
]
EXCLUDED_COLUMNS = {"createdby", "createdtime", "iscandidatefordeletion"}
# Atributos técnicos da UCMDB que não entram como colunas quando vêm do enriquecimento (não do layout do TQL)
TECH_ATTR = re.compile(r"^(root_|data_|calculated_|tenant|track_|monitored_by|last_|ucmdb_id$|global_id$|"
                       r"create_time$|created_by$|candidate_for_deletion|is_candidate|deletion_|lastaccess|"
                       r"user_label$|digest$|document_list$|language$|classification$|display_label_)", re.I)
SENSITIVE_ATTR = re.compile(r"password|passwd|secret|private_?key|token|credential", re.I)
DATE_ATTR = re.compile(r"date|time|valid|expir|not_?after|not_?before|create_?on|_on$|createon|validto|validfrom", re.I)
_STOP = {"de", "da", "do", "das", "dos", "para", "a", "o", "e", "the", "of"}

FILE_MARKER = "Validado pelo ficheiro do certificado"
# Certificado novo sem emissor em nenhuma das fontes: Issuer/IssuerName "Por verificar" (regra da equipa).
# Certificado novo encontrado na internet sem número de série: SerialNumber "x". Nos ficheiros (CA1/CA2/AVI) a
# série vem sempre; se faltar, a linha fica fora dos CSV por omissão.
MISSING_ISSUER = "Por verificar"
MISSING_SERIAL = "x"           # numerado na geração: x1, x2... para a chave IssuerName + SerialNumber não se repetir
_PLACEHOLDER_SERIAL = re.compile(r"^x(\d*)$", re.I)


def is_placeholder_serial(v: str) -> bool:
    return bool(_PLACEHOLDER_SERIAL.match((v or "").strip()))
GREEN, YELLOW, RED = "E2F0D9", "FFF2CC", "F4CCCC"
COLOR_STATE = {GREEN: "novo", YELLOW: "alterado", RED: "expirado"}

STALE_AFTER = timedelta(minutes=30)
MAX_UPLOAD = 25 * 1024 * 1024
MAX_BACKUP = 50 * 1024 * 1024

DROP_LABELS = {
    "SEM_COMMONNAME": "CommonName em falta",
    "SEM_IDENTIFICADOR_CERTIFICADO": "CommonName vazio e sem Name/Display Label/Hostname utilizável",
    "DATA_VAZIO": "Data de expiração vazia",
    "DATA_NAO_RECONHECIDO": "Formato de data não reconhecido",
    "DATA_INVALIDO": "Data inválida",
    "DATA_SERIAL_INVALIDO": "Serial de Excel inválido",
    "NAO_EMITIDO": "Pedido não emitido (Revoked/Denied/Pending)",
    "EXPIRADO": "Certificado já expirado",
    "NAO_E_DOMINIO": "Nome sem domínio (não é domínio, wildcard nem IP)",
}
DATE_WARN = {
    "ANO_SUSPEITO": "Ano fora do intervalo esperado (2000-2100)",
    "VAZIO": "Data vazia",
    "NAO_RECONHECIDO": "Formato de data não reconhecido",
    "INVALIDO": "Data inválida",
    "SERIAL_INVALIDO": "Serial de Excel inválido",
}
LIVE_LABELS = {
    "ATUALIZAR_COM_SERVIDOR": "Atualizado com o certificado do servidor",
    "MANTER_CMDB_WILDCARD": "CMDB mantida: wildcard sem servidor concreto",
    "MANTER_CMDB_NOME_INVALIDO": "CMDB mantida: o nome não é um servidor válido",
    "MANTER_CMDB_SEM_RESPOSTA": "CMDB mantida: o servidor não respondeu",
    "MANTER_CMDB_DATA_INVALIDA": "CMDB mantida: data do servidor ilegível",
}


class FinalError(RuntimeError):
    pass


# ------------------------------------------------------------------ utilitários
def _strip_accents(s: str) -> str:
    return "".join(ch for ch in unicodedata.normalize("NFD", s) if unicodedata.category(ch) != "Mn")


def token_key(name: str) -> str:
    """Chave para comparar nomes de atributos com cabeçalhos: 'responsabilidade_instalacao' e
    'Responsabilidade de instalação' dão o mesmo; 'IssuerName' e 'issuer_name' também."""
    s = _fix_mojibake(str(name or "")).replace("﻿", "")
    s = re.sub(r"^\s*\[[^\]]*\]\s*:\s*", "", s)
    s = re.sub(r"([a-z])([A-Z])", r"\1 \2", s)
    s = _strip_accents(s).lower()
    return "".join(t for t in re.split(r"[^a-z0-9]+", s) if t and t not in _STOP)


def _clean_text(v) -> str:
    return _fix_mojibake(str(v)).replace("﻿", "").replace(" ", " ") if v is not None else ""


def identifier_type(v: str) -> str:
    s = (v or "").strip()
    if not s:
        return "OUTRO"
    if s.startswith("*."):
        return "WILDCARD"
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", s):
        return "IP"
    if "." in s:
        return "DOMINIO"
    return "OUTRO"


def _ipv4(s: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", s)) and all(0 <= int(x) <= 255 for x in s.split("."))


def _valid_hostname(s: str) -> bool:
    if not s or len(s) > 253 or ".." in s:
        return False
    labels = s.split(".")
    return len(labels) >= 2 and all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", x) for x in labels)


@dataclass
class DayParse:
    day: date | None = None
    status: str = "OK"   # OK | VAZIO | INVALIDO | SERIAL_INVALIDO | NAO_RECONHECIDO | ANO_SUSPEITO
    branch: str = ""
    note: str = ""


def parse_day(val) -> DayParse:
    """Data ao DIA, como no workflow: AAAAMMDD, serial do Excel (a parte decimal é a hora e é ignorada),
    AAAA-MM-DD[...] e DD/MM/AAAA, DD-MM-AAAA ou DD.MM.AAAA. Nunca troca dia e mês."""
    out = DayParse()
    if isinstance(val, datetime):
        out.day, out.branch = val.date(), "DATA_EXCEL"
    elif isinstance(val, date):
        out.day, out.branch = val, "DATA_EXCEL"
    else:
        s = "" if val is None else str(val).strip()
        if s == "":
            out.status = "VAZIO"
            return out

        def build(y, m, d):
            try:
                return date(y, m, d)
            except ValueError:
                return None

        m = re.fullmatch(r"(\d{4})(\d{2})(\d{2})", s)
        if m and 2000 <= int(m.group(1)) <= 2100:
            out.branch = "YYYYMMDD"
            out.day = build(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            if out.day is None:
                out.status, out.note = "INVALIDO", f'"{s}"'
                return out
        elif (isinstance(val, (int, float)) and not isinstance(val, bool)) or re.fullmatch(r"\d+(\.\d+)?", s):
            serial = float(val) if isinstance(val, (int, float)) else float(s)
            if not (0 < serial <= 2958465):
                out.status, out.note = "SERIAL_INVALIDO", f"serial={s}"
                return out
            out.branch = "SERIAL_EXCEL"
            out.day = date(1899, 12, 30) + timedelta(days=int(serial))
        elif (m := re.match(r"^(\d{4})-(\d{1,2})-(\d{1,2})(?:[ T]|$)", s)):
            out.branch = "YYYY-MM-DD"
            out.day = build(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            if out.day is None:
                out.status, out.note = "INVALIDO", f'"{s}"'
                return out
        elif (m := re.match(r"^(\d{1,2})([/\-.])(\d{1,2})\2(\d{4})(?:[ T]|$)", s)):
            out.branch = "DD/MM/YYYY"
            out.day = build(int(m.group(4)), int(m.group(3)), int(m.group(1)))
            if out.day is None:
                out.status, out.note = "INVALIDO", f'"{s}"'
                return out
        else:
            out.status, out.note = "NAO_RECONHECIDO", f'"{s}"'
            return out
    if not 2000 <= out.day.year <= 2100:
        out.status = "ANO_SUSPEITO"
        out.note = (out.note + f" ano={out.day.year}").strip()
    return out


def valid_to_text(d: date | None) -> str:
    """ValidTo como o workflow o escreve: DD-MM-AAAA 00:00:00 (a hora não é usada)."""
    return d.strftime("%d-%m-%Y 00:00:00") if d else ""


def _audit_date(v) -> str:
    p = parse_day(v)
    if p.day:
        return p.day.strftime("%d/%m/%Y")
    s = str(v or "").strip()
    return s or "(vazio)"


def _serial_text(v) -> str:
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    return str(v).strip() if v is not None else ""


# ------------------------------------------------------------------ CMDB pela API
@dataclass
class CmdbTable:
    headers: list[str]                 # cabeçalhos com prefixo, pela ordem do ficheiro final
    display: dict[str, str]            # nome sem prefixo -> cabeçalho
    rows: list[dict[str, str]]
    ids: list[str]                     # ucmdbId de cada linha
    diag: dict = field(default_factory=dict)

    def h(self, name: str) -> str:
        return self.display[name]


def load_column_overrides(settings: Settings) -> tuple[dict[str, str | None], list[str], str | None]:
    """Ficheiro import/cmdb-colunas.csv: 'atributo;coluna' por linha (coluna vazia = não incluir).
    Devolve (mapa, ordem dos atributos no ficheiro, nome do ficheiro)."""
    d = settings.import_dir
    if not settings.final_columns_file or not d.is_dir():
        return {}, [], None
    cands = sorted((p for p in d.iterdir() if p.is_file() and p.name.lower().startswith(settings.final_columns_file)
                    and p.suffix.lower() in (".csv", ".txt")), key=lambda p: p.stat().st_mtime, reverse=True)
    if not cands:
        return {}, [], None
    from .reconcile import _decode
    text = _decode(cands[0].read_bytes())
    mapping: dict[str, str | None] = {}
    order: list[str] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = re.split(r"[;\t|]", line, maxsplit=1) if re.search(r"[;\t|]", line) else line.split(",", 1)
        attr = parts[0].strip().strip('"')
        col = (parts[1].strip().strip('"') if len(parts) > 1 else "")
        if not attr or attr.lower() in ("atributo", "attribute"):
            continue
        col = re.sub(r"^\s*\[[^\]]*\]\s*:\s*", "", col)
        mapping[attr] = col or None
        order.append(attr)
    return mapping, order, cands[0].name


def plan_columns(attrs: list[str], from_tql: set[str], overrides: dict[str, str | None], order: list[str],
                 prefix: str) -> tuple[list[tuple[str | None, str]], dict]:
    """Decide a coluna (nome sem prefixo) de cada atributo. Devolve [(atributo|None, coluna)] pela ordem final
    e um diagnóstico. As 26 colunas do certs_update existem sempre (vazias se nenhum atributo lhes corresponde)."""
    known = {token_key(c): c for c in OUTPUT_COLUMNS}
    known.update({norm_header(c): c for c in OUTPUT_COLUMNS})
    chosen: dict[str, str] = {}          # coluna -> atributo
    mapping: list[dict] = []
    unmatched: list[str] = []
    for a in attrs:
        if a in overrides:
            col = overrides[a]
            how = "ficheiro de colunas"
        else:
            col = known.get(norm_header(a)) or known.get(token_key(a))
            how = "automático" if col else ""
            if col is None:
                if a not in from_tql and TECH_ATTR.search(a):
                    continue
                col = a
                how = "sem correspondência (nome interno)"
        if col is None:
            mapping.append({"atributo": a, "coluna": "", "como": "excluído no ficheiro de colunas"})
            continue
        if norm_header(col) in EXCLUDED_COLUMNS or norm_header(col) == "globalid":
            mapping.append({"atributo": a, "coluna": col, "como": "não incluído (coluna gerida pelo certwatch)"
                            if norm_header(col) == "globalid" else "não incluído (excluído como no workflow)"})
            continue
        if col in chosen:
            mapping.append({"atributo": a, "coluna": col, "como": f"ignorado: a coluna já vem de {chosen[col]}"})
            continue
        if how.startswith("sem correspondência"):
            unmatched.append(a)
        chosen[col] = a
        mapping.append({"atributo": a, "coluna": col, "como": how})
    chosen["Global Id"] = "(Global Id do CI)"
    # Ordem: a do ficheiro de colunas; senão as 26 colunas do certs_update e depois as restantes
    ordered: list[str] = []
    if order:
        for a in order:
            col = next((c for c, at in chosen.items() if at == a), None)
            if col and col not in ordered:
                ordered.append(col)
    for c in OUTPUT_COLUMNS:
        if c not in ordered:
            ordered.append(c)
    for c in sorted(chosen, key=lambda x: token_key(x)):
        if c not in ordered:
            ordered.append(c)
    plan = [(chosen.get(c), c) for c in ordered]
    diag = {
        "mapeamento": mapping,
        "sem_correspondencia": unmatched,
        "colunas_vazias": [c for c in OUTPUT_COLUMNS if c not in chosen],
        "prefixo": prefix,
    }
    return plan, diag


def _cert_safe(props: dict) -> dict:
    return {k: v for k, v in (props or {}).items() if not SENSITIVE_ATTR.search(k)}


def format_value(attr: str, v, tz: ZoneInfo) -> str:
    """Valor de um atributo da API como texto de célula (datas em DD-MM-AAAA HH:MM:SS, hora de Lisboa)."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (list, tuple, set)):
        return ", ".join(format_value(attr, x, tz) for x in v if x not in (None, ""))
    if isinstance(v, dict):
        return json.dumps(v, ensure_ascii=False)
    is_date = bool(DATE_ATTR.search(attr))
    if isinstance(v, (int, float)):
        if is_date and abs(v) > 100_000_000_000:
            return datetime.fromtimestamp(v / 1000, tz=timezone.utc).astimezone(tz).strftime("%d-%m-%Y %H:%M:%S")
        if is_date and abs(v) > 1_000_000_000:
            return datetime.fromtimestamp(v, tz=timezone.utc).astimezone(tz).strftime("%d-%m-%Y %H:%M:%S")
        return str(int(v)) if isinstance(v, float) and v.is_integer() else str(v)
    s = _clean_text(v)
    if is_date and re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", s):
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
            d = d if d.tzinfo else d.replace(tzinfo=timezone.utc)
            return d.astimezone(tz).strftime("%d-%m-%Y %H:%M:%S")
        except ValueError:
            pass
    return s


def build_cmdb_table(cis: list[dict], settings: Settings, tql_attrs: set[str] | None = None,
                     diag: dict | None = None) -> CmdbTable:
    tz = ZoneInfo(settings.timezone)
    overrides, order, ofile = load_column_overrides(settings)
    attrs: list[str] = []
    seen: set[str] = set()
    for ci in cis:
        for k in _cert_safe(ci.get("properties") or {}):
            if k not in seen:
                seen.add(k)
                attrs.append(k)
    attrs.sort(key=lambda a: (a not in (tql_attrs or seen), a))
    plan, cdiag = plan_columns(attrs, tql_attrs if tql_attrs is not None else seen, overrides, order,
                               settings.final_header_prefix)
    prefix = settings.final_header_prefix
    headers = [prefix + col for _, col in plan]
    display = {col: prefix + col for _, col in plan}
    rows, ids = [], []
    for ci in cis:
        props = _cert_safe(ci.get("properties") or {})
        row = {}
        for attr, col in plan:
            if col == "Global Id":
                row[prefix + col] = str(ci.get("globalId") or props.get("global_id") or "")
            else:
                row[prefix + col] = format_value(attr, props.get(attr), tz) if attr else ""
        rows.append(row)
        ids.append(str(ci.get("ucmdbId") or ""))
    filled = {col: sum(1 for r in rows if r[prefix + col]) for _, col in plan}
    cdiag.update({"ficheiro_colunas": ofile, "preenchidas": filled, "total_cis": len(cis)})
    return CmdbTable(headers=headers, display=display, rows=rows, ids=ids, diag={**(diag or {}), **cdiag})


def fetch_cmdb_table(settings: Settings, client=None) -> tuple[CmdbTable, list[dict]]:
    """Lê o TQL dos certificados e, se faltarem atributos ao layout, completa-os pela REST API.
    Devolve a tabela e os registos no formato da ingestão (para atualizar também a CMDB do certwatch)."""
    from .collectors.ucmdb import UcmdbError, UcmdbSession
    if not settings.ucmdb_tql:
        raise FinalError("Defina CERTWATCH_UCMDB_TQL no ficheiro .env")
    notes: list[str] = []
    method = "tql"
    with UcmdbSession(settings, client) as s:
        cis = s.topology(settings.ucmdb_tql)
        if not cis:
            raise FinalError(f"O TQL {settings.ucmdb_tql} não devolveu certificados.")
        tql_attrs = {k for c in cis for k in (c.get("properties") or {})}
        mode = settings.final_enrich
        if mode != "off":
            ids = [str(c.get("ucmdbId")) for c in cis if c.get("ucmdbId")]
            try:
                probe = _cert_safe((s.ci(ids[0]).get("properties") or {}))
            except UcmdbError as exc:
                probe = {}
                notes.append(f"Não foi possível ler um CI completo: {exc}")
            missing = sorted(k for k in probe if k not in tql_attrs and not TECH_ATTR.search(k))
            if missing:
                extra: dict[str, dict] = {}
                if mode in ("auto", "query"):
                    try:
                        ci_type = str(cis[0].get("type") or "")
                        got = s.topology_query(ci_type, sorted(tql_attrs | set(missing)), ids)
                        extra = {str(c.get("ucmdbId")): (c.get("properties") or {}) for c in got}
                        if extra:
                            method = "topologyQuery"
                    except UcmdbError as exc:
                        notes.append(f"Consulta ad-hoc (topologyQuery) recusada: {exc}")
                if not extra and mode in ("auto", "ci"):
                    for uid in ids:
                        try:
                            extra[uid] = s.ci(uid).get("properties") or {}
                        except UcmdbError as exc:
                            notes.append(f"CI {uid}: {exc}")
                            if len(notes) > 8:
                                break
                    if extra:
                        method = "ci"
                if extra:
                    keep = set(tql_attrs) | set(missing)
                    for c in cis:
                        add = {k: v for k, v in (extra.get(str(c.get("ucmdbId"))) or {}).items() if k in keep}
                        c["properties"] = {**add, **{k: v for k, v in (c.get("properties") or {}).items()
                                                     if v not in (None, "")}}
                else:
                    notes.append("Os atributos em falta no layout do TQL não foram obtidos: "
                                 + ", ".join(missing[:20]))
    table = build_cmdb_table(cis, settings, tql_attrs, {"metodo": method, "avisos": notes[:10], "tql": settings.ucmdb_tql})
    records = []
    for c in cis:
        p = c.get("properties") or {}
        records.append({"ucmdb_id": str(c.get("ucmdbId") or ""), "global_id": p.get("global_id") or c.get("globalId"),
                        "common_name": str(p.get("common_name") or "").strip(), "valid_to": p.get("valid_to"),
                        "issuer": str(p.get("issuer") or "").strip(), "issuer_name": str(p.get("issuer_name") or "").strip()})
    return table, records


# ------------------------------------------------------------------ fontes CA1 / CA2 / AVI
@dataclass
class SourceItem:
    source: str
    row_no: int
    cn: str
    day: date | None
    serial: str = ""
    issuer: str = ""
    san: str = ""
    disposition: str = ""
    ref: str = ""            # Req ID (CA) ou Nome (AVI)
    requester: str = ""
    keep: bool = True
    drop: str = ""
    date_status: str = "OK"
    raw_date: str = ""
    note: str = ""
    triage: str = ""         # só na fonte INTERNET: triagem feita na página "Na internet"
    auth: str = ""           # só na fonte RENOVACAO: "servidor" ou "ficheiro" = dados do próprio certificado


def read_source(source: str, filename: str, data: bytes, today: date) -> tuple[list[SourceItem], dict]:
    headers, rows = read_table_bytes(data, Path(filename).suffix)
    cols = map_columns(headers) if headers else {}
    normed = [norm_header(h) for h in headers]
    fallback = next((normed.index(c) for c in ("nome", "name") if c in normed), None)
    info = {"ficheiro": filename, "linhas": len(rows), "colunas": {k: headers[v] for k, v in cols.items()}}
    if "cn" not in cols and fallback is None:
        raise FinalError(f"{source} ({filename}): coluna do CommonName não encontrada. "
                         f"Cabeçalhos: {', '.join(h for h in headers if h)[:400]}")
    date_missing = "valid_to" not in cols
    has_disp = "disposition" in cols

    def cell(row, key=None, idx=None):
        i = cols.get(key) if key else idx
        return row[i] if i is not None and i < len(row) else None

    out = []
    for n, row in enumerate(rows, start=2):
        cn = _clean_text(cell(row, "cn") or "").strip()
        if not cn and fallback is not None:
            cn = _clean_text(cell(row, idx=fallback) or "").strip()
        raw = cell(row, "valid_to")
        p = parse_day(raw)
        if date_missing:
            p.status, p.note = "NAO_RECONHECIDO", "coluna da data de expiração ausente no ficheiro"
        disp = _clean_text(cell(row, "disposition") or "").strip()
        it = SourceItem(
            source=source, row_no=n, cn=cn, day=p.day, serial=_serial_text(cell(row, "serial")),
            issuer=_clean_text(cell(row, "issuer") or "").strip(), san=_clean_text(cell(row, "san") or "").strip(),
            disposition=disp, ref=_clean_text(cell(row, "req_id") or (cell(row, idx=fallback) if fallback is not None else "") or "").strip(),
            requester=_clean_text(cell(row, "requester") or "").strip(),
            date_status=p.status, raw_date="" if raw is None else str(raw), note=p.note,
        )
        if not cn:
            it.keep, it.drop = False, "SEM_COMMONNAME"
        elif p.status in ("VAZIO", "NAO_RECONHECIDO", "INVALIDO", "SERIAL_INVALIDO"):
            it.keep, it.drop = False, f"DATA_{p.status}"
        elif has_disp and disp and not re.search(r"issued|emitid", disp, re.I):
            it.keep, it.drop = False, "NAO_EMITIDO"
        elif p.day and p.day < today:
            it.keep, it.drop = False, "EXPIRADO"
        elif cn.upper() == "EMPTY" or identifier_type(cn) == "OUTRO":
            it.keep, it.drop = False, "NAO_E_DOMINIO"
        out.append(it)
    info["validas"] = sum(1 for x in out if x.keep)
    info["descartadas"] = {}
    for x in out:
        if not x.keep:
            info["descartadas"][x.drop] = info["descartadas"].get(x.drop, 0) + 1
    return out, info


def ct_source(session: Session, settings: Settings, today: date) -> tuple[list[SourceItem], dict]:
    """Certificados encontrados na internet (CT) como fonte: por nome, só o mais recente ainda válido.
    Os marcados "Ignorar" na triagem não entram."""
    latest: dict[str, CtCert] = {}
    ignored = 0
    for c in session.scalars(select(CtCert).where(CtCert.not_after.is_not(None))):
        if c.triage == "ignorar":
            ignored += 1
            continue
        name = (c.primary_name or (c.names or [""])[0] or "").strip().lower()
        if not name:
            continue
        cur = latest.get(name)
        if cur is None or as_utc(c.not_after) > as_utc(cur.not_after):
            latest[name] = c
    out = []
    for n, (name, c) in enumerate(sorted(latest.items()), start=1):
        day = as_utc(c.not_after).date()
        it = SourceItem(source=INTERNET, row_no=n, cn=name, day=day, serial=(c.serial_hex or "").upper(),
                        issuer=(c.issuer_cn or "").strip(), san=", ".join(c.names or []),
                        ref=f"CT #{c.id}", triage=c.triage or "por_triar", raw_date=day.isoformat())
        if day < today:
            continue                       # expirados não interessam (nem para o relatório de erros)
        if identifier_type(name) == "OUTRO":
            it.keep, it.drop = False, "NAO_E_DOMINIO"
        out.append(it)
    info = {"ficheiro": "certificados encontrados na internet", "linhas": len(out),
            "validas": sum(1 for x in out if x.keep), "ignorados_na_triagem": ignored,
            "triagem": {t: sum(1 for x in out if x.keep and x.triage == t) for t in ("adicionar", "por_triar", "investigar")}}
    return out, info


def source_files(session: Session, settings: Settings) -> dict[str, dict]:
    """Por fonte: o ficheiro mais recente da diretoria import/ e o último carregado na página (cada um ou None)."""
    out: dict[str, dict] = {src: {"diretoria": None, "carregado": None} for src in [*settings.final_sources, AZURE_SOURCE]}
    d = settings.import_dir
    if d.is_dir():
        for p in sorted(d.iterdir()):
            if not p.is_file() or p.name.startswith(".") or p.suffix.lower() not in ALLOWED_EXT:
                continue
            src = source_for(p.name, settings)
            if src not in out:
                continue
            try:
                mtime = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)
            except OSError:
                continue
            cur = out[src]["diretoria"]
            if cur is None or mtime > cur["quando"]:
                out[src]["diretoria"] = {"fonte": src, "origem": "diretoria", "nome": p.name, "quando": mtime, "path": str(p)}
    for src in out:
        up = session.scalar(select(FinalInput).where(FinalInput.source == src).order_by(FinalInput.id.desc()).limit(1))
        if up is not None:
            out[src]["carregado"] = {"fonte": src, "origem": "carregado", "nome": up.name, "quando": as_utc(up.uploaded_at),
                                     "id": up.id, "por": up.uploaded_by}
    return out


def current_inputs(session: Session, settings: Settings) -> dict[str, dict]:
    """Ficheiro em uso por fonte: o da diretoria import/, a não ser que tenha sido carregado na página um mais
    recente. Sem nada carregado, usa sempre a diretoria."""
    out: dict[str, dict] = {}
    for src, f in source_files(session, settings).items():
        dir_f, up = f["diretoria"], f["carregado"]
        if up is not None and (dir_f is None or up["quando"] >= dir_f["quando"]):
            out[src] = up
        elif dir_f is not None:
            out[src] = dir_f
    return out


def _input_bytes(session: Session, info: dict) -> bytes:
    if info["origem"] == "carregado":
        up = session.get(FinalInput, info["id"])
        if up is None or up.data is None:
            raise FinalError(f"O ficheiro carregado de {info['fonte']} já não está disponível.")
        return up.data
    try:
        return Path(info["path"]).read_bytes()
    except PermissionError:
        raise FinalError(f"Sem permissão para ler {info['nome']} (no servidor: chmod 644 import/{info['nome']})")


# ------------------------------------------------------------------ reconstrução (núcleo do workflow)
LiveLookup = Callable[[str], dict]


@dataclass
class Result:
    table: CmdbTable
    mods: dict[int, list[str]]
    new_rows: set[int]
    live_rows: set[int]
    expired_rows: set[int]
    changes: list[dict]
    problems: list[dict]
    live: list[dict]
    summary: dict
    originals: dict[int, dict]
    row_src: dict[int, dict] = field(default_factory=dict)
    extra: dict = field(default_factory=dict)          # outras vistas: só na CMDB, Azure


def _identity(row: dict, t: CmdbTable) -> tuple[str, str | None]:
    cn = (row.get(t.h("CommonName")) or "").strip()
    if cn:
        return cn, "CommonName"
    for name in ("Name", "Display Label", "Hostname"):
        v = (row.get(t.h(name)) or "").strip()
        if v and identifier_type(v) != "OUTRO":
            return v, name
    return "", None


def _src_label(fonte: str) -> str:
    return SOURCE_LABELS.get(fonte, fonte)


def _fmt_day(d) -> str:
    if isinstance(d, str):
        d = parse_day(d).day
    return d.strftime("%d-%m-%Y") if d else "sem data"


def _why(entry: dict, src: dict) -> str:
    """Porque é que esta linha é uma alteração, em linguagem simples (a partir dos dados da comparação)."""
    fonte = _src_label(src.get("fonte") or "")
    onde = f"{fonte}" + (f", linha {src['linha']}" if src.get("linha") else "") + (f" ({src['ref']})" if src.get("ref") else "")
    if entry["tipo"] == "novo":
        return (f"Não existe na CMDB: nenhum certificado com este CommonName (nem com este Name, Display Label ou "
                f"Hostname quando o CommonName está vazio). Vem de {onde}, válido até {_fmt_day(src.get('dia_final'))}.")
    if src.get("servidor") and src.get("dia_fonte") and src.get("dia_cmdb") and src["dia_fonte"] < src["dia_cmdb"]:
        return (f"{onde} tem {_fmt_day(src['dia_fonte'])}, anterior à CMDB ({_fmt_day(src['dia_cmdb'])}). Para não andar "
                f"para trás por engano, decidiu o certificado que o servidor apresenta: {_fmt_day(src.get('dia_final'))}.")
    if src.get("dia_cmdb") and src.get("dia_final"):
        rel = "mais recente" if src["dia_final"] > src["dia_cmdb"] else "diferente"
        return (f"Na CMDB está {_fmt_day(src['dia_cmdb'])}; {onde} tem {_fmt_day(src['dia_final'])} ({rel}). "
                "Comparado pelo CommonName e pela data ao dia.")
    return f"Os dados de {onde} são diferentes dos da CMDB."


KnownLookup = Callable[[str, "date | None"], dict]


def reconcile_final(table: CmdbTable, sources: dict[str, list[SourceItem]], settings: Settings,
                    live_lookup: LiveLookup, today: date, known: KnownLookup | None = None) -> Result:
    t = table
    H = t.h
    if not t.rows:
        raise FinalError("CMDB vazia ou não lida. Execução interrompida para evitar a criação em massa de certificados novos.")
    problems: list[dict] = []

    # --- CMDB normalizada
    cmdb_index: dict[str, list[tuple[int, date | None]]] = {}
    for i, row in enumerate(t.rows):
        ident, how = _identity(row, t)
        p = parse_day(row.get(H("ValidTo")))
        if not ident:
            problems.append({"fonte": "CMDB", "ref": row.get(H("Global Id"), ""), "cn": "", "data": row.get(H("ValidTo"), ""),
                             "cmdb": "", "erro": DROP_LABELS["SEM_IDENTIFICADOR_CERTIFICADO"]})
            continue
        if p.status in DATE_WARN:
            problems.append({"fonte": "CMDB", "ref": row.get(H("Global Id"), ""), "cn": ident,
                             "data": row.get(H("ValidTo"), ""), "cmdb": "",
                             "erro": DATE_WARN[p.status] + (f" ({p.note})" if p.note else "")})
        cmdb_index.setdefault(ident.lower(), []).append((i, p.day))

    def cmdb_date_text(cn: str) -> str:
        e = cmdb_index.get(cn.lower())
        return e[0][1].isoformat() if e and e[0][1] else ""

    # --- relatório de erros das fontes
    for src, items in sources.items():
        for it in items:
            if not it.keep or it.date_status in DATE_WARN:
                parts = []
                if it.drop:
                    parts.append(DROP_LABELS.get(it.drop, it.drop))
                if it.date_status in DATE_WARN and not it.drop.startswith("DATA_"):
                    parts.append(DATE_WARN[it.date_status])
                if it.note:
                    parts.append(f"({it.note})")
                problems.append({"fonte": src, "ref": it.ref, "cn": it.cn, "linha": it.row_no,
                                 "data": it.day.isoformat() if it.day else it.raw_date,
                                 "cmdb": cmdb_date_text(it.cn), "erro": " - ".join(parts) or "OK"})

    # --- comparação (CA1, CA2... e depois AVI, pela ordem configurada)
    order = ([RENOVACAO] if RENOVACAO in sources else []) + list(settings.final_sources) + \
        [k for k in sources if k not in settings.final_sources and k != RENOVACAO]
    ordered = [it for src in order for it in sources.get(src, []) if it.keep]
    enriched = []
    for it in ordered:
        cn = it.cn.lower().strip()
        entries = cmdb_index.get(cn, [])
        match = next((e for e in entries if e[1] is not None and it.day is not None and e[1] == it.day), None)
        shown = match or (entries[0] if entries else None)
        enriched.append({"it": it, "match": match is not None, "cmdb_day": shown[1] if shown else None})
    kept: list[dict] = []
    seen: dict[tuple, dict] = {}
    for e in enriched:
        key = (e["it"].cn.lower().strip(), e["it"].day)
        if key in seen:
            cur = seen[key]
            prefer = (e["match"] and not cur["match"]) or (not cur["it"].issuer.strip() and e["it"].issuer.strip())
            if prefer:
                cur.update(e)
            continue
        seen[key] = e
        kept.append(e)
    falsos = [e for e in kept if not e["match"]]

    # --- regressões: a fonte tem data ANTERIOR à da CMDB -> decide o servidor
    live_rows_info: list[dict] = []
    final_items: list[dict] = []
    for e in falsos:
        it = e["it"]
        item = {"cn": it.cn, "day": it.day, "serial": it.serial, "issuer": it.issuer, "san": it.san,
                "source": it.source, "live": it.auth == "servidor", "auth": it.auth, "triage": it.triage,
                "row_no": it.row_no, "ref": it.ref, "cmdb_day": e["cmdb_day"], "source_day": it.day}
        regress = e["cmdb_day"] is not None and it.day is not None and it.day < e["cmdb_day"]
        if not regress:
            final_items.append(item)
            continue
        host = it.cn.strip().rstrip(".")
        info = {"cn": it.cn, "fonte": it.source, "data_fonte": it.day.isoformat(), "data_cmdb": e["cmdb_day"].isoformat()}
        if host.startswith("*."):
            info["decisao"] = "MANTER_CMDB_WILDCARD"
        elif not (_ipv4(host) or _valid_hostname(host)):
            info["decisao"] = "MANTER_CMDB_NOME_INVALIDO"
        else:
            try:
                res = live_lookup(host.lower()) or {}
            except Exception as exc:   # nunca fazer downgrade por falha da verificação
                res = {"status": "ERROR", "detail": str(exc)[:200]}
            info.update({"origem": res.get("origem", ""), "detalhe": res.get("detail", "")})
            if res.get("status") != "OK":
                info["decisao"] = "MANTER_CMDB_SEM_RESPOSTA"
            elif not res.get("not_after"):
                info["decisao"] = "MANTER_CMDB_DATA_INVALIDA"
            else:
                live_day = as_utc(res["not_after"]).date()
                item.update({"day": live_day, "serial": res.get("serial") or item["serial"],
                             "issuer": res.get("issuer_cn") or item["issuer"], "live": True})
                info.update({"decisao": "ATUALIZAR_COM_SERVIDOR", "data_servidor": live_day.isoformat(),
                             "serie_servidor": res.get("serial", ""), "emissor_servidor": res.get("issuer_cn", "")})
                final_items.append(item)
        info["decisao_texto"] = LIVE_LABELS[info["decisao"]]
        live_rows_info.append(info)

    # --- atualização da CMDB
    rows = t.rows
    originals = {i: dict(r) for i, r in enumerate(rows)}
    mods: dict[int, list[str]] = {}
    new_rows: set[int] = set()
    modified: set[int] = set()
    new_by_cn: dict[str, int] = {}
    live_rows: set[int] = set()
    file_rows: set[int] = set()         # dados confirmados pelo ficheiro do certificado (renovação registada)
    issuer_by_source = {k.upper(): v for k, v in settings.import_issuers.items()}

    def set_field(i: int, col: str, value: str) -> None:
        before = rows[i].get(col) or ""
        if before != (value or ""):
            rows[i][col] = value or ""
            mods.setdefault(i, [])
            if col not in mods[i]:
                mods[i].append(col)

    def set_valid_to(i: int, d: date | None) -> None:
        if parse_day(rows[i].get(H("ValidTo"))).day != d:
            set_field(i, H("ValidTo"), valid_to_text(d))

    def set_serial(i: int, serial: str) -> None:
        cur = rows[i].get(H("SerialNumber")) or ""
        if norm_serial(cur) != norm_serial(serial) or (not cur and serial) or (cur and not serial):
            set_field(i, H("SerialNumber"), serial)

    def resolve_issuer(it: dict) -> str:
        if it["source"] in issuer_by_source:
            return issuer_by_source[it["source"]]
        return (it["issuer"] or "").strip()

    # Emissor e número de série de cada certificado (nome + data de fim) em qualquer das fontes
    hints: dict[tuple[str, date | None], dict] = {}
    for src_items in sources.values():
        for x in src_items:
            h = hints.setdefault((x.cn.lower().strip(), x.day), {"issuer": "", "serial": ""})
            iss = issuer_by_source.get(x.source.upper()) or (x.issuer or "").strip()
            if iss and not h["issuer"]:
                h["issuer"] = iss
            if x.serial and not h["serial"]:
                h["serial"] = x.serial

    def complete(it: dict) -> tuple[str, str]:
        """Emissor e série do certificado: a própria linha, outra fonte com o mesmo certificado ou um certificado
        já visto pelo certwatch (servidores ou internet) com o mesmo nome e a mesma data de fim."""
        cn_ = it["cn"].lower().strip()
        iss, ser = resolve_issuer(it), (it["serial"] or "").strip()
        if not iss or not ser:
            h = hints.get((cn_, it["day"])) or {}
            iss, ser = iss or h.get("issuer", ""), ser or h.get("serial", "")
        if (not iss or not ser) and known is not None:
            k = known(cn_, it["day"]) or {}
            iss, ser = iss or (k.get("issuer") or "").strip(), ser or (k.get("serial") or "").strip()
        return iss, ser

    pending: dict[int, list[str]] = {}

    placeholder_rows: set[int] = set()   # SerialNumber "x" posto aqui (numerado mais abaixo)

    def mark_pending(i: int) -> None:
        p = []
        if (rows[i].get(H("IssuerName")) or "").strip() == MISSING_ISSUER:
            p.append("IssuerName")
        ser_ = (rows[i].get(H("SerialNumber")) or "").strip()
        if not ser_ or (i in placeholder_rows and is_placeholder_serial(ser_)):
            p.append("SerialNumber")
        if p:
            pending[i] = p
        else:
            pending.pop(i, None)

    row_src: dict[int, dict] = {}

    def note_src(i: int, it: dict) -> None:
        row_src.setdefault(i, {"fonte": it["source"], "triagem": it.get("triage", ""), "linha": it.get("row_no"),
                               "ref": it.get("ref") or "", "dia_fonte": it.get("source_day"), "dia_cmdb": it.get("cmdb_day"),
                               "dia_final": it.get("day"), "servidor": bool(it.get("live"))})

    for it in final_items:
        cn = it["cn"].lower().strip()
        if not cn:
            continue
        originals_for = [i for i, _ in cmdb_index.get(cn, [])]
        if originals_for:
            cands = [i for i in originals_for if i not in modified] or list(originals_for)
            target, best = None, None
            for i in cands:
                d = parse_day(rows[i].get(H("ValidTo"))).day
                if d is not None and it["day"] is not None:
                    diff = abs((d - it["day"]).days)
                    if best is None or diff < best:
                        best, target = diff, i
            if target is None:
                target = cands[0]
            if not (rows[target].get(H("CommonName")) or "").strip():
                set_field(target, H("CommonName"), it["cn"])
            serial = (it["serial"] or "").strip() or complete(it)[1]
            if not serial and parse_day(rows[target].get(H("ValidTo"))).day != it["day"]:
                # outro certificado (outra data) sem série em nenhuma fonte: a série antiga já não é a dele e, mantida,
                # repetia a chave IssuerName + SerialNumber noutras linhas; o workflow deixava-a vazia, aqui fica x<n>
                serial = MISSING_SERIAL
                placeholder_rows.add(target)
            set_valid_to(target, it["day"])
            if serial:
                set_serial(target, serial)
                mark_pending(target)
            if target in mods:
                note_src(target, it)
            if it["live"] or it.get("auth") == "ficheiro":
                if (it["issuer"] or "").strip():
                    set_field(target, H("Issuer"), it["issuer"].strip())
                    set_field(target, H("IssuerName"), it["issuer"].strip())
                (live_rows if it["live"] else file_rows).add(target)
            modified.add(target)
        elif cn in new_by_cn:
            i = new_by_cn[cn]
            note_src(i, it)
            set_valid_to(i, it["day"])
            iss, serial = complete(it)
            if serial:
                set_serial(i, serial)
            elif it["source"] == INTERNET and not (rows[i].get(H("SerialNumber")) or "").strip():
                set_field(i, H("SerialNumber"), MISSING_SERIAL)
                placeholder_rows.add(i)
            if iss and (rows[i].get(H("IssuerName")) or "").strip() in ("", MISSING_ISSUER):
                set_field(i, H("Issuer"), iss)
                set_field(i, H("IssuerName"), iss)
            mark_pending(i)
            if it["san"] and not (rows[i].get(H("Subject Alternative Names")) or "").strip():
                set_field(i, H("Subject Alternative Names"), it["san"])
            if it["live"]:
                live_rows.add(i)
        else:
            iss, serial = complete(it)
            iss = iss or MISSING_ISSUER          # Issuer e IssuerName sempre preenchidos nas linhas novas
            if not serial and it["source"] == INTERNET:
                serial = MISSING_SERIAL
                placeholder_new = True
            else:
                placeholder_new = False
            row = {h: "" for h in t.headers}
            row.update({
                H("Display Label"): it["cn"], H("Name"): it["cn"], H("CommonName"): it["cn"],
                H("ValidTo"): valid_to_text(it["day"]), H("Localização"): it["source"],
                H("Certificate Status"): "Ativo", H("SerialNumber"): serial,
                H("Issuer"): iss, H("IssuerName"): iss, H("Subject Alternative Names"): it["san"] or "",
                H("Certificate Type"): "SSL", H("Description"): f"{settings.final_description} - novo certificado",
                H("Global Id"): "x",
            })
            rows.append(row)
            t.ids.append("")
            i = len(rows) - 1
            new_rows.add(i)
            new_by_cn[cn] = i
            if placeholder_new:
                placeholder_rows.add(i)
            note_src(i, it)
            mark_pending(i)
            if it["live"]:
                live_rows.add(i)

    # SerialNumber "x" numerado (x1, x2...) a seguir ao maior que já exista na CMDB: cada certificado sem série
    # tem uma chave IssuerName + SerialNumber só sua e nunca a de um CI que já lá está
    used = [int(m.group(1)) for r in originals.values()
            if (m := _PLACEHOLDER_SERIAL.match((r.get(H("SerialNumber")) or "").strip())) and m.group(1)]
    n = max(used, default=0)
    for i in sorted((i for i in placeholder_rows if (rows[i].get(H("SerialNumber")) or "").strip().lower() == MISSING_SERIAL),
                    key=lambda i: (i in new_rows, (rows[i].get(H("CommonName")) or "").lower(), i)):
        n += 1
        rows[i][H("SerialNumber")] = f"{MISSING_SERIAL}{n}"
        mark_pending(i)

    # --- Description das linhas existentes alteradas (estado final vs. original)
    def audit(lst, label, before, after, is_date):
        a, d = (before or "").strip(), (after or "").strip()
        if a == d:
            return
        af = _audit_date(before) if is_date else (a or "(vazio)")
        df = _audit_date(after) if is_date else (d or "(vazio)")
        if not a and d:
            lst.append(f"{label} preenchido com {df}")
        elif a and not d:
            lst.append(f"{label} removido (valor anterior: {af})")
        else:
            lst.append(f"{label} alterado de {af} para {df}")

    changes: list[dict] = []
    for i in sorted(mods):
        if i in new_rows:
            continue
        orig, row = originals[i], rows[i]
        lst: list[str] = []
        audit(lst, "CommonName", orig.get(H("CommonName")), row.get(H("CommonName")), False)
        audit(lst, "Data de expiracao", orig.get(H("ValidTo")), row.get(H("ValidTo")), True)
        audit(lst, "SerialNumber", orig.get(H("SerialNumber")), row.get(H("SerialNumber")), False)
        audit(lst, "Issuer", orig.get(H("Issuer")), row.get(H("Issuer")), False)
        audit(lst, "IssuerName", orig.get(H("IssuerName")), row.get(H("IssuerName")), False)
        desc = settings.final_description
        marker = settings.final_live_marker if i in live_rows else (FILE_MARKER if i in file_rows else "")
        if marker:
            desc += f" - {marker}"
        if lst:
            desc += ("; " if marker else " - ") + "; ".join(lst)
        set_field(i, H("Description"), desc)

    inv = {v: k for k, v in t.display.items()}
    for i in sorted(set(mods) | new_rows):
        row = rows[i]
        src = row_src.get(i, {})
        entry = {"chave": i, "linha": i + 2, "tipo": "novo" if i in new_rows else "alterado",
                 "cn": row.get(H("CommonName"), ""), "global_id": row.get(H("Global Id"), ""),
                 "fonte": src.get("fonte", ""), "triagem": src.get("triagem", ""),
                 "servidor": i in live_rows, "descricao": row.get(H("Description"), ""),
                 "validto": row.get(H("ValidTo"), ""), "issuer": row.get(H("Issuer"), ""),
                 "issuer_name": row.get(H("IssuerName"), ""), "serial": row.get(H("SerialNumber"), ""),
                 "pendente": pending.get(i, [])}
        if i not in new_rows:
            entry["campos"] = [{"campo": inv.get(c, c), "antes": originals[i].get(c, ""), "depois": row.get(c, "")}
                               for c in mods[i] if c != H("Description")]
        entry["motivo"] = _why(entry, src)
        changes.append(entry)

    # --- só na CMDB: certificados com o emissor de uma CA lida que não aparecem na exportação dessa CA
    issuer_of = {src.upper(): norm_issuer(v) for src, v in settings.import_issuers.items() if v}
    so_na_cmdb = []
    for src, items in sources.items():
        inorm = issuer_of.get(src.upper())
        if not inorm or not items:
            continue
        present = {x.cn.lower().strip() for x in items if x.cn}
        for i, r in originals.items():
            ident, _ = _identity(r, t)
            d = parse_day(r.get(H("ValidTo"))).day
            iss = norm_issuer(r.get(H("IssuerName")) or r.get(H("Issuer")) or "")
            if ident and iss == inorm and ident.lower() not in present and d is not None and d >= today:
                so_na_cmdb.append({"cn": ident, "fonte": src, "ucmdb_id": t.ids[i] if i < len(t.ids) else "",
                                   "global_id": r.get(H("Global Id"), ""), "validto": d.isoformat(),
                                   "issuer": r.get(H("IssuerName")) or r.get(H("Issuer")) or "",
                                   "estado": r.get(t.display.get("Certificate Status", ""), "") if "Certificate Status" in t.display else "",
                                   "description": r.get(H("Description"), "")})
    so_na_cmdb.sort(key=lambda x: (x["fonte"], x["cn"].lower()))

    expired = {i for i, r in enumerate(rows) if (d := parse_day(r.get(H("ValidTo"))).day) is not None and d < today}
    src_counts = {src: {"lidas": len(items), "validas": sum(1 for x in items if x.keep)} for src, items in sources.items()}
    summary = {
        "cmdb_linhas": len(originals), "final_linhas": len(rows),
        "novos": len(new_rows), "alterados": len([i for i in mods if i not in new_rows]),
        "expirados": len(expired), "diferencas_fontes": len(falsos), "coincidentes": len(kept) - len(falsos),
        "regressoes": len(live_rows_info),
        "regressoes_atualizadas": sum(1 for x in live_rows_info if x["decisao"] == "ATUALIZAR_COM_SERVIDOR"),
        "erros": len(problems), "fontes": src_counts, "hoje": today.isoformat(), "so_na_cmdb": len(so_na_cmdb),
        "fontes_validas": sum(v["validas"] for v in src_counts.values()),
        "fontes_comparadas": len(kept),
    }
    return Result(table=t, mods=mods, new_rows=new_rows, live_rows=live_rows, expired_rows=expired,
                  changes=changes, problems=problems, live=live_rows_info, summary=summary, originals=originals,
                  row_src=row_src, extra={"so_na_cmdb": so_na_cmdb})


# ------------------------------------------------------------------ saídas
_ILLEGAL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def build_xlsx(res: Result) -> bytes:
    from openpyxl import Workbook
    from openpyxl.cell import WriteOnlyCell
    from openpyxl.styles import PatternFill

    fills = {k: PatternFill("solid", fgColor="FF" + k) for k in (GREEN, YELLOW, RED)}
    wb = Workbook(write_only=True)
    ws = wb.create_sheet("CMDB")

    def cells(values, fill=None):
        out = []
        for v in values:
            c = WriteOnlyCell(ws, value=_ILLEGAL.sub("", v or ""))
            c.data_type = "s"      # sempre texto: nunca fórmulas
            if fill is not None:
                c.fill = fill
            out.append(c)
        return out

    ws.append(cells(res.table.headers))
    for i, row in enumerate(res.table.rows):
        color = RED if i in res.expired_rows else (GREEN if i in res.new_rows else (YELLOW if i in res.mods else None))
        ws.append(cells([row.get(h, "") for h in res.table.headers], fills[color] if color else None))
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _delta_rows(res: Result) -> list[dict[str, str]]:
    t = res.table
    out = []
    for i, row in enumerate(t.rows):
        if i in res.new_rows or i in res.mods:
            out.append({c: row.get(t.display.get(c, ""), "") if c in t.display else "" for c in OUTPUT_COLUMNS})
    return out


def validate_delta(rows: list[dict[str, str]]) -> list[str]:
    problems = []
    bad = [r for r in rows if r["Global Id"].strip().lower() == "x"
           and not (r["Issuer"].strip() and r["IssuerName"].strip() and r["SerialNumber"].strip())]
    if bad:
        ex = " | ".join(f"{r['CommonName'] or '(sem CommonName)'} [Issuer={r['Issuer'] or 'VAZIO'}; "
                        f"IssuerName={r['IssuerName'] or 'VAZIO'}; SerialNumber={r['SerialNumber'] or 'VAZIO'}]"
                        for r in bad[:10])
        problems.append(f"{len(bad)} certificado(s) novo(s) (Global Id = x) sem Issuer, IssuerName ou SerialNumber. Como "
                        f"IssuerName + SerialNumber formam a chave primária na CMDB, os CSV não são gerados: exclua-os ou "
                        f"complete a fonte. Exemplos: {ex}")
    groups: dict[tuple[str, str], list[dict]] = {}
    for r in rows:
        iss, ser = r["IssuerName"].strip().lower(), r["SerialNumber"].strip().lower()
        if not iss or not ser or iss == MISSING_ISSUER.lower():
            continue                     # "Por verificar" não identifica o emissor: avisado à parte
        groups.setdefault((iss, ser), []).append(r)
    dup = [g for g in groups.values() if len(g) > 1]
    if dup:
        ex = " | ".join(f"{g[0]['IssuerName']} + {g[0]['SerialNumber']}: " +
                        ", ".join(f"{r['CommonName'] or '(sem CommonName)'} (Global Id {r['Global Id'] or '—'})" for r in g)
                        for g in dup[:10])
        problems.append(f"Chave primária repetida (IssuerName + SerialNumber) em {len(dup)} caso(s): a mesma chave em "
                        f"mais de uma linha do certs_update faria a UCMDB juntar certificados diferentes. Deixe só uma "
                        f"linha de cada chave incluída. {ex}")
    return problems


def duplicate_groups(changes: list[dict]) -> list[list[dict]]:
    """Alterações com a mesma chave IssuerName + SerialNumber (o mesmo certificado com vários nomes)."""
    groups: dict[tuple[str, str], list[dict]] = {}
    for c in changes:
        iss, ser = (c.get("issuer_name") or "").strip().lower(), (c.get("serial") or "").strip().lower()
        if iss and ser and iss != MISSING_ISSUER.lower():
            groups.setdefault((iss, ser), []).append(c)
    return [g for g in groups.values() if len(g) > 1]


def _keep_one(g: list[dict], prefer: dict | None = None) -> None:
    """Fica uma alteração incluída por chave: a escolhida, a de um CI que já existe, ou a do nome mais curto."""
    keeper = prefer or min(g, key=lambda c: (c["tipo"] == "novo", len(c.get("cn") or ""), c.get("cn") or ""))
    for c in g:
        others = ", ".join(f"{o['cn'] or '(sem CommonName)'} (Global Id {o['global_id'] or '—'})" for o in g if o is not c)
        c["chave_repetida"] = others
        if c is keeper:
            continue
        if c.get("incluir", True):
            c["incluir"] = False
            c["porque"] = (f"mesmo certificado que {keeper['cn']} (mesmo emissor e número de série): é um certificado "
                           "com vários nomes e na CMDB fica um só registo. Para trocar, inclua este; o outro sai.")


def flag_duplicate_keys(changes: list[dict], decisions: dict) -> None:
    """Na mesma chave IssuerName + SerialNumber só fica uma alteração incluída (a UCMDB juntaria as duas)."""
    for g in duplicate_groups(changes):
        chosen = [c for c in g if (d := decisions.get(decision_key(c))) is not None and d.include]
        _keep_one(g, chosen[0] if chosen else None)


def _placeholder_clashes(rows: list[dict[str, str]]) -> int:
    """Linhas novas com o mesmo par IssuerName + SerialNumber por causa de "Por verificar" (mesma série real)."""
    seen: dict[tuple[str, str], int] = {}
    for r in rows:
        if r["Global Id"].strip().lower() != "x":
            continue
        iss, ser = r["IssuerName"].strip().lower(), r["SerialNumber"].strip().lower()
        if ser and iss == MISSING_ISSUER.lower():
            seen[(iss, ser)] = seen.get((iss, ser), 0) + 1
    return sum(n for n in seen.values() if n > 1)


def _csv_text(v: str) -> str:
    return _fix_mojibake(v or "").replace("﻿", "").replace(" ", " ").replace("\r\n", " ") \
        .replace("\r", " ").replace("\n", " ").replace("\t", " ").replace("|", " / ")


def build_csv(rows: list[dict[str, str]], header: bool = True) -> bytes:
    lines = []
    if header:
        lines.append("|".join('"' + _csv_text(c).replace('"', '""') + '"' for c in OUTPUT_COLUMNS))
        for r in rows:
            lines.append("|".join('"' + _csv_text(r[c]).replace('"', '""') + '"' for c in OUTPUT_COLUMNS))
    else:
        for r in rows:
            lines.append("|".join(re.sub(r'["“”]', "", _csv_text(r[c])) for c in OUTPUT_COLUMNS))
    return ("\r\n".join(lines) + "\r\n").encode("utf-8") if lines else b""


# ------------------------------------------------------------------ seleção: incluir ou não cada alteração
def decision_key(change: dict) -> str:
    """A mesma alteração em gerações diferentes: mesmo CommonName e mesma nova data de expiração."""
    day = parse_day(change.get("validto")).day
    return f"{(change.get('cn') or '').strip().lower()}|{day.isoformat() if day else ''}"


def default_include(change: dict, decisions: dict) -> tuple[bool, str]:
    d = decisions.get(decision_key(change))
    if d is not None:
        return d.include, f"{'incluída' if d.include else 'excluída'} por {d.by} em {as_utc(d.at):%d-%m-%Y}"
    if change.get("fonte") == INTERNET and change.get("triagem") != "adicionar":
        return False, 'encontrado na internet e ainda não marcado "Adicionar à CMDB"'
    if change.get("tipo") == "novo" and not (change.get("serial") or "").strip():
        return False, "sem SerialNumber em nenhuma fonte (IssuerName + SerialNumber é a chave primária na CMDB)"
    return True, ""


def pack_state(res: Result) -> bytes:
    t = res.table
    data = {"headers": t.headers, "display": t.display, "rows": t.rows, "ids": t.ids,
            "originals": {str(i): res.originals[i] for i in res.mods if i not in res.new_rows},
            "new": sorted(res.new_rows), "mods": {str(i): c for i, c in res.mods.items()},
            "today": res.summary["hoje"]}
    return gzip.compress(json.dumps(data, ensure_ascii=False).encode("utf-8"))


def unpack_state(blob: bytes) -> dict:
    return json.loads(gzip.decompress(blob).decode("utf-8"))


@dataclass
class Materialized:
    table: CmdbTable
    new_rows: set[int]
    mods: dict[int, list[str]]
    expired_rows: set[int]
    line_of: dict[int, int]


def materialize(state: dict, excluded: set[int]) -> Materialized:
    """CMDB final sem as alterações excluídas: linhas novas excluídas saem, linhas alteradas voltam ao original."""
    today = date.fromisoformat(state["today"])
    new = set(state["new"])
    mods = {int(k): v for k, v in state["mods"].items()}
    originals = {int(k): v for k, v in state["originals"].items()}
    rows, ids, m_new, m_mods, line_of = [], [], set(), {}, {}
    for i, row in enumerate(state["rows"]):
        if i in excluded:
            if i in new:
                continue
            row = originals.get(i, row)
        j = len(rows)
        rows.append(row)
        ids.append(state["ids"][i] if i < len(state["ids"]) else "")
        line_of[i] = j + 2
        if i not in excluded:
            if i in new:
                m_new.add(j)
            elif i in mods:
                m_mods[j] = mods[i]
    display = state["display"]
    vt = display["ValidTo"]
    expired = {j for j, r in enumerate(rows) if (d := parse_day(r.get(vt)).day) is not None and d < today}
    return Materialized(CmdbTable(headers=state["headers"], display=display, rows=rows, ids=ids),
                        m_new, m_mods, expired, line_of)


def build_outputs(state: dict, changes: list[dict]) -> tuple[bytes, bytes | None, bytes | None, list[str], dict]:
    excluded = {c["chave"] for c in changes if not c.get("incluir", True)}
    m = materialize(state, excluded)
    for c in changes:
        c["linha"] = m.line_of.get(c["chave"])
    delta = _delta_rows(m)
    problems = validate_delta(delta)
    if any(list(r) != OUTPUT_COLUMNS for r in delta):       # o formato do certs_update é fixo
        problems.append("Formato do certs_update diferente das 26 colunas fixas.")
    csv = csv_sem = None
    if not problems:
        csv, csv_sem = build_csv(delta, True), build_csv(delta, False)
    counts = {"novos": len(m.new_rows), "alterados": len(m.mods), "excluidos": len(excluded), "delta": len(delta),
              "final_linhas": len(m.table.rows), "expirados": len(m.expired_rows),
              "por_verificar": sum(1 for c in changes if c.get("pendente") and c.get("incluir", True)),
              "por_verificar_repetidos": _placeholder_clashes(delta)}
    return build_xlsx(m), csv, csv_sem, problems, counts


def editable(session: Session, run: FinalRun) -> bool:
    if run.status not in ("pronto", "bloqueado") or run.state is None:
        return False
    newest = session.scalar(select(FinalRun.id).where(FinalRun.status.in_(("pronto", "bloqueado")))
                            .order_by(FinalRun.id.desc()).limit(1))
    return newest == run.id


def apply_selection(session: Session, run: FinalRun, shown: list[int], chosen: set[int], actor: str) -> int:
    """Grava a escolha (incluir/excluir) das alterações mostradas e refaz os ficheiros. Devolve quantas mudaram."""
    if not editable(session, run):
        raise FinalError("Só a reconciliação mais recente pode ser alterada. Reconcilie de novo.")
    changes = [dict(c) for c in (run.changes or [])]
    by_key = {c["chave"]: c for c in changes}
    changed = 0
    just_in: set[int] = set()          # as que passaram agora a incluídas (ganham numa chave repetida)
    for k in shown:
        c = by_key.get(k)
        if c is None:
            continue
        inc = k in chosen
        if c.get("incluir", True) == inc:
            continue
        if inc:
            just_in.add(k)
        c["incluir"] = inc
        c["porque"] = f"{'incluída' if inc else 'excluída'} por {actor} em {utcnow():%d-%m-%Y}"
        changed += 1
        key = decision_key(c)
        d = session.scalar(select(FinalDecision).where(FinalDecision.key == key))
        if d is None:
            d = FinalDecision(key=key)
            session.add(d)
        d.include, d.by, d.at = inc, actor, utcnow()
    if not changed:
        return 0
    # Chave repetida: ao incluir uma, a outra sai (só pode ficar uma)
    for g in duplicate_groups(changes):
        if sum(1 for c in g if c.get("incluir", True)) > 1:
            pick = next((c for c in g if c["chave"] in just_in and c.get("incluir", True)), None)
            _keep_one(g, pick)
            for c in g:
                if not c.get("incluir", True):
                    d = session.scalar(select(FinalDecision).where(FinalDecision.key == decision_key(c)))
                    if d is not None:
                        d.include, d.by, d.at = False, actor, utcnow()
    xlsx, csv, csv_sem, problems, counts = build_outputs(unpack_state(run.state), changes)
    run.changes = changes
    run.xlsx, run.csv, run.csv_sem = xlsx, csv, csv_sem
    run.validation = problems
    run.status = "bloqueado" if problems else "pronto"
    run.summary = {**(run.summary or {}), **counts}
    return changed


# ------------------------------------------------------------------ verificação no servidor
def make_live_lookup(session: Session, settings: Settings) -> LiveLookup:
    """Certificado apresentado em host:443: usa o scan do certwatch se for recente, senão liga-se na hora."""
    from .scanner import scan_endpoint, summarize
    from .trust import build_bundle
    max_age = timedelta(hours=settings.final_live_max_age_h)

    def look(host: str) -> dict:
        ep = session.scalar(select(Endpoint).where(Endpoint.host == host, Endpoint.port == 443))
        if ep is not None and ep.last_scan_id:
            sr = session.get(ScanResult, ep.last_scan_id)
            if sr is not None and sr.status == "ok" and sr.leaf_sha256 and utcnow() - as_utc(sr.scanned_at) <= max_age:
                c = session.get(Certificate, sr.leaf_sha256)
                if c is not None:
                    return {"status": "OK", "not_after": c.not_after, "serial": (c.serial_hex or "").upper(),
                            "issuer_cn": c.issuer_cn, "origem": f"verificação de {as_utc(sr.scanned_at):%d-%m-%Y %H:%M} UTC"}
        out = scan_endpoint(host, 443, build_bundle(settings), timeout=12.0)
        if out.status != "ok" or not out.chain_der:
            return {"status": "ERROR", "detail": out.error or out.status, "origem": "ligação na hora"}
        s = summarize(out.chain_der[0])
        return {"status": "OK", "not_after": s["not_after"], "serial": s["serial_hex"].upper(),
                "issuer_cn": s["issuer_cn"], "origem": "ligação na hora"}
    return look


def make_known_lookup(session: Session, settings: Settings) -> KnownLookup:
    """Certificados já vistos pelo certwatch (nos servidores ou na internet), por nome e data de fim (±1 dia)."""
    tz = ZoneInfo(settings.timezone)
    index: dict[str, list[tuple[date, str, str, int]]] = {}

    def add(names, not_after, issuer, serial, rank):
        if not_after is None or not (issuer or serial):
            return
        d = as_utc(not_after).astimezone(tz).date()
        for n in {(x or "").strip().lower() for x in names if x}:
            index.setdefault(n, []).append((d, (issuer or "").strip(), (serial or "").upper(), rank))

    for cn, sans, na, iss, ser in session.execute(select(Certificate.subject_cn, Certificate.sans_dns, Certificate.not_after,
                                                         Certificate.issuer_cn, Certificate.serial_hex)
                                                  .where(Certificate.is_ca.is_(False))):
        add([cn, *(sans or [])], na, iss, ser, 0)
    for names, primary, na, iss, ser in session.execute(select(CtCert.names, CtCert.primary_name, CtCert.not_after,
                                                               CtCert.issuer_cn, CtCert.serial_hex)):
        add([primary, *(names or [])], na, iss, ser, 1)

    def look(cn: str, day: date | None) -> dict:
        if day is None:
            return {}
        best = None
        for d, iss, ser, rank in index.get(cn, []):
            diff = abs((d - day).days)
            if diff <= 1 and (best is None or (diff, rank) < best[0]):
                best = ((diff, rank), iss, ser)
        return {"issuer": best[1], "serial": best[2]} if best else {}
    return look


# ------------------------------------------------------------------ execução
def azure_view(session: Session, table: CmdbTable, filename: str, data: bytes, today: date) -> tuple[list[dict], dict]:
    """Compara a exportação do Azure com a lista de APIs (cópia do certwatch) e com os certificados da CMDB lida agora."""
    from .azure_rec import compare, read_azure
    rows, info = read_azure(data, filename, today)
    apis = [{"ucmdb_id": a.ucmdb_id, "nome": a.name, "aplicacao": a.application, "localizacao": a.location,
             "data": as_utc(a.expiry).date() if a.expiry else None}
            for a in session.scalars(select(ApiRecord).where(ApiRecord.active.is_(True)))]
    H = table.h
    certs = []
    for i, r in enumerate(table.rows):
        names = [r.get(table.display[c], "") for c in ("CommonName", "Name", "Display Label") if c in table.display]
        certs.append({"ucmdb_id": table.ids[i] if i < len(table.ids) else "", "nomes": [x for x in names if x],
                      "data": parse_day(r.get(H("ValidTo"))).day})
    info["apis_lidas"] = len(apis)
    return compare(rows, apis, certs, today), info


def start_run(session: Session, actor: str, only: list[str] | None = None) -> FinalRun:
    busy = session.scalar(select(FinalRun).where(FinalRun.status == "a_gerar").limit(1))
    if busy is not None:
        if utcnow() - as_utc(busy.created_at) < STALE_AFTER:
            raise FinalError(f"A reconciliação #{busy.id} ainda está a decorrer. Aguarde que termine.")
        busy.status, busy.error, busy.finished_at = "erro", "Interrompido (o processo parou durante a reconciliação).", utcnow()
    run = FinalRun(created_by=actor, status="a_gerar", summary={"ambito": list(only)} if only else {})
    session.add(run)
    session.flush()
    return run


def all_sources(settings: Settings) -> list[str]:
    """Todas as fontes que podem ser reconciliadas, pela ordem da página."""
    return [*settings.final_sources, AZURE_SOURCE, *([INTERNET] if settings.final_ct else []), RENOVACAO]


def source_name(src: str) -> str:
    return {AZURE_SOURCE: "Azure", INTERNET: "Internet", RENOVACAO: "Renovações"}.get(src, src)


def missing_message(settings: Settings, missing: list[str]) -> str:
    from .reconcile import scan_import_dir
    names = ", ".join(f"{m} (import/{settings.import_sources.get(m, m.lower())}…)" for m in missing)
    other = [f["name"] for f in scan_import_dir(settings) if not f["ok"]][:10]
    return (f"Falta o ficheiro de: {names}. Coloque-o na diretoria import/ do servidor com um nome a começar assim, "
            "ou carregue-o na página." + (f" Ficheiros em import/ que não são de nenhuma fonte: {', '.join(other)}." if other else ""))


def generate(run_id: int, settings: Settings, fetch: Callable | None = None,
             live_factory: Callable[[Session, Settings], LiveLookup] | None = None, today: date | None = None,
             only: list[str] | None = None) -> None:
    """Gera os três ficheiros de uma execução. Nunca deixa a execução em "a_gerar".
    `only`: reconcilia só estas fontes (as outras não são lidas nem obrigatórias)."""
    tz = ZoneInfo(settings.timezone)
    today = today or datetime.now(tz).date()
    scope = {x.upper() for x in only} if only else None
    use = lambda src: scope is None or src in scope
    try:
        table, records = (fetch or fetch_cmdb_table)(settings)
        with session_scope() as s:
            inputs = current_inputs(s, settings)
            files = [src for src in settings.final_sources if use(src)]
            missing = [src for src in files if src not in inputs]
            if scope is not None and AZURE_SOURCE in scope and AZURE_SOURCE not in inputs:
                missing.append(AZURE_SOURCE)
            if missing:
                raise FinalError(missing_message(settings, missing))
            sources, src_info = {}, {}
            for src in files:
                info = inputs[src]
                data = _input_bytes(s, info)
                items, rinfo = read_source(src, info["nome"], data, today)
                sources[src] = items
                src_info[src] = {**rinfo, "origem": info["origem"], "quando": info["quando"].isoformat(),
                                 "sha256": hashlib.sha256(data).hexdigest()}
            from .renewal import source_items
            ren = [SourceItem(source=RENOVACAO, row_no=n, cn=x["cn"], day=x["day"], serial=x["serial"], issuer=x["issuer"],
                              san=x["san"], ref=x["ref"], auth=x["origin"] if x["origin"] in ("servidor", "ficheiro") else "",
                              raw_date=x["day"].isoformat())
                   for n, x in enumerate(source_items(s, today), start=1)] if use(RENOVACAO) else []
            if ren:
                sources[RENOVACAO] = ren
                src_info[RENOVACAO] = {"ficheiro": "renovações registadas nos pedidos", "linhas": len(ren),
                                       "validas": len(ren), "origem": "certwatch"}
            if settings.final_ct and use(INTERNET):
                ct_items, ct_info = ct_source(s, settings, today)
                if ct_items:
                    sources[INTERNET] = ct_items
                    src_info[INTERNET] = {**ct_info, "origem": "internet"}
            res = reconcile_final(table, sources, settings, (live_factory or make_live_lookup)(s, settings), today,
                                  make_known_lookup(s, settings))
            if AZURE_SOURCE in inputs and use(AZURE_SOURCE):
                az_info = inputs[AZURE_SOURCE]
                az_data = _input_bytes(s, az_info)
                try:
                    res.extra["azure"], ainfo = azure_view(s, table, az_info["nome"], az_data, today)
                    src_info[AZURE_SOURCE] = {**{k: v for k, v in ainfo.items() if k != "problemas"},
                                              "origem": az_info["origem"], "quando": az_info["quando"].isoformat(),
                                              "sha256": hashlib.sha256(az_data).hexdigest()}
                    res.problems.extend(ainfo["problemas"])
                except ValueError as exc:
                    res.problems.append({"fonte": AZURE_SOURCE, "cn": "", "erro": f"Ficheiro do Azure ignorado: {exc}"})
            decisions = {d.key: d for d in s.scalars(select(FinalDecision))}
            for c in res.changes:
                c["incluir"], c["porque"] = default_include(c, decisions)
            flag_duplicate_keys(res.changes, decisions)
        state = pack_state(res)
        xlsx, csv, csv_sem, problems, counts = build_outputs(unpack_state(state), res.changes)
        with session_scope() as s:
            run = s.get(FinalRun, run_id)
            run.summary = {**res.summary, **counts, "novos_total": len(res.new_rows),
                           "alterados_total": len([i for i in res.mods if i not in res.new_rows]),
                           "ambito": [x for x in all_sources(settings) if x in scope] if scope is not None else None}
            run.inputs = src_info
            run.columns = table.diag
            run.changes = res.changes
            run.problems = res.problems[:5000]
            run.live = res.live
            run.validation = problems
            run.vistas = res.extra
            run.state = state
            run.xlsx, run.csv, run.csv_sem = xlsx, csv, csv_sem
            run.status = "bloqueado" if problems else "pronto"
            run.finished_at = utcnow()
            _prune(s, settings)
        _refresh_cmdb(records, settings)
    except Exception as exc:
        if not isinstance(exc, FinalError):
            log.exception("Geração da CMDB final #%s falhou", run_id)
        with session_scope() as s:
            run = s.get(FinalRun, run_id)
            if run is not None:
                run.status, run.error, run.finished_at = "erro", str(exc)[:2000], utcnow()


def _refresh_cmdb(records: list[dict], settings: Settings) -> None:
    """A mesma leitura serve para atualizar a CMDB do certwatch (usada na comparação)."""
    if not records:
        return
    from .jobs import IngestAborted, ingest_cmdb
    try:
        with session_scope() as s:
            ingest_cmdb(s, settings, records)
    except IngestAborted as exc:
        log.warning("CMDB do certwatch não atualizada: %s", exc)
    except Exception:
        log.exception("CMDB do certwatch não atualizada")


def generate_in_background(run_id: int, settings: Settings, only: list[str] | None = None) -> None:
    threading.Thread(target=generate, args=(run_id, settings), kwargs={"only": only},
                     name=f"cmdb-final-{run_id}", daemon=True).start()


def _prune(session: Session, settings: Settings) -> None:
    """Mantém os ficheiros das últimas N execuções (os resumos ficam)."""
    keep = max(settings.final_keep_runs, 1)
    ids = list(session.scalars(select(FinalRun.id).order_by(FinalRun.id.desc()).offset(keep)))
    if ids:
        session.execute(update(FinalRun).where(FinalRun.id.in_(ids)).values(xlsx=None, csv=None, csv_sem=None, state=None))


def run_file(run: FinalRun, key: str) -> bytes | None:
    return {"xlsx": run.xlsx, "csv": run.csv, "csv_sem": run.csv_sem}.get(key)


def read_final_xlsx(data: bytes) -> list[dict]:
    """Lê um CMDB_Final.xlsx (deste certwatch ou do n8n): identificação, ValidTo, Issuer, IssuerName e a cor."""
    from openpyxl import load_workbook
    wb = load_workbook(io.BytesIO(data), data_only=True)
    try:
        ws = wb.worksheets[0]
        rows = ws.iter_rows()
        header = next(rows, None)
        if not header:
            raise FinalError("O ficheiro está vazio.")
        idx = {norm_header(c.value): i for i, c in enumerate(header) if c.value not in (None, "")}
        if "validto" not in idx or not ({"commonname", "globalid"} & set(idx)):
            raise FinalError("O ficheiro não tem as colunas ValidTo e CommonName/Global Id: não parece um CMDB_Final.")
        out = []
        for n, r in enumerate(rows, start=2):
            vals = [c.value for c in r]
            if not any(v not in (None, "") for v in vals):
                continue

            def g(k):
                i = idx.get(k)
                v = vals[i] if i is not None and i < len(vals) else None
                return "" if v is None else (v if isinstance(v, (datetime, date)) else str(v).strip())
            color = None
            try:
                fg = r[0].fill.fgColor.rgb if r[0].fill is not None and r[0].fill.fill_type == "solid" else None
                color = COLOR_STATE.get(str(fg or "")[-6:].upper())
            except (AttributeError, IndexError, TypeError):
                color = None
            cn = g("commonname")
            if not cn:
                for k in ("name", "displaylabel", "hostname"):
                    v = g(k)
                    if v and identifier_type(str(v)) != "OUTRO":
                        cn = v
                        break
            out.append({"linha": n, "cn": str(cn), "global_id": str(g("globalid")), "validto": g("validto"),
                        "issuer": str(g("issuer")), "issuer_name": str(g("issuername")), "cor": color})
        return out
    finally:
        wb.close()


# ------------------------------------------------------------------ o que cada separador compara (para o utilizador)
VIEWS = {
    "novos": {
        "label": "Novos",
        "compara": "Cada certificado das fontes (CA1, CA2, AVI, internet e renovações registadas) com os certificados da CMDB lidos agora pela API.",
        "chave": "O CommonName (sem maiúsculas). Se o CommonName da CMDB estiver vazio, usa-se o Name, o Display Label ou o Hostname.",
        "regra": "Está aqui quando o nome não existe na CMDB.",
        "aplicar": "Cria o certificado na UCMDB (no certs_update fica com Global Id = x). Emissor que nenhuma fonte tenha fica \"Por verificar\"; série que falte num certificado da internet fica x1, x2…",
    },
    "alterados": {
        "label": "Renovados e alterados",
        "compara": "Os mesmos certificados, quando o nome já existe na CMDB.",
        "chave": "O CommonName e a data de expiração ao dia (a hora não conta).",
        "regra": "Está aqui quando a data é diferente. Data da fonte mais recente: renovação por registar. Data mais antiga: decide o servidor (separador seguinte). Também quando o CommonName da CMDB estava vazio e foi encontrado pelo Name.",
        "aplicar": "Atualiza só os campos que mudaram (ValidTo, SerialNumber, emissor e a Description com o registo da mudança), depois de confirmar que a UCMDB ainda tem os valores de antes.",
    },
    "servidor": {
        "label": "Data mais antiga",
        "compara": "A data da fonte com a da CMDB, quando a da fonte é anterior.",
        "chave": "O nome do certificado como servidor, na porta 443.",
        "regra": "Para não andar para trás por engano, usa-se o certificado que o servidor apresenta (verificação do certwatch recente ou ligação na hora). Sem resposta, num wildcard ou num nome que não é servidor, a CMDB fica como está.",
        "aplicar": "Os que o servidor confirma passam para Renovados e alterados, com os dados do servidor.",
    },
    "confirmar": {
        "label": "Por confirmar",
        "compara": "As alterações dos dois primeiros separadores que precisam de atenção.",
        "chave": "IssuerName + SerialNumber, a chave do certificado na CMDB.",
        "regra": "Está aqui quando nenhuma fonte trouxe o emissor (\"Por verificar\") ou a série (x1, x2…), ou quando outra linha tem a mesma chave IssuerName + SerialNumber.",
        "aplicar": "Pode aplicar. Na chave repetida (o mesmo certificado com vários nomes) fica incluída uma; para trocar, inclua a outra.",
    },
    "so_na_cmdb": {
        "label": "Só na CMDB",
        "compara": "Os certificados da CMDB com o emissor de uma CA (CERTWATCH_IMPORT_ISSUERS) com a exportação dessa CA.",
        "chave": "O CommonName.",
        "regra": "Está aqui quando está na CMDB, ainda válido, mas não aparece na exportação da CA: pode ter sido revogado, ou a exportação estar incompleta.",
        "aplicar": "Nada é feito automaticamente. Use Editar para mudar o que entender, por exemplo o estado.",
    },
    "azure": {
        "label": "Azure",
        "compara": "Cada credencial das App Registrations (exportação do Azure) com a lista de APIs e com a lista de certificados da CMDB.",
        "chave": "O nome da App Registration e, como alternativa, o da Enterprise Application (sem sufixos nem maiúsculas); a data de fim ao dia, com 1 dia de tolerância.",
        "regra": "É uma API (segredo) ou um certificado: se já está numa das listas, é dessa; senão decide o tipo de credencial do Azure (Certificate ou Secret). Pode sempre escolher a outra.",
        "aplicar": "Não existe: inclui na lista escolhida (cria o registo). Data mais recente: atualiza a data do registo, quando só há um com esse nome.",
    },
    "erros": {
        "label": "Erros nas fontes",
        "compara": "Cada linha dos ficheiros, antes da comparação.",
        "chave": "—",
        "regra": "Linhas postas de lado: sem nome, data vazia ou ilegível, pedido não emitido, já expirado, nome que não é domínio. Também avisos sobre datas da CMDB.",
        "aplicar": "Nada. Corrija a fonte, se for preciso, e reconcilie de novo.",
    },
}


def data_flow(run, tql: str = "") -> list[dict]:
    """Percurso dos dados na reconciliação, com os números desta execução."""
    sm, inp = run.summary or {}, run.inputs or {}
    srcs = [f"{k}: {v.get('validas', 0)} de {v.get('linhas', 0)}" for k, v in inp.items() if k != AZURE_SOURCE]
    az = inp.get(AZURE_SOURCE)
    azure = (run.vistas or {}).get("azure") or []
    return [
        {"titulo": "Fontes", "n": sm.get("fontes_validas", sum(v.get("validas", 0) for k, v in inp.items() if k != AZURE_SOURCE)),
         "txt": "linhas válidas", "det": "; ".join(srcs) or "—",
         "como": "Lê cada ficheiro, reconhece as colunas e as datas (DD/MM/AAAA, nunca troca dia e mês) e põe de lado as linhas sem nome, sem data, não emitidas, expiradas ou que não são domínios."},
        {"titulo": "CMDB", "n": sm.get("cmdb_linhas", 0), "txt": "certificados lidos",
         "det": f"TQL {(run.columns or {}).get('tql') or tql or '(não definido)'}",
         "como": "Lê os certificados ativos pela REST API da UCMDB, com todos os atributos."},
        {"titulo": "Comparação", "n": sm.get("fontes_comparadas", 0), "txt": "certificados comparados",
         "det": f"{sm.get('coincidentes', 0)} iguais, {sm.get('diferencas_fontes', 0)} diferentes",
         "como": "Procura cada certificado na CMDB pelo CommonName e compara a data de expiração ao dia. Repetidos entre fontes contam uma vez."},
        {"titulo": "Servidor", "n": sm.get("regressoes", 0), "txt": "com data mais antiga",
         "det": f"{sm.get('regressoes_atualizadas', 0)} atualizados com o servidor",
         "como": "Quando a fonte tem uma data anterior à da CMDB, decide o certificado que o servidor apresenta."},
        {"titulo": "Resultado", "n": sm.get("novos", 0) + sm.get("alterados", 0), "txt": "alterações",
         "det": f"{sm.get('novos', 0)} novos, {sm.get('alterados', 0)} alterados, {sm.get('so_na_cmdb', 0)} só na CMDB"
                + (f", {sum(1 for x in azure if x['estado'] in ('novo', 'data_posterior'))} do Azure por tratar" if az else ""),
         "como": "Cada alteração pode ser incluída ou excluída e aplicada na UCMDB, uma a uma ou todas."},
    ]

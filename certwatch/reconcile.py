"""Reconciliação com ficheiros de exportação (CA1, CA2, AVI…) colocados na diretoria de importação.

Lê CSV (UTF-8, UTF-16 do certutil, Windows-1252) e Excel (.xlsx), reconhece as colunas mesmo com
acentos estragados ("LocalizaÃ§Ã£o"), interpreta datas portuguesas (DD/MM/AAAA, nunca troca dia e
mês), seriais do Excel e ISO, e compara cada certificado com a CMDB e com o que o servidor apresenta.
"""
from __future__ import annotations

import csv
import hashlib
import io
import re
import unicodedata
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .config import Settings
from .db import as_utc, utcnow
from .evaluator import load_snapshot
from .models import CmdbRecord, ImportFile, ImportRecord
from .normalize import norm_host, norm_issuer, norm_label, norm_serial

ALLOWED_EXT = {".csv", ".txt", ".xlsx", ".xlsm"}
MAX_PROBLEMS = 200

COLUMNS = {
    "cn": ["issuedcommonname", "subjectcommonname", "commonname", "cn", "appregistration"],
    "cn_fallback": ["nome", "name", "displaylabel", "hostname", "enterpriseapplication"],
    "valid_to": ["certificateexpirationdate", "validitynotafter", "notafter", "validto", "expirationdate",
                 "dataexpiracao", "datadeexpiracao", "datadevalidade", "validade", "expira", "enddate"],
    "serial": ["serialnumber", "serial", "numerodeserie", "keyid"],
    # Azure AD (credenciais de App Registrations)
    "cred_type": ["credentialtype"],
    "app_id": ["appid", "applicationid", "clientid"],
    "enterprise_app": ["enterpriseapplication"],
    "start": ["startdate"],
    "status": ["status"],
    "issuer": ["issuercommonname", "issuername", "issuer", "emissor"],
    "san": ["subjectalternativename", "subjectalternativenames", "san"],
    "disposition": ["requestdisposition", "disposition"],
    "req_id": ["reqid", "requestid"],
    "requester": ["requestername"],
}

REC_STATES = {
    "novo": "Novo: não existe na CMDB",
    "data_posterior": "Data mais recente do que a CMDB",
    "data_anterior": "Data mais antiga do que a CMDB",
    "igual": "Igual à CMDB",
    "so_na_cmdb": "Só na CMDB (ausente da fonte)",
    "expirado": "Expirado na fonte",
}
REC_TABS = {"novo": "Novos", "data_posterior": "Data mais recente", "data_anterior": "Data mais antiga",
            "igual": "Iguais", "so_na_cmdb": "Só na CMDB", "expirado": "Expirados"}
REC_HELP = {
    "novo": "Existe na fonte mas não na CMDB (no Azure: nem na lista de APIs nem nos certificados). Normalmente deve ser registado.",
    "data_posterior": "A fonte tem um certificado mais recente: foi renovado e a CMDB não foi atualizada.",
    "data_anterior": "A fonte tem um certificado mais antigo do que o registado. Confirmar no servidor qual está em uso antes de mexer na CMDB.",
    "igual": "Nome e data coincidem com a CMDB.",
    "so_na_cmdb": "A CMDB indica este emissor (ou, no Azure, uma App Registration), mas o registo não aparece na exportação. Pode ter sido revogado ou apagado, ou a exportação estar incompleta.",
    "expirado": "Já expirou na fonte; não é comparado.",
}


# ------------------------------------------------------------------ leitura de ficheiros
def _fix_mojibake(s: str) -> str:
    if re.search(r"Ã.|Â.|â€", s):
        try:
            fixed = s.encode("latin-1").decode("utf-8")
            if "�" not in fixed:
                return fixed
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
    return s


def norm_header(h) -> str:
    s = _fix_mojibake(str(h or "")).replace("﻿", "").replace(" ", " ")
    s = unicodedata.normalize("NFD", s)
    s = "".join(ch for ch in s if unicodedata.category(ch) != "Mn")
    s = re.sub(r"^\s*\[[^\]]*\]\s*:\s*", "", s.lower())   # "[Digital Certificate] : ValidTo"
    return re.sub(r"[^a-z0-9]", "", s)


def _decode(data: bytes) -> str:
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16")
    if len(data) > 4 and data[1:2] == b"\x00" and data[3:4] == b"\x00":
        return data.decode("utf-16-le")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


def read_table(path: Path) -> tuple[list[str], list[list]]:
    if path.suffix.lower() in (".xlsx", ".xlsm"):
        from openpyxl import load_workbook
        wb = load_workbook(path, read_only=True, data_only=True)
        try:
            rows = [list(r) for r in wb.worksheets[0].iter_rows(values_only=True)]
        finally:
            wb.close()
    else:
        text = _decode(path.read_bytes())
        sample = text[:8192]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            delim = dialect.delimiter
        except csv.Error:
            delim = ";" if sample.count(";") > sample.count(",") else ","
        rows = [r for r in csv.reader(io.StringIO(text), delimiter=delim)]
    # Cabeçalho = primeira linha com pelo menos duas células preenchidas
    start = next((i for i, r in enumerate(rows) if sum(1 for c in r if str(c or "").strip()) >= 2), None)
    if start is None:
        return [], []
    headers = [str(c or "").strip() for c in rows[start]]
    body = [r for r in rows[start + 1:] if any(str(c or "").strip() for c in r)]
    return headers, body


def map_columns(headers: list[str]) -> dict[str, int]:
    normed = [norm_header(h) for h in headers]
    found: dict[str, int] = {}
    for field, cands in COLUMNS.items():
        for cand in cands:
            if cand in normed:
                found[field] = normed.index(cand)
                break
    if "cn" not in found and "cn_fallback" in found:
        found["cn"] = found["cn_fallback"]
    if "valid_to" not in found:
        for i, h in enumerate(normed):
            if "expir" in h or "notafter" in h or h.endswith("validto"):
                found["valid_to"] = i
                break
    if "cn" not in found:
        for i, h in enumerate(normed):
            if "commonname" in h:
                found["cn"] = i
                break
    found.pop("cn_fallback", None)
    return found


_DMY = re.compile(r"^(\d{1,2})([/.\-])(\d{1,2})\2(\d{4})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?)?$", re.I)


def parse_date(value, tz: ZoneInfo) -> datetime | None:
    """Datas de exportação: datetime do Excel, serial do Excel, ISO, AAAAMMDD, DD/MM/AAAA[ HH:MM[:SS]].
    DD/MM nunca é trocado por MM/DD, exceto quando a data tem AM/PM (formato americano explícito)."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return (value.replace(tzinfo=tz) if value.tzinfo is None else value).astimezone(timezone.utc)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=tz).astimezone(timezone.utc)
    if isinstance(value, (int, float)):
        if 20000 < value < 2958466:
            return (datetime(1899, 12, 30, tzinfo=tz) + timedelta(days=float(value))).astimezone(timezone.utc)
        return None
    s = str(value).strip()
    if re.fullmatch(r"\d{8}", s):
        try:
            return datetime(int(s[:4]), int(s[4:6]), int(s[6:]), tzinfo=tz).astimezone(timezone.utc)
        except ValueError:
            return None
    if re.fullmatch(r"\d+(\.\d+)?", s):
        return parse_date(float(s), tz)
    if re.match(r"^\d{4}-\d{1,2}-\d{1,2}", s):
        try:
            d = datetime.fromisoformat(s.replace(" ", "T", 1) if "T" not in s and " " in s else s)
        except ValueError:
            return None
        return (d.replace(tzinfo=tz) if d.tzinfo is None else d).astimezone(timezone.utc)
    m = _DMY.match(s)
    if m:
        a, b, year = int(m.group(1)), int(m.group(3)), int(m.group(4))
        hh, mm, ss = int(m.group(5) or 0), int(m.group(6) or 0), int(m.group(7) or 0)
        ampm = (m.group(8) or "").upper()
        if ampm:
            month, day = a, b
            hh = (hh % 12) + (12 if ampm == "PM" else 0)
        else:
            day, month = a, b
        try:
            return datetime(year, month, day, hh, mm, ss, tzinfo=tz).astimezone(timezone.utc)
        except ValueError:
            return None
    return None


def source_for(filename: str, settings: Settings) -> str | None:
    base = filename.lower()
    best = None
    for label, prefix in settings.import_sources.items():
        p = prefix.lower()
        if p and base.startswith(p) and (best is None or len(p) > len(settings.import_sources[best])):
            best = label
    return best


# ------------------------------------------------------------------ importação
def import_file(session: Session, path: Path, source: str, settings: Settings) -> dict:
    data = path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    current = session.scalar(select(ImportFile).where(ImportFile.source == source, ImportFile.is_current.is_(True)))
    if current is not None and current.sha256 == sha:
        return {"ficheiro": path.name, "estado": "sem alterações"}

    tz = ZoneInfo(settings.timezone)
    problems: list[str] = []
    try:
        headers, rows = read_table(path)
    except Exception as exc:
        headers, rows = [], []
        problems.append(f"Não foi possível ler o ficheiro: {exc}")
    cols = map_columns(headers) if headers else {}
    f = ImportFile(name=path.name, source=source, sha256=sha, size=len(data), rows_total=len(rows),
                   columns={k: headers[v] for k, v in cols.items()}, is_current=True)
    if headers and ("cn" not in cols or "valid_to" not in cols):
        problems.append("Colunas obrigatórias não encontradas (nome do certificado e data de expiração). "
                        f"Cabeçalhos lidos: {', '.join(h for h in headers if h)[:500]}")

    records = []
    skipped = defaultdict(int)
    # Exportação de credenciais do Azure AD: compara-se com a lista de APIs (segredos) da CMDB
    azure = "cred_type" in cols or "appregistration" in {norm_header(h) for h in headers}
    if "cn" in cols and "valid_to" in cols:
        def cell(row, key):
            i = cols.get(key)
            return row[i] if i is not None and i < len(row) else None

        for n, row in enumerate(rows, start=2):
            disp = str(cell(row, "disposition") or "").strip()
            if disp and not re.search(r"issued|emitid", disp, re.I):
                skipped["não emitido"] += 1
                continue
            cn = _fix_mojibake(str(cell(row, "cn") or "")).strip()
            if not cn or cn.upper() == "EMPTY":
                skipped["sem nome"] += 1
                continue
            raw_date = cell(row, "valid_to")
            vt = parse_date(raw_date, tz)
            if vt is None:
                if len(problems) < MAX_PROBLEMS:
                    problems.append(f"Linha {n}: data de expiração não reconhecida ({raw_date!r}) para {cn}")
                continue
            if azure:
                ctype = str(cell(row, "cred_type") or "").strip()
                records.append(ImportRecord(
                    source=source, row_no=n, common_name=cn, cn_norm=norm_label(cn), valid_to=vt,
                    serial=str(cell(row, "serial") or "").strip()[:200], issuer=ctype, san="",
                    extra={"tipo": "azure", **{k: str(cell(row, k)).strip() for k in
                           ("cred_type", "app_id", "enterprise_app", "start", "status") if cell(row, k) not in (None, "")}},
                ))
                continue
            issuer = str(cell(row, "issuer") or "").strip() or settings.import_issuers.get(source, "")
            records.append(ImportRecord(
                source=source, row_no=n, common_name=cn, cn_norm=norm_host(cn), valid_to=vt,
                serial=norm_serial(str(cell(row, "serial") or "")), issuer=issuer,
                san=str(cell(row, "san") or "")[:4000],
                extra={k: str(cell(row, k)) for k in ("req_id", "requester", "disposition") if cell(row, k) not in (None, "")},
            ))

    f.rows_ok = len(records)
    f.problems = problems[:MAX_PROBLEMS] + [f"{v} linha(s) ignorada(s): {k}" for k, v in skipped.items()]
    f.status = "erro" if not records else "ok"
    if not records:
        f.is_current = False
        session.add(f)
        return {"ficheiro": path.name, "estado": "erro", "problemas": f.problems[:5]}

    # O ficheiro novo passa a ser o atual desta fonte; os registos do anterior são apagados
    old = list(session.scalars(select(ImportFile).where(ImportFile.source == source, ImportFile.is_current.is_(True))))
    for o in old:
        o.is_current = False
        session.execute(delete(ImportRecord).where(ImportRecord.file_id == o.id))
    session.add(f)
    session.flush()
    for r in records:
        r.file_id = f.id
    session.add_all(records)
    return {"ficheiro": path.name, "estado": "importado", "registos": len(records), "problemas": len(f.problems)}


def ingest_imports(session: Session, settings: Settings) -> dict:
    d = settings.import_dir
    if not d.is_dir():
        return {"aviso": f"Diretoria {d} não existe"}
    newest: dict[str, Path] = {}
    ignored = []
    for p in sorted(d.iterdir()):
        if not p.is_file() or p.name.startswith(".") or p.suffix.lower() not in ALLOWED_EXT:
            continue
        if settings.apis_file and p.name.lower().startswith(settings.apis_file):
            continue   # lista de APIs: lida pela importação de APIs, não pela reconciliação
        src = source_for(p.name, settings)
        if src is None:
            ignored.append(p.name)
            continue
        if src not in newest or p.stat().st_mtime > newest[src].stat().st_mtime:
            newest[src] = p
    out = {}
    for src, path in sorted(newest.items()):
        try:
            out[src] = import_file(session, path, src, settings)
        except PermissionError:
            out[src] = {"ficheiro": path.name, "estado": "erro",
                        "problemas": [f"Sem permissão de leitura: no servidor, correr chmod 644 import/{path.name}"]}
        except OSError as exc:
            out[src] = {"ficheiro": path.name, "estado": "erro", "problemas": [f"Não foi possível ler: {exc}"]}
    if ignored:
        out["ignorados"] = ignored[:50]
    return out


# ------------------------------------------------------------------ comparação
def reconcile(session: Session, settings: Settings, now: datetime | None = None) -> dict:
    now = now or utcnow()
    snap = load_snapshot(session)
    live: dict[str, datetime] = {}
    for cn, eps in snap.ep_by_cn.items():
        for ep in eps:
            leaf = snap.leaf_for(snap.scan_for(ep))
            if leaf is not None and leaf.not_after:
                live[cn] = leaf.not_after
                break

    files = list(session.scalars(select(ImportFile).where(ImportFile.is_current.is_(True)).order_by(ImportFile.source)))
    file_by_id = {f.id: f for f in files}
    recs = list(session.scalars(select(ImportRecord).where(ImportRecord.file_id.in_(list(file_by_id) or [-1]))))

    # O Azure tem segredos e certificados: cada credencial é procurada nas duas listas da CMDB
    api_by_label: dict[str, list] = defaultdict(list)
    for a in snap.apis:
        api_by_label[norm_label(a.name)].append(a)
    cert_by_label: dict[str, list] = defaultdict(list)
    for c in snap.records:
        cert_by_label[norm_label(c.common_name)].append(c)

    rows, seen = [], set()
    present: dict[str, set[str]] = defaultdict(set)
    azure_sources: set[str] = set()
    for r in recs:
        is_azure = (r.extra or {}).get("tipo") == "azure"
        present[r.source].add(r.cn_norm)
        key = (r.source, r.cn_norm, as_utc(r.valid_to).date() if r.valid_to else None, r.serial if is_azure else "")
        if key in seen:
            continue
        seen.add(key)
        if is_azure:
            azure_sources.add(r.source)
            labels = {r.cn_norm, norm_label((r.extra or {}).get("enterprise_app"))} - {""}
            apis = {a.ucmdb_id: a for lb in labels for a in api_by_label.get(lb, [])}.values()
            certs = {c.ucmdb_id: c for lb in labels for c in cert_by_label.get(lb, [])}.values()
            cmdb = [*apis, *certs]
            cmdb_dates = sorted([as_utc(a.expiry) for a in apis if a.expiry] +
                                [as_utc(c.valid_to) for c in certs if c.valid_to], reverse=True)
            where = [x for x, ok in (("Lista de APIs", apis), ("Certificados", certs)) if ok]
        else:
            cmdb = snap.by_cn.get(r.cn_norm, [])
            cmdb_dates = sorted((as_utc(c.valid_to) for c in cmdb if c.valid_to), reverse=True)
            where = ["Certificados"] if cmdb else []
        vt = as_utc(r.valid_to)
        if vt < now:
            state = "expirado"
        elif not cmdb:
            state = "novo"
        elif any(abs((d.date() - vt.date()).days) <= 1 for d in cmdb_dates):
            state = "igual"
        elif cmdb_dates and vt > cmdb_dates[0]:
            state = "data_posterior"
        else:
            state = "data_anterior"
        lv = None if is_azure else live.get(r.cn_norm)
        # Para o Azure mostra-se a data da CMDB mais próxima (pode haver vários segredos por aplicação)
        shown = (min(cmdb_dates, key=lambda d: abs((d - vt).total_seconds())) if is_azure and cmdb_dates
                 else (cmdb_dates[0] if cmdb_dates else None))
        rows.append({
            "source": r.source, "cn": r.common_name, "cn_norm": r.cn_norm, "valid_to": vt,
            "cmdb_valid_to": shown, "live_valid_to": lv,
            "live_confirma": bool(lv and abs((as_utc(lv).date() - vt.date()).days) <= 1),
            "serial": r.serial, "issuer": r.issuer, "san": r.san, "state": state,
            "file": file_by_id[r.file_id].name, "row_no": r.row_no, "azure": is_azure,
            "app": (r.extra or {}).get("enterprise_app", ""), "onde": where,
        })

    # CMDB com o emissor de uma CA importada, mas ausente da exportação dessa CA
    for f in files:
        issuer = settings.import_issuers.get(f.source)
        if not issuer:
            continue
        inorm = norm_issuer(issuer)
        for c in snap.records:
            if c.issuer_norm == inorm and c.cn_norm not in present[f.source] and c.valid_to and as_utc(c.valid_to) >= now:
                rows.append({
                    "source": f.source, "cn": c.common_name, "cn_norm": c.cn_norm, "valid_to": None,
                    "cmdb_valid_to": as_utc(c.valid_to), "live_valid_to": live.get(c.cn_norm), "live_confirma": False,
                    "serial": "", "issuer": c.issuer_name or c.issuer, "san": "", "state": "so_na_cmdb",
                    "file": f.name, "row_no": None, "azure": False, "app": "", "onde": ["Certificados"],
                })

    # Segredos do Azure registados na CMDB que não aparecem na exportação do Azure
    for f in files:
        if f.source not in azure_sources:
            continue
        for a in snap.apis:
            label = norm_label(a.name)
            if ("azure" in (a.location or "").lower() and label not in present[f.source]
                    and a.expiry is not None and as_utc(a.expiry) >= now):
                rows.append({
                    "source": f.source, "cn": a.name, "cn_norm": label, "valid_to": None,
                    "cmdb_valid_to": as_utc(a.expiry), "live_valid_to": None, "live_confirma": False,
                    "serial": "", "issuer": a.location, "san": "", "state": "so_na_cmdb",
                    "file": f.name, "row_no": None, "azure": True, "app": a.application, "onde": ["Lista de APIs"],
                })

    order = {"novo": 0, "data_posterior": 1, "data_anterior": 2, "so_na_cmdb": 3, "igual": 4, "expirado": 5}
    rows.sort(key=lambda x: (order[x["state"]], x["source"], x["cn_norm"]))
    counts = defaultdict(int)
    for x in rows:
        counts[x["state"]] += 1
    return {"rows": rows, "counts": dict(counts), "files": files}


# ------------------------------------------------------------------ lista de APIs a partir de ficheiro
API_COLUMNS = {
    "name": ["displaylabel", "nome", "name", "label"],
    "application": ["aplicacao", "application", "app", "aplicacoes"],
    "expiry": ["datadeexpiracao", "dataexpiracao", "datadevalidade", "expirationdate", "expirydate", "enddate",
               "validade", "validto", "expira"],
    "expired": ["expirado", "expired", "estaexpirado"],
    "location": ["localizacao", "location", "local"],
    "registered": ["dataderegistonacmdb", "dataderegisto", "createtime", "datacriacao", "datadecriacao", "registo"],
    "url": ["url", "endpoint", "endpointurl", "endereco", "enderecourl"],
    "ucmdb_id": ["ucmdbid", "globalid", "id", "cmdbid"],
}
_BOOL = {"true": True, "sim": True, "yes": True, "1": True, "false": False, "nao": False, "não": False, "no": False, "0": False}


def find_api_file(settings: Settings) -> Path | None:
    """Ficheiro mais recente com o prefixo CERTWATCH_APIS_FILE (ex.: api-cmdb.csv) na diretoria de importação."""
    d, prefix = settings.import_dir, settings.apis_file
    if not prefix or not d.is_dir():
        return None
    files = [p for p in d.iterdir() if p.is_file() and p.name.lower().startswith(prefix)
             and p.suffix.lower() in ALLOWED_EXT]
    return max(files, key=lambda p: p.stat().st_mtime) if files else None


def read_api_file(path: Path, settings: Settings) -> tuple[list[dict], dict]:
    """Lê a exportação da lista de APIs da CMDB (CSV/TSV/Excel, cabeçalhos "[API secrets] : Display Label"...)."""
    from .collectors.ucmdb import parse_api_url
    tz = ZoneInfo(settings.timezone)
    headers, rows = read_table(path)
    normed = [norm_header(h) for h in headers]
    cols = {}
    for field, cands in API_COLUMNS.items():
        for cand in cands:
            if cand in normed:
                cols[field] = normed.index(cand)
                break
    if "name" not in cols:
        raise ValueError(f"{path.name}: coluna de nome (Display Label) não encontrada. Cabeçalhos: {', '.join(headers)[:300]}")
    out, seen, problems = [], defaultdict(int), []
    for n, row in enumerate(rows, start=2):
        cell = lambda f: (row[cols[f]] if f in cols and cols[f] < len(row) else None)
        name = _fix_mojibake(str(cell("name") or "")).strip()
        if not name:
            continue
        raw_exp = cell("expiry")
        expiry = parse_date(raw_exp, tz)
        if raw_exp not in (None, "") and expiry is None and len(problems) < MAX_PROBLEMS:
            problems.append(f"Linha {n}: data de expiração não reconhecida ({raw_exp!r}) para {name}")
        app = _fix_mojibake(str(cell("application") or "")).strip()
        loc = _fix_mojibake(str(cell("location") or "")).strip()
        raw_url = str(cell("url") or "").strip()
        scheme, host, port = parse_api_url(raw_url)
        uid = str(cell("ucmdb_id") or "").strip()
        if not uid:   # sem ID da CMDB: identificador estável a partir do nome, aplicação e localização
            base = hashlib.sha1(f"{name.lower()}|{app.lower()}|{loc.lower()}".encode()).hexdigest()[:24]
            seen[base] += 1
            uid = f"ficheiro:{base}" + (f"-{seen[base]}" if seen[base] > 1 else "")
        exp_flag = cell("expired")
        out.append({
            "ucmdb_id": uid[:64], "name": name[:512], "application": app[:512], "location": loc[:512],
            "cmdb_expired": exp_flag if isinstance(exp_flag, bool) else _BOOL.get(str(exp_flag or "").strip().lower()),
            "registered_at": parse_date(cell("registered"), tz),
            "url": raw_url[:1024] if host else "", "scheme": scheme, "host": host, "port": port,
            "expiry": expiry, "extra": {},
        })
    fields = {"nome": headers[cols["name"]], **{k: (headers[cols[f]] if f in cols else None) for k, f in (
        ("aplicacao", "application"), ("validade", "expiry"), ("expirado", "expired"), ("localizacao", "location"),
        ("registo", "registered"), ("url", "url"))}, "metodo": "ficheiro", "ficheiro": path.name}
    if problems:
        fields["avisos"] = problems[:5]
    return out, fields


def scan_import_dir(settings: Settings) -> list[dict]:
    """O que está na diretoria de importação e o que acontece a cada ficheiro (para a página)."""
    import os
    d = settings.import_dir
    if not d.is_dir():
        return []
    out = []
    for p in sorted(d.iterdir(), key=lambda x: x.name.lower()):
        if not p.is_file() or p.name.startswith(".") or p.name.lower() == "readme.md":
            continue
        name = p.name.lower()
        readable = os.access(p, os.R_OK)
        if p.suffix.lower() not in ALLOWED_EXT:
            what, ok = f"ignorado: extensão {p.suffix or '(nenhuma)'} não suportada (usar .csv, .txt ou .xlsx)", False
        elif settings.apis_file and name.startswith(settings.apis_file):
            what, ok = "lista de APIs (usada na página APIs)", True
        elif source_for(p.name, settings) is None:
            what, ok = ("ignorado: o nome não começa por nenhum prefixo conhecido ("
                        + ", ".join(f"{v}*" for v in settings.import_sources.values()) + ")"), False
        else:
            what, ok = f"fonte {source_for(p.name, settings)}", True
        if not readable:
            what, ok = f"sem permissão de leitura: correr chmod 644 import/{p.name}", False
        out.append({"name": p.name, "size": p.stat().st_size, "what": what, "ok": ok})
    return out

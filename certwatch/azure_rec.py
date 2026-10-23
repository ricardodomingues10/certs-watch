"""Segredos e certificados das App Registrations do Azure (exportação do Azure AD) contra a CMDB.

Cada credencial do Azure pode ser um segredo de API (client secret) ou um certificado. Para cada linha:
1. procura-se o nome (AppRegistration e, como alternativa, a Enterprise Application) na lista de APIs da CMDB e na
   lista de certificados, sem sufixos ("Radar - 0123…" = "Radar") e sem diferenças de maiúsculas;
2. classifica-se: se já está numa das listas, é dessa lista; senão decide o tipo de credencial do Azure
   (Certificate -> certificado; Secret/Password -> API); se nada disso disser, fica por decidir;
3. compara-se a data de fim com as datas registadas para esse nome (ao dia, com 1 dia de tolerância):
   igual, mais recente (segredo/certificado novo ainda não registado), mais antiga, ou novo (nome não existe).
Os segredos do Azure registados na lista de APIs que já não aparecem na exportação ficam em "só na CMDB".
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import date
from pathlib import Path

from .normalize import norm_label

AZURE = "AZURE"
CLASS_LABELS = {"api": "API (segredo)", "certificado": "Certificado", "?": "Por decidir"}
STATE_LABELS = {"novo": "Não existe na CMDB", "data_posterior": "Data mais recente do que a CMDB",
                "data_anterior": "Data mais antiga do que a CMDB", "igual": "Igual à CMDB",
                "expirado": "Expirado no Azure", "so_na_cmdb": "Só na CMDB"}
CERT_TYPES = re.compile(r"cert|x509|asymmetric", re.I)
SECRET_TYPES = re.compile(r"secret|password|symmetric|client", re.I)


def read_azure(data: bytes, filename: str, today: date) -> tuple[list[dict], dict]:
    """Linhas da exportação do Azure: nome, aplicação, tipo de credencial, KeyId e data de fim."""
    from .cmdb_final import parse_day
    from .reconcile import map_columns, read_table_bytes, _fix_mojibake
    headers, rows = read_table_bytes(data, Path(filename).suffix)
    cols = map_columns(headers) if headers else {}
    info = {"ficheiro": filename, "linhas": len(rows), "colunas": {k: headers[v] for k, v in cols.items()}}
    if "cn" not in cols or "valid_to" not in cols:
        raise ValueError("colunas do Azure não encontradas (AppRegistration e EndDate). Cabeçalhos: "
                         + ", ".join(h for h in headers if h)[:300])

    def cell(row, key):
        i = cols.get(key)
        return row[i] if i is not None and i < len(row) else None

    out, problems = [], []
    for n, row in enumerate(rows, start=2):
        name = _fix_mojibake(str(cell(row, "cn") or "")).strip()
        app = _fix_mojibake(str(cell(row, "enterprise_app") or "")).strip()
        p = parse_day(cell(row, "valid_to"))
        if not name:
            problems.append({"fonte": AZURE, "linha": n, "cn": app, "erro": "AppRegistration em falta"})
            continue
        if p.day is None:
            problems.append({"fonte": AZURE, "linha": n, "cn": name, "data": str(cell(row, "valid_to") or ""),
                             "erro": "Data de fim não reconhecida"})
            continue
        out.append({"linha": n, "nome": name, "app": app, "app_id": str(cell(row, "app_id") or "").strip(),
                    "tipo_credencial": str(cell(row, "cred_type") or "").strip(),
                    "key_id": str(cell(row, "serial") or "").strip(), "fim": p.day,
                    "estado_azure": str(cell(row, "status") or "").strip()})
    info["validas"] = len(out)
    info["problemas"] = problems
    return out, info


def compare(rows: list[dict], apis: list[dict], certs: list[dict], today: date) -> list[dict]:
    """apis: [{"ucmdb_id", "nome", "data": date|None, "localizacao", "aplicacao"}]; certs: [{"ucmdb_id", "nomes": [...], "data"}]."""
    api_by: dict[str, list[dict]] = defaultdict(list)
    for a in apis:
        api_by[norm_label(a["nome"])].append(a)
    cert_by: dict[str, list[dict]] = defaultdict(list)
    for c in certs:
        for nm in {norm_label(x) for x in c["nomes"] if x}:
            cert_by[nm].append(c)

    out, present = [], set()
    for k, r in enumerate(rows):
        labels = [x for x in (norm_label(r["nome"]), norm_label(r["app"])) if x]
        present.update(labels)
        a_match = list({a["ucmdb_id"]: a for lb in labels for a in api_by.get(lb, [])}.values())
        c_match = list({c["ucmdb_id"]: c for lb in labels for c in cert_by.get(lb, [])}.values())
        how = "pelo nome da App Registration" if any(norm_label(r["nome"]) in d for d in (api_by, cert_by)) \
            else "pelo nome da Enterprise Application"
        # classificação
        if a_match and not c_match:
            cls, why = "api", f"Já está na lista de APIs ({how})."
        elif c_match and not a_match:
            cls, why = "certificado", f"Já está na lista de certificados ({how})."
        elif CERT_TYPES.search(r["tipo_credencial"]):
            cls, why = "certificado", f"O Azure diz que a credencial é \"{r['tipo_credencial']}\" (um certificado)."
        elif SECRET_TYPES.search(r["tipo_credencial"]):
            cls, why = "api", f"O Azure diz que a credencial é \"{r['tipo_credencial']}\" (um segredo de API)."
        else:
            cls, why = "?", "O tipo de credencial do Azure não diz se é segredo ou certificado: escolha."
        if a_match and c_match:
            why = f"Aparece nas duas listas ({how}); " + why
        # comparação de datas
        dates = sorted({x["data"] for x in (a_match + c_match) if x.get("data")})
        fim = r["fim"]
        if fim < today:
            st = "expirado"
        elif not (a_match or c_match):
            st = "novo"
        elif any(abs((d - fim).days) <= 1 for d in dates):
            st = "igual"
        elif dates and fim > dates[-1]:
            st = "data_posterior"
        else:
            st = "data_anterior"
        onde = [x for x, ok in (("Lista de APIs", a_match), ("Certificados", c_match)) if ok]
        target = None
        if st == "data_posterior":
            pool = a_match if cls == "api" else c_match if cls == "certificado" else []
            if len(pool) == 1:
                target = pool[0]["ucmdb_id"]
        out.append({**r, "chave": k, "fim": fim.isoformat(), "estado": st, "classe": cls, "classe_motivo": why,
                    "onde": onde, "cmdb_datas": [d.isoformat() for d in dates], "alvo": target,
                    "cmdb": [{"lista": "Lista de APIs", "ucmdb_id": a["ucmdb_id"], "nome": a["nome"],
                              "data": a["data"].isoformat() if a.get("data") else ""} for a in a_match]
                            + [{"lista": "Certificados", "ucmdb_id": c["ucmdb_id"], "nome": c["nomes"][0] if c["nomes"] else "",
                                "data": c["data"].isoformat() if c.get("data") else ""} for c in c_match],
                    "motivo": _why(st, r, dates, how)})
    # segredos do Azure registados na lista de APIs que já não aparecem na exportação
    n = len(out)
    for a in apis:
        lb = norm_label(a["nome"])
        if "azure" in (a.get("localizacao") or "").lower() and lb not in present and a.get("data") and a["data"] >= today:
            out.append({"chave": n, "linha": None, "nome": a["nome"], "app": a.get("aplicacao", ""), "app_id": "",
                        "tipo_credencial": "", "key_id": "", "fim": "", "estado": "so_na_cmdb", "classe": "api",
                        "classe_motivo": "Registado na lista de APIs como segredo do Azure.", "onde": ["Lista de APIs"],
                        "cmdb_datas": [a["data"].isoformat()], "alvo": a["ucmdb_id"], "estado_azure": "",
                        "cmdb": [{"lista": "Lista de APIs", "ucmdb_id": a["ucmdb_id"], "nome": a["nome"],
                                  "data": a["data"].isoformat()}],
                        "motivo": "Está na lista de APIs (localização Azure) mas não aparece na exportação do Azure: "
                                  "pode ter sido apagado, ou a exportação estar incompleta."})
            n += 1
    order = {"novo": 0, "data_posterior": 1, "data_anterior": 2, "so_na_cmdb": 3, "igual": 4, "expirado": 5}
    out.sort(key=lambda x: (order[x["estado"]], x["nome"].lower()))
    return out


def _why(st: str, r: dict, dates: list[date], how: str) -> str:
    fim = r["fim"].strftime("%d-%m-%Y")
    reg = ", ".join(d.strftime("%d-%m-%Y") for d in dates[-3:]) or "sem data"
    return {
        "expirado": f"Terminou a {fim} no Azure: não é comparado.",
        "novo": "Nem a App Registration nem a Enterprise Application existem na lista de APIs ou na de certificados.",
        "igual": f"Encontrado {how}; a data {fim} já está registada.",
        "data_posterior": f"Encontrado {how}, mas a data {fim} é mais recente do que as registadas ({reg}): "
                          "segredo ou certificado novo ainda não registado.",
        "data_anterior": f"Encontrado {how}; a data {fim} é mais antiga do que as registadas ({reg}).",
    }[st]

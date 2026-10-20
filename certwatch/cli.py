"""CLI de administração.

  python -m certwatch.cli init-db
  python -m certwatch.cli run {pipeline,ingest_cmdb,scan,evaluate}
  python -m certwatch.cli trust-fetch HOST[:PORTA]
"""
from __future__ import annotations

import argparse
import json
import logging
import sys

from .config import get_settings
from .db import init_db
from .jobs import JOBS, run_now
from .trust import describe, fetch_presented_chain


def _trust_fetch(target: str) -> int:
    host, _, port = target.partition(":")
    port_n = int(port or 443)
    chain = fetch_presented_chain(host, port_n)
    if not chain:
        print("O servidor não apresentou certificados.", file=sys.stderr)
        return 1
    print(f"# Chain apresentada por {host}:{port_n} — NÃO VALIDADA.", file=sys.stderr)
    print("# Confirme o SHA-256 da raiz com a equipa de PKI antes de a colocar em trust/.", file=sys.stderr)
    for i, der in enumerate(chain):
        d = describe(der)
        print(f"# [{i}] subject : {d['subject']}", file=sys.stderr)
        print(f"#     issuer  : {d['issuer']}", file=sys.stderr)
        print(f"#     expira  : {d['not_after']}  autoassinado: {d['self_signed']}", file=sys.stderr)
        print(f"#     sha256  : {d['sha256']}", file=sys.stderr)
        print(d["pem"], end="")
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    p = argparse.ArgumentParser(prog="certwatch")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-db")
    r = sub.add_parser("run")
    r.add_argument("job", choices=JOBS)
    t = sub.add_parser("trust-fetch")
    t.add_argument("target", help="host[:porta]")
    a = p.parse_args(argv)

    if a.cmd == "trust-fetch":
        return _trust_fetch(a.target)

    init_db()
    if a.cmd == "init-db":
        print("Base de dados inicializada.")
        return 0
    jr = run_now(a.job, "cli", get_settings())
    print(json.dumps({"job": jr.job, "estado": jr.status, "resumo": jr.summary}, ensure_ascii=False, indent=2, default=str))
    return 0 if jr.status == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())

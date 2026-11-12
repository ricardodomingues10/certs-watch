"""CLI de administração.

  python -m certwatch.cli init-db
  python -m certwatch.cli run {pipeline,ingest_cmdb,scan,evaluate}
  python -m certwatch.cli trust-fetch HOST[:PORTA]
  python -m certwatch.cli inspect-tql NOME_DO_TQL     (atributos de um TQL, sem valores sensíveis)
  python -m certwatch.cli ct-test DOMINIO             (testa as fontes de Certificate Transparency)
  python -m certwatch.cli ssllabs-register --nome N --apelido A --email E --organizacao O
  python -m certwatch.cli ssllabs-test HOST           (avaliação SSL Labs de um nome, 1-2 minutos)
  python -m certwatch.cli postura <host[:porta]>      (revogação, CAA e HSTS de um site real, sem gravar nada)
  python -m certwatch.cli smax-test                   (login no SMAX e primeiros pedidos, sem mostrar segredos)
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


def _posture_smoke(target: str) -> int:
    """Teste de fumo contra um site real: liga-se, e mostra o que as verificações novas veem. Não grava nada.
    Útil para confirmar, no servidor, que há saída para as CAs (OCSP/CRL) e para o DNS público."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from .fontes import dns as fdns
    from .fontes import hsts as fhsts
    from .fontes import revogacao as frev
    from .fontes.servidores import scan_endpoint, summarize
    from .postura import caa_ids, matched_by_wildcard
    from .trust import build_bundle
    st = get_settings()
    host, _, port = target.partition(":")
    port = int(port or 443)
    out = scan_endpoint(host, port, build_bundle(st), st.scan_timeout)
    print(f"{host}:{port}  ligação: {out.status}  cadeia confiável: {out.verify_ok}  {out.tls_version}")
    if not out.chain_der:
        print("  sem certificado: nada mais a verificar.", out.error)
        return 1
    pem = [x509.load_der_x509_certificate(d).public_bytes(serialization.Encoding.PEM).decode() for d in out.chain_der]
    leaf = summarize(out.chain_der[0])
    print(f"  certificado: {leaf['subject_cn']}  emissor: {leaf['issuer_cn']}  até {leaf['not_after']:%d-%m-%Y}")
    if not out.verify_ok:
        print("  revogação: não se pergunta (a cadeia não é confiável, os endereços não merecem crédito)")
    else:
        with frev.new_client(st.scan_timeout + 4) as c:
            r = frev.check(pem[0], pem[1] if len(pem) > 1 else "", c, max_crl_bytes=st.crl_max_mb * 1024 * 1024)
        print(f"  revogação: {r.status.upper()}  via {r.metodo or '—'}  {r.detalhe}  {r.url}")
        if r.status == "revogado":
            print(f"             revogado em {r.revogado_em}  motivo: {r.motivo or '—'}")
    caa = fdns.caa_lookup(host, list(st.public_dns_urls))
    if caa.erro:
        print(f"  CAA: não foi possível ler ({caa.erro})")
    elif not caa.registos:
        print("  CAA: o domínio não tem registos (qualquer CA pode emitir)")
    else:
        ids = caa_ids(leaf["issuer_dn"], st.caa_issuers)
        wild = matched_by_wildcard(host, type("L", (), {"sans_dns": leaf["sans_dns"], "subject_cn": leaf["subject_cn"]})())
        verdict, phrase = fdns.caa_evaluate(caa.registos, ids, wild)
        print(f"  CAA em {caa.zona}: " + "; ".join(f"{t} {v}" for _, t, v in caa.registos))
        print(f"       {verdict.upper()}: {phrase}  (identificadores desta CA: {', '.join(sorted(ids)) or 'desconhecidos'})")
    h = fhsts.fetch(host, port, timeout=st.scan_timeout)
    print(f"  HSTS: {h.status.upper()}  {h.cabecalho or h.erro}" + (f"  (HTTP {h.http_status})" if h.http_status else ""))
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
    i = sub.add_parser("inspect-tql")
    i.add_argument("tql")
    c = sub.add_parser("ct-test")
    c.add_argument("domain")
    reg = sub.add_parser("ssllabs-register", help="registo único na API v4 do SSL Labs (email da organização)")
    reg.add_argument("--nome", required=True)
    reg.add_argument("--apelido", required=True)
    reg.add_argument("--email", required=True)
    reg.add_argument("--organizacao", required=True)
    sl = sub.add_parser("ssllabs-test")
    sl.add_argument("host")
    sub.add_parser("smax-test")
    po = sub.add_parser("postura")
    po.add_argument("alvo")
    a = p.parse_args(argv)

    if a.cmd == "postura":
        return _posture_smoke(a.alvo)

    if a.cmd == "smax-test":
        from .fontes import smax
        st = get_settings()
        print(f"URL: {st.smax_url or '(vazio)'}  tenant: {st.smax_tenant or '(vazio)'}  entidade: {st.smax_entity}")
        print(f"utilizador: {'(vazio)' if not st.smax_user else st.smax_user[:2] + '…' + f' ({len(st.smax_user)} caracteres)'}"
              f"  password: {'(vazia)' if not st.smax_password else f'{len(st.smax_password)} caracteres'}")
        print(f"filtro: {st.smax_filter or '(sem filtro)'}  verificar TLS: {st.smax_verify_tls}")
        if not smax.configured(st):
            print("SMAX não configurado.", file=sys.stderr)
            return 2
        with smax.client(st) as cl:
            try:
                token = smax.login(cl, st)
            except smax.SmaxError as exc:
                print(f"LOGIN: FALHOU — {exc}")
                return 1
            print(f"LOGIN: ok (token com {len(token)} caracteres)")
            from dataclasses import replace
            try:
                tickets = smax.fetch_tickets(replace(st, smax_max_tickets=5), cl)
            except smax.SmaxError as exc:
                print(f"CONSULTA: FALHOU — {exc}")
                return 1
        print(f"CONSULTA: ok, {len(tickets)} pedidos na primeira página (amostra)")
        for t in tickets[:5]:
            print(f"   {t['id']} | {t['phase']} | endpoint: {t['endpoint'] or '(vazio)'} | expira: {t['cert_expiry']} | {t['environment']}")
        if tickets and not any(t["endpoint"] for t in tickets):
            print("Nenhum pedido com endpoint: confirme CERTWATCH_SMAX_FIELD_ENDPOINT.")
        return 0

    if a.cmd == "ssllabs-register":
        from .fontes import ssllabs
        with ssllabs.client(get_settings()) as cl:
            print(json.dumps(ssllabs.register(cl, a.nome, a.apelido, a.email, a.organizacao), ensure_ascii=False))
        print(f"Defina CERTWATCH_SSLLABS_EMAIL={a.email} no .env e reinicie (docker compose up -d).")
        return 0

    if a.cmd == "ssllabs-test":
        from .fontes import ssllabs
        st = get_settings()
        if not st.ssllabs_email:
            print("Defina primeiro CERTWATCH_SSLLABS_EMAIL no .env.", file=sys.stderr)
            return 2
        with ssllabs.client(st) as cl:
            res = ssllabs.assess(cl, a.host.strip().lower(), st.ssllabs_email)
        print(json.dumps(res, ensure_ascii=False, indent=2, default=str))
        print(f"Relatório: {ssllabs.report_url(a.host)}")
        return 0 if res["status"] == "READY" else 1

    if a.cmd == "ct-test":
        from dataclasses import replace
        from .fontes.ct import FETCHERS, SOURCE_LABELS, _client
        st = replace(get_settings(), ct_domains=[a.domain])
        client = _client(st)
        ok = False
        for name in st.ct_sources:
            try:
                recs = FETCHERS[name](client, a.domain, st)
                ok = True
                print(f"{SOURCE_LABELS.get(name, name)}: {len(recs)} certificados")
                for r in recs[:3]:
                    print(f"   {', '.join(r.names[:3])} | {r.issuer_cn} | até {r.not_after}")
            except Exception as exc:
                print(f"{SOURCE_LABELS.get(name, name)}: ERRO {type(exc).__name__}: {exc}")
        return 0 if ok else 1

    if a.cmd == "trust-fetch":
        return _trust_fetch(a.target)
    if a.cmd == "inspect-tql":
        from .fontes.ucmdb import describe_tql
        print(json.dumps(describe_tql(get_settings(), a.tql), ensure_ascii=False, indent=2, default=str))
        return 0

    init_db()
    if a.cmd == "init-db":
        print("Base de dados inicializada.")
        return 0
    jr = run_now(a.job, "cli", get_settings())
    print(json.dumps({"job": jr.job, "estado": jr.status, "resumo": jr.summary}, ensure_ascii=False, indent=2, default=str))
    return 0 if jr.status == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())

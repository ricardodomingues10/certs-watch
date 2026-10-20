"""Catálogo de testes e avaliação por endpoint.

Cada teste pertence a uma camada (Rede → Ligação TLS → Cadeia → Identidade → Validade →
Criptografia → Inventário), tem uma explicação em linguagem simples e passos concretos de
correção. O motor de regras (evaluator) gera os findings a partir destes resultados, por isso
o que se vê na aba "Testes" e os alertas vêm sempre da mesma lógica.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime

from .config import Settings
from .classify import is_auto_renew
from .db import as_utc
from .normalize import hostname_matches, norm_issuer

OK, AVISO, FALHA, NA, NT = "ok", "aviso", "falha", "na", "nt"
STATUS_LABELS = {OK: "Passou", AVISO: "Atenção", FALHA: "Falhou", NA: "Não se aplica", NT: "Não testado"}
STATUS_RANK = {NT: 0, NA: 0, OK: 1, AVISO: 2, FALHA: 3}

WEAK_HASHES = {"md2", "md5", "sha1"}
LEGACY_TLS = {"SSLv3", "TLSv1", "TLSv1.1"}
X509_CERT_HAS_EXPIRED = 10
X509_DEPTH_ZERO_SELF_SIGNED = 18

LAYERS = [
    ("rede", "Rede", "O servidor é encontrado e aceita ligações?"),
    ("tls", "Ligação TLS", "Consegue-se estabelecer uma ligação cifrada moderna?"),
    ("cadeia", "Cadeia de confiança", "O certificado é reconhecido por uma autoridade em que confiamos?"),
    ("identidade", "Identidade", "O certificado pertence a este servidor?"),
    ("validade", "Validade", "O certificado está dentro do prazo?"),
    ("cripto", "Criptografia", "A assinatura e a chave são fortes?"),
    ("inventario", "Inventário", "O que está instalado coincide com a CMDB?"),
]


@dataclass(frozen=True)
class CheckDef:
    id: str
    layer: str
    title: str
    question: str
    how: str
    meaning: str
    fix: tuple[str, ...]


CHECKS: tuple[CheckDef, ...] = (
    CheckDef(
        "rede.dns", "rede", "Nome resolve no DNS",
        "O nome do servidor existe no DNS?",
        "Resolve o nome a partir do servidor onde o certwatch corre (mesmo DNS interno).",
        "O nome não existe ou o DNS deste servidor não o conhece. Pode ser um serviço desativado ou um registo errado na CMDB.",
        ("Confirmar com a equipa de sistemas se o serviço ainda existe.",
         "Se foi desativado, marcar o certificado como inativo na CMDB.",
         "Se existe com outro nome, corrigir o CommonName na CMDB ou adicionar o endpoint certo em Servidores."),
    ),
    CheckDef(
        "rede.porta", "rede", "Porta aceita ligações",
        "O servidor responde na porta indicada?",
        "Abre uma ligação TCP à porta (443 por omissão) com tempo limite.",
        "O servidor não respondeu: está desligado, a porta é outra, ou uma firewall bloqueia o servidor do certwatch.",
        ("Verificar se o serviço está ativo e em que porta escuta.",
         "Pedir abertura de firewall do servidor certwatch para esse destino e porta.",
         "Se a porta não é a 443, adicionar o endpoint com a porta correta em Servidores."),
    ),
    CheckDef(
        "tls.handshake", "tls", "Ligação TLS estabelecida",
        "O servidor fala TLS e apresenta um certificado?",
        "Faz o mesmo aperto de mão que um browser e recolhe o certificado e a cadeia.",
        "A porta responde mas não foi possível estabelecer TLS: pode não ser um serviço HTTPS, ou só aceitar cifras incompatíveis.",
        ("Confirmar que o serviço nessa porta usa TLS (HTTPS, LDAPS…).",
         "Se é HTTP simples, ativar TLS ou retirar o endpoint da lista.",
         "Rever a configuração de cifras do servidor."),
    ),
    CheckDef(
        "tls.protocolo", "tls", "Protocolo TLS atual",
        "A ligação usa TLS 1.2 ou superior?",
        "Regista a versão de protocolo negociada.",
        "O servidor negociou TLS 1.0/1.1 ou SSLv3, que têm falhas conhecidas e já não são aceites por browsers atuais.",
        ("Desativar SSLv3, TLS 1.0 e TLS 1.1 no servidor.",
         "Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3 · nginx: ssl_protocols TLSv1.2 TLSv1.3;",
         "IIS: desativar os protocolos antigos no registo (SCHANNEL) ou com IIS Crypto · AVI: perfil SSL só com TLS 1.2/1.3."),
    ),
    CheckDef(
        "cadeia.confianca", "cadeia", "Cadeia completa e confiável",
        "Sobe-se do certificado até uma raiz em que confiamos, sem elos em falta?",
        "Valida a cadeia apresentada contra as CAs públicas e as raízes internas configuradas.",
        "Falta um certificado intermédio, a raiz não é reconhecida ou há um elo expirado. Muitos clientes vão recusar a ligação.",
        ("Configurar o servidor para enviar o certificado intermédio junto com o do site (\"full chain\").",
         "Apache: SSLCertificateFile com fullchain (ou SSLCertificateChainFile) · nginx: ssl_certificate com o ficheiro fullchain.pem.",
         "IIS: importar a intermédia em \"Intermediate Certification Authorities\" do computador · AVI: importar a CA e associá-la ao certificado.",
         "Java/Tomcat: incluir a cadeia completa no keystore.",
         "Se a raiz é interna e não reconhecida, adicionar a raiz certa em trust/ do certwatch (confirmar com a PKI)."),
    ),
    CheckDef(
        "cadeia.autoassinado", "cadeia", "Não é autoassinado",
        "O certificado foi emitido por uma autoridade, e não por ele próprio?",
        "Compara o emissor com o sujeito do certificado.",
        "Um certificado autoassinado não é confirmado por ninguém; habitua os utilizadores a ignorar avisos de segurança.",
        ("Pedir um certificado à CA interna (serviços internos) ou a uma CA pública (serviços externos).",
         "Instalar o novo certificado com a cadeia completa e retirar o autoassinado."),
    ),
    CheckDef(
        "identidade.nome", "identidade", "Nome corresponde ao servidor",
        "O nome do servidor está no certificado (CN/SAN)?",
        "Compara o nome do endpoint com os nomes do certificado; um wildcard só cobre um nível.",
        "O certificado foi feito para outro nome. O browser mostra um aviso e as integrações falham.",
        ("Emitir um certificado que inclua este nome nos Subject Alternative Names (SAN).",
         "Se o servidor serve vários nomes, confirmar que o SNI está configurado para entregar o certificado certo.",
         "Um wildcard *.exemplo.pt não cobre a.b.exemplo.pt nem exemplo.pt."),
    ),
    CheckDef(
        "validade.prazo", "validade", "Dentro da validade",
        "Quanto tempo falta até expirar?",
        "Usa a data do certificado instalado (ou da CMDB se o servidor não responder).",
        "O certificado está perto de expirar ou já expirou. Depois dessa data o serviço deixa de abrir.",
        ("Pedir a renovação já: a CA interna precisa de pedido formal; as públicas podem demorar dias a validar.",
         "Instalar o certificado novo com a cadeia completa e reiniciar o serviço se necessário.",
         "Atualizar a data na CMDB e abrir change para a renovação.",
         "Se possível, automatizar a renovação (ACME) para não depender de pessoas."),
    ),
    CheckDef(
        "cripto.assinatura", "cripto", "Assinatura forte",
        "O certificado e os intermédios estão assinados com SHA-256 ou superior?",
        "Lê o algoritmo de assinatura de cada certificado da cadeia (exceto a raiz).",
        "SHA-1 e MD5 permitem falsificar certificados. Browsers atuais recusam-nos.",
        ("Pedir um certificado novo assinado com SHA-256 (ou superior).",
         "Se o intermédio é SHA-1, a PKI tem de emitir uma intermédia nova; contactar a equipa de PKI."),
    ),
    CheckDef(
        "cripto.chave", "cripto", "Chave forte",
        "A chave tem tamanho suficiente (RSA ≥ 2048, EC ≥ 256)?",
        "Lê o tipo e o tamanho da chave pública do certificado.",
        "Chaves pequenas podem ser quebradas com recursos acessíveis.",
        ("Gerar um novo par de chaves RSA 2048/3072 ou EC P-256 e pedir novo certificado.",
         "Nunca reutilizar a chave antiga no pedido novo."),
    ),
    CheckDef(
        "inventario.registo", "inventario", "Registado na CMDB",
        "Este certificado em uso está na CMDB?",
        "Procura o nome do endpoint nos certificados ativos da CMDB.",
        "Está em uso um certificado que a CMDB não conhece; ninguém vai ser avisado da expiração por outras vias.",
        ("Registar o certificado na CMDB com responsável e data de validade.",),
    ),
    CheckDef(
        "inventario.emissor", "inventario", "Emissor coincide com a CMDB",
        "A entidade que emitiu o certificado instalado é a que a CMDB indica?",
        "Compara o emissor servido com os emissores registados para esse nome.",
        "Mudou a entidade emissora sem registo: troca de fornecedor não documentada, ou um certificado que ninguém autorizou.",
        ("Confirmar com o responsável quem pediu este certificado.",
         "Se é legítimo, atualizar o emissor na CMDB; se não, investigar como incidente de segurança."),
    ),
    CheckDef(
        "inventario.data", "inventario", "Validade coincide com a CMDB",
        "A data de expiração instalada é a da CMDB?",
        "Compara a data do certificado instalado com a da CMDB (tolerância de 1 dia).",
        "Se a CMDB tem data posterior, alguém renovou mas não instalou. Se tem data anterior, a CMDB está desatualizada.",
        ("CMDB com data posterior: instalar o certificado renovado no servidor (é o caso urgente).",
         "CMDB com data anterior: atualizar a data na CMDB."),
    ),
)
CHECK_BY_ID = {c.id: c for c in CHECKS}


@dataclass
class CheckResult:
    check: str
    status: str
    detail: str = ""


@dataclass
class Evaluation:
    results: dict[str, CheckResult] = field(default_factory=dict)
    findings: list[tuple[str, str, dict]] = field(default_factory=list)  # (tipo, severidade, detalhes)
    matched_issuer: str | None = None

    def set(self, check: str, status: str, detail: str = "") -> None:
        self.results[check] = CheckResult(check, status, detail)

    def worst(self) -> str:
        return max((r.status for r in self.results.values()), key=lambda s: STATUS_RANK[s], default=NT)


def days_left(not_after: datetime, now: datetime) -> int:
    return math.floor((as_utc(not_after) - now).total_seconds() / 86400)


SEV_ORDER = ("info", "baixa", "media", "alta", "critica")


def expiry_severity(days: int, pct_left: float | None, settings: Settings, auto_renew: bool = False) -> str | None:
    """Gravidade do alerta de expiração. Com renovação automática (Let's Encrypt) só há alerta quando faltam
    CERTWATCH_AUTO_RENEW_ALERT_DAYS dias ou menos: a renovação devia ter acontecido antes, por isso falhou."""
    if auto_renew and settings.auto_renew_alert_days > 0:
        if days > settings.auto_renew_alert_days:
            return None
        pct_left = None
    t = settings.expiry_thresholds
    if days < 0 or days <= t["critica"]:
        sev = "critica"
    elif days <= t["alta"]:
        sev = "alta"
    elif days <= t["media"]:
        sev = "media"
    elif days <= t["baixa"]:
        sev = "baixa"
    else:
        sev = None
    if pct_left is not None and pct_left <= settings.lifetime_warn_pct:
        if sev is None or SEV_ORDER.index(sev) < SEV_ORDER.index("media"):
            sev = "media"
    return sev


def _fmt(dt: datetime | None) -> str:
    return as_utc(dt).strftime("%d-%m-%Y") if dt else "—"


def _iso(dt: datetime | None) -> str | None:
    return as_utc(dt).isoformat() if dt else None


def evaluate_endpoint(ep, sr, leaf, latest_by_issuer: dict, settings: Settings, now: datetime) -> Evaluation:
    """Corre todos os testes para um endpoint. Não acede à base de dados."""
    ev = Evaluation()
    if sr is None:
        for c in CHECKS:
            ev.set(c.id, NT, "ainda não verificado")
        return ev

    # Rede
    if sr.status == "dns_error":
        ev.set("rede.dns", FALHA, sr.error)
        ev.set("rede.porta", NT)
    else:
        ev.set("rede.dns", OK, f"resolve para {sr.resolved_ip}" if sr.resolved_ip else "resolve")
        ev.set("rede.porta", FALHA if sr.status == "unreachable" else OK,
               sr.error if sr.status == "unreachable" else f"porta {ep.port} aberta")
    # Ligação
    if sr.status in ("dns_error", "unreachable"):
        ev.set("tls.handshake", NT)
    elif sr.status == "tls_error" or leaf is None:
        ev.set("tls.handshake", FALHA, sr.error or "sem certificado")
    else:
        ev.set("tls.handshake", OK, f"{sr.tls_version} · {sr.cipher}")

    if leaf is None:
        for c in CHECKS:
            ev.results.setdefault(c.id, CheckResult(c.id, NT, "sem ligação TLS"))
        if ep.consecutive_failures >= settings.unreachable_after:
            ev.findings.append(("INALCANCAVEL", "baixa", {"estado": sr.status, "erro": sr.error,
                                                        "falhas_consecutivas": ep.consecutive_failures}))
        return ev

    if sr.tls_version in LEGACY_TLS:
        ev.set("tls.protocolo", FALHA, f"negociado {sr.tls_version}")
        ev.findings.append(("TLS_LEGADO", "media", {"protocolo": sr.tls_version}))
    else:
        ev.set("tls.protocolo", OK, sr.tls_version)

    na, nb = as_utc(leaf.not_after), as_utc(leaf.not_before)

    # Cadeia
    if leaf.self_issued:
        ev.set("cadeia.autoassinado", FALHA, leaf.subject_dn)
        ev.set("cadeia.confianca", NA, "certificado autoassinado (ver teste anterior)")
        ev.findings.append(("SELF_SIGNED", "media", {"subject_dn": leaf.subject_dn}))
    else:
        ev.set("cadeia.autoassinado", OK, f"emitido por {leaf.issuer_cn}")
        if sr.verify_ok:
            ev.set("cadeia.confianca", OK, " ← ".join(x.get("subject_cn") or "?" for x in (sr.chain or [])))
        elif sr.verify_ok is False:
            intermediate_expired = any(
                not x.get("self_issued") and x.get("not_after") and as_utc(datetime.fromisoformat(x["not_after"])) < now
                for x in (sr.chain or [])[1:]
            )
            only_leaf_expired = sr.verify_code == X509_CERT_HAS_EXPIRED and na < now and not intermediate_expired
            if only_leaf_expired:
                ev.set("cadeia.confianca", OK, "cadeia válida; o certificado está expirado (ver Validade)")
            elif sr.verify_code == X509_DEPTH_ZERO_SELF_SIGNED:
                ev.set("cadeia.confianca", NA, "autoassinado")
            else:
                ev.set("cadeia.confianca", FALHA, f"[{sr.verify_code}] {sr.verify_message}")
                ev.findings.append(("CHAIN_INVALIDA", "media", {
                    "codigo": sr.verify_code, "motivo": sr.verify_message,
                    "cadeia": [f"{x.get('subject_cn')} ← {x.get('issuer_cn')}" for x in (sr.chain or [])]}))
        else:
            ev.set("cadeia.confianca", AVISO, sr.error or "validação não concluída")
            ev.findings.append(("VALIDACAO_INCOMPLETA", "baixa", {"erro": sr.error}))

    # Identidade
    names = leaf.sans_dns or ([leaf.subject_cn] if leaf.subject_cn else [])
    if hostname_matches(ep.host, names, leaf.sans_ip):
        ev.set("identidade.nome", OK, f"{ep.host} coberto")
    else:
        ev.set("identidade.nome", FALHA, "certificado para " + ", ".join((names + leaf.sans_ip)[:4]))
        ev.findings.append(("HOSTNAME_MISMATCH", "media", {"nomes_no_certificado": names[:20] + leaf.sans_ip[:5]}))

    # Validade
    dl = days_left(na, now)
    total = (na - nb).total_seconds() if nb else 0
    pct = max(0.0, (na - now).total_seconds() / total) if total > 0 else None
    auto = is_auto_renew(settings, leaf.issuer_dn, leaf.issuer_cn)
    sev = expiry_severity(dl, pct, settings, auto_renew=auto)
    label = f"expirou há {-dl} dias ({_fmt(na)})" if dl < 0 else f"expira em {dl} dias ({_fmt(na)})"
    if auto:
        label += " · renovação automática" + (" falhou?" if sev else "")
    ev.set("validade.prazo", FALHA if sev in ("critica", "alta") else (AVISO if sev else OK), label)
    if sev:
        ev.findings.append(("EXPIRACAO", sev, {
            "fonte": "live", "dias": dl, "expira_em": _iso(na),
            "vida_restante_pct": round(pct * 100, 1) if pct is not None else None,
            "emissor": leaf.issuer_cn, "serial": leaf.serial_hex, "sha256": leaf.sha256,
            "renovacao_automatica": auto or None}))

    # Criptografia
    weak, leaf_weak = [], False
    if leaf.sig_hash in WEAK_HASHES:
        weak.append(f"assinatura {leaf.sig_hash.upper()}")
        leaf_weak = True
        ev.set("cripto.assinatura", FALHA, f"assinado com {leaf.sig_hash.upper()}")
    else:
        weak_inter = [x for x in (sr.chain or [])[1:] if not x.get("self_issued") and x.get("sig_hash") in WEAK_HASHES]
        for x in weak_inter:
            weak.append(f"intermédio '{x.get('subject_cn')}' assinado com {x['sig_hash'].upper()}")
        ev.set("cripto.assinatura", AVISO if weak_inter else OK,
               (f"intermédio com {weak_inter[0]['sig_hash'].upper()}" if weak_inter else (leaf.sig_hash or "?").upper()))
    if (leaf.key_type == "RSA" and (leaf.key_bits or 0) < 2048) or leaf.key_type == "DSA" or \
       (leaf.key_type == "EC" and (leaf.key_bits or 0) < 256):
        weak.append(f"chave {leaf.key_type} {leaf.key_bits}")
        leaf_weak = True
        ev.set("cripto.chave", FALHA, f"{leaf.key_type} {leaf.key_bits} bits")
    else:
        ev.set("cripto.chave", OK, f"{leaf.key_type} {leaf.key_bits} bits")
    if weak:
        ev.findings.append(("CRIPTO_FRACA", "alta" if leaf_weak else "media", {"problemas": weak}))

    # Inventário
    if not latest_by_issuer:
        ev.set("inventario.registo", AVISO, "nenhum registo ativo na CMDB para este nome")
        ev.set("inventario.emissor", NA, "sem registo na CMDB")
        ev.set("inventario.data", NA, "sem registo na CMDB")
        ev.findings.append(("NAO_REGISTADO_CMDB", "baixa", {"emissor": leaf.issuer_cn, "expira_em": _iso(na)}))
        return ev
    ev.set("inventario.registo", OK, f"{len(latest_by_issuer)} emissor(es) registado(s)")
    li = norm_issuer(leaf.issuer_cn)
    rec = latest_by_issuer.get(li)
    if rec is None:
        cmdb_issuers = sorted({r.issuer_name or r.issuer for r in latest_by_issuer.values()})
        ev.set("inventario.emissor", AVISO, f"servido: {leaf.issuer_cn} · CMDB: {', '.join(cmdb_issuers)}")
        ev.set("inventario.data", NA, "emissor diferente")
        ev.findings.append(("ISSUER_DIVERGENTE", "media", {"emissor_servido": leaf.issuer_cn, "emissores_cmdb": cmdb_issuers}))
        return ev
    ev.matched_issuer = li
    ev.set("inventario.emissor", OK, leaf.issuer_cn)
    if rec.valid_to is None:
        ev.set("inventario.data", NA, "CMDB sem data")
        return ev
    diff = (na.date() - as_utc(rec.valid_to).date()).days
    details = {"validade_servida": _iso(na), "validade_cmdb": _iso(rec.valid_to), "ucmdb_id": rec.ucmdb_id}
    if diff > 1:
        ev.set("inventario.data", AVISO, f"instalado {_fmt(na)} · CMDB {_fmt(rec.valid_to)} (CMDB desatualizada)")
        ev.findings.append(("RENOVADO_NAO_REFLETIDO", "baixa", details))
    elif diff < -1:
        ev.set("inventario.data", FALHA, f"instalado {_fmt(na)} · CMDB {_fmt(rec.valid_to)} (renovado mas não instalado)")
        ev.findings.append(("RENOVACAO_NAO_INSTALADA", "alta", details))
    else:
        ev.set("inventario.data", OK, _fmt(na))
    return ev

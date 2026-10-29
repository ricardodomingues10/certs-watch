"""Conectores de tickets (pedidos de renovação de certificados).

Todos devolvem os pedidos no formato de sempre (o do SMAX), que a aplicação guarda em smax_tickets:
    id, display_label, endpoint (nome normalizado), environment, cert_expiry, cert_type, phase, priority,
    owner_group, owner_person, last_update, scheduled_end, service_component, created
O endpoint vem de um campo próprio, se o sistema o tiver, ou do primeiro nome de host no título.
Os pedidos fechados ficam com a fase "Closed" (ou "Done"), que a aplicação já reconhece.

Criar um pedido: create(draft) devolve (estado, id, detalhe), com estado "criado", "falhou" ou
"indeterminado" (sem resposta: nunca se repete sozinho, como no SMAX).
"""
from __future__ import annotations

import re
from datetime import datetime

import httpx

from . import Connector, ConnectorError, Field, TestResult, as_text, dig, host_in_text, to_datetime


def _norm_endpoint(v: str) -> str:
    from ..fontes.smax import norm_endpoint

    return norm_endpoint(v)


def _ticket(tid, label, endpoint="", phase="", priority="", group="", person="", updated=None, created=None,
            expiry=None, env="", ctype="", due=None) -> dict:
    label = as_text(label)
    ep = _norm_endpoint(as_text(endpoint)) or host_in_text(label)
    return {"id": str(tid)[:64], "display_label": label[:512], "endpoint": ep[:253], "environment": as_text(env)[:32],
            "cert_expiry": to_datetime(expiry), "cert_type": as_text(ctype)[:128], "phase": as_text(phase)[:64],
            "priority": as_text(priority)[:64], "owner_group": as_text(group)[:256],
            "owner_person": as_text(person)[:256], "last_update": to_datetime(updated),
            "scheduled_end": to_datetime(due), "service_component": "", "created": to_datetime(created)}


CREATE_FIELD = Field("criar_pedidos", "Permitir criar pedidos a partir do Atalaia", kind="bool", default="nao",
                     help="Desligado, o Atalaia só lê os pedidos. Ligado, os pedidos são sempre revistos antes de criar.")

TITLE_FIELD = Field("titulo", "Título dos pedidos novos", advanced=True,
                    default="Renovação do certificado {cn} (expira a {data})",
                    help="{cn}, {data}, {emissor}, {ambito} e {sites} são substituídos.")


def _fmt_title(template: str, draft) -> tuple[str, str]:
    data = draft.expiry.strftime("%d/%m/%Y") if isinstance(draft.expiry, datetime) else "?"
    sites = ", ".join(draft.sites or [])[:500]
    vals = {"cn": draft.cn, "data": data, "emissor": draft.issuer or "", "ambito": draft.scope or "", "sites": sites}
    try:
        title = template.format(**vals)
    except (KeyError, IndexError, ValueError):
        title = f"Renovação do certificado {draft.cn} (expira a {data})"
    body = (f"Certificado: {draft.cn}\nExpira a: {data}\nEmissor: {draft.issuer or '—'}\n"
            f"Âmbito: {draft.scope or '—'}\nSites: {sites or '—'}\n"
            f"Responsável pela instalação: {draft.responsavel or '—'}\nLocalização: {draft.localizacao or '—'}\n\n"
            "Pedido criado pelo Atalaia Cert.")
    return title[:250], body


class _Http(Connector):
    role = "tickets"
    capabilities = frozenset({"ler", "criar"})

    def client(self, base: str, *, headers: dict | None = None, auth=None) -> httpx.Client:
        from ..trust import ssl_context_for_api

        return httpx.Client(base_url=base.rstrip("/"), headers={"Accept": "application/json", **(headers or {})},
                            auth=auth, timeout=httpx.Timeout(30.0, read=120.0), verify=ssl_context_for_api(self.settings),
                            follow_redirects=True)

    @staticmethod
    def check(r: httpx.Response, what: str) -> None:
        if r.status_code in (401, 403):
            raise ConnectorError(f"{what}: acesso recusado ({r.status_code}). Confirma a credencial e as permissões.")
        if r.status_code >= 400:
            raise ConnectorError(f"{what}: HTTP {r.status_code} — {r.text[:200]}")

    def test(self) -> TestResult:
        if self.missing():
            return TestResult(False, "Falta preencher: " + ", ".join(self.missing()))
        try:
            ts = self.fetch_tickets()
        except (ConnectorError, httpx.HTTPError) as exc:
            return TestResult(False, str(exc))
        with_ep = sum(1 for t in ts if t["endpoint"])
        sample = [{k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in t.items()
                   if k in ("id", "display_label", "endpoint", "phase", "owner_group", "last_update")} for t in ts[:8]]
        return TestResult(True, f"{len(ts)} pedidos lidos · {with_ep} ligados a um nome de certificado",
                          sample=sample, total=len(ts))

    def preview(self, draft) -> dict:
        title, body = _fmt_title(self.p("titulo", TITLE_FIELD.default), draft)
        return {"sistema": self.label, "titulo": title, "descricao": body}


# ---------------------------------------------------------------- SMAX (o de sempre)
class SmaxTickets(Connector):
    role, kind, label = "tickets", "smax", "SMAX"
    description = "Service Management Automation X: a configuração do .env (README, secção 7), como até agora."
    capabilities = frozenset({"ler", "criar", "comentar", "fase"})
    FIELDS = ()

    def configured(self) -> bool:
        from ..fontes.smax import configured

        return configured(self.settings)

    def missing(self) -> list[str]:
        return [] if self.configured() else ["CERTWATCH_SMAX_URL, CERTWATCH_SMAX_TENANT e segredos smax_user/smax_password"]

    def summary(self) -> str:
        return f"SMAX · {self.settings.smax_url} · tenant {self.settings.smax_tenant}"

    def fetch_tickets(self) -> list[dict]:
        from ..fontes.smax import fetch_tickets

        return fetch_tickets(self.settings)

    def ticket_url(self, ticket_id: str) -> str:
        from ..fontes.smax import ticket_url

        return ticket_url(self.settings, ticket_id)

    def test(self) -> TestResult:
        from ..fontes.smax import SmaxError

        try:
            ts = self.fetch_tickets()
        except (SmaxError, httpx.HTTPError) as exc:
            return TestResult(False, str(exc))
        return TestResult(True, f"{len(ts)} pedidos lidos do SMAX", total=len(ts),
                          sample=[{"id": t["id"], "display_label": t["display_label"], "endpoint": t["endpoint"],
                                   "phase": t["phase"]} for t in ts[:8]])


class NoTickets(Connector):
    role, kind, label = "tickets", "nenhum", "Sem sistema de tickets"
    description = "Os pedidos de renovação não são lidos nem criados (os alertas e o relatório por email continuam)."
    capabilities = frozenset()

    def configured(self) -> bool:
        return False

    def fetch_tickets(self) -> list[dict]:
        return []

    def ticket_url(self, ticket_id: str) -> str:
        return ""

    def test(self) -> TestResult:
        return TestResult(True, "Sem sistema de tickets ligado.")


# ---------------------------------------------------------------- Jira
class JiraTickets(_Http):
    kind, label = "jira", "Jira"
    description = "Jira Cloud ou Data Center/Server: lê os pedidos de certificados por JQL e cria issues novas."
    FIELDS = (
        Field("url", "Endereço do Jira", required=True, help="https://empresa.atlassian.net ou https://jira.empresa.pt"),
        Field("tipo", "Tipo", kind="select", default="cloud",
              options=(("cloud", "Jira Cloud (email + API token)"), ("server", "Data Center / Server (token pessoal)"))),
        Field("utilizador", "Email (Jira Cloud)"),
        Field("token", "API token ou token pessoal", kind="password", secret=True, required=True),
        Field("projeto", "Projeto (chave)", required=True, help="Ex.: CERT ou INFRA"),
        Field("jql", "JQL dos pedidos de certificados", default='project = {projeto} AND labels = certificado',
              help="{projeto} é substituído. Os pedidos fechados contam pelo estado (categoria Concluído)."),
        Field("campo_endpoint", "Campo do nome do certificado (opcional)", advanced=True,
              help="Ex.: customfield_10050. Vazio = o primeiro nome de host no resumo."),
        Field("campo_expiracao", "Campo da data de expiração (opcional)", advanced=True, default="duedate"),
        Field("tipo_issue", "Tipo de issue nos pedidos novos", default="Task", advanced=True),
        Field("etiquetas", "Etiquetas nos pedidos novos", default="certificado", advanced=True),
        CREATE_FIELD,
        TITLE_FIELD,
    )

    def _client(self) -> httpx.Client:
        if self.p("tipo", "cloud") == "cloud":
            return self.client(self.p("url"), auth=(self.p("utilizador"), self.s("token")))
        return self.client(self.p("url"), headers={"Authorization": f"Bearer {self.s('token')}"})

    def _api(self) -> str:
        return "/rest/api/3" if self.p("tipo", "cloud") == "cloud" else "/rest/api/2"

    def summary(self) -> str:
        return f"Jira · {self.p('url')} · projeto {self.p('projeto')}"

    def ticket_url(self, ticket_id: str) -> str:
        return f"{self.p('url').rstrip('/')}/browse/{ticket_id}"

    def fetch_tickets(self) -> list[dict]:
        jql = self.p("jql", "project = {projeto}").replace("{projeto}", self.p("projeto"))
        extra = [f for f in (self.p("campo_endpoint"), self.p("campo_expiracao")) if f]
        fields = ",".join(["summary", "status", "priority", "assignee", "updated", "created", "duedate", "components", *extra])
        out: list[dict] = []
        cloud = self.p("tipo", "cloud") == "cloud"
        start, token = 0, None
        with self._client() as c:
            while len(out) < 5000:
                if cloud:   # Jira Cloud: pesquisa nova (/search/jql), paginada por nextPageToken
                    params = {"jql": jql, "maxResults": 100, "fields": fields}
                    if token:
                        params["nextPageToken"] = token
                    r = c.get(f"{self._api()}/search/jql", params=params)
                else:
                    r = c.get(f"{self._api()}/search", params={"jql": jql, "startAt": start, "maxResults": 100,
                                                              "fields": fields})
                self.check(r, "Pesquisa no Jira")
                data = r.json() or {}
                issues = data.get("issues") or []
                for it in issues:
                    f = it.get("fields") or {}
                    done = dig(f, "status.statusCategory.key") == "done"
                    out.append(_ticket(
                        it.get("key"), f.get("summary"),
                        endpoint=as_text(f.get(self.p("campo_endpoint"))) if self.p("campo_endpoint") else "",
                        phase="Done" if done else as_text(f.get("status")), priority=as_text(f.get("priority")),
                        group=", ".join(as_text(x) for x in (f.get("components") or [])),
                        person=as_text(f.get("assignee")), updated=f.get("updated"), created=f.get("created"),
                        expiry=f.get(self.p("campo_expiracao")) if self.p("campo_expiracao") else None,
                        due=f.get("duedate")))
                if not issues:
                    break
                if cloud:
                    token = data.get("nextPageToken")
                    if data.get("isLast", not token) or not token:
                        break
                else:
                    start += len(issues)
                    if start >= int(data.get("total") or 0):
                        break
        return out

    def create(self, draft) -> tuple[str, str, dict]:
        title, body = _fmt_title(self.p("titulo", TITLE_FIELD.default), draft)
        desc = body if self.p("tipo", "cloud") == "server" else {
            "type": "doc", "version": 1,
            "content": [{"type": "paragraph", "content": [{"type": "text", "text": line}]} for line in body.splitlines() if line]}
        fields = {"project": {"key": self.p("projeto")}, "summary": title, "description": desc,
                  "issuetype": {"name": self.p("tipo_issue", "Task")},
                  "labels": [x for x in re.split(r"[,\s]+", self.p("etiquetas", "certificado")) if x]}
        if isinstance(draft.expiry, datetime):
            fields["duedate"] = draft.expiry.strftime("%Y-%m-%d")
        return _post_create(self._client, f"{self._api()}/issue", {"fields": fields}, lambda d: d.get("key"))


# ---------------------------------------------------------------- ServiceNow
SN_CLOSED = {"closed", "cancelled", "canceled", "complete", "completed", "resolved", "fechado", "cancelado", "concluído"}


class ServiceNowTickets(_Http):
    kind, label = "servicenow", "ServiceNow"
    description = "Changes (change_request) ou incidentes do ServiceNow pela Table API."
    FIELDS = (
        Field("instancia", "Instância", required=True, help="https://empresa.service-now.com"),
        Field("utilizador", "Utilizador de integração", required=True),
        Field("token", "Palavra-passe", kind="password", secret=True, required=True),
        Field("tabela", "Tabela", default="change_request", options=(), help="change_request, incident, sc_req_item…"),
        Field("consulta", "Filtro dos pedidos de certificados (sysparm_query)",
              default="short_descriptionLIKEcertificado", help="Ex.: categoryLIKEcertificate^ORshort_descriptionLIKEcertificado"),
        Field("campo_endpoint", "Campo do nome do certificado (opcional)", advanced=True,
              help="Ex.: u_endpoint. Vazio = o primeiro nome de host na descrição curta."),
        Field("campo_expiracao", "Campo da data de expiração (opcional)", advanced=True),
        Field("grupo", "Grupo de atribuição nos pedidos novos (opcional)", advanced=True),
        CREATE_FIELD,
        TITLE_FIELD,
    )

    def _client(self) -> httpx.Client:
        return self.client(self.p("instancia"), auth=(self.p("utilizador"), self.s("token")))

    def summary(self) -> str:
        return f"ServiceNow · {self.p('instancia')} · {self.p('tabela')}"

    def ticket_url(self, ticket_id: str) -> str:
        return f"{self.p('instancia').rstrip('/')}/nav_to.do?uri={self.p('tabela', 'change_request')}.do?sysparm_query=number={ticket_id}"

    def fetch_tickets(self) -> list[dict]:
        out: list[dict] = []
        offset = 0
        table = self.p("tabela", "change_request")
        with self._client() as c:
            while offset < 20000:
                params = {"sysparm_limit": 500, "sysparm_offset": offset, "sysparm_display_value": "all",
                          "sysparm_exclude_reference_link": "true"}
                if self.p("consulta"):
                    params["sysparm_query"] = self.p("consulta")
                r = c.get(f"/api/now/table/{table}", params=params)
                self.check(r, "Leitura do ServiceNow")
                rows = (r.json() or {}).get("result") or []
                for row in rows:
                    def v(name, display=True, _row=row):
                        cell = _row.get(name)
                        if isinstance(cell, dict):
                            return cell.get("display_value" if display else "value")
                        return cell
                    state = as_text(v("state"))
                    out.append(_ticket(
                        v("number"), v("short_description"),
                        endpoint=as_text(v(self.p("campo_endpoint"))) if self.p("campo_endpoint") else "",
                        phase="Closed" if state.lower() in SN_CLOSED else state, priority=v("priority"),
                        group=v("assignment_group"), person=v("assigned_to"), updated=v("sys_updated_on", False),
                        created=v("opened_at", False) or v("sys_created_on", False),
                        expiry=v(self.p("campo_expiracao"), False) if self.p("campo_expiracao") else None,
                        due=v("end_date", False)))
                offset += len(rows)
                if len(rows) < 500:
                    break
        return out

    def create(self, draft) -> tuple[str, str, dict]:
        title, body = _fmt_title(self.p("titulo", TITLE_FIELD.default), draft)
        payload = {"short_description": title, "description": body}
        if self.p("grupo"):
            payload["assignment_group"] = self.p("grupo")
        return _post_create(self._client, f"/api/now/table/{self.p('tabela', 'change_request')}", payload,
                            lambda d: dig(d, "result.number"))


# ---------------------------------------------------------------- GLPI
GLPI_STATUS = {1: "Novo", 2: "Em curso (atribuído)", 3: "Em curso (planeado)", 4: "Pendente", 5: "Closed", 6: "Closed"}


class GlpiTickets(_Http):
    kind, label = "glpi", "GLPI"
    description = "Tickets do GLPI pela API REST (apirest.php)."
    FIELDS = (
        Field("url", "Endereço da API", required=True, help="https://glpi.empresa.pt/apirest.php"),
        Field("app_token", "App-Token (Configuração → Geral → API)", kind="password", secret=True),
        Field("token", "Token de utilizador (Preferências → Chaves de acesso remoto)", kind="password", secret=True, required=True),
        Field("pesquisa", "Texto que identifica os pedidos de certificados", default="certificado",
              help="Procurado no título dos tickets."),
        CREATE_FIELD,
        TITLE_FIELD,
    )

    def summary(self) -> str:
        return f"GLPI · {self.p('url')}"

    def ticket_url(self, ticket_id: str) -> str:
        base = re.sub(r"/apirest\.php/?$", "", self.p("url").rstrip("/"))
        return f"{base}/front/ticket.form.php?id={ticket_id}"

    def _session(self, c: httpx.Client) -> dict:
        headers = {"Authorization": f"user_token {self.s('token')}"}
        if self.s("app_token"):
            headers["App-Token"] = self.s("app_token")
        r = c.get("/initSession", headers=headers)
        self.check(r, "Sessão no GLPI")
        token = (r.json() or {}).get("session_token")
        if not token:
            raise ConnectorError("O GLPI não devolveu session_token.")
        out = {"Session-Token": token}
        if self.s("app_token"):
            out["App-Token"] = self.s("app_token")
        return out

    def fetch_tickets(self) -> list[dict]:
        term = self.p("pesquisa", "certificado").lower()
        out: list[dict] = []
        with self.client(self.p("url")) as c:
            h = self._session(c)
            try:
                start = 0
                while start < 10000:
                    r = c.get("/Ticket", params={"range": f"{start}-{start + 199}", "expand_dropdowns": "true",
                                                 "order": "DESC", "sort": "date_mod"}, headers=h)
                    if r.status_code not in (200, 206):
                        self.check(r, "Leitura dos tickets do GLPI")
                    rows = r.json() or []
                    for t in rows:
                        if term and term not in str(t.get("name", "")).lower() and term not in str(t.get("content", "")).lower():
                            continue
                        try:
                            status = GLPI_STATUS.get(int(t.get("status") or 0), str(t.get("status") or ""))
                        except (TypeError, ValueError):
                            status = str(t.get("status") or "")
                        out.append(_ticket(t.get("id"), t.get("name"), phase=status, priority=t.get("priority"),
                                           updated=t.get("date_mod"), created=t.get("date"), due=t.get("time_to_resolve")))
                    if r.status_code == 200 or len(rows) < 200:
                        break
                    start += 200
            finally:
                c.get("/killSession", headers=h)
        return out

    def create(self, draft) -> tuple[str, str, dict]:
        title, body = _fmt_title(self.p("titulo", TITLE_FIELD.default), draft)
        with self.client(self.p("url")) as c:
            try:
                h = self._session(c)
            except ConnectorError as exc:
                return "falhou", "", {"motivo": str(exc)}
            try:
                r = c.post("/Ticket", json={"input": {"name": title, "content": body, "type": 2}}, headers=h)
            except httpx.HTTPError as exc:
                return "indeterminado", "", {"motivo": f"Sem resposta do GLPI: {exc.__class__.__name__}"}
            finally:
                c.get("/killSession", headers=h)
        if r.status_code in (200, 201) and isinstance(r.json(), dict) and r.json().get("id"):
            return "criado", str(r.json()["id"]), {"texto": r.text[:2000]}
        return "falhou", "", {"motivo": f"HTTP {r.status_code}", "texto": r.text[:2000]}


def _post_create(make_client, path: str, payload: dict, get_id) -> tuple[str, str, dict]:
    try:
        with make_client() as c:
            r = c.post(path, json=payload)
    except httpx.TimeoutException as exc:
        return "indeterminado", "", {"motivo": f"Sem resposta a tempo ({exc.__class__.__name__}): confirmar no sistema."}
    except httpx.HTTPError as exc:
        return "falhou", "", {"motivo": f"Sem ligação: {exc.__class__.__name__}"}
    if r.status_code in (200, 201):
        try:
            tid = get_id(r.json())
        except ValueError:
            tid = None
        if tid:
            return "criado", str(tid), {"texto": r.text[:2000]}
        return "indeterminado", "", {"motivo": "Resposta sem número do pedido: confirmar no sistema.", "texto": r.text[:2000]}
    return "falhou", "", {"motivo": f"HTTP {r.status_code}", "texto": r.text[:2000]}


TYPES: dict[str, type[Connector]] = {
    "smax": SmaxTickets,
    "jira": JiraTickets,
    "servicenow": ServiceNowTickets,
    "glpi": GlpiTickets,
    "nenhum": NoTickets,
}

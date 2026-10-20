# certwatch 0.1

Aplicação autónoma de gestão de certificados X.509 de uma organização. Não depende do n8n.

**O que faz:**
1. Importa os certificados da UCMDB por REST API (TQL configurável). Da CMDB usa **apenas** CommonName, ValidTo e Issuer/IssuerName.
2. Liga-se por TLS a cada endpoint e observa o certificado **realmente servido**: chain completa, validação contra as CAs confiáveis (públicas e raízes internas), hostname, algoritmos, chave e protocolo.
3. Cruza a CMDB com a realidade e gera *findings* com ciclo de vida (aberto → aceite com prazo → resolvido automaticamente).
4. Disponibiliza uma interface web (inventário, findings, endpoints, jobs, auditoria) e uma API JSON só de leitura.

Fora desta versão: tickets ITSM, escrita `certs_update.csv`/UCMDB, CT, AVI, ADCS, email.

---

## 1. Instalação no servidor de testes

Requisitos: Docker com o plugin `compose`, e acesso a `docker.io` e PyPI para o build. Se o servidor não tiver acesso, ver a secção 7.

```bash
sudo unzip ~/certwatch-0.1.0.zip -d /opt     # cria /opt/certwatch
sudo chown -R "$USER" /opt/certwatch
cd /opt/certwatch
cp .env.example .env                         # definir os valores reais (URL e TQL da UCMDB, etc.)
```

### 1.1 Segredos (nunca no `.env`)

```bash
mkdir -p secrets && chmod 700 secrets
openssl rand -base64 32 | tr -d '\n' > secrets/db_password
printf '%s' 'conta-servico-ucmdb'      > secrets/ucmdb_user
printf '%s' 'PASSWORD_DA_CONTA'        > secrets/ucmdb_password
openssl rand -base64 18 | tr -d '\n' > secrets/admin_password   # login da interface (utilizador: admin)
sudo chown 10001:10001 secrets/*       # o contentor corre como UID 10001
sudo chmod 400 secrets/*
```

Use uma **conta de serviço UCMDB só de leitura**, não uma conta pessoal nem `sysadmin`. Para fazer `printf` de uma password com plicas, use `read -rs P; printf '%s' "$P" > secrets/ucmdb_password; unset P`.

### 1.2 Confiança TLS (raízes internas)

A aplicação valida o TLS da UCMDB e dos endpoints internos contra as raízes colocadas em `trust/`. Nunca usa `-k`.

```bash
mkdir -p trust
# Ver a chain que a UCMDB apresenta (não é validada; serve só para identificar a raiz)
docker compose run --rm --no-deps worker python -m certwatch.cli trust-fetch cmdb.exemplo.local:8443 > /tmp/cmdb-chain.pem
```

O comando mostra o subject, o emissor e o SHA-256 de cada certificado. **Confirme o SHA-256 da raiz com a equipa de PKI** e grave só a raiz (e, se necessário, as intermédias) em `trust/raiz-interna.pem`. Em alternativa, exporte a raiz de uma máquina do domínio (`certutil -ca.cert raiz.cer`, ou a store "Trusted Root") e converta-a com `openssl x509 -inform der -in raiz.cer -out trust/raiz-interna.pem`.

### 1.3 Arranque

```bash
docker compose build
docker compose up -d
docker compose ps
docker compose logs -f worker
```

### 1.4 Primeira execução

Na interface, em **Jobs → Pipeline completo**, ou pela linha de comandos:

```bash
docker compose exec worker python -m certwatch.cli run pipeline
```

Depois disto o pipeline corre sozinho todos os dias às `CERTWATCH_PIPELINE_DAILY_AT` (06:15 por omissão).

---

## 2. Aceder à interface

A interface só escuta em `127.0.0.1:8088` no servidor. No seu posto:

```bash
ssh -L 8088:127.0.0.1:8088 utilizador@servidor
```

Abrir `http://localhost:8088`. O utilizador é `admin` e a palavra-passe é o conteúdo de `secrets/admin_password`.

| Página | Para que serve |
|---|---|
| Painel | Contagens por prazo e severidade, o que precisa de atenção imediata, últimos jobs |
| Certificados | Inventário por CN: data CMDB vs. data live, prazo efetivo, pior finding. Filtros por prazo, severidade e tipo |
| Detalhe | Registos CMDB, endpoints, chain apresentada, validação, histórico de verificações, findings |
| Findings | Lista filtrável; **aceitar risco** (com justificação obrigatória e data de expiração até 1 ano) ou reabrir |
| Endpoints | Alvos de verificação; adicionar endpoints manuais (ex.: hosts que servem um wildcard) |
| Jobs e auditoria | Executar jobs, histórico de execuções, registo de quem fez o quê |

API só de leitura (mesma autenticação): `GET /api/inventario`, `GET /api/findings?status=aberto|aceite|resolvido`.

---

## 3. Regras (findings)

| Tipo | Severidade | Quando |
|---|---|---|
| `EXPIRACAO` | crítica ≤ 7 d (ou expirado) · alta ≤ 20 d · média ≤ 30 d · baixa ≤ 90 d; sobe para média se restar ≤ 20% da vida | Data **live** se o endpoint respondeu; senão, data da CMDB |
| `CMDB_REGISTO_EXPIRADO` | baixa | Registo expirado há mais de 30 dias e ainda ativo na CMDB (sem endpoint que o confirme) |
| `RENOVACAO_NAO_INSTALADA` | alta | A CMDB tem uma data posterior à do certificado servido: renovou-se mas não foi instalado |
| `RENOVADO_NAO_REFLETIDO` | baixa | O endpoint serve um certificado mais recente do que o da CMDB |
| `ISSUER_DIVERGENTE` | média | O emissor servido não corresponde a nenhum emissor registado na CMDB para esse CN |
| `CHAIN_INVALIDA` | média | Intermédia em falta, raiz desconhecida, intermédia expirada… (código e motivo OpenSSL) |
| `VALIDACAO_INCOMPLETA` | baixa | O handshake com validação falhou por outro motivo (protocolo, cifra) |
| `HOSTNAME_MISMATCH` | média | O certificado não cobre o nome do endpoint (RFC 6125: wildcard só cobre um nível) |
| `SELF_SIGNED` | média | Certificado autoassinado |
| `CRIPTO_FRACA` | alta (folha) · média (intermédia) | SHA-1/MD5, RSA < 2048, DSA, EC < 256 |
| `TLS_LEGADO` | média | Negociado TLS 1.0/1.1 ou SSLv3 |
| `INALCANCAVEL` | baixa | Sem resposta TLS em ≥ `CERTWATCH_UNREACHABLE_AFTER` verificações seguidas |
| `WILDCARD_SEM_ENDPOINT` | info | Wildcard sem hosts conhecidos para verificar |

**Ciclo de vida:** o ID de cada finding é estável (tipo + alvo), por isso não há duplicados. Um finding que deixa de se verificar passa a *resolvido* sozinho. Uma aceitação expirada volta a *aberto*.

**Limitação conhecida:** a OpenSSL reporta só o **primeiro** erro da chain. O hostname, o autoassinado e a criptografia são avaliados à parte, para não ficarem escondidos.

---

## 4. Segurança da própria aplicação

- A interface escuta só em localhost; o acesso é por túnel SSH. Autenticação HTTP Basic, proteção CSRF (cookie `SameSite=Strict` + token), CSP restritiva, `X-Frame-Options: DENY` e redirecionamentos apenas para caminhos locais.
- Os segredos ficam em ficheiros montados (`/run/secrets`), nunca em variáveis de ambiente nem no código.
- Os contentores correm como UID 10001, com filesystem só de leitura, `cap_drop: ALL` e `no-new-privileges`.
- O TLS para a UCMDB é sempre verificado contra o trust store.
- Os dados da CMDB são tratados como não confiáveis: só hostnames e IPs válidos e portas da allowlist são alvos. Nenhum valor passa por uma shell.
- A ingestão é abortada se a UCMDB devolver menos de `CERTWATCH_UCMDB_MIN_CIS` registos, para que uma resposta truncada não desative o inventário.
- Toda a ação humana (aceitar risco, adicionar endpoint, pedir job) fica registada na auditoria.
- **A base de dados é um mapa da superfície TLS da organização**: o volume `pgdata` e os backups devem ser tratados como sensíveis.

---

## 5. Operação

```bash
docker compose logs --tail 100 worker                     # o que o worker está a fazer
docker compose exec worker python -m certwatch.cli run scan
docker compose exec db pg_dump -U certwatch certwatch | gzip > backup-$(date +%F).sql.gz
docker compose down          # parar (os dados ficam no volume pgdata)
```

Atualizar: substituir o código, depois `docker compose build && docker compose up -d`.

---

## 6. Desenvolvimento e testes

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt pytest
pytest -q                                                   # SQLite
CERTWATCH_TEST_DATABASE_URL=postgresql+psycopg://certwatch@127.0.0.1:55432/certwatch pytest -q
```

Os testes levantam servidores TLS reais em localhost com uma PKI de teste (chain válida, intermédia em falta, autoassinado, raiz desconhecida, expirado, SHA-1 + RSA 1024, sem resposta) e uma UCMDB simulada.

---

## 7. Servidor sem acesso à internet

Fazer o build numa máquina com acesso e transferir a imagem:

```bash
docker compose build && docker save certwatch:0.1.0 postgres:16-alpine | gzip > certwatch-images.tar.gz
# no servidor:
gunzip -c certwatch-images.tar.gz | docker load && docker compose up -d --no-build
```

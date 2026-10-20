# certwatch 0.4

Aplicação autónoma de gestão de certificados X.509 de uma organização. Não depende do n8n.

**O que faz:**
1. Importa os certificados da UCMDB por REST API (TQL configurável). Da CMDB usa **apenas** CommonName, ValidTo e Issuer/IssuerName.
2. Liga-se por TLS a cada endpoint e observa o certificado **realmente servido**: chain completa, validação contra as CAs confiáveis (públicas e raízes internas), hostname, algoritmos, chave e protocolo.
3. Cruza a CMDB com a realidade e gera alertas com ciclo de vida (aberto → aceite com prazo → resolvido automaticamente).
4. Importa a lista de APIs e segredos da UCMDB (opcional): nome, aplicação, data de expiração, "expirado?", localização e data de registo, sem nunca importar os segredos em si.
5. Classifica cada certificado por tipo (Hostname, Wildcard, IP, API, CA, outro) e âmbito (interno/externo).
6. Mostra a árvore de certificados (raiz → intermédias → certificados finais) e uma aba de testes por camada, com o que significa cada falha e como corrigir.
7. Procura na internet (Certificate Transparency: crt.sh, Cert Spotter, ctlogs.dev) os certificados emitidos para os domínios da organização e mostra os que não estão na CMDB, para triagem.
8. Reconcilia ficheiros de exportação da CA1, CA2, AVI e Azure AD colocados numa diretoria com a CMDB: certificados e segredos novos, datas alteradas e registos em falta.
9. Identifica os certificados com renovação automática (Let's Encrypt) e só alerta quando a renovação falhou.
10. Pede (opcional) ao Qualys SSL Labs a nota A+–F dos nomes externos, vista a partir da internet.

Fora desta versão: tickets ITSM, escrita na UCMDB, email.

---

## 1. Instalação no servidor de testes

Requisitos: Docker com o plugin `compose`, e acesso a `docker.io` e PyPI para o build. Se o servidor não tiver acesso, ver a secção 12.

```bash
sudo git clone https://github.com/ricardodomingues10/certs-watch.git /opt/certwatch
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
S='secrets/db_password secrets/ucmdb_user secrets/ucmdb_password secrets/admin_password'
sudo chown 10001:10001 $S && sudo chmod 400 $S     # o contentor corre como UID 10001
```

Use uma **conta de serviço UCMDB só de leitura**, não uma conta pessoal nem `sysadmin`. Para fazer `printf` de uma password com plicas, use `read -rs P; printf '%s' "$P" > secrets/ucmdb_password; unset P`.

### 1.2 Confiança TLS (raízes internas)

A aplicação valida o TLS da UCMDB e dos endpoints internos contra as raízes colocadas em `trust/`. Nunca usa `-k`.

```bash
mkdir -p trust
# Ver a chain que a UCMDB apresenta (não é validada; serve só para identificar a raiz)
docker compose run --rm --no-deps worker python -m certwatch.cli trust-fetch cmdb.exemplo.local:8443 > /tmp/cmdb-chain.pem
```

**Para que serve:** os certificados internos (da UCMDB e dos servidores internos) são emitidos pela CA interna da organização, que nenhum sistema operativo conhece. Sem a raiz dessa CA em `trust/`, a aplicação não consegue confirmar que fala com a UCMDB verdadeira e marca todos os certificados internos como "cadeia não confiável". Com a raiz, a ligação à UCMDB é verificada e o teste "Cadeia completa e confiável" passa a distinguir uma cadeia interna correta de uma partida ou falsa. É só o certificado público da raiz: não contém chaves privadas.

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

A navegação lateral está agrupada por tarefa: **Inventário** (o que existe), **Verificação** (o que está bem ou mal), **Descoberta** (o que existe e ninguém registou) e **Operação**. A caixa no topo procura em tudo.

| Página | Para que serve |
|---|---|
| Painel | Quantos certificados há, quantos falham, por tipo e âmbito, expirações dos próximos 12 meses, testes com mais falhas |
| Certificados | Inventário com estado, tipo, âmbito, situação em linguagem simples, prazo e **renovação automática** (Let's Encrypt). Filtros por tudo isto e exportação CSV |
| Detalhe | Todos os testes do servidor por camada, com **o que significa e como corrigir** cada falha; cadeia; registos CMDB; alertas |
| Testes | Resumo de cada teste, notas externas do SSL Labs e matriz servidor × teste; clicar num teste mostra os servidores com problemas e a correção |
| Como testamos | Explicação de cada teste, de como é feito e de como se corrige |
| Árvore | Raízes → intermédias → certificados finais, com onde cada um está instalado e quantos registos CMDB indicam cada CA |
| APIs e segredos | Lista de APIs da CMDB: aplicação, localização, expiração, "Expirado?" (e se está desatualizado), registo; vistas e CSV |
| Na internet | Certificados públicos dos domínios da organização, comparados com a CMDB; decidir adicionar, investigar ou ignorar; exportar CSV |
| Reconciliação | Exportações CA1/CA2/AVI comparadas com a CMDB e com o servidor, e Azure comparado com a lista de APIs; CSV |
| Alertas | Lista filtrável; **aceitar risco** (justificação obrigatória e prazo até 1 ano) ou reabrir |
| Endpoints | Alvos de verificação; adicionar endpoints manuais (ex.: servidores que usam um wildcard) |
| Jobs | Executar jobs, histórico de execuções e auditoria |

API só de leitura (mesma autenticação): `GET /api/inventario`, `GET /api/testes`, `GET /api/findings?status=aberto|aceite|resolvido`.

---

## 3. Lista de APIs e segredos (opcional)

A lista "API secrets" da CMDB descreve sobretudo segredos de aplicações (client secrets de App Registrations do Azure AD). Campos usados: **Display Label, Aplicação, Data de expiração, Expirado?, Localização, Data de registo na CMDB** e, se existir, um URL.

1. Definir `CERTWATCH_UCMDB_TQL_APIS=NOME_DO_TQL` no `.env`, `docker compose up -d`, e **Importar lista agora** na página APIs.
2. A página mostra que atributo foi usado para cada campo e quantas datas foram reconhecidas. As datas podem vir em ISO, DD-MM-AAAA HH:MM:SS ou epoch.
3. Se algum campo estiver errado, ver os nomes internos dos atributos e defini-los no `.env` (`CERTWATCH_APIS_FIELD_NAME`, `_APP`, `_EXPIRY`, `_EXPIRED`, `_LOCATION`, `_REGISTERED`, `_URL`):
   ```bash
   docker compose exec worker python -m certwatch.cli inspect-tql NOME_DO_TQL
   ```

Atributos com nomes como *secret*, *password*, *token* ou *key* só são guardados quando o nome descreve o segredo (data, tipo, localização, estado) e o valor é uma data, um sim/não ou um texto curto legível. Segredos expirados há mais de 30 dias dão um alerta de limpeza de gravidade baixa; os que estão a expirar seguem os prazos normais.

## 4. Procura na internet (Certificate Transparency)

As autoridades públicas são obrigadas a publicar todos os certificados que emitem em registos abertos. O certwatch consulta três serviços gratuitos para os domínios em `CERTWATCH_CT_DOMAINS` (vários separados por vírgulas, ex.: `exemplo.pt,exemplo.com`; os subdomínios são incluídos) e funde os resultados pelo número de série ou pela validade e nomes, porque cada fonte escreve o emissor de forma diferente:

| Fonte | Sem chave | Notas |
|---|---|---|
| crt.sh (Sectigo) | sim | Histórico completo; por vezes lento ou indisponível |
| Cert Spotter (SSLMate) | sim, com limite horário | Sem chave é para uso pessoal ou de avaliação; para produção, chave no segredo `certspotter_api_key` |
| ctlogs.dev | 100 pedidos/hora | Últimos 90 dias sem chave; chave opcional no segredo `ctlogs_api_key` |

Cada certificado encontrado fica numa de três situações: **nome não existe na CMDB**, **nome existe mas este certificado não** (renovação não registada, segundo certificado ou outra CA) e **já na CMDB**. Os dois primeiros ficam *por triar* até alguém decidir: adicionar à CMDB, investigar ou ignorar (com motivo). A lista "Adicionar à CMDB" exporta-se em CSV.

O servidor precisa de saída HTTPS para estes três serviços. Para testar a partir do servidor:

```bash
docker compose exec worker python -m certwatch.cli ct-test exemplo.pt
```

Se a saída for por proxy, acrescente `HTTPS_PROXY=http://proxy:porta` e `NO_PROXY=.local,10.0.0.0/8` (ajustado) ao `.env`.

SSL Shopper e SSL Labs não servem para descoberta: não procuram certificados, avaliam um nome que já se conhece. O SSL Shopper não tem API; o SSL Labs está integrado como avaliação externa (secção 6).

## 5. Reconciliação com exportações

Copie os ficheiros exportados para a diretoria `import/` da aplicação. O início do nome indica a fonte (`CERTWATCH_IMPORT_SOURCES`, por omissão `ca1*`, `ca2*`, `avi*` e `azure*`). São aceites CSV (UTF-8, UTF-16 do certutil, Windows-1252; vírgula, ponto e vírgula ou tabulação) e Excel `.xlsx`.

- Colunas reconhecidas: as do certutil (`Issued Common Name`, `Certificate Expiration Date`, `Serial Number`, `Request Disposition`) e as do AVI (`Subject_CommonName`, `Validity_NotAfter`, `SerialNumber`, `Issuer_CommonName`, `SubjectAlternativeName`), mesmo com acentos estragados.
- Datas: DD/MM/AAAA (nunca trocadas por MM/DD), ISO, seriais do Excel e AAAAMMDD; o formato americano só é aceite com AM/PM explícito.
- Pedidos revogados ou não emitidos são ignorados; linhas com problemas aparecem na página com o número da linha.
- Em cada fonte é usado o ficheiro mais recente; um ficheiro igual ao anterior não é lido de novo.

**Azure AD** (`azure*.csv`, colunas `EnterpriseApplication;AppRegistration;AppId;CredentialType;KeyId;StartDate;EndDate;DaysRemaining;Status`): cada credencial (Secret ou Certificate) é comparada com a lista de APIs da CMDB pelo nome da App Registration (sem o sufixo de identificador que a CMDB às vezes acrescenta) e pela data de fim. Segredos da CMDB com localização "AzureAD…" que não aparecem na exportação ficam como **só na CMDB**.

Resultados: **novo** (não existe na CMDB), **data mais recente** (renovado; atualizar a CMDB), **data mais antiga** (confirmar no servidor), **só na CMDB** (quando `CERTWATCH_IMPORT_ISSUERS` diz qual é o emissor de cada CA) e **igual**. Quando o servidor foi verificado, a data que ele apresenta é mostrada ao lado para desempatar.

## 6. Renovação automática e avaliação externa

**Renovação automática.** Um certificado é marcado como renovado automaticamente quando o Issuer ou o IssuerName da CMDB, ou o emissor visto no servidor, é Let's Encrypt: pelo nome (`Let's Encrypt`, `ISRG`) ou pelo CN das intermédias (`R3`, `R10`, `R11`, `E5`, `E6`…), que muitas vezes é o único texto no campo. Estes certificados duram 90 dias e são renovados pelo servidor a cerca de 30 dias do fim, por isso o aviso dos 90 dias seria ruído: só há alerta quando faltam `CERTWATCH_AUTO_RENEW_ALERT_DAYS` dias ou menos (20 por omissão), o que significa que a renovação falhou. Os padrões ajustam-se em `CERTWATCH_AUTO_RENEW_ISSUERS`.

**SSL Labs (opcional).** Dá a nota A+–F de cada nome externo, vista da internet (protocolos, cifras, cadeia, vulnerabilidades conhecidas). Complementa os testes do certwatch, que correm a partir da rede interna.

1. Registo único com um **email da organização** (a Qualys recusa Gmail, Hotmail, etc.):
   ```bash
   docker compose exec worker python -m certwatch.cli ssllabs-register --nome Nome --apelido Apelido --email nome@exemplo.pt --organizacao "Exemplo"
   ```
2. `CERTWATCH_SSLLABS_EMAIL=nome@exemplo.pt` no `.env` e `docker compose up -d`.
3. Testar um nome: `docker compose exec worker python -m certwatch.cli ssllabs-test www.exemplo.pt`.

Na execução diária são avaliados até `CERTWATCH_SSLLABS_MAX_HOSTS` nomes externos (não wildcards nem IPs), um de cada vez, com resultados em cache de 24 h, sem publicar na lista pública, e cada nome é reavaliado a cada `CERTWATCH_SSLLABS_MAX_AGE_DAYS` dias. Cada avaliação demora 1 a 2 minutos; o tempo total está limitado a `CERTWATCH_SSLLABS_BUDGET_MIN` minutos e o que ficar por fazer passa para o dia seguinte. As notas aparecem em **Testes** e no detalhe de cada certificado.

**Termos da Qualys:** o uso é gratuito para testar a própria infraestrutura; o uso comercial (por exemplo, incluir a avaliação num produto vendido) exige autorização expressa da Qualys, e os resultados não podem ser publicados sem autorização do dono do site.

## 7. Classificação

- **Tipo**: API (está na lista de APIs) · Wildcard · Endereço IP · Hostname · Autoridade (CA) · Outro.
- **Âmbito**: interno se o nome termina num sufixo de `CERTWATCH_INTERNAL_SUFFIXES`, se o IP (ou o IP para onde o nome resolve) é privado, ou se o emissor contém um padrão de `CERTWATCH_INTERNAL_ISSUER_PATTERNS`. Os restantes nomes são externos.
- **Estado**: Falha (alerta alto ou crítico) · Atenção (alerta médio ou baixo) · OK (verificado sem alertas) · Por verificar · Só CMDB (sem servidor para testar, ex.: CAs).

## 8. Regras (alertas)

| Tipo | Severidade | Quando |
|---|---|---|
| `EXPIRACAO` | crítica ≤ 7 d (ou expirado) · alta ≤ 20 d · média ≤ 30 d · baixa ≤ 90 d; sobe para média se restar ≤ 20% da vida. Renovação automática: só a partir de 20 d | Data **live** se o endpoint respondeu; senão, data da CMDB |
| `CMDB_REGISTO_EXPIRADO` | baixa | Registo expirado há mais de 30 dias e ainda ativo na CMDB (sem endpoint que o confirme) |
| `RENOVACAO_NAO_INSTALADA` | alta | A CMDB tem uma data posterior à do certificado servido: renovou-se mas não foi instalado |
| `RENOVADO_NAO_REFLETIDO` | baixa | O endpoint serve um certificado mais recente do que o da CMDB |
| `ISSUER_DIVERGENTE` | média | O emissor servido não corresponde a nenhum emissor registado na CMDB para esse CN |
| `NAO_REGISTADO_CMDB` | baixa | Um servidor (API ou manual) usa um certificado que não está na CMDB |
| `API_EXPIRACAO` | como `EXPIRACAO` | O segredo registado na lista de APIs está a terminar |
| `API_REGISTO_EXPIRADO` | baixa | Segredo expirado há mais de 30 dias ainda na lista (limpeza no Azure e na CMDB) |
| `SSLLABS_NOTA` | média (B, M) · alta (C–F, T) | Nota externa do SSL Labs abaixo de A- |
| `API_SEM_TLS` | alta | A API está publicada em `http://` |
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

## 9. Segurança da própria aplicação

- A interface escuta só em localhost; o acesso é por túnel SSH. Autenticação HTTP Basic, proteção CSRF (cookie `SameSite=Strict` + token), CSP restritiva, `X-Frame-Options: DENY` e redirecionamentos apenas para caminhos locais.
- Os segredos ficam em ficheiros montados (`/run/secrets`), nunca em variáveis de ambiente nem no código.
- Os contentores correm como UID 10001, com filesystem só de leitura, `cap_drop: ALL` e `no-new-privileges`.
- O TLS para a UCMDB é sempre verificado contra o trust store.
- Os dados da CMDB são tratados como não confiáveis: só hostnames e IPs válidos e portas da allowlist são alvos. Nenhum valor passa por uma shell.
- A ingestão é abortada se a UCMDB devolver menos de `CERTWATCH_UCMDB_MIN_CIS` registos, para que uma resposta truncada não desative o inventário.
- Toda a ação humana (aceitar risco, decidir sobre um certificado encontrado na internet, adicionar servidor, pedir execução) fica registada na auditoria.
- As exportações CSV protegem contra injeção de fórmulas no Excel.
- A diretoria de importação é montada só de leitura.
- **A base de dados é um mapa da superfície TLS da organização**: o volume `pgdata` e os backups devem ser tratados como sensíveis.

---

## 10. Operação

```bash
docker compose logs --tail 100 worker                     # o que o worker está a fazer
docker compose exec worker python -m certwatch.cli run scan
docker compose exec db pg_dump -U certwatch certwatch | gzip > backup-$(date +%F).sql.gz
docker compose down          # parar (os dados ficam no volume pgdata)
```

Atualizar: `git pull && docker compose up -d --build`. O esquema da base de dados é atualizado sozinho no arranque.

---

## 11. Desenvolvimento e testes

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt pytest
pytest -q                                                   # SQLite
CERTWATCH_TEST_DATABASE_URL=postgresql+psycopg://certwatch@127.0.0.1:55432/certwatch pytest -q
```

Os testes levantam servidores TLS reais em localhost com uma PKI de teste (chain válida, intermédia em falta, autoassinado, raiz desconhecida, expirado, SHA-1 + RSA 1024, sem resposta) e uma UCMDB simulada.

---

## 12. Servidor sem acesso à internet

Fazer o build numa máquina com acesso e transferir a imagem:

```bash
docker compose build && docker save certwatch:0.4.0 postgres:16-alpine | gzip > certwatch-images.tar.gz
# no servidor:
gunzip -c certwatch-images.tar.gz | docker load && docker compose up -d --no-build
```

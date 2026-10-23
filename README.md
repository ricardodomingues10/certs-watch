# certwatch 0.11

Aplicação autónoma de gestão de certificados X.509 de uma organização. Não depende do n8n.

**O que faz:**
1. Importa os certificados da UCMDB por REST API (TQL configurável). Da CMDB usa **apenas** CommonName, ValidTo e Issuer/IssuerName.
2. Liga-se por TLS a cada endpoint e observa o certificado **realmente servido**: chain completa, validação contra as CAs confiáveis (públicas e raízes internas), hostname, algoritmos, chave e protocolo.
3. Cruza a CMDB com a realidade e gera alertas com ciclo de vida (aberto → aceite com prazo → resolvido automaticamente).
4. Importa a lista de APIs e segredos da UCMDB (opcional): nome, aplicação, data de expiração, "expirado?", localização e data de registo, sem nunca importar os segredos em si.
5. Classifica cada certificado por tipo (Hostname, Wildcard, IP, API, CA, outro) e âmbito (interno/externo).
6. Mostra uma aba de testes por camada, com o que significa cada falha e como corrigir.
7. Procura na internet (Certificate Transparency: crt.sh, Cert Spotter, ctlogs.dev) os certificados emitidos para os domínios da organização e mostra os que não estão na CMDB, para triagem.
8. Reconcilia ficheiros de exportação da CA1, CA2, AVI e Azure AD colocados numa diretoria com a CMDB: certificados e segredos novos, datas alteradas e registos em falta.
9. Identifica os certificados com renovação automática (Let's Encrypt) e só alerta quando a renovação falhou.
10. Pede (opcional) ao Qualys SSL Labs a nota A+–F dos nomes externos, vista a partir da internet.
11. Lê (opcional) os pedidos de certificados do SMAX e mostra, para cada certificado, o número do pedido com link para o SMAX.
12. Cria (opcional) pedidos de renovação no SMAX para um certificado, para os selecionados ou para todos os de uma vista filtrada, com revisão e confirmação.
13. Distingue o **site** (onde está instalado) do **certificado** (o que se renova): um wildcard ou um certificado com vários nomes pode servir muitos sites, e os pedidos são sempre feitos para o certificado.
14. **Atualiza a CMDB** com a lógica do workflow n8n de reconciliação: lê a CMDB pela API e as exportações CA1, CA2 e AVI, mostra as diferenças, aplica as escolhidas diretamente na UCMDB pela REST API e deixa descarregar o `CMDB_Final.xlsx`, o `certs_update.csv` e o `certs_update_sem_cabecalho.csv`.
15. **Acompanha cada pedido SMAX até ao fim**: comentários com imagens e anexos, percurso da renovação (pedido → renovado → instalado → CMDB atualizada → fechado), registo da renovação, fechar e reabrir o pedido no SMAX.
16. **Envia o relatório por email**: alertas e reconciliação com o Excel, com intervalo, prazo de alerta e destinatários à escolha.

Fora desta versão: escrita direta na UCMDB pela API (a atualização é feita pela integração que lê os ficheiros), email.

---

## 1. Instalação no servidor de testes

Requisitos: Docker com o plugin `compose`, e acesso a `docker.io` e PyPI para o build. Se o servidor não tiver acesso, ver a secção 13.

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
touch secrets/smax_user secrets/smax_password                   # preencher só se usar o SMAX (secção 7)
openssl rand -base64 18 | tr -d '\n' > secrets/admin_password   # login da interface (utilizador: admin)
S='secrets/db_password secrets/ucmdb_user secrets/ucmdb_password secrets/admin_password secrets/smax_user secrets/smax_password'
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

A interface ocupa a largura toda do ecrã e adapta-se a qualquer tamanho. Cada tabela ajusta-se ao espaço que tem: se não couber, escondem-se primeiro as colunas secundárias e, se ainda não couber, cada linha passa a cartão com os campos em grelha. No telemóvel há menu no botão do canto e cartões com o nome de cada campo à esquerda. A matriz de testes desliza na horizontal, com o nome sempre visível. A navegação lateral está agrupada por tarefa: **Inventário** (o que existe), **Verificação** (o que está bem ou mal), **Descoberta** (o que existe e ninguém registou) e **Operação**. A caixa no topo procura em tudo.

| Página | Para que serve |
|---|---|
| Painel | Frase de estado, o que fazer hoje (agir, rever), renovações com e sem pedido SMAX, certificados em falha, expirações dos próximos 12 meses, testes com mais falhas |
| Certificados | Inventário com estado, tipo, âmbito, situação em linguagem simples, prazo e **renovação automática** (Let's Encrypt). Filtros por tudo isto e exportação CSV |
| Detalhe | Todos os testes do servidor por camada, com **o que significa e como corrigir** cada falha; cadeia; registos CMDB; alertas |
| Testes | Resumo de cada teste, notas externas do SSL Labs e matriz servidor × teste; clicar num teste mostra os servidores com problemas e a correção |
| Como testamos | Explicação de cada teste, de como é feito e de como se corrige |
| APIs e segredos | Lista de APIs da CMDB: aplicação, localização, expiração, "Expirado?" (e se está desatualizado), registo; vistas e CSV |
| Na internet | Certificados públicos dos domínios da organização, comparados com a CMDB; decidir adicionar, investigar ou ignorar; exportar CSV |
| Reconciliação | Exportações CA1/CA2/AVI comparadas com a CMDB e com o servidor, e Azure comparado com a lista de APIs; CSV |
| Alertas | Lista filtrável; **aceitar risco** (justificação obrigatória e prazo até 1 ano) ou reabrir |
| Servidores | Alvos de verificação; adicionar servidores à mão (ex.: os que usam um wildcard) |
| Jobs | Executar jobs, histórico de execuções e auditoria |

API só de leitura (mesma autenticação): `GET /api/inventario`, `GET /api/testes`, `GET /api/findings?status=aberto|aceite|resolvido`.

---

## 3. Lista de APIs e segredos (opcional)

A lista "API secrets" da CMDB descreve sobretudo segredos de aplicações (client secrets de App Registrations do Azure AD). Campos usados: **Display Label, Aplicação, Data de expiração, Expirado?, Localização, Data de registo na CMDB** e, se existir, um URL.

1. Definir `CERTWATCH_UCMDB_TQL_APIS=NOME_DO_TQL` no `.env`, `docker compose up -d`, e **Importar lista agora** na página APIs.
2. **Se o layout do TQL só trouxer o nome** (caso comum: as colunas da vista não passam para a REST API), a aplicação vai buscar os atributos sozinha, sem ser preciso mexer no TQL (`CERTWATCH_APIS_ENRICH=auto`):
   - lê um CI com `GET /rest-api/dataModel/ci/{id}` para saber que atributos existem;
   - pede esses atributos para todos os CIs numa consulta ad-hoc, `POST /rest-api/topologyQuery` (exige a permissão "executar consultas por definição");
   - se essa consulta não for permitida, lê CI a CI com `GET /rest-api/dataModel/ci/{id}`.
   Os atributos sensíveis são descartados em memória e nunca são guardados.
3. **Alternativa sem REST:** exportar a lista da CMDB (CSV, TSV ou Excel, com os cabeçalhos `[API secrets] : Display Label`, `Aplicação`, `Data de expiração`, `Expirado?`, `Localização`, `Data de registo na CMDB`) e gravá-la em `import/api-cmdb.csv`. O ficheiro é usado quando a REST falha ou não traz datas de expiração (prefixo configurável em `CERTWATCH_APIS_FILE`).
4. A página mostra a origem dos dados, que atributo foi usado para cada campo e quantas datas foram reconhecidas. As datas podem vir em ISO, DD-MM-AAAA HH:MM:SS ou epoch. Para ver tudo o que a REST devolve (sem valores sensíveis):
   ```bash
   docker compose exec worker python -m certwatch.cli inspect-tql NOME_DO_TQL
   ```
   Se algum campo ficar errado, defina-o no `.env` (`CERTWATCH_APIS_FIELD_NAME`, `_APP`, `_EXPIRY`, `_EXPIRED`, `_LOCATION`, `_REGISTERED`, `_URL`).

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

**Azure AD** (`azure*.csv`, colunas `EnterpriseApplication;AppRegistration;AppId;CredentialType;KeyId;StartDate;EndDate;DaysRemaining;Status`): cada credencial (Secret ou Certificate) é procurada **nas duas listas da CMDB**, a lista de APIs e os certificados, pelo nome da App Registration ou da Enterprise Application (sem o sufixo de identificador que a CMDB às vezes acrescenta) e pela data de fim. A página e o CSV indicam em que lista foi encontrada. Segredos da CMDB com localização "AzureAD…" que não aparecem na exportação ficam como **só na CMDB**.

Resultados: **novo** (não existe na CMDB), **data mais recente** (renovado; atualizar a CMDB), **data mais antiga** (confirmar no servidor), **só na CMDB** (quando `CERTWATCH_IMPORT_ISSUERS` diz qual é o emissor de cada CA) e **igual**. Quando o servidor foi verificado, a data que ele apresenta é mostrada ao lado para desempatar.

## 5.1 Atualizar a CMDB (CMDB_Final e certs_update)

Página **Atualizar a CMDB**. Faz o mesmo que o workflow n8n "Reconciliação de Certificados", com cliques:

1. **Fontes**: CA1, CA2 e AVI (`CERTWATCH_FINAL_SOURCES`). Usa o ficheiro mais recente de cada fonte, seja o da diretoria `import/` (mesmos prefixos da reconciliação) ou o carregado na página. Entram também os **certificados encontrados na internet** (`CERTWATCH_FINAL_CT=true`), como fonte `INTERNET`, depois do AVI:
   - por nome, só o mais recente ainda válido;
   - o emissor e o número de série são os do certificado;
   - os marcados "Ignorar" na triagem ficam de fora.
2. **Gerar ficheiros**: lê a CMDB pela REST API (o TQL de `CERTWATCH_UCMDB_TQL`) com **todos** os atributos e aplica as regras do workflow. A página mostra o resultado: alterações (antes → depois), certificados novos, decisões da verificação no servidor e relatório de erros.
3. **Escolher o que entra**: no separador **Alterações**, cada alteração tem uma caixa **Incluir**.
   - Ao excluir uma linha nova, ela sai do Excel e dos CSV; ao excluir uma linha alterada, ela volta ao que está na CMDB.
   - "Guardar seleção" refaz os três ficheiros e volta a validá-los. Excluir um certificado novo sem emissor desbloqueia os CSV.
   - A escolha fica guardada para as gerações seguintes (mesmo CommonName e mesma nova data).
   - Por omissão, as alterações vindas da internet só vêm incluídas se o certificado estiver marcado "Adicionar à CMDB" na página **Na internet**.
3a. **Na comparação com a CMDB** de uma geração, as linhas novas ou alteradas também têm a caixa **Incluir**. Desmarcar e guardar refaz os ficheiros dessa geração.
4. **Aplicar na UCMDB**: cria e atualiza os certificados pela REST API (ver "Escrever diretamente na UCMDB"). Os ficheiros continuam disponíveis para descarregar.
5. **Comparar com a CMDB**: compara um CMDB_Final (de uma geração ou um carregado, incluindo o do n8n) com a CMDB atual, linha a linha, pelo Global Id ou, nas linhas novas, pelo CommonName. Mostra as diferenças de data de validade (ao dia), Issuer e IssuerName. Antes de aplicar, mostra o que vai mudar; depois, o que ficou por aplicar.

**Regras**: são as do workflow.
- Datas ao dia, sem trocar dia e mês.
- Procura pelo CommonName. Se o CommonName estiver vazio, usa Name, Display Label ou Hostname, e o CommonName é preenchido na mesma linha.
- Ficam de fora:
  - linhas sem CommonName;
  - datas ilegíveis;
  - pedidos não emitidos;
  - certificados expirados;
  - nomes sem domínio.
- Linhas da CMDB que já existem: são atualizados ValidTo e SerialNumber na linha de data mais próxima.
- Certificados novos: linha com `Global Id = x`, com o emissor de `CERTWATCH_IMPORT_ISSUERS` para CA1/CA2 ou o `Issuer_CommonName` no AVI.
- **Linhas novas** (`Global Id = x`): Issuer e IssuerName vão sempre preenchidos, porque IssuerName + SerialNumber é a chave primária do certificado na CMDB. O emissor e a série que faltem procuram-se primeiro noutra fonte com o mesmo certificado (mesmo nome e mesma data de fim) e depois nos certificados já vistos pelo certwatch nos servidores ou na internet (mesmo nome, data de fim com ±1 dia). Sem emissor em lado nenhum: Issuer e IssuerName `Por verificar`. Certificado encontrado na internet sem série: SerialNumber `x1`, `x2`… numerados a seguir ao maior `xN` que já exista na CMDB, para que cada um tenha a sua chave IssuerName + SerialNumber e nunca coincida com um CI que já lá está. Nos ficheiros (CA1/CA2/AVI) a série vem sempre; se faltar, a linha fica fora dos CSV por omissão (pode incluí-la, mas então os CSV ficam bloqueados). Numa linha que já existe e cujo certificado mudou (outra data de fim) sem que nenhuma fonte traga a série nova, o SerialNumber também passa a `x<n>`: a série antiga já não é a do certificado e, mantida, repetia a chave noutras linhas (o workflow deixava-a vazia). Com a mesma data, a série fica como está. A geração avisa quantos ficaram assim, com o filtro "Só com dados por confirmar".
- Fonte com data anterior à CMDB: decide o certificado apresentado na porta 443.
- A Description regista o que mudou, a começar por "Changed with n8n" (`CERTWATCH_FINAL_DESCRIPTION`).
- Os CSV levam só o delta, sempre com estas 26 colunas, por esta ordem: Display Label, ValidTo, Aplicação, Localização, Responsabilidade de instalação, Certificate Status, Certificado Gerido, Ambiente, Name, CommonName, Issuer, IssuerName, SerialNumber, Certificate Type, IsSelfSigned, Global Id, Link para a Documentação, Subject Alternative Names, Organization, Version, Type, Subject, CreateOn, Hostname, Description, OrganizationUnit. Separador `|`, CRLF, UTF-8 sem BOM. Uma coluna que não exista na CMDB vai vazia, mas vai.
- **Chave repetida**: alterações com o mesmo `IssuerName + SerialNumber` ficam de fora por omissão, marcadas "chave repetida" com o nome e o Global Id da outra linha, para se escolher qual entra; a pesquisa da lista também procura pelo SerialNumber. Se mais de uma for incluída, os CSV são recusados (como no workflow), com os nomes e Global Ids na mensagem. Nesse caso o Excel continua disponível. Linhas novas com o mesmo par por causa de `Por verificar` (mesma série, emissor desconhecido) não bloqueiam, mas são avisadas: se a UCMDB usar o par como chave, podem ficar num só CI.
- O Excel não leva as colunas Created By, Created Time e Is Candidate For Deletion. Cores: verde para linhas novas, amarelo para alteradas, vermelho para expiradas.

**Diferenças em relação ao workflow**:
- A verificação no servidor usa o scan do certwatch, se tiver menos de `CERTWATCH_FINAL_LIVE_MAX_AGE_H` horas, ou uma ligação na hora, em vez do OpenSSL. A Description diz "Validado via TLS" (`CERTWATCH_FINAL_LIVE_MARKER`).
- Uma data vazia na fonte vai para o relatório de erros.
- ValidTo e SerialNumber só contam como alterados se mudarem de facto: mesmo dia, ou mesmo número escrito de outra forma, não conta.
- Emissor em falta numa linha nova: `Por verificar`; série em falta num certificado da internet: `x1`, `x2`…; em vez de bloquear os CSV (ver acima).

Com os mesmos dados (e todos os emissores e séries presentes), os ficheiros gerados são iguais byte a byte aos do workflow.

**Emissores das CAs**: os ficheiros do certutil não trazem o emissor. Para os certificados novos de CA1/CA2 não ficarem com `Por verificar`, defina-o no `.env` com o texto usado pelo workflow: `CERTWATCH_IMPORT_ISSUERS=CA1=<nome da CA01>;CA2=<nome da CA02>`.

**Colunas**: os atributos da UCMDB passam a colunas com os cabeçalhos do export (`[Digital Certificate] : CommonName`). Se o layout do TQL só tiver alguns atributos, os restantes são pedidos à REST API (`CERTWATCH_FINAL_ENRICH=auto`). A correspondência atributo → coluna é automática (`issuer_name` → IssuerName, `responsabilidade_instalacao` → Responsabilidade de instalação). Para corrigir: na geração, separador **Colunas**, descarregue o modelo `cmdb-colunas.csv`, ajuste-o e coloque-o em `import/`. Em cada linha fica `atributo;coluna`; a coluna vazia exclui o atributo e a ordem das linhas é a ordem das colunas.

### Permissões da conta na UCMDB

Em **Atualizar a CMDB → Permissões na UCMDB** verifica-se o que a conta configurada (segredo `ucmdb_user`) consegue fazer pela REST API:
- **Leitura** (não muda nada): `POST /rest-api/authenticate`, execução de cada TQL configurado (`POST /rest-api/topology`) e leitura de um CI completo (`GET /rest-api/dataModel/ci/{id}`).
- **Escrita** (só com confirmação, num certificado escolhido): `PUT /rest-api/dataModel/ci/{id}` com a Description (ou o Display Label) igual ao valor que já tem. A UCMDB verifica a permissão de atualização, mas nenhum valor muda. Criar (`POST /rest-api/dataModel`) e apagar (`DELETE /rest-api/dataModel/ci/{id}`) não são testados, porque o único teste seria criar ou apagar um CI de verdade.

- **Criação** (dois passos, com confirmação):
  1. **Descobrir o atributo de estado** (só leitura): os atributos do certificado com "status/estado/ativo" no nome, ou com o valor "Ativo", com o valor que têm na lista dos ativos e quantos certificados há com cada valor.
  2. **Criar o certificado de teste**: `POST /rest-api/dataModel` com um certificado **não ativo** (o valor escolhido), nome `certwatch-teste-<código>.invalid`, emissor e série de teste únicos e a Description a dizer que é um teste. Depois lê-o, confirma que não aparece no TQL dos ativos e apaga-o (`DELETE`), o que também testa a permissão de apagar. Só apaga se foi mesmo criado agora (está em `addedCis` e a Description é a do teste). Para o ver na UCMDB antes de desaparecer, desmarque "Apagar no fim": a página mostra o nome e o ID e um botão para o apagar depois. Em "Apagar um certificado de teste que ficou na UCMDB" apaga-se pelo ID, mas só CIs com o nome `certwatch-teste-….invalid` e a Description do teste.

Cada verificação fica na auditoria (`ucmdb.permissoes`, `ucmdb.teste_criacao`), sem credenciais.

### Escrever diretamente na UCMDB

Com `CERTWATCH_UCMDB_WRITE=true` no `.env`, a aplicação cria e atualiza os certificados na UCMDB pela REST API, com a mesma conta da leitura.

**A partir de uma geração** (Atualizar a CMDB → geração → Alterações → **Aplicar na UCMDB**):
1. **Um certificado:** botão **Aplicar** na linha. Linha nova → `POST /rest-api/dataModel` (cria). Linha alterada → `PUT /rest-api/dataModel/ci/{id}` só com os campos que mudaram (ValidTo, SerialNumber, Issuer, IssuerName, Description…).
2. **Todos:** **Aplicar todas na UCMDB** aplica as alterações incluídas que ainda não foram aplicadas, uma a uma, em segundo plano; a página mostra o progresso.

Cada linha mostra o resultado (criado / atualizado / aviso / erro / não aplicado) e o ID do CI. Uma alteração já aplicada não é enviada de novo.

**Editar um certificado** (Atualizar a CMDB → **Editar um certificado**, ou **Editar na UCMDB** na página do certificado): procura-se pelo CommonName, Global Id ou ID do CI; os valores são lidos na hora da UCMDB. Muda-se o que for preciso (data, emissor, série, estado, Description…), **Rever alterações** mostra o antes e o depois e **Gravar na UCMDB** envia só esses campos. Por omissão a Description regista a alteração ("Changed with n8n - Data de expiracao alterado de … para …").

**Proteções:**
- Só se escrevem estes campos: Display Label, Name, CommonName, ValidTo, Localização, Certificate Status, SerialNumber, Issuer, IssuerName, Subject Alternative Names, Certificate Type e Description. Nunca o Global Id nem datas de criação.
- Antes de atualizar, o CI é lido e os campos a mudar têm de ter ainda o valor da geração (ou o que estava no ecrã ao rever). Se alguém os mudou entretanto, não se escreve e a linha diz o que mudou.
- Depois de escrever, o CI é lido de novo e confirma-se que ficou o que foi enviado; se não, a linha fica com aviso.
- Se a UCMDB identificar um certificado "novo" como um CI que já existia (regra de identificação), a linha fica com aviso a dizer qual.
- Só a geração mais recente pode ser aplicada.
- Datas: ValidTo vai às 00:00 de Lisboa, primeiro como `AAAA-MM-DDThh:mm:ss` (sem fuso: a UCMDB recusa o `Z` do UTC); se a UCMDB recusar o formato, tenta com milissegundos (`.000`), depois em milissegundos desde 1970 e por fim em UTC. O formato que funcionar passa a ser o primeiro a tentar. Uma alteração com erro pode ser repetida com **Tentar de novo**.
- Tudo fica em **Execuções e auditoria → Alterações na UCMDB**: quando, quem, origem (geração ou edição à mão), certificado, CI, cada campo com o valor que tinha e o que foi enviado, o resultado e se foi confirmado na UCMDB. **Exportar todas (CSV)** dá o histórico completo, uma linha por campo. A auditoria também regista cada escrita (`ucmdb.escrever`, `ucmdb.editar`).

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

## 7. Pedidos no SMAX

A aplicação lê os pedidos (changes) de certificados do SMAX e liga-os a cada certificado pelo **endpoint** e pela **data de expiração** do certificado a renovar, guardados nos campos personalizados do pedido (`UserOptions`). Não cria nem altera pedidos.

1. Conta de serviço SMAX só de leitura nos segredos `secrets/smax_user` e `secrets/smax_password` (dono 10001, modo 400).
2. No `.env`: `CERTWATCH_SMAX_URL`, `CERTWATCH_SMAX_TENANT`, `CERTWATCH_SMAX_FILTER` (o modelo de change dos certificados) e os nomes dos campos personalizados `CERTWATCH_SMAX_FIELD_*`.
3. `docker compose up -d`; a leitura corre na execução diária ou em **Execuções → Ler pedidos do SMAX**.

Situações de cada certificado:

| Situação | Significa |
|---|---|
| Pedido em curso | Há um pedido aberto com o mesmo endpoint e a mesma data de expiração |
| Pedido aberto para outra data | Há um pedido aberto para o nome, mas para outro certificado (anterior por fechar, ou data errada no pedido) |
| Só pedidos fechados | Já houve pedidos, todos fechados |
| Sem pedido | Nenhum pedido para o nome; destacado a vermelho quando faltam 30 dias ou menos |

Onde aparece: coluna **Pedido SMAX** em Certificados (filtro "Sem pedido em curso", pesquisa pelo número do pedido, exportação CSV com o link), secção **Pedidos no SMAX** no topo do detalhe de cada certificado (todos os pedidos, abertos e fechados), e no Painel ("expiram em 30 dias … destes sem pedido em curso" e coluna Pedido em "Precisam de ação"). O número do pedido abre o SMAX (`CERTWATCH_SMAX_TICKET_URL`).

### 7.0 Página Pedidos SMAX

Todos os pedidos lidos, ligados ao certificado ou à API a que se referem, com separadores: **abertos**, **abertos com certificado já expirado** (a data de expiração do pedido já passou), **abertos com fim planeado ultrapassado**, **com comentários**, **fechados**. Para os pedidos abertos são lidos os comentários (`GET /rest/{tenant}/collaboration/comments/{entidade}/{id}`, sem os do sistema), com autor e data, porque muitas vezes os técnicos comentam sem mudar o estado; o link abre a discussão no SMAX. Os pedidos de APIs são ligados pelo nome (o "endpoint" do pedido é o nome da API) e aparecem na página APIs. Se os pedidos das APIs usarem outro modelo de change, alargar `CERTWATCH_SMAX_FILTER`, por exemplo `(BasedOnChangeModel = '111' or BasedOnChangeModel = '222')`.

### 7.1 Criar pedidos de renovação

Ligar com `CERTWATCH_SMAX_CREATE_ENABLED=true` e os valores do modelo de change (`CERTWATCH_SMAX_CHANGE_MODEL`, `CERTWATCH_SMAX_SERVICE`, `CERTWATCH_SMAX_DATA_DOMAINS`, ver `.env.example`). A conta SMAX tem de poder criar changes nesse modelo.

1. **Escolher**: em Certificados, marcar os certificados (ou "Preparar para os N desta vista", que usa os filtros ativos), ou no detalhe de um certificado "Preparar pedido de renovação". Máximo `CERTWATCH_SMAX_CREATE_MAX` por lote.
2. **Preencher**: a CMDB só dá nome, validade e emissor; o lote pede ambiente, tipo de certificado, Application ID, responsabilidade de instalação e localização. Os valores são sugeridos a partir do último pedido do mesmo certificado (criado aqui ou já existente no SMAX), do âmbito e dos valores por omissão, e cada sugestão diz de onde vem. "Valores para todos" preenche o lote de uma vez. Ficam desmarcados à partida os certificados com pedido em curso e os de renovação automática.
3. **Rever**: título e payload exatos de cada pedido.
4. **Confirmar**: só com a caixa de confirmação e o número de pedidos certo. Depois:
   - o lote passa a "A criar" numa única operação na base de dados, por isso um duplo clique ou dois utilizadores não criam pedidos repetidos;
   - os pedidos do SMAX são relidos e são postos de lado os certificados que entretanto ganharam um pedido em curso, ou que já tiveram um pedido criado ou indeterminado noutro lote;
   - os pedidos são criados um de cada vez (`POST /rest/{tenant}/ems/bulk`) e o lote para no primeiro erro;
   - **indeterminado** (erro 5xx, tempo esgotado, resposta inesperada) nunca é repetido automaticamente: o pedido pode ter sido criado e tem de ser verificado no SMAX;
   - "Novo lote com os que falharam" repete apenas os que falharam ou não foram tentados.

Tudo fica na auditoria (quem criou, confirmou e cada pedido criado). As respostas do SMAX guardadas nunca incluem o token de sessão.

## 7.2 Sites e certificados

Um site (`adfs.exemplo.pt:443`) serve um certificado de cada vez; um certificado (um wildcard `*.exemplo.pt` ou um certificado com vários nomes) pode estar em muitos sites. A aplicação sabe qual é pelo que cada servidor apresenta na verificação.

- **Detalhe de um site** servido por outro certificado: aviso no topo ("Este site usa o certificado `*.exemplo.pt`… também instalado em…"). Se a CMDB tem um registo com o nome do site e a **mesma data**, é um registo "por site" desse certificado; com **outra data**, está desatualizado ou há um certificado próprio por instalar.
- **Detalhe de um certificado**: "Onde está instalado", com a versão (SHA-256) servida em cada site; versões diferentes indicam uma renovação por instalar em alguns sites.
- **Certificados**: "servido por …" e "instalado em N sites"; filtro "Próprio ou partilhado".
- **Pedidos**: escolher um site gera o pedido para o certificado que ele serve; vários sites do mesmo certificado dão um só pedido; a descrição lista os sites.
- Um site sem registo próprio na CMDB é comparado com os registos do certificado que serve; os alertas de expiração da CMDB de um certificado que já é visto nos sites são substituídos pelos alertas da verificação.
- Para descobrir onde estão os wildcards, a aplicação verifica os nomes encontrados na internet (`CERTWATCH_CT_SCAN`): só nomes concretos dos domínios configurados, de certificados ainda válidos; os que não respondem são desligados sem alerta e não aparecem no inventário.

## 7.3 Página do pedido: comentários, percurso da renovação, fechar e reabrir

Em **Pedidos SMAX**, o número do pedido abre a página do pedido. O link "SMAX ↗" continua a abrir o SMAX. A lista pode ser filtrada por pedido, por fase e pela data do último comentário (de/até, ou "sem comentários"), e ordenada pelo comentário mais recente.

**Comentários com imagens.** Em cada leitura do SMAX são guardadas as imagens coladas nos comentários (prints) e os anexos dos comentários, para se verem na aplicação.
- Só são pedidos ao próprio SMAX os caminhos do repositório de ficheiros (`/rest/<tenant>/frs/…` e `/ces/attachment/<id>`). Imagens noutros servidores nunca são descarregadas.
- Só PNG, JPEG, GIF, WebP e BMP são mostrados como imagem, e o tipo é verificado pelo conteúdo. O resto (PDF…) é descarregado como anexo.
- Limites: até 10 MB por ficheiro e `CERTWATCH_SMAX_FILES_MAX` ficheiros novos por leitura.

**Percurso da renovação.** Cinco passos, cada um feito quando há prova:
1. **Pedido aberto.**
2. **Certificado renovado.** Fica feito quando há uma validade mais recente do que a do pedido, numa destas fontes:
   - uma renovação registada aqui;
   - o certificado que o servidor apresenta;
   - a CMDB;
   - a internet (CT).

   Para registar a renovação, há três formas:
   - usar o certificado que o servidor apresenta (o certwatch liga-se na hora);
   - carregar o ficheiro do certificado (`.cer`, `.crt`, `.pem`, `.der`);
   - indicar à mão a nova data (por exemplo, a partir do print num comentário).
3. **Instalado no servidor.** Fica feito quando todos os servidores verificados apresentam o certificado novo. Use **Verificar agora** para os verificar logo. Para servidores que o certwatch não vê, a instalação pode ser confirmada à mão, com uma nota.
4. **CMDB atualizada.** A renovação registada entra como fonte `RENOVACAO` na próxima geração de **Atualizar a CMDB**. Se veio do servidor ou do ficheiro, atualiza também o emissor. O passo fica feito quando a alteração é aplicada na UCMDB ou quando a CMDB lida pelo certwatch mostra a nova data. Até lá, a página diz em que reconciliação está e se já foi aplicada.
5. **Pedido fechado.** O botão **Fechar no SMAX** faz um `bulk UPDATE` com `CERTWATCH_SMAX_CLOSE_FIELDS` (por omissão `{"PhaseId": "Close"}`):
   - pode escrever um comentário no pedido, antes de fechar;
   - depois o pedido é lido de novo para confirmar a fase;
   - se o modelo de change exigir outros campos para fechar, o motivo do SMAX aparece na página; acrescente esses campos ao JSON;
   - **Reabrir** usa `CERTWATCH_SMAX_REOPEN_FIELDS`.

   Fica ativo com `CERTWATCH_SMAX_UPDATE_ENABLED=true`. Todas as ações ficam em **Execuções e auditoria**.

## 7.4 Relatório por email

Página **Relatório por email**. Escolhe-se:
- **o intervalo**: certificados que expiram de X a Y dias, contados até à validade efetiva (a do servidor quando verificado, senão a da CMDB);
- **o prazo de alerta**: N dias ou menos;
- **os certificados a retirar**, se houver.

Depois pré-visualiza-se e envia-se:
- **Alertas**: caixa de alerta com os certificados a N dias ou menos (com os dias restantes) e as tabelas dos internos e externos do intervalo. As tabelas têm as colunas CommonName, ValidTo, Alteração (pedido aberto, vários pedidos ou sem pedido ativo) e Renovação automática.
- **Reconciliação**: os certificados cujo servidor já apresenta uma validade posterior à da CMDB, com o Excel `Certificados_<Y>_Dias.xlsx` em anexo. O Excel tem a análise de cada certificado: validades, pedidos e Estado_Analise.
- **Certificados novos na internet, para aprovação**: os certificados encontrados na internet (Certificate Transparency) nos últimos N dias que não estão na CMDB e não foram ignorados na triagem. Ficam separados em "nome desconhecido" e "nome já na CMDB, com outro certificado". O email pede à equipa de Sistemas que aprove ou não o registo de cada um e leva em anexo `Certificados_Internet.xlsx`, com uma coluna "Aprovado (Sim/Não)" para preencher.
- **Várias partes**: num só email ou um email por parte.

**Editar os emails.** Cada email aparece na página tal como vai ser enviado. Em **Editar este email** escreve-se e apaga-se diretamente no email, como num documento:
- **Mudar texto:** clicar e escrever. Também se muda o assunto. Há botões de negrito e itálico.
- **Tirar uma linha de uma tabela:** tocar na linha (ou apontar com o rato) e carregar no ✕ vermelho. Também se pode selecionar várias linhas e carregar em Delete. Se todas as linhas de uma tabela saírem, a tabela sai também.
- **Tirar uma coluna:** clicar numa célula da coluna e carregar em **Apagar a coluna**.
- **Desfazer** (ou Ctrl+Z) volta atrás. **Guardar o email** grava; a pré-visualização e o envio passam a usar exatamente esse texto. **Voltar ao email gerado** descarta as alterações.
- A saudação e o fecho são os mesmos nos três emails.
- O texto editado fica como está, mesmo que os dados mudem. O anexo Excel não muda: para tirar um certificado também do Excel, usa-se **Retirar certificados do email e do Excel**.
- Segurança: o email editado passa por uma lista de permissões antes de ser guardado e enviado (só texto, tabelas e estilos simples; sem scripts, imagens, links ou eventos). As alterações ficam na auditoria (`relatorio.editar_email`).

**Texto por omissão (modelo).** Em **Texto por omissão dos emails** muda-se o texto base que a aplicação gera para todos os relatórios: assuntos, saudação, parágrafos, fecho e assinatura, com variáveis entre chavetas (`{n_alerta}`, `{alerta}`, `{janela}`, `{desde}`, `{ate}`, `{n_internos}`, `{n_externos}`, `{n_renovados}`, `{n_internet}`, `{periodo}`, `{data}`, `{saudacao}`, `{assinatura}`). Guarda-se só para o relatório ou como modelo para os próximos.

Configuração no `.env`: `CERTWATCH_SMTP_HOST`, `_PORT`, `_SECURITY` (starttls/ssl/none), `_FROM` e `_USER`. A password vai no segredo `secrets/smtp_password`. Este ficheiro tem de existir, nem que seja vazio (`touch secrets/smtp_password`). `CERTWATCH_REPORT_ALLOWED_DOMAINS` limita os destinatários aos domínios da organização. Os envios ficam registados no relatório e na auditoria.

## 8. Classificação

- **Tipo**: API (está na lista de APIs) · Wildcard · Endereço IP · Hostname · Autoridade (CA) · Outro.
- **Âmbito**: interno se o nome termina num sufixo de `CERTWATCH_INTERNAL_SUFFIXES`, se o IP (ou o IP para onde o nome resolve) é privado, ou se o emissor contém um padrão de `CERTWATCH_INTERNAL_ISSUER_PATTERNS`. Os restantes nomes são externos.
- **Estado**: Falha (alerta alto ou crítico) · Atenção (alerta médio ou baixo) · OK (verificado sem alertas) · Por verificar · Só CMDB (sem servidor para testar, ex.: CAs).

## 9. Regras (alertas)

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

## 10. Segurança da própria aplicação

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

## 11. Operação

```bash
docker compose logs --tail 100 worker                     # o que o worker está a fazer
docker compose exec worker python -m certwatch.cli run scan
docker compose exec db pg_dump -U certwatch certwatch | gzip > backup-$(date +%F).sql.gz
docker compose down          # parar (os dados ficam no volume pgdata)
```

Atualizar: `git pull && docker compose up -d --build`. O esquema da base de dados é atualizado sozinho no arranque.

---

## 12. Desenvolvimento e testes

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt pytest
pytest -q                                                   # SQLite
CERTWATCH_TEST_DATABASE_URL=postgresql+psycopg://certwatch@127.0.0.1:55432/certwatch pytest -q
```

Os testes levantam servidores TLS reais em localhost com uma PKI de teste (chain válida, intermédia em falta, autoassinado, raiz desconhecida, expirado, SHA-1 + RSA 1024, sem resposta) e uma UCMDB simulada.

---

## 13. Servidor sem acesso à internet

Fazer o build numa máquina com acesso e transferir a imagem:

```bash
docker compose build && docker save certwatch:0.8.0 postgres:16-alpine | gzip > certwatch-images.tar.gz
# no servidor:
gunzip -c certwatch-images.tar.gz | docker load && docker compose up -d --no-build
```

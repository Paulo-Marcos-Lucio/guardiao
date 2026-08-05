# Changelog

Todos os lançamentos notáveis deste projeto são documentados aqui.
O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e
[Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [0.5.0] — 2026-08-05

### Corrigido — calibração anti-falso-positivo (medição de campo 2026-08-05)

Bateria contra repositórios reais fixados por commit (`encode/httpx@b5addb6`, `psf/requests`,
`pallets/flask`) expôs **regressão de falso-positivo** — 25 achados no `httpx`, todos falsos, contra
0 do gitleaks no mesmo alvo. A adjudicação manual revelou que **não eram 25 defeitos, mas 3 CLASSES**;
cada uma foi fechada com um invariante travado por teste property-based (Hypothesis), não por remendo:

- **Identificador de código tratado como segredo.** `cert_encrypted_private_key_file` virava achado de
  entropia porque a palavra `encrypted` tem uma corrida de 6 consoantes (`ncrypt`). `looks_like_secret_token`
  agora rejeita tokens que se decompõem em sub-palavras legíveis (snake_case/kebab/camelCase). Invariante:
  *identificador de código nunca é token de segredo* (`test_identificador_de_codigo_nunca_e_segredo`).
- **Binário lido como texto.** `requests-logo.ai` (Adobe Illustrator, cabeçalho PostScript ASCII, sem NUL
  nos primeiros 8 KiB) era lido como texto e o corpo rendia entropia. `decode_text_bytes` passa a reconhecer
  **assinaturas de contêiner binário** (PDF, PostScript, PNG, ZIP, ELF, gzip…) além da heurística de NUL.
  Invariante: *arquivo com assinatura binária nunca é lido como texto* (`test_assinatura_binaria_...`).
- **Fixture de parser de URL / valor URL-encoded tratado como credencial.** A suíte de conformidade WHATWG
  (`http://user:pass@/`, `http://&a:foo@d:2/`) e `"password": "%F0%9F%92%A9"` viravam achados. `basic-auth-url`
  ganhou validador que exige host de forma de domínio **e** senha de aparência real; `looks_like_secret_value`
  ignora valores predominantemente URL-encoded; e o motor deixa de tratar como *path* uma `/` interna a um
  base64 entre aspas (`opaque="FQhe/qaU…"`) — distinguindo-a do caminho real `/_internal/<seg>/…` (o F-007).

Efeito medido: **httpx 25 → 4** (os 4 restantes são heurísticas corretamente rebaixadas a `low` em arquivos de
teste), **as 4 chaves TLS privadas reais do `psf/requests` continuam detectadas**, e o **recall do corpus
`bench/` permanece 13/14 (0 FP)**. Nenhum falso-negativo introduzido.

### Removido

- Arquivo-lixo `6.100` (0 bytes) versionado por engano na raiz — resíduo de um `pip install "hypothesis>=6.100"`
  sem aspas no PowerShell (o `>` criou o arquivo). Removido do controle de versão.

### ⚠️ Mudanças que quebram compatibilidade

- **Contrato JSON (`suite-appsec/1`).** O relatório JSON passa a declarar
  `"schema": "suite-appsec/1"` no topo, a chave do identificador do achado mudou de
  `rule` para **`id`**, e cada achado ganhou `severity_rank` (inteiro). `by_severity`
  agora traz **sempre** as cinco severidades, inclusive zeradas — um dashboard deixa
  de precisar tratar chave ausente. Alinha as quatro ferramentas Python da suíte.
- **Fingerprint.** A *fingerprint* publicada em SARIF, JSON e baseline passou a ser
  derivada de `(regra, arquivo, valor ocultado)` em vez de `(regra, arquivo, segredo
  cru)`. Consequência prática: **os valores mudam**, então o primeiro `upload-sarif`
  após a atualização reabre os alertas do Code Scanning e o baseline existente precisa
  ser regravado com `--update-baseline`. O namespace `guardiaoSecretHash/v1` foi
  mantido de propósito.
- **Regra de entropia sem teto de comprimento.** A contagem de achados pode subir em
  bases com blobs base64 longos versionados; o baseline de cliente muda junto.
- **Rótulos OWASP migrados para o Top 10:2025.** `A05:2021 Security Misconfiguration`
  virou `A02:2025`, `A02:2021 Cryptographic Failures` virou `A04:2025`, e as regras de
  supply chain (`npm-token`, `huggingface-token`) foram de `A08:2021` para
  `A03:2025 Software Supply Chain Failures`. O dado antigo não estava *errado* (cada
  rótulo carregava o próprio ano), mas era incoerente com a Sentinela — e `A03`
  significa coisas opostas nas duas edições.
- **Comando `rules` renomeado para `regras`** (`rules` continua funcionando como alias).

### Corrigido

- **Falso-negativo silencioso: diretório excluído sumia do relatório.** `vendor/`,
  `dist/`, `node_modules/` e virtualenvs eram pulados sem entrar em `summary.skipped`:
  um token real versionado em `vendor/` produzia `✓ Nenhum segredo encontrado` com
  **todos os contadores zerados** e exit 0 — enquanto o mesmo arquivo em stage
  bloqueava o commit pelo hook. O motivo `diretorio` passa a existir e é reportado
  **sempre**, mesmo zerado, no console e no JSON.
- **Vazamento no artefato publicado: 8 caracteres em claro.** O baseline (feito para
  ser **commitado**) e o SARIF (que sobe para o Code Scanning) usavam a mesma
  ocultação do console — 4 caracteres de cada ponta, ou seja 8 em claro de qualquer
  segredo com 13+. Numa senha humana de 16 é metade dela. Esses dois destinos passam a
  mostrar **2 por ponta**; console e JSON seguem em 4. A nota do baseline, que
  afirmava que os valores "não permitem recuperar o segredo", foi reescrita para
  descrever o fragmento que o arquivo de fato carrega.
- **Falso-negativo: blob órfão perdia as regras por nome de arquivo.** Um `.env`
  "removido" com `commit --amend` — o cenário-assinatura da varredura de histórico —
  voltava "nenhum segredo encontrado": o blob solto recebe caminho sintético, e
  `dotenv-assignment` (regra `only_files`) era descartada por não casar nome. Sem
  caminho recuperável, a decisão passa a ser por **conteúdo**.
- **`--git-history` num clone não declarava o que não alcançou.** `git clone`/`fetch`
  transferem só objetos alcançáveis: blob de `--amend`, rebase, branch deletado e
  stash ficam na origem (medido em auditoria: 7 achados no original → 2 no clone,
  exit 0, sem aviso). O relatório passa a **declarar o limite** —
  `summary.coverage_warnings` no JSON, `properties.coverageWarnings` no SARIF — sem
  falhar: limite conhecido do protocolo do Git não é motivo para travar o CI.
- **Segredo cru podia sair no traceback.** O piso `typer>=0.12` permitia a 0.12.5, cujo
  `pretty_exceptions_show_locals` vem ligado por padrão e imprime as variáveis locais
  do frame — incluindo o valor do segredo. Piso elevado para `typer>=0.16` **e**
  parâmetro passado explicitamente na construção do app.
- **Falso-negativo: chave de fornecedor engolida pelo filtro de placeholder.**
  `abcdefgh` e `1234567890` estavam em `PLACEHOLDER_SUBSTRINGS`, então qualquer valor
  que contivesse a sequência era descartado **em silêncio** — inclusive uma senha
  humana plausível como `Cliente1234567890`. As duas saíram; exemplo canônico por
  valor INTEIRO (`AKIAIOSFODNN7EXAMPLE`, `password123`) continua suprimido. O
  relatório passa a informar **quantos** valores foram descartados como placeholder.
- **Falso-negativo: `\b` não existe entre `_` e letra.** `DB_PASSWORD`, `JWT_SECRET`,
  `DJANGO_SECRET_KEY`, `SECRET_KEY` e `app_secret` **nunca** casaram `\bpassword\b` /
  `\bsecret\b`. A âncora virou fronteira por caractere alfanumérico, com um ramo
  camelCase (`dbPassword`, `secretKey`) que deliberadamente **exclui** `token` e `key`
  isolados — em código real `...Token` é sufixo de lexer/parser e era a origem de 48
  dos 79 falso-positivos medidos.
- **Falso-negativo: `.env` sem aspas.** Nova regra `dotenv-assignment` (severidade
  alta), restrita por **nome de arquivo** a `.env`, `.env.*`, `*.env` e `.envrc`
  (excluindo `*.example`/`*.sample`/`*.template`/`*.dist`). Pega
  `DB_PASSWORD=Brasil@2024` e `export JWT_SECRET=…`. Fora desses arquivos a regra não
  vale: `token = alguma_funcao()` é uma das linhas mais comuns que existem em código,
  e soltar o padrão no geral gerou **+1.319 falso-positivos** em 24.943 arquivos
  reais na medição.
- **Falso-negativo: segredo longo era menos visível que segredo curto.** O teto de
  120 caracteres do regex de entropia tornava invisíveis o `secret_key_base` do Rails
  (128 hex), `openssl rand -hex 64` e `token_urlsafe(128)`. O teto real de custo já é
  o `--max-line-length`.
- **Entropia: critério length-aware.** O estimador plug-in de Shannon é enviesado para
  baixo em cadeias curtas (não pode passar de `log2(n)`), então comparar contra um
  limiar absoluto de 4,3 bits/char rejeitava **61%** dos segredos aleatórios de 24
  caracteres — e **97%** dos de 24 caracteres alfanuméricos minúsculos. O critério
  passou a ser **Miller-Madow ≥ 0,80 · log2(|alfabeto|)**. Medido sobre 5.992 segredos
  aleatórios × 12.206 cadeias de 24+ chars extraídas de código real: recall
  **85,3% → 94,9%** e falso-positivo **282 → 239**. Ganha nos dois eixos — não é troca.
- **Entropia: `NOME=VALOR` capturado como se fosse o segredo.** O `=` estava dentro do
  corpo do regex, então o achado apontava para o par inteiro: a coluna vinha errada e
  o "Trecho (ocultado)" escondia o **nome da variável** e revelava o fim do segredo.
- **Entropia não distingue hash de segredo.** MD5 (32 hex) e SHA-256 (64 hex) são tão
  aleatórios quanto uma chave; `is_probable_hash_or_id` só conhecia UUID e SHA-1 de 40.
  Novo **contexto negativo**: linha que fala em `md5`/`etag`/`integrity`/`checksum`/
  `digest` desliga a regra de entropia. É heurística, e está declarado como tal.
- **CPF/CNPJ sem dígito verificador.** Qualquer número formatado virava "dado pessoal
  (LGPD)", incluindo `000.000.000-00`. Agora há validação módulo 11 (`rules/br.py`) e
  os CPFs de tutorial (`123.456.789-09`, `111.444.777-35`) são tratados como exemplo.
  **Limitação declarada:** o CNPJ alfanumérico novo da Receita não é detectado.
- **`db-connection-uri` perdia a forma canônica do Redis/AMQP.** O regex exigia usuário
  não-vazio, e `redis://:senha@host` é exatamente como o redis-cli, o Sidekiq e o
  `REDIS_URL` do Heroku escrevem.
- **`--git-history` perdia o blob órfão.** Blob sem caminho em `rev-list --objects
  --all` era descartado — ou seja, exatamente o que sobra de um `commit --amend`,
  `rebase` ou `reset`, que é o cenário-assinatura da ferramenta. Agora é varrido e
  reportado como `<objeto solto …>`.
- **`--git-history` em clone raso.** `actions/checkout` clona raso por padrão; varrer
  "todo o histórico" nele é promessa falsa. Agora **falha fechado** (exit 2) com a
  instrução do `fetch-depth: 0`; `--permitir-shallow` é a saída explícita.
- **Exaustão de memória no histórico Git.** O limite de tamanho era conferido **depois**
  de o objeto inteiro estar na memória, e todo commit/tree também era materializado à
  toa: um blob de 100 MB virava 100 MB de RAM para ser descartado em seguida. O
  conteúdo que não interessa passa a ser descartado em fluxo, em blocos de 64 KB, com
  guarda de EOF. Pico medido: **12 MB → menos de 4 MB** com limite de 1 MB.
- **Varredura saía da árvore por *junction* do Windows.** `mklink /J` não exige
  administrador e **não** é symlink para o Python, então `entry.is_symlink()` não a
  barrava e a ferramenta lia e reportava arquivos de fora do diretório pedido. A
  checagem passou a ser de **contenção pelo caminho real**, correta nas três plataformas.
- **Injeção de markup do Rich.** Um arquivo contendo `[/]` derrubava o relatório de
  console com `MarkupError`, e `[black on black]` esconderia o próprio achado. Todo
  dado vindo do alvo é impresso como `Text`.
- **SARIF inválido: `tags` com item repetido.** 23 das 26 regras violavam
  `uniqueItems` do schema 2.1.0 (categoria `secret` emitida duas vezes).
- **`--only`/`--skip`/`--skip-category` com id inexistente saía com 0.** Um typo
  (`--only aws-acess-key-id`) devolvia "✓ Nenhum segredo encontrado" e exit 0 — o CI
  ficava verde para sempre. Agora aborta com **exit 2** listando os ids válidos.
  Caminho inexistente idem. Diretório onde nada era elegível continua saindo 0, com aviso.
- **Pulos silenciosos.** Arquivo acima do limite, lockfile, binário e linha longa eram
  descartados sem deixar rastro: três arquivos com chave `sk_live_` produziam "✓ Nenhum
  segredo encontrado" e exit 0. Agora há `summary.skipped` no JSON e no SARIF, aviso no
  console, e o tique verde só aparece quando **nada** foi pulado.
- **`pre-commit` e `scan` divergiam.** O hook instanciava `Scanner()` com `Config`
  padrão e lia direto de `git show`, sem `is_noise_file`/`max_file_size` — um
  `package-lock.json` que o CI considerava limpo bloqueava o commit. Os três comandos
  passam pelo mesmo `Scanner.scan_units`, e o `pre-commit` aceita
  `--baseline/--only/--skip/--skip-category/--no-entropy/--scan-lockfiles`.
- **Falso-positivo em virtualenvs de nome atípico:** a exclusão de diretórios era por nome exato
  (`.venv`/`venv`), então um venv chamado `.venv-locust` (ou `venv311`, `.env-ci`…) era varrido e o
  `site-packages` interno inundava o relatório com certificados/chaves de teste de bibliotecas.
  Agora **qualquer** virtualenv é reconhecido pelo marcador canônico `pyvenv.cfg` e `site-packages`
  entra na exclusão padrão. Em auditoria de campo real, cortou o ruído pela metade (ex.: **106 → 58
  achados, 0 em `venv`/`site-packages`**).

### Adicionado

- **Mensagens de commit e de tag anotada entram na varredura de `--git-history`.**
  Segredo colado em mensagem de commit é comum e nenhum `git rm` o alcança; o
  streaming descartava tudo que não fosse blob. Só a mensagem é lida — cabeçalho do
  objeto (autor, e-mail) fica de fora, para não encher o laudo de ruído e de PII.
- `summary.coverage_warnings` (JSON) e `properties.coverageWarnings` (SARIF): limites
  de **alcance** declarados pela fonte, distintos de `skipped` (o que foi pulado).
- `--max-file-size` e `--max-line-length` na CLI: sem elas não havia caminho de
  recuperação para `dump.sql` e `bundle.js`, que é exatamente onde credencial de
  produção costuma parar.
- `--permitir-shallow` para varrer histórico de clone raso conscientemente.
- Painel **"Plano de ação"** no relatório de console com os três piores achados e a
  **recomendação** de cada um — o campo `recommendation` existia e nunca era impresso.
  Rótulos de severidade em pt-BR na tela (o identificador em inglês continua no JSON).
- `owasp_edition` como campo próprio no JSON e nas `properties` do SARIF: um dashboard
  não deveria precisar fazer parsing da string do rótulo para saber a edição.
- `helpUri` (referência do CWE) em cada regra declarada no SARIF.
- `.github/dependabot.yml`: pinar action por SHA sem mecanismo de atualização é
  congelar a versão — inclusive a vulnerável.
- Portão de cobertura `--cov-fail-under=90` no `pyproject.toml` (medido hoje: 95%), e
  o CI passou a rodar literalmente `pytest`, o mesmo comando do desenvolvimento.
- Meta-teste **"toda regra do catálogo tem ao menos um caso positivo"**: um id novo
  nasce coberto ou o CI reprova. Fechou 8 regras órfãs, entre elas
  `aws-secret-access-key` e `stripe-secret-key`.
- Testes para as áreas em que o código de produção podia ser sabotado com a suíte
  verde: renderizador de console (imprimir o segredo cru), mapeamento SARIF de
  severidade, detecção de virtualenv por `pyvenv.cfg`, ramo hexadecimal da entropia,
  e as duas guardas do ramo de entropia isoladas uma da outra.
- Três novos detectores de provedores com formato público e documentado:
  **Shopify** (`shpat_`/`shpca_`/`shppa_` = access token e `shpss_` = shared secret,
  prefixo + 32 hex; acesso à Admin API da loja), **Doppler** personal token
  (`dp.pt.` + 43 base62 — chave-mestra de um gestor de segredos, severidade crítica) e
  **Linear** API key (`lin_api_` + 40 base62). Cada regra ancora no prefixo fixo do
  fornecedor (baixo falso-positivo) e tem teste positivo (token sintético realista) e
  negativo (uso benigno do prefixo, ex.: `shpat_`/`dp.pt.`/`lin_api_` sem o corpo do token).
- Três novos detectores de provedores com formato público e documentado:
  **Twilio** API Key SID (`SK` + 32 hex, 34 chars — REST API Key Resource),
  **DigitalOcean** access token (`dop_`/`doo_`/`dor_v1_` + 64 hex) e
  **Hugging Face** access token (`hf_`, risco de supply chain de ML). Cada regra
  ancora no prefixo fixo do fornecedor (baixo falso-positivo) e tem teste positivo
  (token sintético realista) e negativo (uso benigno do prefixo, ex.: `SKU-`, `hf_model_config`).
- Quatro novos detectores de provedores, todos com formato público e documentado:
  **Mercado Pago** access token (`APP_USR-<appid>-<data>-<hash>-<userid>`, crítico —
  atende ao item de roadmap de gateways de pagamento BR), **GitLab** PAT (`glpat-`),
  **npm** token (`npm_`, risco de supply chain) e **SendGrid** API key (`SG.`).
- O detector do Mercado Pago distingue o **access token** (segredo de backend) da
  **public key** de frontend: exige que o primeiro segmento seja numérico, evitando
  falso-positivo na chave pública. Cada regra tem teste positivo (token realista) e
  negativo (entrada benigna / chave pública).

### Removido

- `Rule.find`/`RuleMatch`: o invólucro Python custava mais que o próprio motor de
  regex. Medido em 462.871 linhas de código real × 27 regras: **7,04 s → 4,26 s**
  (−39,5%), com contagem de matches idêntica (13.644). O `Rule` volta a ser só o
  dataclass declarativo que o README promete.
- Código sem chamador: `is_git_repo`, `redact_preview`, `redact_line`,
  `Severity.from_name`, `rules_by_id` e `charset_of` (substituído por
  `tamanho_do_alfabeto`, que é o que o critério de entropia realmente usa).

## [0.1.0] — 2026-07-21

### Adicionado

- Motor de varredura por linha com 16 regras (chaves privadas, AWS, GitHub,
  Google, Slack, Stripe, JWT, URIs de banco, atribuições genéricas de alta
  entropia e PII/LGPD).
- Detecção por **entropia de Shannon** com limiares por alfabeto.
- Redução de falso-positivo: filtro de placeholder, allowlist inline
  (`# guardiao:allow`) e **baseline** para o CI falhar só em segredos novos.
- Varredura do **histórico Git** completo (`git rev-list --all`).
- Renderizadores **console**, **JSON** e **SARIF 2.1.0** — nenhum expõe o segredo cru.
- CLI `guardiao` com `scan`, `rules` e `pre-commit`.
- Suíte de testes (41 casos), tipos estritos (mypy) e CI multi-versão.

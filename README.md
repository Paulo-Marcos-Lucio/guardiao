<p align="center"><a href="README.en.md"><img src="https://img.shields.io/badge/🇺🇸-READ_IN_ENGLISH-B22234?style=for-the-badge&labelColor=3C3B6E" alt="Read this document in English"/></a></p>

<a href="https://paulo-marcos-lucio.github.io"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/guardiao/main/assets/banner-abismo-v2.svg" alt="Guardião — o escudo que guarda a fronteira do seu código: scanner de segredos no código e no histórico Git" width="100%"/></a>

<div align="center">

# 🔑 Guardião

### Encontra segredos vazados no seu código **e no histórico do Git** — antes que virem incidente.

*Chaves de API, tokens, senhas e chaves privadas commitados por engano são uma das causas mais comuns e mais baratas de vazamento. O Guardião varre a árvore atual **e todo o histórico**, oculta o segredo no relatório, entende baseline para o CI só falhar no que é novo, e exporta **SARIF** para o GitHub Code Scanning.*

[![CI](https://github.com/Paulo-Marcos-Lucio/guardiao/actions/workflows/ci.yml/badge.svg)](https://github.com/Paulo-Marcos-Lucio/guardiao/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Ruff](https://img.shields.io/badge/lint-ruff-261230.svg)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-2A6DB2.svg)](https://mypy-lang.org/)
[![OWASP](https://img.shields.io/badge/OWASP_Top_10-2025-000000.svg)](https://owasp.org/Top10/)
[![Tests](https://img.shields.io/badge/tests-186%20passing-brightgreen.svg)](#-qualidade-de-engenharia--método)
[![Coverage](https://img.shields.io/badge/coverage-95%25-green.svg)](#-qualidade-de-engenharia--método)

</div>

---

## 📌 O problema

Remover um segredo do código **não** o remove do repositório. Ele continua vivo em commits antigos — acessível a qualquer pessoa com acesso de leitura (ou ao mundo inteiro, se o repo for público). Por isso "apagar e commitar de novo" é uma falsa sensação de segurança: **uma vez commitado, um segredo deve ser considerado comprometido e rotacionado.**

O Guardião foi feito para os dois momentos:

- **Preventivo** — como hook de *pre-commit*, ele barra o segredo **antes** de entrar no histórico.
- **Investigativo** — varre **todo o histórico** (`git rev-list --all`) para achar o que já foi commitado e esquecido.

> **Ângulo LGPD.** Além de credenciais, o Guardião sinaliza **dados pessoais** (CPF/CNPJ) versionados em texto claro — exposição relevante para a **LGPD (art. 46)**. Gestão de segredos documentada é evidência de medida técnica de segurança.

---

## 🔎 O que ele detecta

> Os códigos abaixo são do **OWASP Top 10:2025**. Atenção: `A03` significa coisas
> diferentes em 2021 e em 2025 — por isso a edição está sempre declarada
> (`owasp_edition` no JSON e no SARIF, e no cabeçalho da coluna em `guardiao regras`).

| Regra | Detecta | Severidade | OWASP 2025 / CWE |
| --- | --- | --- | --- |
| `private-key` | Chave privada PEM/OpenSSH (RSA, EC, DSA, ENCRYPTED) | 🔴 Crítica | A04 · CWE-321 |
| `stripe-secret-key` | Chave de produção da Stripe (`sk_live`/`rk_live`) | 🔴 Crítica | A02 · CWE-798 |
| `aws-access-key-id` / `aws-secret-access-key` | Credenciais AWS | 🟠 Alta | A02 · CWE-798 |
| `github-token` / `github-pat-fine-grained` | Tokens do GitHub (PAT, OAuth, App) | 🟠 Alta | A07 · CWE-798 |
| `mercadopago-access-token` | Access token de produção do Mercado Pago (`APP_USR-…`) | 🔴 Crítica | A02 · CWE-798 |
| `google-api-key` | Chave de API do Google | 🟠 Alta | A02 · CWE-798 |
| `gitlab-pat` | Personal Access Token do GitLab (`glpat-`) | 🟠 Alta | A07 · CWE-798 |
| `npm-token` | Token de acesso do npm (`npm_`) — supply chain | 🟠 Alta | A03 · CWE-798 |
| `sendgrid-api-key` | Chave de API do SendGrid (`SG.`) | 🟠 Alta | A02 · CWE-798 |
| `twilio-api-key` | API Key SID do Twilio (`SK` + 32 hex) | 🟠 Alta | A02 · CWE-798 |
| `digitalocean-token` | Token de acesso da DigitalOcean (`dop_`/`doo_`/`dor_v1_`) | 🟠 Alta | A02 · CWE-798 |
| `huggingface-token` | Token de acesso do Hugging Face (`hf_`) — supply chain de ML | 🟠 Alta | A03 · CWE-798 |
| `shopify-token` | Access token / shared secret da Shopify (`shpat_`/`shpca_`/`shppa_`/`shpss_`) | 🟠 Alta | A02 · CWE-798 |
| `doppler-token` | Token pessoal do Doppler (`dp.pt.`) — gestor de segredos | 🔴 Crítica | A02 · CWE-798 |
| `linear-api-key` | Chave de API pessoal do Linear (`lin_api_`) | 🟠 Alta | A07 · CWE-798 |
| `slack-token` / `slack-webhook` | Token/Webhook do Slack | 🟠/🟡 | A02/A01 |
| `db-connection-uri` | URI de banco com `usuário:senha` (usuário pode ser vazio: `redis://:senha@host`) | 🟠 Alta | A02 · CWE-798 |
| `basic-auth-url` | Credencial embutida em URL | 🟡 Média | A07 · CWE-522 |
| `jwt` | JSON Web Token no código | 🟡 Média | A07 · CWE-522 |
| `dotenv-assignment` | Valor **sem aspas** atribuído a chave sensível em `.env`/`.envrc`/`*.env` | 🟠 Alta | A02 · CWE-798 |
| `generic-assignment` | Valor atribuído a chave sensível (`DB_PASSWORD`, `JWT_SECRET`, `apiKey`…) | 🟡 Média | A02 · CWE-798 |
| `high-entropy-string` | Cadeia aleatória de 24+ chars perto de contexto de segredo | 🟡 Média | A02 · CWE-798 |
| `cpf` / `cnpj` | Dado pessoal em texto claro, **com dígito verificador conferido** (**LGPD**) | 🔵 Baixa/Info | A04 · CWE-359 |

Cada achado traz **severidade**, **evidência ocultada**, **recomendação** (começando por *rotacionar*) e classificação **OWASP + CWE**.

> **O que foi medido, contra o quê, e com que margem.** Corpus rotulado versionado em
> [`bench/`](./bench) — 14 segredos plantados em formato de produção e 14 linhas-armadilha.
> Nesta versão (commit desta árvore, medido em 2026-08-04, Python 3.12/Windows):
> **recall 13/14 = 93% · IC95% [69% ; 99%] · zero falso-positivo** nas armadilhas.
> Rode você mesmo: `guardiao scan bench -f json -o r.json && python bench/avaliar.py r.json`.
>
> Isto é **laboratório, não campo**: os segredos foram plantados por mim, então o número
> mede cobertura de formato conhecido — não acurácia contra uma base arbitrária. Com n=14
> o intervalo é largo, e é por isso que ele está escrito aqui em vez de um número redondo.
> O único caso que escapa é um blob de alta entropia **sem contexto nenhum** — escolha
> deliberada, porque perseguir entropia solta é a maior fonte de ruído em código real.
>
> **Comparação honesta contra os incumbentes** (gitleaks, trufflehog): [`BENCHMARK.md`](./BENCHMARK.md)
> — reprodutível, versões e commits fixados, e diz **onde perdemos**. A recalibração de 2026-08-05
> derrubou o falso-positivo no `encode/httpx` de 25 para 4 (empatando com o gitleaks nas chaves reais
> do `psf/requests`), com o recall do corpus preservado.
>
> A calibração que produz esses números **está neste repositório**; não há motor secreto.
> Exemplo concreto do que ela corrigiu: a chave `sk_live_…` que por acaso contém a sequência
> `abcdefgh` **não é mais engolida** pelo filtro de placeholder — antes uma credencial
> CRÍTICA sumia em silêncio por coincidir com 8 letras de um exemplo de documentação.

### Como evita falso-positivo

- **Entropia com correção de viés.** O estimador de Shannon é enviesado para baixo em cadeias curtas (ele não pode passar de `log2(n)`), então comparar a um limiar fixo em bits/char cria falso-negativo dependente do comprimento. O critério usa **Miller-Madow** contra uma fração do máximo teórico do alfabeto do token. Medido em 5.992 segredos aleatórios × 12.206 cadeias reais extraídas de código: recall **85,3% → 94,9%** e falso-positivo **282 → 239** — ganha nos dois eixos.
- **Contexto obrigatório.** A regra de entropia só dispara perto de `token`/`secret`/`key`/`password`… — inclusive em `DB_PASSWORD` e `accessToken`, que a fronteira `\b` não cobre.
- **Contexto negativo.** Entropia **não** distingue hash de segredo (são matematicamente idênticos). Se a linha fala em `md5`/`etag`/`integrity`/`checksum`, o achado é descartado.
- **Dígito verificador** em CPF/CNPJ (módulo 11): `000.000.000-00` não é dado pessoal.
- **Filtro de placeholder**: descarta exemplos de documentação (`AKIAIOSFODNN7EXAMPLE`), `your-key-here`, `${VAR}`, valores repetidos. O relatório **informa quantos** valores foram descartados assim — a supressão é auditável, não silenciosa.
- **Allowlist inline**: uma linha com `# guardiao:allow` (ou `pragma: allowlist secret`) é ignorada.
- **Baseline**: aceita a dívida atual e passa a barrar só o que for **novo**.

### 🚧 Limitações conhecidas

Honestidade primeiro — o que esta ferramenta **não** faz:

- **Não valida a credencial.** Um `sk_live_` já revogado é reportado igual a um ativo.
- **Contexto negativo é heurística.** Um segredo numa linha que também contenha `checksum` ou `commit` é descartado junto com os hashes.
- **CNPJ alfanumérico** (formato novo da Receita, `AA.AAA.AAA/AAAA-DD`) **não** é detectado — só o numérico.
- **Segredo multilinha** (corpo de chave privada, JSON de service account) é detectado pelo cabeçalho, não pelo corpo: a varredura é linha a linha.
- **Não reescreve histórico.** Achar é metade; `git filter-repo` e a rotação são trabalho separado.
- **O que é pulado aparece no relatório** (`summary.skipped`): **diretório inteiro excluído** (`vendor/`, `dist/`, `node_modules/`, virtualenv), lockfile, binário, arquivo acima de `--max-file-size` e linha acima de `--max-line-length`. "Não olhei" e "olhei e está limpo" são saídas visualmente distintas.

---

## 🚀 Instalação

Requer **Python 3.10+**. Verifique com `python --version`.

### ⚡ Quickstart — do zero ao primeiro achado

```bash
# 1. instale a ferramenta (do repositório; veja o aviso de nome no PyPI abaixo)
pip install "git+https://github.com/Paulo-Marcos-Lucio/guardiao.git"

# 2. confirme que instalou
guardiao --version

# 3. rode contra o SEU projeto — árvore atual + TODO o histórico Git
guardiao scan . --git-history
```

O comando `guardiao` sai com **código 1** se encontrar algo de severidade ≥ `medium`
(o padrão) — é o que faz o CI falhar. Nada acima do limiar: código `0`.

> **Quer vê-lo pegar algo antes de apontar para o seu código?** Clone o repositório e
> rode contra o corpus de exemplo — 14 segredos plantados em formato de produção
> (chave privada, AWS, Stripe, GitHub, Slack, `.env`…), 13 com detecção garantida:
>
> ```bash
> git clone https://github.com/Paulo-Marcos-Lucio/guardiao.git
> cd guardiao
> python bench/gerar.py   # materializa os fixtures que não são versionados em claro
> guardiao scan bench     # ou: pip install -e ".[dev]" antes, se quiser rodar a suíte
> ```

### Formas de instalar

```bash
# isolado do resto do sistema (recomendado para uso como CLI) — pipx cuida do venv
pipx install "git+https://github.com/Paulo-Marcos-Lucio/guardiao.git"

# ou dentro de um venv que você mesmo criou
python -m venv .venv && . .venv/Scripts/activate   # Linux/macOS: source .venv/bin/activate
pip install "git+https://github.com/Paulo-Marcos-Lucio/guardiao.git"

# desenvolvimento (testes, lint, tipos)
git clone https://github.com/Paulo-Marcos-Lucio/guardiao.git
cd guardiao && pip install -e ".[dev]"
```

> ⚠️ **Não** existe pacote `guardiao` publicado por mim no PyPI. Se alguém publicar
> um pacote com esse nome, `pip install guardiao` traria código de terceiro para
> dentro do seu CI. Instale sempre por URL de repositório — e, em CI, **fixando o
> SHA do commit**, que é a única referência imutável:
>
> ```bash
> pip install "git+https://github.com/Paulo-Marcos-Lucio/guardiao.git@<sha-de-40-hex>"
> ```

---

## 🧑‍💻 Uso

```bash
# varre o diretório atual
guardiao scan .

# varre TODO o histórico Git (onde moram os segredos esquecidos)
guardiao scan . --git-history

# relatório SARIF para subir no GitHub Code Scanning
guardiao scan . -f sarif -o guardiao.sarif

# aceita a dívida atual como baseline...
guardiao scan . --update-baseline
# ...e a partir daí o CI só falha em segredos NOVOS
guardiao scan . --baseline .guardiao-baseline.json --fail-on high

# lista todas as regras
guardiao regras          # `guardiao rules` é alias
```

Principais opções do `scan`:

| Opção | Descrição |
| --- | --- |
| `-f, --format` | `console` (padrão), `json`, `sarif`. Repetível. |
| `-o, --output` | Arquivo de saída (para um formato de arquivo). |
| `--git-history` | Varre todos os blobs do histórico — inclusive objetos soltos (`--amend`/rebase) — **e as mensagens de commit e de tag anotada**, não só a árvore atual. |
| `--permitir-shallow` | Aceita rodar `--git-history` em clone raso (histórico incompleto). |
| `--baseline` / `--update-baseline` | Suprime achados conhecidos / (re)grava o baseline. |
| `--fail-on` | `none`/`info`/`low`/`medium`/`high`/`critical` — código de saída 1 para CI. |
| `--only` / `--skip` / `--skip-category` | Filtra regras ou categorias (ex.: `--skip-category pii`). |
| `--no-entropy` | Desliga a detecção por entropia. |
| `--scan-lockfiles` | Também varre lockfiles/minificados (pulados por padrão). |
| `--max-file-size` / `--max-line-length` | Tetos de varredura (padrão: 5 MB / 4.000 chars). |

### Códigos de saída

| Código | Significado |
| --- | --- |
| `0` | Varredura concluída; nada acima de `--fail-on`. |
| `1` | Achado de severidade ≥ `--fail-on`. |
| `2` | **Erro de uso**: id de regra/categoria inexistente, caminho inexistente, repositório sem Git, clone raso com `--git-history`. Nunca "verde silencioso". |

### `--fail-on` na suíte AppSec

O padrão **não** é o mesmo nas quatro ferramentas, e isso é decisão de projeto, não
descuido: a consequência de uma credencial vazada é categoricamente pior que a de um
cabeçalho HTTP ausente, então o scanner de segredos tem gatilho mais sensível.

| Ferramenta | Padrão de `--fail-on` | Por quê |
| --- | --- | --- |
| **Guardião** (segredos) | `medium` | `generic-assignment`, `high-entropy-string` e CPF/CNPJ (LGPD) vivem na faixa média — subir para `high` desligaria o gate justamente onde ele paga. |
| Chaveiro (JWT) | `high` | — |
| Esteira (CI/CD) | `high` | — |
| Sentinela (superfície web) | `alta` | — |

Precisa alinhar? Passe `--fail-on` explicitamente em todas — nunca confie no padrão numa receita de CI.

### Contrato do relatório JSON

Formato `suite-appsec/1`, igual nas quatro ferramentas: chaves e valores de enumeração
em inglês (são identificadores), texto para humano em pt-BR. `summary.by_severity` traz
**sempre** as cinco severidades, inclusive zeradas, e `summary.skipped` diz o que **não**
foi analisado. A chave do identificador do achado é `id`.

### Hook de pre-commit

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: guardiao
        name: Guardião (secret scan)
        entry: guardiao pre-commit
        language: system
        pass_filenames: false
```

### No GitHub Actions (com upload de SARIF)

```yaml
- uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
  with:
    fetch-depth: 0          # sem isto o --git-history só enxerga 1 commit
    persist-credentials: false
- run: pip install "git+https://github.com/Paulo-Marcos-Lucio/guardiao.git@<sha-de-40-hex>"
- run: guardiao scan . --git-history -f sarif -o guardiao.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@08d09a53f0f5d694f253bd25732e4429c9e9337f # v3
  if: always()
  with:
    sarif_file: guardiao.sarif
```

O `fetch-depth: 0` não é detalhe: o padrão do `actions/checkout` é clone **raso**, e
num clone raso `--git-history` só vê os commits baixados. O Guardião **aborta com
exit 2** nesse caso em vez de reportar sucesso (use `--permitir-shallow` se você
realmente quiser varrer o histórico parcial).

E mesmo com `fetch-depth: 0` **há um limite que nenhuma flag remove**: `git clone` e
`git fetch` transferem apenas objetos **alcançáveis**. O blob que sobrou de um
`commit --amend`, de um rebase, de um branch deletado ou de um stash existe só no
repositório de origem e **não chega ao runner** — é o esconderijo mais comum de
segredo. Rodando num clone, o Guardião **declara esse limite** no relatório
(`summary.coverage_warnings` no JSON, `properties.coverageWarnings` no SARIF) em vez
de entregar "0 achado" como se tivesse olhado tudo. Ele **não falha** por isso: um
limite conhecido do protocolo do Git não é motivo para travar o seu CI. Para alcance
total, rode a varredura no próprio repositório de origem.

---

## 🔓 Versão Pro (privada) — é SERVIÇO, não outro motor

Sendo direto, porque aqui a honestidade é o produto: **a ferramenta deste repo já é a engine calibrada,
e é a mais completa que existe.** Não há motor mais forte escondido no privado — nem versão melhor em
lugar nenhum. O que você roda de graça é exatamente o que eu rodo num contrato. O Pro não é outra
detecção; é **trabalho humano conduzido por mim** em cima desta engine:

| | **Ferramenta pública (você roda)** | **Pro / serviço (eu conduzo com você)** |
| --- | --- | --- |
| **Motor de detecção** | Esta engine — recall 13/14 no corpus de [`bench/`](./bench), zero falso-positivo | **A mesma engine, sem uma linha a mais.** O que você paga é a condução, não o motor |
| **Escopo** | O caminho ou repositório que você aponta | **A organização inteira**: todos os repositórios e **todo o histórico Git**, não só o `HEAD` |
| **Triagem** | Você lê o relatório e adjudica cada achado | Eu **trio cada achado** como verdadeiro ou falso-positivo e entrego a lista já limpa — sem despejar ruído no time |
| **Rotação** | A ferramenta acha; rotacionar é com você (ela *não* rotaciona) | **Plano de rotação por provedor**, passo a passo, + **reteste que comprova** que a credencial saiu de circulação |
| **Evidência (LGPD art. 46)** | JSON/SARIF datado que você mesmo gera | Relatório datado: o que existia, o que foi rotacionado e a confirmação de que a chave antiga não responde mais |
| **O que muda** | Código completo, aberto e auditável | **Trabalho humano conduzido** — não um motor secreto |

> **Tem repositórios ou um histórico Git longo que nunca foram auditados?** Eu conduzo a varredura, a triagem e a rotação com você — com a **mesma engine que está neste repositório**.

<div align="center">

[![Pacotes e valores](https://img.shields.io/badge/Pacotes_e_valores-paulo--marcos--lucio.github.io-0f766e?style=for-the-badge)](https://paulo-marcos-lucio.github.io)
[![Falar no LinkedIn](https://img.shields.io/badge/LinkedIn-Falar_agora-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/paulo-marcos-a07379174/)

</div>

---

## 🏗️ Arquitetura

O Guardião resolve um problema simples de enunciar e caro de ignorar: **segredos commitados por engano** — na árvore atual e, sobretudo, escondidos no histórico do Git. O dado entra por duas fontes (arquivos do disco e blobs de **todo** o histórico), atravessa o motor **linha a linha**, onde cada regra combina **regex de provedor + entropia + validador BR** e uma bateria de filtros derruba placeholder, hash e allowlist. O que sobrevive vira um `Finding` com o **segredo já ocultado**, classificado em **OWASP 2025 + CWE**. Sai em três formatos — **console**, **JSON** (`suite-appsec/1`) e **SARIF 2.1.0** para o Code Scanning —, com um **baseline** que faz o CI falhar só no que é novo.

```mermaid
flowchart TD
    A["<b>cli.py</b><br/>Typer · scan / pre-commit"] --> SRC["<b>sources/</b><br/>arquivos + histórico Git"]
    SRC --> ENG["<b>core/engine.py</b><br/>Scanner · linha a linha"]
    ENG --> RUL["<b>rules/</b><br/>regex + entropia + validador BR"]
    RUL --> FLT["<b>filtros</b><br/>placeholder · hash · allowlist"]
    FLT --> RED["<b>core/redaction.py</b><br/>oculta o segredo"]
    RED --> FND["<b>core/models.py</b><br/>Finding imutável"]
    FND --> TAX["<b>rules/definitions.py</b><br/>OWASP 2025 + CWE"]
    TAX --> BAS["<b>core/baseline.py</b><br/>barra só o que é novo"]
    BAS --> REP["<b>report/</b><br/>renderização"]
    REP --> OUT
    subgraph OUT [" Formatos de saída "]
        direction LR
        CON["console"] ~~~ JS["json · suite-appsec/1"] ~~~ SA["SARIF 2.1.0"]
    end
    classDef nucleo fill:#0e2a24,stroke:#3fb79e,stroke-width:2px,color:#e7ede9;
    classDef saida fill:#241d0f,stroke:#d6a94e,color:#f5ecd9;
    class A,SRC,ENG,RUL,FLT,RED,FND,TAX,BAS,REP nucleo;
    class CON,JS,SA saida;
```

A árvore de módulos:

```
src/guardiao/
├── core/       # modelos, entropia, ocultação, config, motor, baseline
├── rules/      # catálogo de regras (regex + entropia) e registro
├── sources/    # fontes: sistema de arquivos e histórico Git
├── report/     # renderizadores: console (rich), json, sarif
└── cli.py      # interface typer
```

Princípios de projeto:

- **O segredo cru nunca sai.** Ele existe no objeto `Finding` só para mascarar a linha de contexto; os renderizadores usam exclusivamente o valor ocultado. Há teste garantindo que console, JSON, SARIF e baseline **não** contêm o segredo.
- **Artefato publicado oculta mais.** Console e JSON mostram 4 caracteres de cada ponta (é o que faz o dono reconhecer *qual* credencial é). O **baseline** — que você versiona — e o **SARIF** — que sobe para o Code Scanning e fica legível para quem tem acesso ao repositório — mostram só **2 por ponta**: com 4+4, uma senha humana de 16 caracteres sai com metade em claro, e o resto é dicionário.
- **Fingerprint publicável.** A identidade de um achado é `sha256(regra ‖ arquivo ‖ valor ocultado)` — deliberadamente **sem** o segredo cru e **sem** a linha. Sem o segredo porque um hash truncado de senha humana é um compromisso quebrável em microssegundos, e essa fingerprint viaja no SARIF publicado no Code Scanning e no baseline que você versiona. Sem a linha para que mover o código não feche e reabra o alerta no GitHub.
- **Cada regra é dado, não código**: adicionar um detector é acrescentar uma entrada declarativa (regex + severidade + filtros). O motor é quem percorre a linha.
- **Um pipeline só**: `scan`, `pre-commit` e `--git-history` desembocam no mesmo `Scanner.scan_units` e usam a mesma `Config` — um arquivo que o CI considera limpo não pode bloquear o commit.

---

## 🔬 Qualidade de engenharia & método

**Portões (medidos neste repo em 2026-08-04, não copiados):** 183 testes (1 skip), incluindo *property-based* (Hypothesis) que afirmam invariantes de classe · cobertura **95%** (`--cov-fail-under=90`, gate fixado *abaixo* do medido para ser anti-regressão, não vaidade) · `mypy --strict` limpo (22 arquivos) · `ruff` lint + format limpo (42 arquivos) · CI em matriz **Python 3.10 / 3.11 / 3.12 / 3.13**.

**Teste que morde a mão que o desfaz.** A calibração anti-falso-positivo vive sob guarda: `test_fp_fixes_preserve_recall` (`tests/test_review_fixes.py`) fica **vermelho** se um filtro de precisão voltar a engolir um segredo real — reafirma que AWS, `ghp_`, entropia e chave privada continuam disparando. E `test_toda_regra_do_catalogo_tem_caso_positivo` reprova o CI se uma regra nova nascer sem caso positivo: "regra sem teste" e "regra que nunca casa nada" passam a ser indistinguíveis — e barradas. Dogfooding: `test_source_tree_is_clean` varre o próprio `src/`.

**Arquitetura confirmável no código:**

- **Detecção × taxonomia × renderização separadas**: `core/` (motor, entropia, ocultação), `rules/` (catálogo declarativo — cada regra é **dado**, não código), `sources/` (FS + histórico Git), `report/` (console/json/sarif).
- **Fonte única de verdade** da edição OWASP: `OWASP_EDITION = "2025"` em `rules/definitions.py`, importado por JSON e SARIF — a edição nunca diverge entre as saídas.
- **Contrato de saída estável**: JSON `suite-appsec/1` e **SARIF 2.1.0** (schema oficial do Code Scanning); um teste garante que o segredo cru nunca chega a renderizador algum.
- **Imutabilidade e tipos estritos**: `Finding` e `Location` são `@dataclass(frozen=True)`; todo o `src/` passa em `mypy --strict`.

**Cadeia de suprimentos do próprio repo:** toda action do CI **fixada por SHA de 40 hex** (nunca tag móvel) + **Dependabot** (github-actions e pip, **semanal**, agrupado) para que o SHA fixado não congele também a versão vulnerável; **CodeQL** (análise estática do GitHub, semanal e em cada PR) e **`dependency-review`** barrando dependência nova com CVE conhecida nos PRs; `permissions` mínimo e explícito por job, `persist-credentials: false`, `concurrency` com cancelamento e `timeout-minutes` em todo job.

**PT-BR é decisão de projeto**, não descuido: identificadores e enums em inglês (são chaves de máquina); texto para humano — mensagens, docstrings e nomes de teste (`test_uri_de_redis_sem_usuario_e_detectada`) — em pt-BR, consistente nas quatro ferramentas da suíte.

---

## ⚖️ Uso ético

Ferramenta para **avaliar repositórios que você possui ou tem autorização para analisar**. O objetivo é defensivo: encontrar e remediar exposições. Trate todo segredo encontrado como comprometido — **rotacione**, não apenas remova do histórico.

---

## 🧭 Roadmap

- [ ] Reescrita de histórico assistida (integração com `git filter-repo`).
- [ ] Verificação de validade de credencial (checagem passiva, opt-in).
- [x] Regras para provedores BR (gateways de pagamento) — **Mercado Pago** (`APP_USR-`), além de GitLab, npm, SendGrid, **Twilio** (`SK`), **DigitalOcean** (`dop_v1_`) e **Hugging Face** (`hf_`). *ERPs BR (ex.: Omie, Bling) seguem no radar.*
- [x] Regras para SaaS de e-commerce/plataforma e gestão de segredos — **Shopify** (`shpat_`/`shpss_`), **Doppler** (`dp.pt.`) e **Linear** (`lin_api_`).
- [ ] Saída *pre-commit* incremental por hash de blob.

---

## 📄 Licença

[MIT](LICENSE) © 2026 Paulo Marcos Lucio.

---

<div align="center">
<sub>Parte da suíte AppSec — junto do <a href="https://github.com/Paulo-Marcos-Lucio/sentinela">Sentinela</a>. Segurança é redução de risco, não promessa de perfeição.</sub>
</div>

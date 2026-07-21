<div align="center">

# 🔑 Guardião

### Encontra segredos vazados no seu código **e no histórico do Git** — antes que virem incidente.

*Chaves de API, tokens, senhas e chaves privadas commitados por engano são uma das causas mais comuns e mais baratas de vazamento. O Guardião varre a árvore atual **e todo o histórico**, oculta o segredo no relatório, entende baseline para o CI só falhar no que é novo, e exporta **SARIF** para o GitHub Code Scanning.*

[![CI](https://github.com/Paulo-Marcos-Lucio/guardiao/actions/workflows/ci.yml/badge.svg)](https://github.com/Paulo-Marcos-Lucio/guardiao/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Ruff](https://img.shields.io/badge/lint-ruff-261230.svg)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-2A6DB2.svg)](https://mypy-lang.org/)
[![OWASP](https://img.shields.io/badge/OWASP-A05%2FA07-000000.svg)](https://owasp.org/Top10/)

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

| Regra | Detecta | Severidade | OWASP / CWE |
| --- | --- | --- | --- |
| `private-key` | Chave privada PEM/OpenSSH (RSA, EC, DSA, ENCRYPTED) | 🔴 Crítica | A02 · CWE-321 |
| `stripe-secret-key` | Chave de produção da Stripe (`sk_live`/`rk_live`) | 🔴 Crítica | A05 · CWE-798 |
| `aws-access-key-id` / `aws-secret-access-key` | Credenciais AWS | 🟠 Alta | A05 · CWE-798 |
| `github-token` / `github-pat-fine-grained` | Tokens do GitHub (PAT, OAuth, App) | 🟠 Alta | A07 · CWE-798 |
| `google-api-key` | Chave de API do Google | 🟠 Alta | A05 · CWE-798 |
| `slack-token` / `slack-webhook` | Token/Webhook do Slack | 🟠/🟡 | A05/A01 |
| `db-connection-uri` | URI de banco com usuário:senha | 🟠 Alta | A05 · CWE-798 |
| `basic-auth-url` | Credencial embutida em URL | 🟡 Média | A07 · CWE-522 |
| `jwt` | JSON Web Token no código | 🟡 Média | A07 · CWE-522 |
| `generic-assignment` | Valor de **alta entropia** atribuído a chave sensível (`password`, `secret`, `api_key`…) | 🟡 Média | A05 · CWE-798 |
| `cpf` / `cnpj` | Dado pessoal em texto claro (**LGPD**) | 🔵 Baixa/Info | A02 · CWE-359 |

Cada achado traz **severidade**, **evidência ocultada**, **recomendação** (começando por *rotacionar*) e classificação **OWASP + CWE**.

### Como evita falso-positivo

- **Entropia de Shannon** com limiares por alfabeto (hex ≠ base64) para os segredos genéricos.
- **Filtro de placeholder**: descarta exemplos de documentação (`AKIAIOSFODNN7EXAMPLE`), `your-key-here`, valores repetidos, etc.
- **Allowlist inline**: uma linha com `# guardiao:allow` (ou `pragma: allowlist secret`) é ignorada.
- **Baseline**: aceita a dívida atual e passa a barrar só o que for **novo**.

---

## 🚀 Instalação

Requer **Python 3.10+**.

```bash
git clone https://github.com/Paulo-Marcos-Lucio/guardiao.git
cd guardiao
pip install .           # ou: pip install -e ".[dev]" para desenvolvimento
```

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
guardiao rules
```

Principais opções do `scan`:

| Opção | Descrição |
| --- | --- |
| `-f, --format` | `console` (padrão), `json`, `sarif`. Repetível. |
| `-o, --output` | Arquivo de saída (para um formato de arquivo). |
| `--git-history` | Varre todos os blobs do histórico, não só a árvore atual. |
| `--baseline` / `--update-baseline` | Suprime achados conhecidos / (re)grava o baseline. |
| `--fail-on` | `none`/`info`/`low`/`medium`/`high`/`critical` — código de saída 1 para CI. |
| `--only` / `--skip` / `--skip-category` | Filtra regras ou categorias (ex.: `--skip-category pii`). |
| `--no-entropy` | Desliga a detecção por entropia. |

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
- run: pip install guardiao
- run: guardiao scan . --git-history -f sarif -o guardiao.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: guardiao.sarif
```

---

## 🏗️ Arquitetura

```
src/guardiao/
├── core/       # modelos, entropia, ocultação, config, motor, baseline
├── rules/      # catálogo de regras (regex + entropia) e registro
├── sources/    # fontes: sistema de arquivos e histórico Git
├── report/     # renderizadores: console (rich), json, sarif
└── cli.py      # interface typer
```

Princípios de projeto:

- **O segredo cru nunca sai.** Ele existe no objeto `Finding` só para gerar a *fingerprint* — os renderizadores usam exclusivamente o valor ocultado. Há teste garantindo que JSON e SARIF **não** contêm o segredo.
- **Fingerprint estável** por `(regra, arquivo, hash do segredo)` — mover o código não invalida o baseline; trocar o segredo sim.
- **Cada regra é dado, não código**: adicionar um detector é acrescentar uma entrada declarativa.

---

## ⚖️ Uso ético

Ferramenta para **avaliar repositórios que você possui ou tem autorização para analisar**. O objetivo é defensivo: encontrar e remediar exposições. Trate todo segredo encontrado como comprometido — **rotacione**, não apenas remova do histórico.

---

## 🧭 Roadmap

- [ ] Reescrita de histórico assistida (integração com `git filter-repo`).
- [ ] Verificação de validade de credencial (checagem passiva, opt-in).
- [ ] Regras para provedores BR (gateways de pagamento, ERPs).
- [ ] Saída *pre-commit* incremental por hash de blob.

---

## 📄 Licença

[MIT](LICENSE) © 2026 Paulo Marcos Lucio.

---

<div align="center">
<sub>Parte da suíte AppSec — junto do <a href="https://github.com/Paulo-Marcos-Lucio/sentinela">Sentinela</a>. Segurança é redução de risco, não promessa de perfeição.</sub>
</div>

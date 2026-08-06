<p align="right"><a href="README.md">🇧🇷 Ler em Português</a></p>

<a href="https://paulo-marcos-lucio.github.io"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/guardiao/main/assets/banner-abismo-v2.svg" alt="Guardião — the shield that guards your code's frontier: a secrets scanner for your code and Git history" width="100%"/></a>

<div align="center">

# 🔑 Guardião

<sub>Portuguese for "Guardian"</sub>

### Finds secrets leaked in your code **and in your Git history** — before they become an incident.

*API keys, tokens, passwords, and private keys committed by mistake are among the most common and cheapest causes of leaks. Guardião scans the current tree **and the entire history**, redacts the secret in the report, understands baselines so CI only fails on what's new, and exports **SARIF** for GitHub Code Scanning.*

[![CI](https://github.com/Paulo-Marcos-Lucio/guardiao/actions/workflows/ci.yml/badge.svg)](https://github.com/Paulo-Marcos-Lucio/guardiao/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Ruff](https://img.shields.io/badge/lint-ruff-261230.svg)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-2A6DB2.svg)](https://mypy-lang.org/)
[![OWASP](https://img.shields.io/badge/OWASP_Top_10-2025-000000.svg)](https://owasp.org/Top10/)
[![Tests](https://img.shields.io/badge/tests-186%20passing-brightgreen.svg)](#-engineering-quality--method)
[![Coverage](https://img.shields.io/badge/coverage-95%25-green.svg)](#-engineering-quality--method)

</div>

---

## 📌 The problem

Removing a secret from your code **does not** remove it from the repository. It stays alive in old commits — accessible to anyone with read access (or to the entire world, if the repo is public). That's why "delete and commit again" is a false sense of security: **once committed, a secret must be considered compromised and rotated.**

Guardião was built for both moments:

- **Preventive** — as a *pre-commit* hook, it blocks the secret **before** it enters the history.
- **Investigative** — scans **the entire history** (`git rev-list --all`) to find what has already been committed and forgotten.

> **LGPD (Brazil's data-protection law, GDPR-equivalent) angle.** Beyond credentials, Guardião flags **personal data** (CPF/CNPJ — Brazilian individual/company tax IDs) versioned in plain text — exposure relevant to **LGPD (art. 46)**. Documented secrets management is evidence of a technical security measure.

---

## 🔎 What it detects

> The codes below are from **OWASP Top 10:2025**. Careful: `A03` means different
> things in 2021 and in 2025 — that's why the edition is always declared
> (`owasp_edition` in the JSON and SARIF, and in the column header in `guardiao regras`).

| Rule | Detects | Severity | OWASP 2025 / CWE |
| --- | --- | --- | --- |
| `private-key` | PEM/OpenSSH private key (RSA, EC, DSA, ENCRYPTED) | 🔴 Critical | A04 · CWE-321 |
| `stripe-secret-key` | Stripe production key (`sk_live`/`rk_live`) | 🔴 Critical | A02 · CWE-798 |
| `aws-access-key-id` / `aws-secret-access-key` | AWS credentials | 🟠 High | A02 · CWE-798 |
| `github-token` / `github-pat-fine-grained` | GitHub tokens (PAT, OAuth, App) | 🟠 High | A07 · CWE-798 |
| `mercadopago-access-token` | Mercado Pago production access token (`APP_USR-…`) | 🔴 Critical | A02 · CWE-798 |
| `google-api-key` | Google API key | 🟠 High | A02 · CWE-798 |
| `gitlab-pat` | GitLab Personal Access Token (`glpat-`) | 🟠 High | A07 · CWE-798 |
| `npm-token` | npm access token (`npm_`) — supply chain | 🟠 High | A03 · CWE-798 |
| `sendgrid-api-key` | SendGrid API key (`SG.`) | 🟠 High | A02 · CWE-798 |
| `twilio-api-key` | Twilio API Key SID (`SK` + 32 hex) | 🟠 High | A02 · CWE-798 |
| `digitalocean-token` | DigitalOcean access token (`dop_`/`doo_`/`dor_v1_`) | 🟠 High | A02 · CWE-798 |
| `huggingface-token` | Hugging Face access token (`hf_`) — ML supply chain | 🟠 High | A03 · CWE-798 |
| `shopify-token` | Shopify access token / shared secret (`shpat_`/`shpca_`/`shppa_`/`shpss_`) | 🟠 High | A02 · CWE-798 |
| `doppler-token` | Doppler personal token (`dp.pt.`) — secrets manager | 🔴 Critical | A02 · CWE-798 |
| `linear-api-key` | Linear personal API key (`lin_api_`) | 🟠 High | A07 · CWE-798 |
| `slack-token` / `slack-webhook` | Slack token/webhook | 🟠/🟡 | A02/A01 |
| `db-connection-uri` | Database URI with `user:password` (user can be empty: `redis://:password@host`) | 🟠 High | A02 · CWE-798 |
| `basic-auth-url` | Credential embedded in URL | 🟡 Medium | A07 · CWE-522 |
| `jwt` | JSON Web Token in code | 🟡 Medium | A07 · CWE-522 |
| `dotenv-assignment` | **Unquoted** value assigned to a sensitive key in `.env`/`.envrc`/`*.env` | 🟠 High | A02 · CWE-798 |
| `generic-assignment` | Value assigned to a sensitive key (`DB_PASSWORD`, `JWT_SECRET`, `apiKey`…) | 🟡 Medium | A02 · CWE-798 |
| `high-entropy-string` | Random 24+ char string near secret-related context | 🟡 Medium | A02 · CWE-798 |
| `cpf` / `cnpj` | Personal data in plain text, **with check-digit validation** (**LGPD**) | 🔵 Low/Info | A04 · CWE-359 |

Every finding includes **severity**, **redacted evidence**, a **recommendation** (starting with *rotate*), and **OWASP + CWE** classification.

> **What was measured, against what, and with what margin.** Labeled corpus versioned in
> [`bench/`](./bench) — 14 secrets planted in production-like format and 14 trap lines.
> In this version (commit of this tree, measured on 2026-08-04, Python 3.12/Windows):
> **recall 13/14 = 93% · 95% CI [69% ; 99%] · zero false positives** on the traps.
> Run it yourself: `guardiao scan bench -f json -o r.json && python bench/avaliar.py r.json`.
>
> This is **lab, not field**: the secrets were planted by me, so the number
> measures coverage of a known format — not accuracy against an arbitrary codebase. With n=14
> the interval is wide, which is why it's written out here instead of a rounded number.
> The one case that slips through is a high-entropy blob **with no context at all** — a
> deliberate choice, because chasing loose entropy is the biggest source of noise in real code.
>
> **Honest comparison against the incumbents** (gitleaks, trufflehog): [`BENCHMARK.md`](./BENCHMARK.md)
> — reproducible, versions and commits pinned, and it states **where we lose**. The 2026-08-05
> recalibration knocked the false positives on `encode/httpx` down from 25 to 4 (tying gitleaks on
> the real keys in `psf/requests`), with the corpus recall preserved.
>
> The calibration that produces these numbers **lives in this repository**; there is no secret engine.
> Concrete example of what it fixed: a `sk_live_…` key that happens to contain the sequence
> `abcdefgh` **is no longer swallowed** by the placeholder filter — previously a CRITICAL
> credential would silently disappear for coinciding with 8 letters from a documentation example.

### How it avoids false positives

- **Bias-corrected entropy.** The Shannon estimator is biased downward on short strings (it cannot exceed `log2(n)`), so comparing against a fixed bits/char threshold creates length-dependent false negatives. The criterion uses **Miller-Madow** against a fraction of the token alphabet's theoretical maximum. Measured on 5,992 random secrets × 12,206 real strings extracted from code: recall **85.3% → 94.9%** and false positives **282 → 239** — improves on both axes.
- **Mandatory context.** The entropy rule only triggers near `token`/`secret`/`key`/`password`… — including inside `DB_PASSWORD` and `accessToken`, which the `\b` boundary doesn't cover.
- **Negative context.** Entropy **cannot** distinguish a hash from a secret (they're mathematically identical). If the line mentions `md5`/`etag`/`integrity`/`checksum`, the finding is discarded.
- **Check-digit validation** on CPF/CNPJ (mod 11): `000.000.000-00` is not personal data.
- **Placeholder filter**: discards documentation examples (`AKIAIOSFODNN7EXAMPLE`), `your-key-here`, `${VAR}`, repeated values. The report **states how many** values were discarded this way — the suppression is auditable, not silent.
- **Inline allowlist**: a line containing `# guardiao:allow` (or `pragma: allowlist secret`) is ignored.
- **Baseline**: accepts the current debt and starts blocking only what's **new**.

### 🚧 Known limitations

Honesty first — what this tool **does not** do:

- **Does not validate the credential.** An already-revoked `sk_live_` is reported the same as an active one.
- **Negative context is a heuristic.** A secret on a line that also contains `checksum` or `commit` gets discarded along with the hashes.
- **Alphanumeric CNPJ** (the new format from Brazil's tax authority — Receita Federal, `AA.AAA.AAA/AAAA-DD`) is **not** detected — only the numeric one.
- **Multi-line secrets** (private key body, service account JSON) are detected by their header, not their body: the scan is line by line.
- **Does not rewrite history.** Finding is half the job; `git filter-repo` and rotation are separate work.
- **What gets skipped shows up in the report** (`summary.skipped`): **entire excluded directories** (`vendor/`, `dist/`, `node_modules/`, virtualenv), lockfiles, binaries, files above `--max-file-size`, and lines above `--max-line-length`. "I didn't look" and "I looked and it's clean" are visually distinct outcomes.

---

## 🚀 Installation

Requires **Python 3.10+**. Check with `python --version`.

### ⚡ Quickstart — from zero to first finding

```bash
# 1. install the tool (from the repository; see the PyPI name warning below)
pip install "git+https://github.com/Paulo-Marcos-Lucio/guardiao.git"

# 2. confirm it installed
guardiao --version

# 3. run it against YOUR project — current tree + the ENTIRE Git history
guardiao scan . --git-history
```

The `guardiao` command exits with **code 1** if it finds anything with severity ≥ `medium`
(the default) — that's what makes CI fail. Nothing above the threshold: code `0`.

> **Want to see it catch something before pointing it at your own code?** Clone the repository and
> run it against the sample corpus — 14 secrets planted in production-like format
> (private key, AWS, Stripe, GitHub, Slack, `.env`…), 13 with guaranteed detection:
>
> ```bash
> git clone https://github.com/Paulo-Marcos-Lucio/guardiao.git
> cd guardiao
> python bench/gerar.py   # materializes the fixtures that aren't versioned in plaintext
> guardiao scan bench     # or: pip install -e ".[dev]" first, if you want to run the test suite
> ```

### Ways to install

```bash
# isolated from the rest of the system (recommended for CLI use) — pipx handles the venv
pipx install "git+https://github.com/Paulo-Marcos-Lucio/guardiao.git"

# or inside a venv you create yourself
python -m venv .venv && . .venv/Scripts/activate   # Linux/macOS: source .venv/bin/activate
pip install "git+https://github.com/Paulo-Marcos-Lucio/guardiao.git"

# development (tests, lint, types)
git clone https://github.com/Paulo-Marcos-Lucio/guardiao.git
cd guardiao && pip install -e ".[dev]"
```

> ⚠️ There is **no** `guardiao` package published by me on PyPI. If someone publishes
> a package under that name, `pip install guardiao` would pull third-party code into
> your CI. Always install from the repository URL — and, in CI, **pin the
> commit SHA**, which is the only immutable reference:
>
> ```bash
> pip install "git+https://github.com/Paulo-Marcos-Lucio/guardiao.git@<sha-de-40-hex>"
> ```

---

## 🧑‍💻 Usage

```bash
# scans the current directory
guardiao scan .

# scans the ENTIRE Git history (where the forgotten secrets live)
guardiao scan . --git-history

# SARIF report to upload to GitHub Code Scanning
guardiao scan . -f sarif -o guardiao.sarif

# accepts the current debt as a baseline...
guardiao scan . --update-baseline
# ...and from then on CI only fails on NEW secrets
guardiao scan . --baseline .guardiao-baseline.json --fail-on high

# lists all rules
guardiao regras          # `guardiao rules` is an alias
```

Main options for `scan`:

| Option | Description |
| --- | --- |
| `-f, --format` | `console` (default), `json`, `sarif`. Repeatable. |
| `-o, --output` | Output file (for a file format). |
| `--git-history` | Scans every blob in the history — including loose objects (`--amend`/rebase) — **and commit messages and annotated tag messages**, not just the current tree. |
| `--permitir-shallow` | Allows running `--git-history` on a shallow clone (incomplete history). |
| `--baseline` / `--update-baseline` | Suppresses known findings / (re)writes the baseline. |
| `--fail-on` | `none`/`info`/`low`/`medium`/`high`/`critical` — exit code 1 for CI. |
| `--only` / `--skip` / `--skip-category` | Filters rules or categories (e.g., `--skip-category pii`). |
| `--no-entropy` | Turns off entropy-based detection. |
| `--scan-lockfiles` | Also scans lockfiles/minified files (skipped by default). |
| `--max-file-size` / `--max-line-length` | Scan ceilings (default: 5 MB / 4,000 chars). |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed; nothing above `--fail-on`. |
| `1` | Finding with severity ≥ `--fail-on`. |
| `2` | **Usage error**: nonexistent rule/category id, nonexistent path, non-Git repository, shallow clone with `--git-history`. Never a "silent green." |

### `--fail-on` across the AppSec suite

The default is **not** the same across the four tools, and that's a design decision, not
an oversight: the consequence of a leaked credential is categorically worse than that of a
missing HTTP header, so the secrets scanner has a more sensitive trigger.

| Tool | `--fail-on` default | Why |
| --- | --- | --- |
| **Guardião** (secrets) | `medium` | `generic-assignment`, `high-entropy-string`, and CPF/CNPJ (LGPD) live in the medium band — raising it to `high` would turn off the gate exactly where it pays off. |
| Chaveiro (JWT) | `high` | — |
| Esteira (CI/CD) | `high` | — |
| Sentinela (web surface) | `alta` | — |

Need them aligned? Pass `--fail-on` explicitly on all of them — never rely on the default in a CI recipe.

### JSON report contract

`suite-appsec/1` format, the same across all four tools: enum keys and values
are in English (they're identifiers), human-facing text is in Brazilian Portuguese (pt-BR). `summary.by_severity`
**always** carries all five severities, including zeroed ones, and `summary.skipped` states what was **not**
analyzed. The finding identifier key is `id`.

### Pre-commit hook

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

### In GitHub Actions (with SARIF upload)

```yaml
- uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
  with:
    fetch-depth: 0          # without this, --git-history only sees 1 commit
    persist-credentials: false
- run: pip install "git+https://github.com/Paulo-Marcos-Lucio/guardiao.git@<sha-de-40-hex>"
- run: guardiao scan . --git-history -f sarif -o guardiao.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@08d09a53f0f5d694f253bd25732e4429c9e9337f # v3
  if: always()
  with:
    sarif_file: guardiao.sarif
```

`fetch-depth: 0` is not a minor detail: the default for `actions/checkout` is a **shallow**
clone, and on a shallow clone `--git-history` only sees the downloaded commits. Guardião
**aborts with exit 2** in that case instead of reporting success (use `--permitir-shallow`
if you really want to scan the partial history).

And even with `fetch-depth: 0` **there's a limit no flag removes**: `git clone` and
`git fetch` transfer only **reachable** objects. The blob left behind by a
`commit --amend`, a rebase, a deleted branch, or a stash exists only in the
origin repository and **never reaches the runner** — it's the most common hiding
place for a secret. When running on a clone, Guardião **declares that limit** in the report
(`summary.coverage_warnings` in JSON, `properties.coverageWarnings` in SARIF) instead
of delivering "0 findings" as if it had looked at everything. It **does not fail** because of
this: a known limitation of the Git protocol is not a reason to block your CI. For full
reach, run the scan on the origin repository itself.

---

## 🔓 Pro Version (private) — it's a SERVICE, not another engine

Being direct, because honesty is the product here: **the tool in this repo is already the
calibrated engine, and it's the most complete one that exists.** There is no stronger engine
hidden away in private — nor a better version anywhere else. What you run for free is exactly
what I run under contract. Pro isn't another detection engine; it's **human work that I
personally conduct** on top of this engine:

| | **Public tool (you run it)** | **Pro / service (I conduct it with you)** |
| --- | --- | --- |
| **Detection engine** | This engine — recall 13/14 on the [`bench/`](./bench) corpus, zero false positives | **The same engine, not a single line more.** What you pay for is the guidance, not the engine |
| **Scope** | The path or repository you point it at | **The entire organization**: every repository and **the entire Git history**, not just `HEAD` |
| **Triage** | You read the report and adjudicate each finding | I **triage every finding** as true positive or false positive and hand you the already-clean list — no dumping noise on your team |
| **Rotation** | The tool finds it; rotating is on you (it does *not* rotate) | **Per-provider rotation plan**, step by step, + **a retest that proves** the credential is out of circulation |
| **Evidence (LGPD art. 46)** | Dated JSON/SARIF that you generate yourself | Dated report: what existed, what was rotated, and confirmation that the old key no longer responds |
| **What changes** | Complete, open, and auditable code | **Human-conducted work** — not a secret engine |

> **Have repositories or a long Git history that's never been audited?** I conduct the scan, triage, and rotation with you — using the **same engine that's in this repository**.

<div align="center">

[![Packages and pricing](https://img.shields.io/badge/Pacotes_e_valores-paulo--marcos--lucio.github.io-0f766e?style=for-the-badge)](https://paulo-marcos-lucio.github.io)
[![Talk on LinkedIn](https://img.shields.io/badge/LinkedIn-Falar_agora-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/paulo-marcos-a07379174/)

</div>

---

## 🏗️ Architecture

Guardião solves a problem that's simple to state and expensive to ignore: **secrets committed by mistake** — in the current tree and, above all, hidden in the Git history. Data enters through two sources (files on disk and blobs from **the entire** history), flows through the engine **line by line**, where each rule combines **provider regex + entropy + BR validator**, and a battery of filters knocks out placeholders, hashes, and allowlist entries. What survives becomes a `Finding` with the **secret already redacted**, classified under **OWASP 2025 + CWE**. It outputs in three formats — **console**, **JSON** (`suite-appsec/1`), and **SARIF 2.1.0** for Code Scanning — with a **baseline** that makes CI fail only on what's new.

```mermaid
flowchart TD
    A["<b>cli.py</b><br/>Typer · scan / pre-commit"] --> SRC["<b>sources/</b><br/>files + Git history"]
    SRC --> ENG["<b>core/engine.py</b><br/>Scanner · line by line"]
    ENG --> RUL["<b>rules/</b><br/>regex + entropy + BR validator"]
    RUL --> FLT["<b>filters</b><br/>placeholder · hash · allowlist"]
    FLT --> RED["<b>core/redaction.py</b><br/>redacts the secret"]
    RED --> FND["<b>core/models.py</b><br/>immutable Finding"]
    FND --> TAX["<b>rules/definitions.py</b><br/>OWASP 2025 + CWE"]
    TAX --> BAS["<b>core/baseline.py</b><br/>blocks only what's new"]
    BAS --> REP["<b>report/</b><br/>rendering"]
    REP --> OUT
    subgraph OUT [" Output formats "]
        direction LR
        CON["console"] ~~~ JS["json · suite-appsec/1"] ~~~ SA["SARIF 2.1.0"]
    end
    classDef nucleo fill:#0e2a24,stroke:#3fb79e,stroke-width:2px,color:#e7ede9;
    classDef saida fill:#241d0f,stroke:#d6a94e,color:#f5ecd9;
    class A,SRC,ENG,RUL,FLT,RED,FND,TAX,BAS,REP nucleo;
    class CON,JS,SA saida;
```

The module tree:

```
src/guardiao/
├── core/       # models, entropy, redaction, config, engine, baseline
├── rules/      # rule catalog (regex + entropy) and registry
├── sources/    # sources: filesystem and Git history
├── report/     # renderers: console (rich), json, sarif
└── cli.py      # typer interface
```

Design principles:

- **The raw secret never leaves.** It exists in the `Finding` object only to mask the context line; the renderers exclusively use the redacted value. There's a test guaranteeing that console, JSON, SARIF, and baseline **do not** contain the secret.
- **Published artifacts redact more.** Console and JSON show 4 characters from each end (enough for the owner to recognize *which* credential it is). The **baseline** — which you version — and the **SARIF** — which gets uploaded to Code Scanning and stays readable to anyone with repository access — show only **2 per end**: at 4+4, a 16-character human password would come out half exposed in plaintext, with the rest within reach of a dictionary attack.
- **Publishable fingerprint.** A finding's identity is `sha256(rule ‖ file ‖ redacted value)` — deliberately **without** the raw secret and **without** the line. Without the secret because a truncated hash of a human password is a commitment breakable in microseconds, and this fingerprint travels inside the SARIF published to Code Scanning and the baseline you version. Without the line so that moving the code doesn't close and reopen the alert on GitHub.
- **Each rule is data, not code**: adding a detector means adding a declarative entry (regex + severity + filters). The engine is what walks the line.
- **A single pipeline**: `scan`, `pre-commit`, and `--git-history` all funnel into the same `Scanner.scan_units` and use the same `Config` — a file the CI considers clean can't block the commit.

---

## 🔬 Engineering quality & method

**Gates (measured in this repo on 2026-08-04, not copied):** 183 tests (1 skip), including *property-based* tests (Hypothesis) that assert class invariants · **95%** coverage (`--cov-fail-under=90`, gate set *below* the measured value to be anti-regression, not vanity) · `mypy --strict` clean (22 files) · `ruff` lint + format clean (42 files) · CI on a **Python 3.10 / 3.11 / 3.12 / 3.13** matrix.

**A test that bites the hand that would undo it.** The anti-false-positive calibration lives under guard: `test_fp_fixes_preserve_recall` (`tests/test_review_fixes.py`) turns **red** if a precision filter starts swallowing a real secret again — it reaffirms that AWS, `ghp_`, entropy, and private-key detection keep firing. And `test_toda_regra_do_catalogo_tem_caso_positivo` fails the CI if a new rule is born without a positive test case: "rule with no test" and "rule that never matches anything" become indistinguishable — and both get blocked. Dogfooding: `test_source_tree_is_clean` scans `src/` itself.

**Architecture confirmable in the code:**

- **Detection × taxonomy × rendering, kept separate**: `core/` (engine, entropy, redaction), `rules/` (declarative catalog — each rule is **data**, not code), `sources/` (FS + Git history), `report/` (console/json/sarif).
- **Single source of truth** for the OWASP edition: `OWASP_EDITION = "2025"` in `rules/definitions.py`, imported by both JSON and SARIF — the edition never diverges between outputs.
- **Stable output contract**: JSON `suite-appsec/1` and **SARIF 2.1.0** (Code Scanning's official schema); a test guarantees the raw secret never reaches any renderer.
- **Immutability and strict types**: `Finding` and `Location` are `@dataclass(frozen=True)`; all of `src/` passes `mypy --strict`.

**The repo's own supply chain:** every CI action **pinned by 40-hex SHA** (never a moving tag) + **Dependabot** (github-actions and pip, **weekly**, grouped) so the pinned SHA doesn't also freeze a vulnerable version in place; **CodeQL** (GitHub's static analysis, weekly and on every PR) and **`dependency-review`** blocking new dependencies with a known CVE on PRs; minimal, explicit `permissions` per job, `persist-credentials: false`, `concurrency` with cancellation, and `timeout-minutes` on every job.

**pt-BR is a design decision**, not an oversight: identifiers and enums are in English (they're machine keys); human-facing text — messages, docstrings, and test names (`test_uri_de_redis_sem_usuario_e_detectada`) — is in Brazilian Portuguese, consistent across all four tools in the suite.

---

## ⚖️ Ethical use

A tool for **assessing repositories you own or are authorized to analyze**. The goal is defensive: find and remediate exposures. Treat every secret found as compromised — **rotate it**, don't just remove it from history.

---

## 🧭 Roadmap

- [ ] Assisted history rewriting (integration with `git filter-repo`).
- [ ] Credential validity verification (passive check, opt-in).
- [x] Rules for Brazilian providers (payment gateways) — **Mercado Pago** (`APP_USR-`), plus GitLab, npm, SendGrid, **Twilio** (`SK`), **DigitalOcean** (`dop_v1_`), and **Hugging Face** (`hf_`). *Brazilian ERPs (e.g., Omie, Bling) remain on the radar.*
- [x] Rules for e-commerce/platform SaaS and secrets management — **Shopify** (`shpat_`/`shpss_`), **Doppler** (`dp.pt.`), and **Linear** (`lin_api_`).
- [ ] Incremental *pre-commit* output by blob hash.

---

## 📄 License

[MIT](LICENSE) © 2026 Paulo Marcos Lucio.

---

<div align="center">
<sub>Part of the AppSec suite — alongside <a href="https://github.com/Paulo-Marcos-Lucio/sentinela">Sentinela</a>. Security is risk reduction, not a promise of perfection.</sub>
</div>

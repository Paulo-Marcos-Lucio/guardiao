<p align="center"><a href="BENCHMARK.md"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/guardiao/main/assets/btn-lang-pt.svg" alt="Ler este documento em Português" width="300"/></a></p>

# Honest benchmark — AppSec suite vs. incumbents (recalibrated 2026-08-05)

A real, reproducible comparison against the free tools the client already knows.
All of them run in static/filesystem mode to keep it fair, on the SAME targets. **No inflating:
where we lose, it's in here.** Versions: gitleaks 8.30.1, trufflehog 3.96.0, zizmor 1.29.0.

> ### 🔧 2026-08-05 recalibration (why Guardião's numbers improved)
> The field run from this date, adjudicated secret by secret, exposed a **false-positive
> regression** in Guardião: 25 findings in `encode/httpx`, all of them false (gitleaks scored 0).
> These weren't 25 bugs — they were **3 classes** (a code identifier read as a secret; a binary
> read as text; a URL-parser fixture). Each was closed with an invariant locked in by a
> property-based test. Result, **on the same commit for each target**: httpx **25 → 4**, requests
> **6 → 4** (now identical to gitleaks on the 4 real TLS keys), corpus recall preserved (13/14, 0 FP).
> The numbers below already reflect the recalibrated version.

> ### ✅ Reproducibility verified on 2026-08-04
> The tables below were **re-run** with targets pinned by commit, and the
> gitleaks and Esteira numbers **matched exactly** with this measurement from July:
>
> | Target | Commit pinned (Aug 4) | gitleaks | Esteira | zizmor |
> |---|---|:---:|:---:|:---:|
> | pallets/flask | `6a2f545` | 6 ✓ | — | — |
> | psf/requests | `1f6589e` | 4 ✓ | — | — |
> | encode/httpx | `b5addb6` | 0 ✓ | 6 ✓ | 8¹ |
> | python-poetry/poetry | `92b74dc` | — | 2 ✓ | 1 ✓ |
> | fastapi/fastapi | `42a41db` | — | 1 ✓ | 0 ✓ |
>
> ¹ zizmor scored 10 in July (v1.28.0) and 8 now (v1.29.0) — the difference comes from the
> tool's own version, and that's exactly why **the evaluator's version + the target's commit
> need to be stated here**. Without the target's SHA, a benchmark is honest but not auditable
> by a third party; with it, anyone can reproduce it. Reproduction:
> `git clone <target> && git checkout <sha>` and then each tool at its pinned version.

---

## 1) Secrets — Guardião vs. gitleaks vs. trufflehog

### Recall (8 real planted secrets: AWS, GitHub, Stripe, Google, private key, DB-URI, basic-auth, entropy)
| | Guardião | gitleaks | trufflehog |
|---|:---:|:---:|:---:|
| secrets detected | **8/8** | 4/8 | 5/8 |

> ⚠️ **Honest caveat:** I designed both the test secrets and Guardião, so
> this number favors Guardião. It counts as a sanity check, not proof of superiority.

### Precision (false positives on mature, CLEAN repos — lower is better)
Measured on 2026-08-05, recalibrated version, same targets pinned by commit:
| repo | Guardião (before → now) | gitleaks | trufflehog (no verif.) |
|---|:---:|:---:|:---:|
| pallets/flask | 12 → **8** | **6** | 0 |
| psf/requests | 6 → **4** | **4** | 32 |
| encode/httpx | 10~25 → **4** | **0** | 22 |

**Honest reading:** the field recalibration brought Guardião closer to gitleaks in the places
where it used to be noisier. On **requests**, the two now tie at **4** — exactly the 4 real
private TLS keys versioned in the repo (full agreement on the findings that matter; the 2 extra
binary findings Guardião used to report were a `.ai` file read as text, now fixed). On **httpx**,
Guardião's 4 remaining findings are **low-confidence heuristics in test files** (example nonces
from RFC 7616, downgraded), while gitleaks scores 0 — here gitleaks is still cleaner.
On **flask**, both are noisy on the documentation's `SECRET_KEY=` examples (8 vs. 6).
**It still holds: we are not more precise than gitleaks on average; what changed is that we
stopped being unnecessarily aggressive.** trufflehog in static mode is erratic (0 on flask, 32
on requests) — its strength is **live verification** (checking whether the secret actually
works), a category Guardião and gitleaks don't have.

### The real differentiator (the "why us")
| | Guardião | gitleaks | trufflehog |
|---|:---:|:---:|:---:|
| **CPF / CNPJ (personal data — LGPD (Brazil's data-protection law, GDPR-equivalent))** | ✅ | ❌ | ❌ |
| Live secret verification | ❌ | ❌ | ✅ |
| pt-BR report + OWASP/CWE + LGPD | ✅ | ❌ | ❌ |

**Guardião is the ONLY one of the three that detects CPF/CNPJ.** For a Brazilian fintech or SME
under LGPD, that's concrete. Positioning: Guardião doesn't replace gitleaks on generic recall —
it **complements** it with a focus on LGPD and a localized report.

---

## 2) CI/CD (GitHub Actions) — Esteira vs. zizmor

| repo | Esteira | zizmor |
|---|:---:|:---:|
| poetry | 2 | 1 |
| fastapi | 1 | 0 |
| **transformers** | **122** | 91 |
| httpx | 6 | 10 |

**Honest reading:** **zizmor is the mature, more complete incumbent.** The benchmark exposed
two checks that Esteira did NOT have and zizmor does: `secrets-inherit` (52 on transformers) and
`unpinned-images` (18). **I closed both gaps** (Esteira now matches the same 52 and 18).
Even so, zizmor has years' worth of extra rules; Esteira is a **competent, focused
subset**, with pt-BR output, OWASP:2025/CWE mapping, SARIF, and compatible
`# zizmor: ignore` suppression. Where Esteira shines: **precision on a clean repo**
(flask/requests = 0 findings) and calibration (doesn't shout CRITICAL on a safe bot; gives
credit for mitigations).

**Gaps still open vs. zizmor** (candidates to close): `bot-conditions`, `cache-poisoning`,
`overprovisioned-secrets`, `ref-confusion`, `stale-action-refs`.

---

## Commercial verdict (calibrated, no false modesty)

1. **Don't sell "my tool is better than gitleaks/zizmor."** It isn't, in raw capability —
   and a technical client will find that out in 5 minutes. Selling that burns your credibility.
2. **Sell what's true:** (a) **localization + LGPD** (CPF/CNPJ, pt-BR, Brazilian legal
   framing) that foreign tools don't have; (b) **expert triage** — you run the suite +
   gitleaks/trufflehog/zizmor together, curate the results, and write the report; (c) **a
   cohesive, polished deliverable** (score, action plan, OWASP/CWE) instead of raw JSON from
   4 separate tools.
3. **The suite is your INSTRUMENTATION, not the product.** The product is your diagnosis + report.
4. **Highest-ROI next step:** publish this benchmark (transparency becomes trust) and close
   1-2 gaps per tool to narrow the distance to the incumbents.

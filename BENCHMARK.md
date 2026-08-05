# Benchmark honesto — suíte AppSec vs. incumbentes (recalibrado 2026-08-05)

Comparação real, reprodutível, contra as ferramentas gratuitas que o cliente já conhece.
Todos rodados em modo estático/filesystem para ser justo, nos MESMOS alvos. **Sem inflar:
onde perdemos, está aqui.** Versões: gitleaks 8.30.1, trufflehog 3.96.0, zizmor 1.29.0.

> ### 🔧 Recalibração de 2026-08-05 (por que os números do Guardião melhoraram)
> A bateria de campo desta data, adjudicada segredo por segredo, expôs uma **regressão de
> falso-positivo** no Guardião: 25 achados no `encode/httpx`, todos falsos (o gitleaks dava 0).
> Não eram 25 bugs — eram **3 classes** (identificador de código lido como segredo; binário lido
> como texto; fixture de parser de URL). Cada uma foi fechada com um invariante travado por teste
> property-based. Resultado, **no mesmo commit de cada alvo**: httpx **25 → 4**, requests **6 → 4**
> (agora idêntico ao gitleaks nas 4 chaves TLS reais), recall do corpus preservado (13/14, 0 FP).
> Os números abaixo já refletem a versão recalibrada.

> ### ✅ Reprodutibilidade verificada em 2026-08-04
> As tabelas abaixo foram **re-executadas** com os alvos fixados por commit, e os números
> do gitleaks e da Esteira **bateram exatamente** com esta medição de julho:
>
> | Alvo | Commit fixado (04/08) | gitleaks | Esteira | zizmor |
> |---|---|:---:|:---:|:---:|
> | pallets/flask | `6a2f545` | 6 ✓ | — | — |
> | psf/requests | `1f6589e` | 4 ✓ | — | — |
> | encode/httpx | `b5addb6` | 0 ✓ | 6 ✓ | 8¹ |
> | python-poetry/poetry | `92b74dc` | — | 2 ✓ | 1 ✓ |
> | fastapi/fastapi | `42a41db` | — | 1 ✓ | 0 ✓ |
>
> ¹ zizmor deu 10 em julho (v1.28.0) e 8 agora (v1.29.0) — a diferença é da versão da
> própria ferramenta, e é exatamente por isso que **versão do avaliador + commit do alvo
> precisam constar aqui**. Sem o SHA do alvo, um benchmark é honesto mas não é auditável
> por terceiro; com ele, qualquer pessoa reproduz. Reprodução:
> `git clone <alvo> && git checkout <sha>` e então cada ferramenta na sua versão fixada.

---

## 1) Segredos — Guardião vs. gitleaks vs. trufflehog

### Recall (8 segredos reais plantados: AWS, GitHub, Stripe, Google, chave privada, DB-URI, basic-auth, entropia)
| | Guardião | gitleaks | trufflehog |
|---|:---:|:---:|:---:|
| segredos detectados | **8/8** | 4/8 | 5/8 |

> ⚠️ **Ressalva honesta:** eu desenhei tanto os segredos-teste quanto o Guardião, então
> esse número favorece o Guardião. Vale como sanidade, não como prova de superioridade.

### Precisão (falso-positivo em repos maduros LIMPOS — quanto menos, melhor)
Medido em 2026-08-05, versão recalibrada, mesmos alvos fixados por commit:
| repo | Guardião (antes → agora) | gitleaks | trufflehog (sem verif.) |
|---|:---:|:---:|:---:|
| pallets/flask | 12 → **8** | **6** | 0 |
| psf/requests | 6 → **4** | **4** | 32 |
| encode/httpx | 10~25 → **4** | **0** | 22 |

**Leitura honesta:** a recalibração de campo aproximou o Guardião do gitleaks onde antes ele era
mais barulhento. Em **requests**, os dois agora empatam em **4** — exatamente as 4 chaves TLS
privadas reais versionadas no repo (concordância total nos achados que importam; os 2 achados de
binário que o Guardião tinha a mais eram um `.ai` lido como texto, corrigido). Em **httpx**, os 4
achados restantes do Guardião são heurísticas de **baixa confiança em arquivos de teste** (nonces
de exemplo do RFC 7616, rebaixadas), enquanto o gitleaks dá 0 — aqui o gitleaks ainda é mais limpo.
Em **flask**, os dois são ruidosos nos exemplos de `SECRET_KEY=` da documentação (8 vs 6).
**Continua valendo: não somos mais precisos que o gitleaks na média; o que mudou é que deixamos de
ser desnecessariamente agressivos.** O trufflehog em modo estático é errático (0 no flask, 32 no
requests) — a força dele é a **verificação ao vivo** (checar se o segredo funciona), categoria que
Guardião e gitleaks não têm.

### O diferencial real (o "porquê nós")
| | Guardião | gitleaks | trufflehog |
|---|:---:|:---:|:---:|
| **CPF / CNPJ (dado pessoal — LGPD)** | ✅ | ❌ | ❌ |
| Verificação de segredo ao vivo | ❌ | ❌ | ✅ |
| Relatório PT-BR + OWASP/CWE + LGPD | ✅ | ❌ | ❌ |

**Guardião é a ÚNICA das três que detecta CPF/CNPJ.** Para uma fintech/PME brasileira sob LGPD,
isso é concreto. Posicionamento: Guardião não substitui o gitleaks em recall genérico — ele
**complementa** com foco em LGPD e relatório localizado.

---

## 2) CI/CD (GitHub Actions) — Esteira vs. zizmor

| repo | Esteira | zizmor |
|---|:---:|:---:|
| poetry | 2 | 1 |
| fastapi | 1 | 0 |
| **transformers** | **122** | 91 |
| httpx | 6 | 10 |

**Leitura honesta:** o **zizmor é o incumbente maduro e mais completo.** O benchmark expôs
dois checks que a Esteira NÃO tinha e o zizmor tem: `secrets-inherit` (52 no transformers) e
`unpinned-images` (18). **Eu fechei esses dois gaps** (a Esteira agora bate os mesmos 52 e 18).
Ainda assim, o zizmor tem anos de regras a mais; a Esteira é um **subconjunto competente e
focado**, com saída PT-BR, mapeamento OWASP:2025/CWE, SARIF e supressão `# zizmor: ignore`
compatível. Onde a Esteira brilha: **precisão em repo limpo** (flask/requests = 0 achados) e
calibração (não grita CRITICAL em bot seguro; credita mitigações).

**Gaps ainda abertos vs. zizmor** (candidatos a fechar): `bot-conditions`, `cache-poisoning`,
`overprovisioned-secrets`, `ref-confusion`, `stale-action-refs`.

---

## Veredicto comercial (calibrado, sem falsa modéstia)

1. **Não venda "minha ferramenta é melhor que gitleaks/zizmor".** Não é, em capacidade bruta —
   e um cliente técnico descobre em 5 minutos. Vender isso queima a credibilidade.
2. **Venda o que é verdade:** (a) **localização + LGPD** (CPF/CNPJ, PT-BR, enquadramento legal
   BR) que os gringos não têm; (b) **triagem de especialista** — você roda a suíte + gitleaks/
   trufflehog/zizmor juntos, curadoria os resultados e escreve o relatório; (c) **um deliverable
   coeso e bonito** (nota, plano de ação, OWASP/CWE) em vez de JSON cru de 4 ferramentas.
3. **A suíte é a sua INSTRUMENTAÇÃO, não o produto.** O produto é o seu diagnóstico + relatório.
4. **Próximo passo de maior ROI:** publicar este benchmark (transparência vira confiança) e
   fechar 1-2 gaps de cada tool para reduzir a distância dos incumbentes.

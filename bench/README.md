# Corpus de referência do Guardião

Corpus rotulado, versionado, com script de avaliação. Existe por um motivo:
**número de detecção sem corpus público não é métrica, é lembrança.**

## Como reproduzir

```bash
pip install -e ".[dev]"
python bench/gerar.py                      # materializa os fixtures de formato sensível
guardiao scan bench -f json -o resultado.json
python bench/avaliar.py resultado.json
```

> **Por que `gerar.py` existe.** Um corpus de segredos não pode versionar segredos em
> **formato de produção**: o *push protection* do GitHub recusa o push — e está certo em
> recusar. Os casos de formato reconhecível (ex.: `sk_live_…`) ficam como `.tpl` e são
> materializados na hora de rodar a bateria. O arquivo gerado está no `.gitignore`.

## O que tem aqui

| | Quantidade | O que é |
|---|---|---|
| `positivos/` | 13 arquivos · **14 segredos rotulados** | Chave AWS, GCP, Slack, Stripe, GitHub PAT, chave privada PEM, hex, string de conexão, YAML, JSON, segredo em comentário, blob de alta entropia, segredo em caminho de teste |
| `negativos/` | 7 arquivos · **14 linhas-armadilha** | `.env.example`, SHA de commit, UUID, literais de teste, senha canônica de fixture, ID técnico, documentação |
| `manifest.json` | 28 entradas | Rótulo de verdade: arquivo, linha, `eh_segredo`, tipo |

## O que este corpus **não** é

- **Não é campo.** Os segredos foram plantados por quem escreveu a ferramenta. O número mede
  *cobertura de formato conhecido*, não acurácia contra uma base arbitrária de produção.
- **Não cobre o catálogo inteiro.** São 14 tipos rotulados; o catálogo do Guardião tem mais regras.
  Uma regra sem caso aqui **não** está medida por este número (o meta-teste `test_toda_regra_do_catalogo_tem_caso_positivo`
  garante que ela tenha teste unitário, que é outra coisa).
- **Não tem tamanho de amostra para três algarismos.** Com n=14, o intervalo de confiança é largo.
  Qualquer número derivado daqui deve vir com o IC, não com precisão falsa.

## Medição de referência

Medido em 2026-08-04, Python 3.12.8, Windows 11:

| Versão | Recall | IC95% (Wilson) | Falso-positivo | Precisão |
|---|---|---|---|---|
| `31925fd` (público antes da calibração) | **9/14 = 64%** | [39% ; 84%] | 1 | 90% |
| `e6f98af` (calibração multi-sinal) | **13/14 = 93%** | [69% ; 99%] | 0 | 100% |

O único falso-negativo remanescente é `positivos/bare_blob.txt` — um blob de alta entropia **sem
contexto nenhum** (sem nome de variável, sem chave, sem provedor). É uma escolha deliberada de
calibração: detectar entropia solta sem contexto é a principal fonte de ruído em código real.
**Está registrado aqui como o custo consciente de manter o falso-positivo baixo.**

## Regra da casa

Quem alterar detecção **roda esta bateria antes e depois** e registra os dois números no CHANGELOG.
Um recall que sobe às custas de falso-positivo não é melhoria — é troca, e a troca precisa estar visível.

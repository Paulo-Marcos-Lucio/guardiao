# Corpus de referência do Guardião

Corpus rotulado, versionado, com script de avaliação. Existe por um motivo:
**número de detecção sem corpus público não é métrica, é lembrança.**

## Como reproduzir

```bash
pip install -e ".[dev]"
python bench/gerar.py                              # materializa os fixtures de formato sensível
guardiao scan bench/positivos bench/negativos -f json -o resultado.json
python bench/avaliar.py resultado.json
```

> **Por que `gerar.py` existe.** Um corpus de segredos não pode versionar segredos em
> **formato de produção**: o *push protection* do GitHub recusa o push — e está certo em
> recusar. Os casos de formato reconhecível (ex.: `sk_live_…`) ficam como molde em
> `bench/moldes/*.tpl` e são materializados em `bench/positivos/` na hora de rodar a
> bateria. O arquivo gerado está no `.gitignore`.
>
> **Por que a varredura é só `bench/positivos bench/negativos`, não `bench` inteiro.**
> `guardiao scan` não respeita `.gitignore` — não é o papel de um scanner de segredos
> ignorar o que o Git ignora. Se o alvo fosse `bench` inteiro, os moldes em
> `bench/moldes/*.tpl` (`TWILIO_API_KEY = "SK{32:hex}"` e afins: chave sensível, valor
> entre aspas com 8+ caracteres) disparariam `generic-assignment` de verdade, e como o
> caminho não começa com `positivos/`/`negativos/`, o achado não vira acerto nem
> falso-positivo em nenhum dos dois lados — só infla o denominador de `achados brutos`
> e derruba a precisão publicada sem nenhuma mudança real no detector.

## O que tem aqui

| | Quantidade | O que é |
|---|---|---|
| `positivos/` | 23 arquivos · **24 segredos rotulados** | Chave AWS, GCP, Slack, Stripe, GitHub PAT (clássico e fine-grained), GitLab PAT, npm, Slack webhook, SendGrid, Twilio, DigitalOcean, Hugging Face, Mercado Pago, Shopify, chave privada PEM, hex, string de conexão, YAML, JSON, segredo em comentário, blob de alta entropia, segredo em caminho de teste |
| `negativos/` | 7 arquivos · **14 linhas-armadilha** | `.env.example`, SHA de commit, UUID, literais de teste, senha canônica de fixture, ID técnico, documentação |
| `manifest.json` | 38 entradas | Rótulo de verdade: arquivo, linha, `eh_segredo`, tipo |

## O que este corpus **não** é

- **Não é campo.** Os segredos foram plantados por quem escreveu a ferramenta. O número mede
  *cobertura de formato conhecido*, não acurácia contra uma base arbitrária de produção.
- **Não cobre o catálogo inteiro.** São 24 tipos rotulados; o catálogo do Guardião tem mais regras
  (`cpf`, `cnpj`, `basic-auth-url`, `jwt`, `doppler-token`, `linear-api-key`, entre outras, ainda sem
  caso aqui). Uma regra sem caso aqui **não** está medida por este número (o meta-teste
  `test_toda_regra_do_catalogo_tem_caso_positivo` garante que ela tenha teste unitário, que é outra
  coisa).
- **Não tem tamanho de amostra para três algarismos.** Com n=24, o intervalo de confiança segue largo.
  Qualquer número derivado daqui deve vir com o IC, não com precisão falsa.

## Medição de referência

Medido em 2026-08-04, Python 3.12.8, Windows 11 (n=14):

| Versão | Recall | IC95% (Wilson) | Falso-positivo | Precisão |
|---|---|---|---|---|
| `31925fd` (público antes da calibração) | **9/14 = 64%** | [39% ; 84%] | 1 | 90% |
| `e6f98af` (calibração multi-sinal) | **13/14 = 93%** | [69% ; 99%] | 0 | 100% |

Medido em 2026-08-25, Python 3.11.15, Linux (n=24, corpus ampliado por `GRD-04` com 10 positivos de
tipos até então sem caso: `github-pat-fine-grained`, `gitlab-pat`, `npm-token`, `slack-webhook`,
`sendgrid-api-key`, `twilio-api-key`, `digitalocean-token`, `huggingface-token`,
`mercadopago-access-token`, `shopify-token`):

| Versão | Recall | IC95% (Wilson) | Falso-positivo | Precisão |
|---|---|---|---|---|
| `53d4e4d` (corpus ampliado, mesma detecção) | **23/24 = 96%** | [80% ; 99%] | 0 | 100% |

Os 10 casos novos foram todos detectados de primeira — nenhum é regra nova, só corpus que faltava
para as 10 que já existiam sem fixture. O IC ficou mais estreito ([69%;99%] tinha 30pp de largura,
[80%;99%] tem 19pp), que é o que se espera ao trocar n=14 por n=24 sem mudar o comportamento do
detector.

O único falso-negativo remanescente continua sendo `positivos/bare_blob.txt` — um blob de alta
entropia **sem contexto nenhum** (sem nome de variável, sem chave, sem provedor). É uma escolha
deliberada de calibração: detectar entropia solta sem contexto é a principal fonte de ruído em
código real. **Está registrado aqui como o custo consciente de manter o falso-positivo baixo.**

## Regra da casa

Quem alterar detecção **roda esta bateria antes e depois** e registra os dois números no CHANGELOG.
Um recall que sobe às custas de falso-positivo não é melhoria — é troca, e a troca precisa estar visível.

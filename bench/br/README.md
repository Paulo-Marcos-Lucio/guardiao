# Corpus de referência do detector BR (CPF/CNPJ)

Mede o que a conferência do dígito verificador (DV) — módulo 11 — compra para
as regras `cpf` e `cnpj`, inclusive o formato **CNPJ alfanumérico** vigente
desde 31/07/2026 (IN RFB nº 2.229/2024).

## Como reproduzir

```bash
python bench/br/avaliar.py
```

Não depende de `guardiao scan`: o corpus inteiro (`casos.py`) é feito de
textos curtos, rotulados em memória — não há arquivo a materializar nem
segredo a plantar em disco.

## O que tem aqui

| | Quantidade | O que é |
|---|---|---|
| positivos | 7 | CPF, CNPJ numérico e CNPJ alfanumérico, todos com DV correto |
| negativos — forma de documento, DV errado | 7 | CPF/CNPJ (inclusive alfanumérico) no formato certo, mas que não passa no módulo 11 — o caso que SÓ a regex aceitaria |
| negativos — ruído realista | 11 | telefone, ID/protocolo e timestamp — não têm a forma de CPF/CNPJ |

## Medição de referência

Medido em 2026-10-13, Python 3.12, n=25:

| Validação | Recall | Precisão | Falso-positivo |
|---|---|---|---|
| **COM DV** (regra real, `cpf_valido`/`cnpj_valido`) | 100% (7/7) | **100%** (7/7) | 0 |
| **SEM DV** (mesma regex, sem checar o módulo 11) | 100% (7/7) | **50%** (7/14) | 7 |

Os 7 falso-positivos de "sem DV" são todos número de pedido/nota/SKU/protocolo
no formato de CPF/CNPJ, com dígito verificador que não confere — exatamente a
classe que o `validator` das regras existe para cortar. Recall é igual nos
dois casos porque o validador só **rejeita**, nunca some com um positivo real.

## O que este corpus não é

- **Não é campo.** Os números foram montados por quem escreveu a ferramenta,
  calculando o DV pela fórmula publicada. Mede cobertura de formato
  conhecido, não acurácia contra uma base arbitrária de produção.
- **Não tem tamanho de amostra para três algarismos.** Com n=7 positivos, um
  número redondo (100%) não garante nada sobre a próxima amostra — é o
  mesmo aviso do corpus de segredos em `bench/README.md`.

## Regra da casa

Quem alterar `src/guardiao/rules/br.py` ou a regex das regras `cpf`/`cnpj`
roda esta bateria antes e depois e registra os dois números (com/sem DV) no
PR — é a mesma regra do corpus de segredos, aplicada ao detector de PII.

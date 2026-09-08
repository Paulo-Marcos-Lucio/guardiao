<p align="center"><a href="CONTRIBUTING.en.md"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/guardiao/main/assets/btn-lang-en.svg" alt="Read this document in English" width="300"/></a></p>

# Contribuindo

Contribuições são bem-vindas — especialmente **novas regras de detecção**.

## Ambiente

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Antes de abrir um PR

Rode a suíte de qualidade (é exatamente o que o CI verifica):

```bash
ruff check . && ruff format --check . && mypy src && pytest
```

## Adicionando uma regra

1. Acrescente uma entrada em `src/guardiao/rules/definitions.py` via `compile_rule(...)`.
2. Preencha **sempre** `owasp`, `cwe` e `recommendation` (há teste que exige isso).
3. Adicione um caso positivo **e** um negativo em `tests/test_rules.py`.
4. Se o valor tiver alta entropia genérica, use `min_entropy`; para exemplos de
   documentação, garanta que caem no filtro de placeholder.

Regras são **dados declarativos** — evite lógica nova no motor sempre que possível.

## Definição de pronto para correção de defeito

Corrigir o exemplo que apareceu no relatório e chamar de resolvido não fecha
o item: é preciso um teste que falhava contra o código anterior à correção,
mais um invariante — property-based com Hypothesis quando a classe for uma
família de entradas — que impeça a classe inteira de voltar. Critério e
exemplos reais em [`docs/definicao-de-pronto.md` da
Sentinela](https://github.com/Paulo-Marcos-Lucio/sentinela/blob/main/docs/definicao-de-pronto.md),
válido para as cinco ferramentas da suíte, não só para ela.

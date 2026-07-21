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

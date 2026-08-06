<p align="center"><a href="CONTRIBUTING.md"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/guardiao/main/assets/btn-lang-pt.svg" alt="Ler este documento em Português" width="300"/></a></p>

# Contributing

Contributions are welcome — especially **new detection rules**.

## Environment

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Before opening a PR

Run the quality suite (it's exactly what CI checks):

```bash
ruff check . && ruff format --check . && mypy src && pytest
```

## Adding a rule

1. Add an entry in `src/guardiao/rules/definitions.py` via `compile_rule(...)`.
2. **Always** fill in `owasp`, `cwe`, and `recommendation` (there's a test that requires it).
3. Add both a positive **and** a negative case in `tests/test_rules.py`.
4. If the value has generic high entropy, use `min_entropy`; for documentation examples,
   make sure they fall under the placeholder filter.

Rules are **declarative data** — avoid adding new logic to the engine whenever possible.

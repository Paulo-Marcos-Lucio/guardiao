"""Registro central de regras."""

from __future__ import annotations

from guardiao.rules.base import Rule
from guardiao.rules.definitions import default_rules


def all_rules() -> list[Rule]:
    """Todas as regras conhecidas, em ordem estável."""
    rules = default_rules()
    _assert_unique_ids(rules)
    return rules


def rules_by_id() -> dict[str, Rule]:
    return {rule.id: rule for rule in all_rules()}


def _assert_unique_ids(rules: list[Rule]) -> None:
    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:  # pragma: no cover - proteção de desenvolvimento
            raise ValueError(f"regra duplicada: {rule.id}")
        seen.add(rule.id)

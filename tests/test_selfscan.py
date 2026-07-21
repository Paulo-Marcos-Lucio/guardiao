"""Dogfooding: o próprio código-fonte do Guardião não pode conter segredos.

Os exemplos canônicos embutidos nas regras (ex.: `AKIAIOSFODNN7EXAMPLE`) devem
ser descartados pela heurística de placeholder — se algum vazar aqui, é bug.
"""

from __future__ import annotations

from pathlib import Path

from guardiao.core.engine import Scanner
from guardiao.core.models import Severity

SRC = Path(__file__).resolve().parents[1] / "src" / "guardiao"


def test_source_tree_is_clean() -> None:
    result = Scanner().scan_paths([SRC])
    offenders = [f for f in result.findings if f.severity.rank >= Severity.MEDIUM.rank]
    assert offenders == [], (
        f"segredo detectado no próprio código: {[f.location.as_str() for f in offenders]}"
    )

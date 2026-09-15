"""O badge de testes é gerado, não digitado (Classe C).

Trava a classe "número escrito à mão que ninguém re-mede": o total real coletado
tem de bater com o número anunciado no badge SVG. Reusa o MESMO código do portão
de CI (``scripts/check_test_count.py``) — uma implementação só, exercida de dois
lugares — para que o gate local e o gate do CI não possam divergir.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_test_count.py"


def _carrega_portao() -> object:
    spec = importlib.util.spec_from_file_location("check_test_count", _SCRIPT)
    assert spec is not None and spec.loader is not None
    modulo = importlib.util.module_from_spec(spec)
    sys.modules["check_test_count"] = modulo
    spec.loader.exec_module(modulo)
    return modulo


def test_badge_bate_com_a_contagem_real() -> None:
    portao = _carrega_portao()
    real = portao.coletados()  # type: ignore[attr-defined]
    badge = portao.declarado_no_badge()  # type: ignore[attr-defined]
    assert badge == real, (
        f"badge diz {badge}, pytest coletou {real}: atualize assets/chip-tests.svg "
        "e o alt-text do README."
    )

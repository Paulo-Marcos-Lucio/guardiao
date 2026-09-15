#!/usr/bin/env python3
"""Portão de contagem de testes: o número do badge é GERADO, não digitado à mão.

A auditoria cruzada da suíte pegou badges que contavam uma história antiga (o
Guardião anunciava "186 / 183 testes" com ~288 de verdade). A causa-raiz é um
número escrito à mão que ninguém re-mede. Este script fecha a classe: coleta o
total real (``pytest --collect-only``) e compara com o número declarado no badge
(``assets/chip-tests.svg``). Diverge → sai com código 1, e o CI reprova.

Referência da suíte: a Esteira já carrega o gate equivalente; os quatro tools
usam o MESMO script para que "badge honesto" seja uma invariante, não um hábito.

Uso:
    python scripts/check_test_count.py            # reprova na divergência
    python scripts/check_test_count.py --print    # só imprime o que mediu
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

_RAIZ = Path(__file__).resolve().parent.parent
_BADGE = _RAIZ / "assets" / "chip-tests.svg"
_RE_COLETADOS = re.compile(r"(\d+)\s+tests?\s+collected")
_RE_BADGE = re.compile(r"(\d+)\s+TESTS", re.IGNORECASE)


def coletados() -> int:
    """Total real de testes coletados (sem executar; sem cobertura, para ser rápido)."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-o", "addopts="],
        cwd=str(_RAIZ),
        capture_output=True,
        text=True,
        check=False,
    )
    achado = _RE_COLETADOS.search(proc.stdout)
    if achado is None:
        raise SystemExit(
            "não consegui ler o total coletado da saída do pytest:\n"
            + (proc.stdout or "")
            + (proc.stderr or "")
        )
    return int(achado.group(1))


def declarado_no_badge() -> int:
    """Número que o badge SVG anuncia — a fonte que o README referencia."""
    texto = _BADGE.read_text(encoding="utf-8")
    achado = _RE_BADGE.search(texto)
    if achado is None:
        raise SystemExit(f"não achei o número de testes em {_BADGE}")
    return int(achado.group(1))


def main() -> int:
    real = coletados()
    badge = declarado_no_badge()
    if "--print" in sys.argv[1:]:
        print(f"coletados={real} badge={badge}")
        return 0
    if real != badge:
        print(
            f"badge de testes desatualizado: o SVG diz {badge}, o pytest coletou {real}.\n"
            f"Atualize o número em {_BADGE.relative_to(_RAIZ)} (e o alt-text no README) "
            f"para {real}.",
            file=sys.stderr,
        )
        return 1
    print(f"badge de testes confere: {real} testes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

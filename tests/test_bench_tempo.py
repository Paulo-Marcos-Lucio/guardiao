"""Guarda de regressão para a medição de desempenho de `bench/tempo.py` (GRD-03).

Não compara contra o número exato publicado em `bench/README.md` — máquina de CI varia
run a run. Compara contra um teto largo (ver o racional em `bench/README.md`) que separa
"mesma ordem de grandeza" de "ficou Nx mais lento", que é justamente o sintoma de um
`git cat-file` por objeto voltando a substituir o `--batch-all-objects` único que
`sources/githistory.py` documenta como a razão de o histórico ser rápido.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

_BENCH = Path(__file__).resolve().parent.parent / "bench"
# ~24x a referência medida em bench/README.md (0,21s, 400 commits) — folga larga o
# bastante para não reagir a variação normal de máquina/CI, apertada o bastante para
# pegar uma regressão de ordem de grandeza.
_TETO_S = 5.0


def _carregar_tempo() -> ModuleType:
    """`bench/` não é um pacote instalado (é ferramenta de dev, não parte de `guardiao`);
    carrega `tempo.py` pelo caminho do arquivo, em vez de rodá-lo como subprocesso —
    assim o teste mede só `scan_git_history`, sem o overhead do interpretador Python."""
    spec = importlib.util.spec_from_file_location("bench_tempo", _BENCH / "tempo.py")
    assert spec is not None and spec.loader is not None
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def test_git_history_nao_regride_uma_ordem_de_grandeza() -> None:
    tempo = _carregar_tempo()
    repo = tempo.gerar_repositorio()
    decorrido = tempo.medir(repo)
    assert decorrido < _TETO_S, (
        f"--git-history levou {decorrido:.2f}s no repositório sintético de "
        f"{tempo.N_COMMITS} commits — teto de {_TETO_S}s (~24x a referência de "
        "bench/README.md) estourado. Ver sources/githistory.py: um único "
        "`git cat-file --batch-all-objects` virando um comando por objeto é a "
        "regressão de ordem de grandeza que este teste existe para pegar."
    )

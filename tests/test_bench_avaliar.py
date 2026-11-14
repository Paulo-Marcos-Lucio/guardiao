"""Invariantes do benchmark (`bench/avaliar.py`): PORTÃO de FP anti-regressão e
determinismo da avaliação.

`bench/` não roda no CI de hoje — é uma bateria manual (ver docstring de
`bench/avaliar.py`). Sem um gate automatizado, uma regressão no corpus rotulado só
aparece quando alguém lembra de rodar `guardiao scan bench` manualmente antes de
publicar. Estes dois testes fecham essa lacuna:

1. `portao_de_fp`: roda o motor REAL contra uma cópia materializada do corpus e trava
   se um falso-positivo aparecer em `negativos/` ou em linha errada de `positivos/`, ou
   se o recall cair abaixo do medido (13/14 — ver `test_bench_avaliar::test_portao_de_fp...`).
2. `avaliacao_e_deterministica`: a FUNÇÃO de avaliação (`avalia`) não pode depender da
   ordem em que os achados chegam no JSON — `scan_paths` varre arquivos sem ordem
   garantida entre execuções, e se a métrica dependesse de ordem, o mesmo scan rodado
   duas vezes poderia reportar recall/precisão diferentes.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from guardiao.core.engine import Scanner
from guardiao.report.json_report import finding_to_dict

_RAIZ = Path(__file__).resolve().parent.parent
_BENCH = _RAIZ / "bench"


def _carrega(nome: str, caminho: Path) -> Any:
    spec = importlib.util.spec_from_file_location(nome, caminho)
    assert spec is not None and spec.loader is not None
    modulo = importlib.util.module_from_spec(spec)
    sys.modules[nome] = modulo
    spec.loader.exec_module(modulo)
    return modulo


_AVALIAR = _carrega("bench_avaliar", _BENCH / "avaliar.py")
_GERAR = _carrega("bench_gerar", _BENCH / "gerar.py")


# ---- 1) PORTÃO de falso-positivo: motor real, corpus real, sem tolerância a regressão ---- #


def test_portao_de_fp_trava_regressao_no_corpus_rotulado(tmp_path: Path) -> None:
    """Medido nesta árvore: 0 FP em `negativos/`, 0 FP em linha errada de `positivos/`,
    recall 13/14 (o único FN aceito é `bare_blob.txt`, entropia pura sem formato de
    provedor — documentado no próprio `avaliar.py`). Se uma mudança no motor piorar
    qualquer um desses três números, este teste reprova.
    """
    copia = tmp_path / "bench"
    shutil.copytree(
        _BENCH,
        copia,
        ignore=shutil.ignore_patterns("resultado.json", "manifest.json", "__pycache__"),
    )
    _GERAR.materializa(str(copia))

    resultado_scan = Scanner().scan_paths([copia])
    achados = [finding_to_dict(f) for f in resultado_scan.findings]
    manifesto = json.loads((_BENCH / "manifest.json").read_text(encoding="utf-8"))

    resultado = _AVALIAR.avalia(manifesto, achados)

    assert resultado["fp_negativos"] == [], (
        f"regressão de classe: {len(resultado['fp_negativos'])} falso-positivo em "
        f"negativos/ (medido hoje: 0) -> {resultado['fp_negativos']}"
    )
    assert resultado["fp_em_positivos"] == [], (
        f"regressão de classe: {len(resultado['fp_em_positivos'])} achado em linha "
        f"errada de positivos/ (medido hoje: 0) -> {resultado['fp_em_positivos']}"
    )
    assert len(resultado["tp"]) >= 13, (
        f"recall caiu: {len(resultado['tp'])}/{len(resultado['positivos'])} "
        f"(medido hoje: 13/14) -> escaparam {[m['arquivo'] for m in resultado['fn']]}"
    )


# ---- 2) avaliação determinística: a métrica não pode depender da ordem dos achados ---- #

_MANIFESTO_SINTETICO = [
    {"arquivo": "positivos/a.py", "linha": 1, "eh_segredo": True, "tipo": "x"},
    {"arquivo": "positivos/b.py", "linha": 5, "eh_segredo": True, "tipo": "x"},
    {"arquivo": "positivos/c.py", "linha": 9, "eh_segredo": True, "tipo": "x"},
    {"arquivo": "negativos/d.py", "linha": 1, "eh_segredo": False, "tipo": "x"},
]

# TP exato (a.py:1), TP com tolerância de 1 linha (b.py:6), FP em negativos (d.py:1),
# achado em linha errada de um positivo que também fica de fora (c.py:50) — as quatro
# categorias que `avalia` discrimina, numa única lista para embaralhar.
_ACHADOS_SINTETICOS = [
    {"path": "positivos/a.py", "line": 1},
    {"path": "positivos/b.py", "line": 6},
    {"path": "negativos/d.py", "line": 1},
    {"path": "positivos/c.py", "line": 50},
]


@settings(max_examples=100)
@given(ordem=st.permutations(_ACHADOS_SINTETICOS))
def test_avaliacao_e_deterministica_sob_qualquer_ordem(ordem: list[dict[str, Any]]) -> None:
    referencia = _AVALIAR.avalia(_MANIFESTO_SINTETICO, _ACHADOS_SINTETICOS)
    resultado = _AVALIAR.avalia(_MANIFESTO_SINTETICO, list(ordem))

    assert resultado["recall"] == referencia["recall"]
    assert resultado["precisao"] == referencia["precisao"]
    assert resultado["ic_wilson"] == referencia["ic_wilson"]
    assert {m["arquivo"] for m in resultado["tp"]} == {m["arquivo"] for m in referencia["tp"]}
    assert {m["arquivo"] for m in resultado["fn"]} == {m["arquivo"] for m in referencia["fn"]}
    assert resultado["fp_negativos"] == referencia["fp_negativos"]
    assert resultado["fp_em_positivos"] == referencia["fp_em_positivos"]


@settings(max_examples=50)
@given(
    duplicatas=st.integers(min_value=0, max_value=5),
    ordem=st.permutations(_ACHADOS_SINTETICOS),
)
def test_avaliacao_e_deterministica_sob_duplicata_de_achado(
    duplicatas: int, ordem: list[dict[str, Any]]
) -> None:
    """A mesma invariante, agora também sob achados repetidos (dedupe de rede, retry de
    paralelismo) — duplicar uma linha encontrada não pode inflar TP nem mudar o recall.
    """
    referencia = _AVALIAR.avalia(_MANIFESTO_SINTETICO, _ACHADOS_SINTETICOS)
    com_duplicatas = list(ordem) + [ordem[0]] * duplicatas if ordem else list(ordem)
    resultado = _AVALIAR.avalia(_MANIFESTO_SINTETICO, com_duplicatas)

    assert resultado["recall"] == referencia["recall"]
    assert {m["arquivo"] for m in resultado["tp"]} == {m["arquivo"] for m in referencia["tp"]}

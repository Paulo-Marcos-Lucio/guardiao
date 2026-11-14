"""Portão anti-regressão do benchmark (G-13c) — invariante de CLASSE, não por-exemplo.

`bench/portao.py` decide verde/vermelho comparando o medido contra o teto versionado
em `bench/limpo/teto.json`. O que precisa estar travado não é o número de hoje (13/14
recall, 0 FP) — é a REGRA de decisão: "recall abaixo do piso ou FP/1k acima do teto
reprova; dentro dos dois, passa", para qualquer medição futura, não só a atual.

Ataca a classe com Hypothesis: gera (recall, fp_por_mil, teto) e afirma a propriedade
em vez de fixar o caso de hoje — se `avalia()` for reescrito e passar a deixar uma
regressão passar despercebida, a propriedade cai para toda a família de entradas.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

_SCRIPT = Path(__file__).resolve().parent.parent / "bench" / "portao.py"


def _carrega_portao() -> object:
    spec = importlib.util.spec_from_file_location("bench_portao", _SCRIPT)
    assert spec is not None and spec.loader is not None
    modulo = importlib.util.module_from_spec(spec)
    sys.modules["bench_portao"] = modulo
    spec.loader.exec_module(modulo)
    return modulo


portao = _carrega_portao()

_FRACAO = st.floats(min_value=0.0, max_value=1.0, allow_nan=False)
_FPMIL = st.floats(min_value=0.0, max_value=1000.0, allow_nan=False)


@given(recall=_FRACAO, piso=_FRACAO, fp_por_mil=_FPMIL, teto=_FPMIL)
def test_portao_fecha_sempre_que_algum_eixo_regride(
    recall: float, piso: float, fp_por_mil: float, teto: float
) -> None:
    medida = {"recall": recall, "fp_por_mil": fp_por_mil, "fp_negativos": 0.0}
    teto_versionado = {"recall_minimo": piso, "fp_por_mil_maximo": teto}
    violacoes = portao.avalia(medida, teto_versionado)  # type: ignore[attr-defined]

    regrediu = recall < piso or fp_por_mil > teto
    assert bool(violacoes) == regrediu


@given(recall=_FRACAO, piso=_FRACAO, fp_por_mil=_FPMIL, teto=_FPMIL)
def test_violacao_de_recall_e_de_fp_sao_discriminadas(
    recall: float, piso: float, fp_por_mil: float, teto: float
) -> None:
    """Quem lê a violação sabe qual eixo regrediu, não só "algo piorou"."""
    medida = {"recall": recall, "fp_por_mil": fp_por_mil, "fp_negativos": 0.0}
    teto_versionado = {"recall_minimo": piso, "fp_por_mil_maximo": teto}
    violacoes = portao.avalia(medida, teto_versionado)  # type: ignore[attr-defined]
    texto = " ".join(violacoes)

    assert ("recall caiu" in texto) == (recall < piso)
    assert ("FP/1k subiu" in texto) == (fp_por_mil > teto)


def test_teto_versionado_bate_com_a_ultima_medicao_registrada() -> None:
    """`bench/limpo/teto.json` não pode anunciar um piso que o próprio relatório de
    `bench/README.md` (13/14 recall, 0 FP em 31 linhas de bench/negativos) não cumpre.

    Não repete o scan (isso é o job `benchmark.yml`, que depende de materializar os
    fixtures .tpl); fixa a leitura honesta do número já medido e versionado, para que
    um teto editado à mão sem rodar a bateria de novo não passe desapercebido.
    """
    import json

    base = _SCRIPT.parent
    with open(base / "limpo" / "teto.json", encoding="utf-8") as fh:
        teto = json.load(fh)

    medida_registrada = {"recall": 13 / 14, "fp_por_mil": 0.0, "fp_negativos": 0.0}
    assert not portao.avalia(medida_registrada, teto)  # type: ignore[attr-defined]

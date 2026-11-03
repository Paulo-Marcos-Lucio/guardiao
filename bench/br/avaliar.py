"""Mede a regra `cpf`/`cnpj` do Guardião contra `casos.py`: precisão COM a
conferência do dígito verificador (DV) vs. SEM ela (regex pura).

Uso:
    python bench/br/avaliar.py

Não depende de arquivo em disco nem de `guardiao scan`: cada caso é um texto
curto, então o corpus inteiro vive em `casos.py` e este script só soma.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))

from casos import CASOS, Caso

from guardiao.core.engine import Scanner
from guardiao.rules.registry import all_rules

_REGRAS_PII = {rule.id: rule for rule in all_rules() if rule.category == "pii"}
_IDS_PII = tuple(_REGRAS_PII)


def _com_dv(caso: Caso) -> bool:
    """O motor real (regra valida o DV) acha `cpf`/`cnpj` neste texto?"""
    return any(a.rule_id in _IDS_PII for a in Scanner().scan_text("bench_br.txt", caso.texto))


def _sem_dv(caso: Caso) -> bool:
    """A MESMA regex, sem chamar o validador — simula a regra sem conferir o DV."""
    return any(_REGRAS_PII[rid].regex.search(caso.texto) for rid in _IDS_PII)


def _precisao(acertos_tp: int, achados: int) -> float:
    return acertos_tp / achados if achados else 1.0


def _avaliar(nome: str, prever: Callable[[Caso], bool]) -> None:
    tp = fp = fn = tn = 0
    falsos_positivos: list[str] = []
    for caso in CASOS:
        achou = prever(caso)
        if achou and caso.eh_pii:
            tp += 1
        elif achou and not caso.eh_pii:
            fp += 1
            falsos_positivos.append(f"{caso.tipo}: {caso.texto!r}")
        elif not achou and caso.eh_pii:
            fn += 1
        else:
            tn += 1
    achados = tp + fp
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    print(f"-- {nome} --")
    print(f"  TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"  RECALL   : {recall:.0%}")
    print(f"  PRECISÃO : {_precisao(tp, achados):.0%}  ({tp}/{achados})")
    if falsos_positivos:
        print("  FALSO-POSITIVO:")
        for item in falsos_positivos:
            print(f"    - {item}")
    print()


def main() -> None:
    positivos = sum(1 for c in CASOS if c.eh_pii)
    negativos = len(CASOS) - positivos
    print(f"corpus: {len(CASOS)} casos ({positivos} positivos, {negativos} negativos)\n")
    _avaliar("COM conferência de DV (motor real)", _com_dv)
    _avaliar("SEM conferência de DV (regex pura)", _sem_dv)


if __name__ == "__main__":
    main()

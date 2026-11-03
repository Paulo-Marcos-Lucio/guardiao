"""Portão anti-regressão do benchmark: reprova o CI se FP/1k subir ou recall cair.

O corpus de `bench/` já media recall e falso-positivo (`avaliar.py`), mas só para
leitura humana — nada impedia um PR piorar os dois números sem que ninguém
notasse antes da revisão. Este script mede os mesmos dois eixos e compara contra
o teto **versionado** em `bench/limpo/teto.json`: sai com código 1 se o medido for
pior que o teto, 0 caso contrário.

Uso:
    guardiao scan bench -f json -o resultado.json --fail-on none
    python bench/portao.py resultado.json
"""

from __future__ import annotations

import json
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))


def normaliza(caminho: object) -> str:
    """Reduz um caminho absoluto ao par `positivos/arquivo` ou `negativos/arquivo`."""
    texto = str(caminho).replace(chr(92), "/")
    for prefixo in ("positivos/", "negativos/"):
        if prefixo in texto:
            return prefixo + texto.split(prefixo, 1)[1]
    return os.path.basename(texto)


def casou(achados: list[tuple[str, int]], arquivo: str, linha: int) -> bool:
    """Tolera 1 linha de diferença: o rótulo aponta a linha do segredo, não a do bloco."""
    return any(arquivo == af and abs((linha or 0) - (al or 0)) <= 1 for af, al in achados)


def conta_linhas_negativas(base: str = BASE) -> int:
    """Total de linhas em `bench/negativos/` — o denominador do FP/1k."""
    pasta = os.path.join(base, "negativos")
    total = 0
    for nome in sorted(os.listdir(pasta)):
        caminho = os.path.join(pasta, nome)
        if os.path.isfile(caminho):
            with open(caminho, encoding="utf-8") as fh:
                total += sum(1 for _ in fh)
    return total


def mede(relatorio: dict, manifesto: list, total_linhas_negativas: int) -> dict[str, float]:
    """Recall e FP/1k medidos no `relatorio` (JSON do `guardiao scan`) contra o `manifesto`."""
    brutos = relatorio.get("achados") or relatorio.get("findings") or []
    achados = [
        (normaliza(a.get("path") or a.get("arquivo") or ""), a.get("line") or a.get("linha") or 0)
        for a in brutos
    ]
    positivos = [m for m in manifesto if m["eh_segredo"]]
    acertos = [m for m in positivos if casou(achados, m["arquivo"], m["linha"])]
    fp_negativos = [(f, ln) for (f, ln) in achados if f.startswith("negativos/")]

    recall = len(acertos) / len(positivos) if positivos else 0.0
    fp_por_mil = (
        len(fp_negativos) / total_linhas_negativas * 1000 if total_linhas_negativas else 0.0
    )
    return {"recall": recall, "fp_por_mil": fp_por_mil, "fp_negativos": float(len(fp_negativos))}


def avalia(medida: dict[str, float], teto: dict[str, float]) -> list[str]:
    """Violações do teto; lista vazia significa portão aberto."""
    violacoes = []
    if medida["fp_por_mil"] > teto["fp_por_mil_maximo"]:
        violacoes.append(
            f"FP/1k subiu: {medida['fp_por_mil']:.2f} > teto {teto['fp_por_mil_maximo']:.2f}"
        )
    if medida["recall"] < teto["recall_minimo"]:
        violacoes.append(f"recall caiu: {medida['recall']:.2%} < piso {teto['recall_minimo']:.2%}")
    return violacoes


def main(argv: list[str]) -> int:
    resultado_path = argv[1] if len(argv) > 1 else os.path.join(BASE, "resultado.json")
    with open(os.path.join(BASE, "manifest.json"), encoding="utf-8") as fh:
        manifesto = json.load(fh)
    with open(os.path.join(BASE, "limpo", "teto.json"), encoding="utf-8") as fh:
        teto = json.load(fh)
    with open(resultado_path, encoding="utf-8") as fh:
        relatorio = json.load(fh)

    medida = mede(relatorio, manifesto, conta_linhas_negativas())
    violacoes = avalia(medida, teto)

    print(f"  recall medido : {medida['recall']:.2%}  (piso {teto['recall_minimo']:.2%})")
    print(
        f"  FP/1k medido  : {medida['fp_por_mil']:.2f}  (teto {teto['fp_por_mil_maximo']:.2f}, "
        f"{int(medida['fp_negativos'])} FP em bench/negativos)"
    )
    if violacoes:
        print("PORTÃO FECHADO — regressão contra bench/limpo/teto.json:")
        for violacao in violacoes:
            print(f"  - {violacao}")
        return 1
    print("PORTÃO ABERTO: nenhuma regressão contra o teto versionado.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

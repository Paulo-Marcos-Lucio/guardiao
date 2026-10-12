"""Mede o Guardião contra o corpus rotulado de `bench/`.

Uso:
    guardiao scan bench -f json -o resultado.json
    python bench/avaliar.py resultado.json

Imprime recall com intervalo de confiança de Wilson — porque com n=14 um número
redondo sozinho anuncia uma precisão que a amostra não comporta.

A lógica de avaliação (`avalia`) é uma função pura — recebe o manifesto e os achados,
devolve as métricas — para que `tests/test_bench_avaliar.py` possa exercê-la como
PORTÃO (gate de regressão no corpus rotulado) e como propriedade (determinismo
independente da ordem dos achados), sem depender de arquivo em disco nem de `sys.argv`.
"""

from __future__ import annotations

import json
import math
import os
import sys
from typing import Any

BASE = os.path.dirname(os.path.abspath(__file__))


def normaliza(caminho: object) -> str:
    """Reduz um caminho absoluto ao par `positivos/arquivo` ou `negativos/arquivo`."""
    texto = str(caminho).replace(chr(92), "/")
    for prefixo in ("positivos/", "negativos/"):
        if prefixo in texto:
            return prefixo + texto.split(prefixo, 1)[1]
    return os.path.basename(texto)


def casou(encontrados: list[tuple[str, int]], arquivo: str, linha: int) -> bool:
    """Tolera 1 linha de diferença: o rótulo aponta a linha do segredo, não a do bloco."""
    return any(arquivo == af and abs((linha or 0) - (al or 0)) <= 1 for af, al in encontrados)


def wilson(acertos: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Intervalo de confiança de Wilson — honesto para amostra pequena."""
    if total == 0:
        return (0.0, 0.0)
    p = acertos / total
    denom = 1 + z * z / total
    centro = (p + z * z / (2 * total)) / denom
    margem = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return (max(0.0, centro - margem), min(1.0, centro + margem))


def avalia(manifesto: list[dict[str, Any]], achados_brutos: list[dict[str, Any]]) -> dict[str, Any]:
    """Núcleo puro da avaliação: TP/FN/FP, recall, precisão e IC de Wilson.

    Não lê arquivo nem depende de ordem — `manifesto` e `achados_brutos` chegam prontos,
    e o resultado é determinístico para qualquer permutação de `achados_brutos`
    (ver `test_avaliacao_e_deterministica_sob_qualquer_ordem`).
    """
    encontrados = [
        (normaliza(a.get("path") or a.get("arquivo") or ""), a.get("line") or a.get("linha") or 0)
        for a in achados_brutos
    ]

    positivos = [m for m in manifesto if m["eh_segredo"]]
    tp = [m for m in positivos if casou(encontrados, m["arquivo"], m["linha"])]
    fn = [m for m in positivos if not casou(encontrados, m["arquivo"], m["linha"])]
    fp_negativos = sorted({(f, ln) for (f, ln) in encontrados if f.startswith("negativos/")})

    linhas_positivas = {(m["arquivo"], m["linha"]) for m in positivos}
    fp_em_positivos = sorted(
        {
            (f, ln)
            for (f, ln) in encontrados
            if f.startswith("positivos/")
            and not any(f == pf and abs((ln or 0) - pl) <= 1 for pf, pl in linhas_positivas)
        }
    )

    recall = len(tp) / len(positivos) if positivos else 0.0
    baixo, alto = wilson(len(tp), len(positivos))
    precisao = len(tp) / len(encontrados) if encontrados else 0.0

    return {
        "encontrados": encontrados,
        "positivos": positivos,
        "tp": tp,
        "fn": fn,
        "fp_negativos": fp_negativos,
        "fp_em_positivos": fp_em_positivos,
        "recall": recall,
        "ic_wilson": (baixo, alto),
        "precisao": precisao,
    }


def imprime(resultado: dict[str, Any], nome_arquivo: str) -> None:
    tp, fn = resultado["tp"], resultado["fn"]
    positivos, encontrados = resultado["positivos"], resultado["encontrados"]
    fp_negativos, fp_em_positivos = resultado["fp_negativos"], resultado["fp_em_positivos"]
    baixo, alto = resultado["ic_wilson"]

    print(f"== {os.path.basename(nome_arquivo)} ==")
    print(f"  achados brutos : {len(encontrados)}")
    print(
        f"  RECALL         : {len(tp)}/{len(positivos)} = {resultado['recall']:.0%}   "
        f"IC95% = [{baixo:.0%} ; {alto:.0%}]"
    )
    print(
        f"  FALSO-POSITIVO : {len(fp_negativos)} em negativos | {len(fp_em_positivos)} em linha errada"
    )
    print(f"  PRECISÃO       : {len(tp)}/{len(encontrados)} = {resultado['precisao']:.0%}")
    if fn:
        print("  FALSO-NEGATIVO (o que escapou):")
        for item in fn:
            print(f"    - {item['arquivo']}:{item['linha']}  [{item.get('tipo', '?')}]")
    if fp_negativos:
        print("  FALSO-POSITIVO em negativos:")
        for arquivo, linha in fp_negativos[:8]:
            print(f"    - {arquivo}:{linha}")


def main() -> None:
    with open(os.path.join(BASE, "manifest.json"), encoding="utf-8") as fh:
        manifesto = json.load(fh)

    caminho_resultado = sys.argv[1] if len(sys.argv) > 1 else os.path.join(BASE, "resultado.json")
    with open(caminho_resultado, encoding="utf-8") as fh:
        relatorio = json.load(fh)
    achados_brutos = relatorio.get("achados") or relatorio.get("findings") or []

    imprime(avalia(manifesto, achados_brutos), caminho_resultado)


if __name__ == "__main__":
    main()

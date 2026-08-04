"""Mede o Guardião contra o corpus rotulado de `bench/`.

Uso:
    guardiao scan bench -f json -o resultado.json
    python bench/avaliar.py resultado.json

Imprime recall com intervalo de confiança de Wilson — porque com n=14 um número
redondo sozinho anuncia uma precisão que a amostra não comporta.
"""

import json
import math
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(BASE, "manifest.json"), encoding="utf-8") as fh:
    MANIFESTO = json.load(fh)

RESULTADO = sys.argv[1] if len(sys.argv) > 1 else os.path.join(BASE, "resultado.json")
with open(RESULTADO, encoding="utf-8") as fh:
    RELATORIO = json.load(fh)

ACHADOS = RELATORIO.get("achados") or RELATORIO.get("findings") or []


def normaliza(caminho: object) -> str:
    """Reduz um caminho absoluto ao par `positivos/arquivo` ou `negativos/arquivo`."""
    texto = str(caminho).replace(chr(92), "/")
    for prefixo in ("positivos/", "negativos/"):
        if prefixo in texto:
            return prefixo + texto.split(prefixo, 1)[1]
    return os.path.basename(texto)


ENCONTRADOS = [
    (normaliza(a.get("path") or a.get("arquivo") or ""), a.get("line") or a.get("linha") or 0)
    for a in ACHADOS
]


def casou(arquivo: str, linha: int) -> bool:
    """Tolera 1 linha de diferença: o rótulo aponta a linha do segredo, não a do bloco."""
    return any(arquivo == af and abs((linha or 0) - (al or 0)) <= 1 for af, al in ENCONTRADOS)


def wilson(acertos: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Intervalo de confiança de Wilson — honesto para amostra pequena."""
    if total == 0:
        return (0.0, 0.0)
    p = acertos / total
    denom = 1 + z * z / total
    centro = (p + z * z / (2 * total)) / denom
    margem = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return (max(0.0, centro - margem), min(1.0, centro + margem))


POSITIVOS = [m for m in MANIFESTO if m["eh_segredo"]]
TP = [m for m in POSITIVOS if casou(m["arquivo"], m["linha"])]
FN = [m for m in POSITIVOS if not casou(m["arquivo"], m["linha"])]
FP_NEGATIVOS = [(f, ln) for (f, ln) in ENCONTRADOS if f.startswith("negativos/")]

LINHAS_POSITIVAS = {(m["arquivo"], m["linha"]) for m in POSITIVOS}
FP_EM_POSITIVOS = [
    (f, ln)
    for (f, ln) in ENCONTRADOS
    if f.startswith("positivos/")
    and not any(f == pf and abs((ln or 0) - pl) <= 1 for pf, pl in LINHAS_POSITIVAS)
]

recall = len(TP) / len(POSITIVOS) if POSITIVOS else 0.0
baixo, alto = wilson(len(TP), len(POSITIVOS))
precisao = len(TP) / len(ENCONTRADOS) if ENCONTRADOS else 0.0

print(f"== {os.path.basename(RESULTADO)} ==")
print(f"  achados brutos : {len(ENCONTRADOS)}")
print(
    f"  RECALL         : {len(TP)}/{len(POSITIVOS)} = {recall:.0%}   IC95% = [{baixo:.0%} ; {alto:.0%}]"
)
print(
    f"  FALSO-POSITIVO : {len(FP_NEGATIVOS)} em negativos | {len(FP_EM_POSITIVOS)} em linha errada"
)
print(f"  PRECISÃO       : {len(TP)}/{len(ENCONTRADOS)} = {precisao:.0%}")
if FN:
    print("  FALSO-NEGATIVO (o que escapou):")
    for item in FN:
        print(f"    - {item['arquivo']}:{item['linha']}  [{item.get('tipo', '?')}]")
if FP_NEGATIVOS:
    print("  FALSO-POSITIVO em negativos:")
    for arquivo, linha in FP_NEGATIVOS[:8]:
        print(f"    - {arquivo}:{linha}")

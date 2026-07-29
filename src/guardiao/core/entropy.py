"""Entropia de Shannon e critério de "alta entropia" corrigido pelo viés de amostragem.

Segredos gerados aleatoriamente (chaves, tokens) têm entropia por caractere bem
mais alta do que texto/identificadores comuns. Medir isso é o que permite pegar
segredos genéricos que nenhuma regex específica conhece.

Por que **não** comparamos a entropia crua contra um limiar fixo em bits/char
----------------------------------------------------------------------------
O estimador plug-in (:func:`shannon_entropy`) é enviesado **para baixo** em
cadeias curtas: ele não pode passar de ``log2(n)``, e o valor esperado fica
abaixo da entropia real por cerca de ``(k-1)/(2·n·ln2)`` (``k`` = símbolos
distintos observados). Comparado a um limiar absoluto de 4,3 bits/char, um
segredo genuinamente aleatório de 24 caracteres era aceito em apenas 39% das
vezes — e um de 24 caracteres alfanuméricos minúsculos, em 3%. Isso é
falso-negativo puro, criado pelo estimador e não pelo segredo.

O critério atual corrige o viés com **Miller-Madow** e compara o resultado a uma
*fração* do máximo teórico do alfabeto do token, em vez de a um número absoluto.
Calibração medida sobre 5.992 segredos aleatórios (base62/alnum/hex/urlsafe, de
24 a 128 chars) contra 12.206 cadeias distintas de 24+ chars extraídas de código
real (``src/`` dos repositórios da suíte + ``site-packages`` de três venvs):

===========================================  =======  ================
critério                                     recall   falso-positivo
===========================================  =======  ================
antigo (H ≥ 4,3 base64 / H ≥ 3,0 hex)         85,3%   282 / 12.206
atual (H_MM ≥ 0,80 · log2(|A|))               94,9%   239 / 12.206
===========================================  =======  ================

Ou seja: o critério novo ganha recall **e** perde falso-positivo ao mesmo tempo —
não é uma troca, é correção de um erro de estimação.
"""

from __future__ import annotations

import math
import string
from collections import Counter

#: Comprimento mínimo de um candidato a segredo. Fonte única: o regex da regra de
#: entropia (``rules/definitions.py``) usa esta mesma constante.
MIN_SECRET_LEN = 24

#: Fração do máximo teórico do alfabeto exigida de um token para ele ser considerado
#: aleatório. Calibrado pela curva de FP/FN descrita no cabeçalho deste módulo.
FRACAO_MINIMA = 0.80

_HEX = frozenset("0123456789abcdefABCDEF")
_ALNUM_MINUSCULO = frozenset(string.ascii_lowercase + string.digits)
_ALNUM_MAIUSCULO = frozenset(string.ascii_uppercase + string.digits)


def shannon_entropy(data: str) -> float:
    """Entropia de Shannon (estimador plug-in) em bits por caractere."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def entropia_corrigida(token: str) -> float:
    """Entropia com correção de viés de Miller-Madow: ``H + (k-1)/(2·n·ln2)``.

    ``k`` é o número de símbolos distintos observados. A correção compensa o viés
    negativo do estimador plug-in em amostras curtas — é o que torna o critério
    comparável entre um token de 24 e um de 128 caracteres.
    """
    if not token:
        return 0.0
    distintos = len(set(token))
    return shannon_entropy(token) + (distintos - 1) / (2 * len(token) * math.log(2))


def tamanho_do_alfabeto(token: str) -> int:
    """Tamanho do alfabeto **teórico** de onde o token plausivelmente veio."""
    chars = set(token)
    if chars <= _HEX:
        return 16
    if chars <= _ALNUM_MINUSCULO or chars <= _ALNUM_MAIUSCULO:
        return 36
    return 64


def is_high_entropy(
    token: str,
    *,
    fracao_minima: float = FRACAO_MINIMA,
    min_length: int = MIN_SECRET_LEN,
) -> bool:
    """Decide se ``token`` é compatível com uma cadeia gerada aleatoriamente."""
    if len(token) < min_length:
        return False
    return entropia_corrigida(token) >= fracao_minima * math.log2(tamanho_do_alfabeto(token))

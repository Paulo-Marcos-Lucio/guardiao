"""Entropia de Shannon e heurística de alta entropia.

Segredos gerados aleatoriamente (chaves, tokens) têm entropia por caractere bem
mais alta do que texto/identificadores comuns. Medir isso é o que permite pegar
segredos genéricos que nenhuma regex específica conhece.
"""

from __future__ import annotations

import math
from collections import Counter

_HEX = set("0123456789abcdefABCDEF")
_BASE64 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_")


def shannon_entropy(data: str) -> float:
    """Entropia de Shannon em bits por caractere."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def charset_of(token: str) -> str:
    chars = set(token)
    if chars <= _HEX:
        return "hex"
    if chars <= _BASE64:
        return "base64"
    return "mixed"


def is_high_entropy(
    token: str,
    *,
    base64_threshold: float = 4.3,
    hex_threshold: float = 3.0,
    min_length: int = 20,
) -> bool:
    """Decide se ``token`` parece um segredo aleatório.

    Usa limiares diferentes por alfabeto: hexadecimal tem no máximo 4 bits/char,
    então exige menos; base64/mixed exige mais.
    """
    if len(token) < min_length:
        return False
    entropy = shannon_entropy(token)
    if charset_of(token) == "hex":
        return entropy >= hex_threshold
    return entropy >= base64_threshold

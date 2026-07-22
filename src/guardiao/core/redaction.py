"""Ocultação de segredos.

Regra de ouro da ferramenta: **o segredo cru nunca sai** para o terminal, JSON
ou SARIF. Mostramos só o suficiente para o dono identificar qual credencial é
(as pontas), sem vazar o valor nem o comprimento exato.
"""

from __future__ import annotations

from collections.abc import Iterable


def redact(secret: str, *, keep: int = 4) -> str:
    """Mascara um segredo preservando apenas as pontas."""
    s = secret.strip()
    n = len(s)
    if n == 0:
        return ""
    # Se as pontas quase se encontram, revela quase nada (e não vaza o comprimento).
    if n <= 2 * keep + 4:
        return s[0] + "…"
    return f"{s[:keep]}…{s[-keep:]}"


def redact_line(line: str, secret: str, *, keep: int = 4) -> str:
    """Devolve a linha com **todas** as ocorrências do segredo mascaradas."""
    stripped = line.strip("\n\r")
    if not secret:
        return stripped.strip()
    masked = redact(secret, keep=keep)
    return stripped.replace(secret, masked).strip()


def redact_spans(line: str, spans: Iterable[tuple[int, int, str]], *, keep: int = 4) -> str:
    """Mascara **todos** os segredos de uma linha, um por span (início, fim, segredo).

    Aplica da direita para a esquerda para não deslocar os índices dos spans
    ainda não processados. Garante que nenhum segredo cru sobre no preview,
    mesmo com vários segredos (iguais ou distintos) na mesma linha.
    """
    result = line.strip("\n\r")
    for start, end, secret in sorted(spans, key=lambda s: s[0], reverse=True):
        if 0 <= start < end <= len(result) and result[start:end] == secret:
            result = result[:start] + redact(secret, keep=keep) + result[end:]
        else:  # fallback defensivo (spans sobrepostos/deslocados)
            result = result.replace(secret, redact(secret, keep=keep))
    return result.strip()

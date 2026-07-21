"""Ocultação de segredos.

Regra de ouro da ferramenta: **o segredo cru nunca sai** para o terminal, JSON
ou SARIF. Mostramos só o suficiente para o dono identificar qual credencial é
(as pontas), sem vazar o valor nem o comprimento exato.
"""

from __future__ import annotations


def redact(secret: str, *, keep: int = 4) -> str:
    """Mascara um segredo preservando apenas as pontas."""
    s = secret.strip()
    n = len(s)
    if n == 0:
        return ""
    if n <= 8:
        return s[0] + "…"
    return f"{s[:keep]}…{s[-keep:]}"


def redact_line(line: str, secret: str, *, keep: int = 4) -> str:
    """Devolve a linha com a primeira ocorrência do segredo mascarada."""
    stripped = line.strip("\n\r")
    if not secret:
        return stripped.strip()
    masked = redact(secret, keep=keep)
    return stripped.replace(secret, masked, 1).strip()

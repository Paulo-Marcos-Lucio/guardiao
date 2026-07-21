"""Modelos de domínio do Guardião.

O objeto :class:`Finding` guarda o segredo cru em ``secret`` apenas para permitir
gerar a *fingerprint* estável (usada no baseline). Esse campo **nunca** é
serializado nem impresso — os renderizadores usam exclusivamente ``redacted``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    """Severidade de um achado, ancorada nas faixas usuais do CVSS."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def from_name(cls, name: str) -> Severity:
        try:
            return cls(name.strip().lower())
        except ValueError as exc:  # pragma: no cover - validação de CLI
            valid = ", ".join(s.value for s in cls)
            raise ValueError(f"severidade inválida: {name!r} (use uma de: {valid})") from exc


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class Location:
    """Onde um segredo foi encontrado."""

    path: str
    line: int
    column: int = 1
    commit: str | None = None

    def as_str(self) -> str:
        base = f"{self.path}:{self.line}"
        return f"{base}@{self.commit}" if self.commit else base


@dataclass(frozen=True)
class Finding:
    """Um segredo potencial encontrado por uma regra."""

    rule_id: str
    title: str
    severity: Severity
    location: Location
    secret: str
    redacted: str
    line_preview: str
    entropy: float | None = None
    cwe: str | None = None
    owasp: str | None = None
    category: str = "secret"
    recommendation: str = ""

    @property
    def fingerprint(self) -> str:
        """Identidade estável de um achado — independente da linha exata.

        Baseada em (regra, arquivo, hash do segredo), para que mover o código
        não invalide o baseline, mas trocar o segredo sim.
        """
        digest = hashlib.sha256()
        digest.update(self.rule_id.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(self.location.path.replace("\\", "/").encode("utf-8"))
        digest.update(b"\x00")
        digest.update(self.secret.encode("utf-8"))
        return digest.hexdigest()[:16]

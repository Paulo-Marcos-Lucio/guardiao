"""Definição de uma regra de detecção."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from guardiao.core.models import Severity


@dataclass(frozen=True)
class RuleMatch:
    """Um trecho casado por uma regra dentro de uma linha."""

    start: int
    end: int
    secret: str


@dataclass(frozen=True)
class Rule:
    """Regra baseada em expressão regular.

    ``secret_group`` indica qual grupo da regex contém o segredo em si (0 = o
    casamento inteiro). ``min_entropy`` e ``keywords`` são filtros aplicados pelo
    motor para reduzir falso-positivo.
    """

    id: str
    title: str
    severity: Severity
    regex: re.Pattern[str]
    cwe: str | None = None
    owasp: str | None = None
    category: str = "secret"
    recommendation: str = ""
    secret_group: int = 0
    min_entropy: float | None = None
    keywords: tuple[str, ...] = field(default_factory=tuple)

    def find(self, text: str) -> Iterator[RuleMatch]:
        for match in self.regex.finditer(text):
            group = self.secret_group
            secret = match.group(group)
            if secret is None:
                continue
            yield RuleMatch(match.start(group), match.end(group), secret)


def compile_rule(
    id: str,
    title: str,
    severity: Severity,
    pattern: str,
    *,
    flags: int = 0,
    cwe: str | None = None,
    owasp: str | None = None,
    category: str = "secret",
    recommendation: str = "",
    secret_group: int = 0,
    min_entropy: float | None = None,
    keywords: tuple[str, ...] = (),
) -> Rule:
    return Rule(
        id=id,
        title=title,
        severity=severity,
        regex=re.compile(pattern, flags),
        cwe=cwe,
        owasp=owasp,
        category=category,
        recommendation=recommendation,
        secret_group=secret_group,
        min_entropy=min_entropy,
        keywords=keywords,
    )

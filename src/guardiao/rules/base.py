"""Definição de uma regra de detecção.

Uma regra é **dado**, não código: o motor (``core/engine.py``) é quem sabe
percorrer a linha, aplicar filtros e montar o achado. Aqui só há o dataclass
declarativo e o construtor que compila a regex.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from guardiao.core.models import Confidence, EvidenceType, Severity


@dataclass(frozen=True)
class Rule:
    """Regra baseada em expressão regular.

    ``secret_group`` indica qual grupo da regex contém o segredo em si (0 = o
    casamento inteiro). ``min_entropy``, ``keywords``, ``validator`` e
    ``only_files`` são filtros aplicados **pelo motor** para reduzir
    falso-positivo:

    - ``keywords``: alguma delas precisa aparecer na linha (contexto de segredo);
    - ``validator``: predicado sobre o valor casado (ex.: dígito verificador de CPF);
    - ``only_files``: a regra só vale para arquivos cujo *nome* case um destes
      padrões :mod:`fnmatch` (ex.: ``.env`` — onde o formato ``CHAVE=valor`` sem
      aspas é a norma, e fora dos quais ele seria ruído puro).

    ``evidence_type`` e ``confidence`` são **obrigatórios** (sem default): é o
    invariante que fecha o EV-10 — uma regra nova no catálogo sem os dois quebra
    a importação do módulo, antes mesmo do meta-teste rodar.
    """

    id: str
    title: str
    severity: Severity
    regex: re.Pattern[str]
    evidence_type: EvidenceType
    confidence: Confidence
    cwe: str | None = None
    owasp: str | None = None
    category: str = "secret"
    recommendation: str = ""
    secret_group: int = 0
    min_entropy: float | None = None
    keywords: tuple[str, ...] = field(default_factory=tuple)
    validator: Callable[[str], bool] | None = None
    only_files: tuple[str, ...] = field(default_factory=tuple)
    #: O valor casado é uma cadeia COMPOSTA (URI, connection string) em que o segredo
    #: está embutido junto de partes não-secretas (host, nome do banco). O filtro
    #: genérico de placeholder por SUBSTRING (``looks_like_placeholder``) foi feito para
    #: valores atômicos e dispara errado aqui — um host ``db.prod.internal/sample_reports``
    #: contém ``sample`` sem ser exemplo. Quando ``True``, o motor pula esse filtro e
    #: delega ao ``validator`` a decisão de real-vs-exemplo (que parseia a estrutura).
    composto: bool = False


def compile_rule(
    id: str,
    title: str,
    severity: Severity,
    pattern: str,
    *,
    evidence_type: EvidenceType,
    confidence: Confidence,
    flags: int = 0,
    cwe: str | None = None,
    owasp: str | None = None,
    category: str = "secret",
    recommendation: str = "",
    secret_group: int = 0,
    min_entropy: float | None = None,
    keywords: tuple[str, ...] = (),
    validator: Callable[[str], bool] | None = None,
    only_files: tuple[str, ...] = (),
    composto: bool = False,
) -> Rule:
    return Rule(
        id=id,
        title=title,
        severity=severity,
        regex=re.compile(pattern, flags),
        evidence_type=evidence_type,
        confidence=confidence,
        cwe=cwe,
        owasp=owasp,
        category=category,
        recommendation=recommendation,
        secret_group=secret_group,
        min_entropy=min_entropy,
        keywords=keywords,
        validator=validator,
        only_files=only_files,
        composto=composto,
    )

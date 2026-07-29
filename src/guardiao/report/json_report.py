"""Renderizador JSON — contrato estável para consumo por outras ferramentas.

Formato ``suite-appsec/1``, compartilhado pelas ferramentas da suíte: chaves e
valores de enumeração em inglês (são identificadores), texto para humano em
português. ``summary.by_severity`` traz **sempre** as cinco severidades, mesmo
zeradas, para que um dashboard não precise tratar chave ausente.
"""

from __future__ import annotations

import json

from guardiao import __version__
from guardiao.core.engine import ScanResult
from guardiao.core.models import Finding, Severity
from guardiao.rules.definitions import OWASP_EDITION

SCHEMA = "suite-appsec/1"


def finding_to_dict(finding: Finding) -> dict[str, object]:
    """Serializa um achado **sem** o segredo cru."""
    return {
        "id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "severity_rank": finding.severity.rank,
        "path": finding.location.path,
        "line": finding.location.line,
        "column": finding.location.column,
        "commit": finding.location.commit,
        "redacted": finding.redacted,
        "entropy": finding.entropy,
        "category": finding.category,
        "cwe": finding.cwe,
        "owasp": finding.owasp,
        "recommendation": finding.recommendation,
        "fingerprint": finding.fingerprint,
    }


def to_document(result: ScanResult) -> dict[str, object]:
    counts = {sev.value: result.counts()[sev] for sev in Severity}
    return {
        "schema": SCHEMA,
        "tool": "guardiao",
        "version": __version__,
        "owasp_edition": OWASP_EDITION,
        "summary": {
            "total": len(result.findings),
            "by_severity": counts,
            "units_scanned": result.units_scanned,
            "duration_s": result.duration_s,
            # Conteúdo NÃO analisado. Sem isto, "0 achados" e "não olhei" são
            # indistinguíveis para quem consome o relatório.
            "skipped": dict(result.skipped),
            "placeholders_discarded": result.placeholders,
        },
        "findings": [finding_to_dict(f) for f in result.findings],
    }


def to_json(result: ScanResult) -> str:
    return json.dumps(to_document(result), indent=2, ensure_ascii=False)

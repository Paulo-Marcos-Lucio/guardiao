"""Renderizador JSON — estável para consumo por outras ferramentas."""

from __future__ import annotations

import json

from guardiao import __version__
from guardiao.core.engine import ScanResult
from guardiao.core.models import Finding


def finding_to_dict(finding: Finding) -> dict[str, object]:
    """Serializa um achado **sem** o segredo cru."""
    return {
        "rule": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
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
    counts = {sev.value: n for sev, n in result.counts().items()}
    return {
        "tool": "guardiao",
        "version": __version__,
        "summary": {
            "total": len(result.findings),
            "by_severity": counts,
            "units_scanned": result.units_scanned,
            "duration_s": result.duration_s,
        },
        "findings": [finding_to_dict(f) for f in result.findings],
    }


def to_json(result: ScanResult) -> str:
    return json.dumps(to_document(result), indent=2, ensure_ascii=False)

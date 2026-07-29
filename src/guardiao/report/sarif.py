"""Renderizador SARIF 2.1.0 — integra com o GitHub Code Scanning.

Emitir SARIF permite subir os achados para a aba *Security* do repositório via
`upload-sarif`. Nenhum segredo cru vai no arquivo: a mensagem usa o valor
ocultado e a de-duplicação usa a *fingerprint* (derivada do valor ocultado).

O documento declara o **catálogo completo** de regras, não só as que dispararam:
isso é explicitamente permitido pelo SARIF 2.1.0 e é o que faz a aba Security
mostrar o metadado de uma regra configurada e silenciosa.
"""

from __future__ import annotations

import json
import re

from guardiao import __version__
from guardiao.core.engine import ScanResult
from guardiao.core.models import Finding, Severity
from guardiao.rules.definitions import OWASP_EDITION
from guardiao.rules.registry import all_rules

_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}

_CWE = re.compile(r"CWE-(\d+)")


def _help_uri(cwe: str | None) -> str | None:
    match = _CWE.search(cwe or "")
    return f"https://cwe.mitre.org/data/definitions/{match.group(1)}.html" if match else None


def _rule_descriptors() -> list[dict[str, object]]:
    descriptors: list[dict[str, object]] = []
    for rule in all_rules():
        descriptor: dict[str, object] = {
            "id": rule.id,
            "name": rule.title,
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.recommendation or rule.title},
            "defaultConfiguration": {"level": _SARIF_LEVEL[rule.severity]},
            "properties": {
                # `tags` exige itens únicos no schema 2.1.0: sem o `sorted(set(...))`,
                # toda regra de categoria "secret" emitia "secret" duas vezes e o
                # documento ficava inválido.
                "tags": sorted({"security", "secret", rule.category}),
                "security-severity": _SECURITY_SEVERITY[rule.severity],
                "cwe": rule.cwe,
                "owasp": rule.owasp,
                "owasp_edition": OWASP_EDITION,
            },
        }
        help_uri = _help_uri(rule.cwe)
        if help_uri:
            descriptor["helpUri"] = help_uri
        descriptors.append(descriptor)
    return descriptors


def _result(finding: Finding) -> dict[str, object]:
    return {
        "ruleId": finding.rule_id,
        "level": _SARIF_LEVEL[finding.severity],
        "message": {"text": f"{finding.title}: {finding.redacted} — {finding.recommendation}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.location.path.replace("\\", "/")},
                    "region": {
                        "startLine": max(finding.location.line, 1),
                        "startColumn": max(finding.location.column, 1),
                    },
                }
            }
        ],
        "partialFingerprints": {"guardiaoSecretHash/v1": finding.fingerprint},
    }


def to_sarif(result: ScanResult) -> str:
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "guardiao",
                        "informationUri": "https://github.com/Paulo-Marcos-Lucio/guardiao",
                        "version": __version__,
                        "rules": _rule_descriptors(),
                    }
                },
                "results": [_result(f) for f in result.findings],
                # Property bag do run (permitido pelo schema): o que NÃO foi analisado.
                "properties": {
                    "owasp_edition": OWASP_EDITION,
                    "skipped": dict(result.skipped),
                    "unitsScanned": result.units_scanned,
                },
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False)

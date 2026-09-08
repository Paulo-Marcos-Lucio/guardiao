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
from guardiao.report import provenance
from guardiao.rules.definitions import OWASP_EDITION

SCHEMA = "suite-appsec/1"


def finding_to_dict(finding: Finding) -> dict[str, object]:
    """Serializa um achado **sem** o segredo cru."""
    return {
        "id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "severity_rank": finding.severity.rank,
        # `type`: o que o achado estruturalmente representa (ver `EvidenceType`).
        # `confidence`: confiança do MECANISMO de detecção (ver `Confidence`) — não
        # uma medição por achado, é herdada da regra que disparou.
        "type": finding.evidence_type.value,
        "confidence": finding.confidence.value,
        "path": finding.location.path,
        "line": finding.location.line,
        "column": finding.location.column,
        "commit": finding.location.commit,
        "occurrences": finding.occurrences,
        "commit_last": finding.commit_last,
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
    document: dict[str, object] = {
        "schema": SCHEMA,
        "tool": "guardiao",
        "version": __version__,
        "owasp_edition": OWASP_EDITION,
        # Proveniência (ver report/provenance.py): sem estes três campos o
        # relatório não é vinculável a um estado do código nem a um estado do
        # catálogo, e um achado que desaparece na entrega seguinte é
        # indistinguível de uma regra que foi afrouxada.
        "commit": provenance.commit(),
        "ruleset_hash": provenance.ruleset_hash(),
        "artifact_sha256": None,
        "summary": {
            "total": len(result.findings),
            "by_severity": counts,
            "units_scanned": result.units_scanned,
            "duration_s": result.duration_s,
            # Conteúdo NÃO analisado. Sem isto, "0 achados" e "não olhei" são
            # indistinguíveis para quem consome o relatório.
            "skipped": dict(result.skipped),
            "placeholders_discarded": result.placeholders,
            # Limites de ALCANCE (o que a varredura não pôde ver, ex.: objetos
            # inalcançáveis que um clone não recebe). Lista vazia = nenhum limite
            # conhecido; a chave existe sempre, para o consumidor não ter de adivinhar.
            "coverage_warnings": list(result.avisos_de_cobertura),
        },
        "findings": [finding_to_dict(f) for f in result.findings],
    }
    # Por último e sobre o documento já completo: o auto-hash cobre TUDO o mais,
    # inclusive a proveniência acima. Trocar o commit depois da entrega invalida
    # o hash.
    document["artifact_sha256"] = provenance.artifact_sha256(document)
    return document


def to_json(result: ScanResult) -> str:
    return json.dumps(to_document(result), indent=2, ensure_ascii=False)

"""Baseline: aceitar achados conhecidos para o CI só falhar em segredos NOVOS.

O baseline guarda apenas *fingerprints* e metadados ocultados — **jamais** o
segredo cru. É o mesmo princípio do `detect-secrets`: você fotografa a dívida
atual e passa a barrar só o que for introduzido depois.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from guardiao.core.models import Finding

BASELINE_VERSION = 1


@dataclass(frozen=True)
class Baseline:
    fingerprints: frozenset[str]

    def contains(self, finding: Finding) -> bool:
        return finding.fingerprint in self.fingerprints


def build_baseline_document(findings: list[Finding]) -> dict[str, object]:
    entries = {
        finding.fingerprint: {
            "rule": finding.rule_id,
            "path": finding.location.path,
            "line": finding.location.line,
            "redacted": finding.redacted,
            "severity": finding.severity.value,
        }
        for finding in findings
    }
    return {
        "version": BASELINE_VERSION,
        "tool": "guardiao",
        "note": "Fingerprints de achados aceitos. Não contém segredos.",
        "findings": entries,
    }


def save_baseline(path: Path, findings: list[Finding]) -> None:
    document = build_baseline_document(findings)
    Path(path).write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def load_baseline(path: Path) -> Baseline:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = data.get("findings", {})
    if not isinstance(findings, dict):  # pragma: no cover - arquivo corrompido
        raise ValueError("baseline inválido: 'findings' deve ser um objeto")
    return Baseline(fingerprints=frozenset(findings.keys()))


def apply_baseline(findings: list[Finding], baseline: Baseline) -> tuple[list[Finding], int]:
    """Devolve (achados_novos, quantidade_suprimida)."""
    kept = [f for f in findings if not baseline.contains(f)]
    return kept, len(findings) - len(kept)

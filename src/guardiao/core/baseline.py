"""Baseline: aceitar achados conhecidos para o CI só falhar em segredos NOVOS.

O baseline guarda apenas *fingerprints* e metadados ocultados — nunca o segredo
cru **nem hash dele**: a fingerprint é derivada do valor já ocultado, justamente
porque este arquivo é feito para ser versionado (ver :attr:`Finding.fingerprint`).
Pelo mesmo motivo a ocultação aqui é mais forte que a do console
(:data:`~guardiao.core.redaction.KEEP_PUBLICADO`): 2 caracteres por ponta, não 4.
É o mesmo princípio do `detect-secrets`: você fotografa a dívida atual e passa a
barrar só o que for introduzido depois.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from guardiao.core.models import Finding
from guardiao.core.redaction import KEEP_PUBLICADO, redact

BASELINE_VERSION = 1


@dataclass(frozen=True)
class Baseline:
    fingerprints: frozenset[str]

    def contains(self, finding: Finding) -> bool:
        return finding.fingerprint in self.fingerprints


def build_baseline_document(findings: list[Finding]) -> dict[str, object]:
    # Ocultação MAIS FORTE que a do console: este arquivo é feito para ser commitado,
    # e o `finding.redacted` do console revela 4+4 caracteres — 8 em claro de toda
    # credencial com 13+ chars, para sempre, no repositório do cliente.
    entries = {
        finding.fingerprint: {
            "rule": finding.rule_id,
            "path": finding.location.path,
            "line": finding.location.line,
            "redacted": redact(finding.secret, keep=KEEP_PUBLICADO),
            "severity": finding.severity.value,
        }
        for finding in findings
    }
    return {
        "version": BASELINE_VERSION,
        "tool": "guardiao",
        # A nota anterior dizia que os valores "não permitem recuperar o segredo" — e o
        # arquivo trazia 8 caracteres em claro. Prometer um sigilo que o formato não
        # entrega é pior que não prometer nada: o cliente versiona confiando na frase.
        "note": (
            "Arquivo feito para ser versionado. Não contém o segredo, mas contém um "
            "FRAGMENTO dele: 2 caracteres de cada ponta do valor ocultado, mais uma "
            "fingerprint derivada de regra + arquivo + valor ocultado. Fragmento e "
            "fingerprint não reconstroem a credencial, mas confirmam palpite de quem já "
            "tiver um. Rotacionou um segredo? rode --update-baseline."
        ),
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

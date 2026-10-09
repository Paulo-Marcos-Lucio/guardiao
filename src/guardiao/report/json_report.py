"""Renderizador JSON — contrato estável para consumo por outras ferramentas.

Formato ``suite-appsec/1``, compartilhado pelas ferramentas da suíte: chaves e
valores de enumeração em inglês (são identificadores), texto para humano em
português. ``summary.by_severity`` traz **sempre** as cinco severidades, mesmo
zeradas, para que um dashboard não precise tratar chave ausente.
"""

from __future__ import annotations

import json

from guardiao import __version__
from guardiao.core import provenance
from guardiao.core.engine import ScanResult
from guardiao.core.models import Finding, Severity
from guardiao.rules.definitions import OWASP_EDITION

SCHEMA = "suite-appsec/1"

#: Frase fixa de G-09: "unknown" é o estado de quem NÃO chamou a API do provedor para
#: confirmar se o segredo ainda é válido — nunca o estado de um achado que foi tirado do
#: relatório. Sem esta nota, um consumidor automatizado poderia ler `unknown` como "sem
#: significado" e descartar o achado na própria esteira, exatamente o oposto do que a
#: ferramenta garante (achado rebaixado ou não-verificado nunca é suprimido, só rotulado).
NOTA_VALIDITY = (
    "'unknown' é 'não verificado' — nenhuma requisição ao provedor foi emitida para "
    "confirmar se o segredo ainda é válido. Não é 'achado descartado': o achado continua "
    "no relatório como qualquer outro."
)


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
        # Proveniência (ver core/provenance.py): sem estes campos o relatório não é
        # vinculável a um estado do código nem a um estado do catálogo, e um achado
        # que desaparece na entrega seguinte é indistinguível de uma regra afrouxada.
        # `commit_scope` diz o SENTIDO de `commit`: no Guardião é o commit do repo
        # AUDITADO (`"target"`), não o da ferramenta — mesmo nome, sentidos opostos
        # entre as tools da suíte sem o discriminador.
        "commit": provenance.commit(result.root),
        "commit_scope": provenance.COMMIT_SCOPE,
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
            # Cobertura de RULESET: QUAIS regras do catálogo rodaram. Sem isto, um laudo de
            # `--only github-token` (1 regra) é indistinguível do laudo completo — os dois
            # dizem "0 achados". `partial=true` sinaliza que "limpo" vale só para as regras
            # executadas; `rules_omitted` diz exatamente o que não foi avaliado.
            "ruleset_coverage": {
                "rules_total": result.regras_total,
                "rules_run": result.regras_total - len(result.regras_omitidas),
                "rules_omitted": list(result.regras_omitidas),
                "entropy_disabled": result.entropia_desligada,
                "partial": result.ruleset_parcial(),
            },
            # Validade do SEGREDO (G-09): hoje nenhuma verificação ativa existe (chamar a
            # API do provedor para confirmar se ainda está vivo), então todo achado é
            # `unknown` por construção — `verified`/`unverified` ficam reservados para
            # quando essa verificação existir, e `requisicoes_emitidas` é o contador
            # auditável de quantas chamadas saíram (hoje sempre 0: nenhuma rede foi tocada).
            "validity": {
                "verified": 0,
                "unverified": 0,
                "unknown": len(result.findings),
                "requisicoes_emitidas": 0,
                "nota": NOTA_VALIDITY,
            },
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

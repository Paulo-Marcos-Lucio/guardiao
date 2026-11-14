"""Importador de relatórios de Gitleaks e TruffleHog — contrapartida pública do G11.

O item G11 (interno) deu ao Guardião o campo ``adjudication`` em cada achado: o
veredito — verdadeiro/falso-positivo — de uma triagem (heurística ou humana) que
ainda não existe neste repositório, mas que o formato já reserva espaço para. Um
achado **importado** de outra ferramenta nunca passou por essa triagem — nem
poderia, ela é do Guardião — então herdar ``null`` sem dizer por quê deixaria a
lacuna implícita. Este módulo declara em prosa, no próprio laudo, que a
cobertura de adjudicação de um import é sempre zero.

Dois formatos de origem, lidos pelo que cada ferramenta publica de fato:

* **gitleaks** (`gitleaks detect -f json`): um array JSON de achados.
* **trufflehog** (`trufflehog ... --json`): JSON Lines — um objeto por linha,
  não um array único.

Os dois carregam o segredo cru (`Secret`/`Raw`) no relatório de origem. Este
módulo nunca repassa esse valor — só a versão ocultada por
:func:`guardiao.core.redaction.redact_publicado`, a mesma receita publicada
pelo resto da suíte.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from guardiao import __version__
from guardiao.core.redaction import redact_publicado

SCHEMA = "suite-appsec/1"

FONTES = ("gitleaks", "trufflehog")


def _redigir(segredo: str | None) -> str | None:
    if not segredo:
        return None
    return redact_publicado(segredo)


def _achado_gitleaks(bruto: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_tool": "gitleaks",
        "id": bruto.get("RuleID"),
        "title": bruto.get("Description") or bruto.get("RuleID"),
        # Nem gitleaks nem trufflehog classificam por severidade — inventar uma
        # aqui seria maquiagem, não dado. `None` declara "a ferramenta de origem
        # não informa isto", em vez de um palpite travestido de medição.
        "severity": None,
        "path": bruto.get("File") or None,
        "line": bruto.get("StartLine"),
        "column": bruto.get("StartColumn"),
        "commit": bruto.get("Commit") or None,
        "entropy": bruto.get("Entropy"),
        "redacted": _redigir(bruto.get("Secret")),
        "fingerprint": bruto.get("Fingerprint"),
        # Nunca passou pela triagem do Guardião (G11) — ver docstring do módulo.
        "adjudication": None,
    }


def importar_gitleaks(caminho: str | Path) -> list[dict[str, Any]]:
    """Lê o array JSON do ``gitleaks detect -f json``. ``[]`` é relatório limpo."""
    texto = Path(caminho).read_text(encoding="utf-8")
    bruto = json.loads(texto) if texto.strip() else []
    if not isinstance(bruto, list):
        raise ValueError("relatório do gitleaks esperado como array JSON")
    return [_achado_gitleaks(item) for item in bruto]


def _metadados_trufflehog(bruto: dict[str, Any]) -> dict[str, Any]:
    """Extrai o sub-objeto de localização de dentro de ``SourceMetadata.Data``.

    O trufflehog varia a chave pelo tipo de fonte (``Git``, ``Filesystem``,
    ``Github``…) e o item só precisa cobrir local/filesystem e Git — os dois
    relevantes para varredura de repositório. Fonte não reconhecida devolve um
    dicionário vazio: os campos de localização ficam ``None`` (declarado), não
    adivinhados.
    """
    dados = (bruto.get("SourceMetadata") or {}).get("Data") or {}
    for valor in dados.values():
        if isinstance(valor, dict):
            return valor
    return {}


def _achado_trufflehog(bruto: dict[str, Any]) -> dict[str, Any]:
    meta = _metadados_trufflehog(bruto)
    return {
        "source_tool": "trufflehog",
        "id": bruto.get("DetectorName"),
        "title": bruto.get("DetectorName"),
        "severity": None,
        "path": meta.get("file"),
        "line": meta.get("line"),
        "column": None,
        "commit": meta.get("commit"),
        # `Verified` é a única classificação que o trufflehog de fato faz (bateu
        # contra a API do provedor) — carregamos como veio, sem reempacotar em
        # severidade.
        "verified": bruto.get("Verified"),
        "redacted": _redigir(bruto.get("Raw")),
        "adjudication": None,
    }


def importar_trufflehog(caminho: str | Path) -> list[dict[str, Any]]:
    """Lê o JSON Lines do trufflehog — um objeto por linha, não um array único."""
    achados: list[dict[str, Any]] = []
    for n, linha in enumerate(Path(caminho).read_text(encoding="utf-8").splitlines(), 1):
        linha = linha.strip()
        if not linha:
            continue
        try:
            bruto = json.loads(linha)
        except json.JSONDecodeError as e:
            raise ValueError(f"linha {n} do relatório trufflehog não é JSON válido: {e}") from e
        achados.append(_achado_trufflehog(bruto))
    return achados


_IMPORTADORES = {
    "gitleaks": importar_gitleaks,
    "trufflehog": importar_trufflehog,
}

_NOTA_ADJUDICACAO = (
    "0/{total} achados importados de {fonte} passaram pela adjudicação heurística "
    "do Guardião (triagem de verdadeiro/falso-positivo, item G11) — vieram prontos "
    "de outra ferramenta, sem a triagem própria do motor. `adjudication` fica "
    "`null` em todo achado até alguém, humano ou heurística, decidir."
)


def documento(fonte: str, caminho: str | Path) -> dict[str, Any]:
    """Monta o documento ``suite-appsec/1`` para um relatório externo importado.

    Não reaproveita :func:`guardiao.report.json_report.to_document`: aquele é o
    contrato de um scan do próprio motor, com proveniência de regra e cobertura
    de *ruleset* que um relatório importado não tem como declarar com
    honestidade — não rodamos as regras do gitleaks/trufflehog, só lemos a saída
    delas.
    """
    if fonte not in _IMPORTADORES:
        raise ValueError(f"fonte desconhecida: {fonte!r} (válidas: {FONTES})")
    achados = _IMPORTADORES[fonte](caminho)
    total = len(achados)
    return {
        "schema": SCHEMA,
        "tool": "guardiao-importador",
        "version": __version__,
        "fonte": fonte,
        "summary": {
            "total": total,
            # Cobertura de ADJUDICAÇÃO, não de ruleset (isto não é um scan do motor):
            # sem isto, um achado importado fica indistinguível, no laudo, de um
            # achado que já passou pela triagem heurística do próprio Guardião — a
            # ausência ficaria implícita em vez de declarada.
            "adjudicacao_heuristica": {
                "cobertura": f"0/{total}",
                "nota": _NOTA_ADJUDICACAO.format(total=total, fonte=fonte),
            },
        },
        "findings": achados,
    }


def to_json(fonte: str, caminho: str | Path) -> str:
    return json.dumps(documento(fonte, caminho), indent=2, ensure_ascii=False)

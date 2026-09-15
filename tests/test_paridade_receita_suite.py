"""Paridade de receita da SUÍTE AppSec (Classe F) — travada por teste.

Um cliente confere os QUATRO laudos da suíte (Guardião, Sentinela, Chaveiro, Esteira)
com UMA receita só. Os valores-ouro abaixo são IDÊNTICOS nos quatro repositórios; o que
muda de repo para repo é apenas a linha de ``import`` que casa com a API real.

O ponto do teste é provar que o CÓDIGO DE PRODUÇÃO do Guardião bate com o ouro: não há
stub nem reimplementação da receita à mão — importamos as funções reais
(:func:`guardiao.core.provenance.artifact_sha256` e
:func:`guardiao.core.redaction.redact_publicado`, as mesmas que os renderizadores
JSON/SARIF/baseline chamam). Se a receita divergir, o teste falha.

**Invariante F:** os quatro tools produzem saída idêntica para a mesma entrada canônica.
"""

from __future__ import annotations

from guardiao.core.provenance import artifact_sha256, canonical_sha256
from guardiao.core.redaction import redact_publicado

# Entrada canônica compartilhada e seu hash de artefato (mesma serialização determinística
# nos 4: json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False)).
GOLDEN_DOC = {"alvo": "exemplo.com.br", "achados": 2, "regra": "pção-ção", "z": 1, "a": [3, 2, 1]}
GOLDEN_ARTIFACT_SHA256 = "bcd1a357a62308d43397cf4357ffb4fa45b904f9a31353da7e10468f213f6af1"

# Redação PUBLICADA da suíte: keep=2, marcador U+2026, 2 pontas; segredo <= 2*keep vira
# só o marcador (nem uma ponta, nem o comprimento).
GOLDEN_REDACT = {
    "AKIAIOSFODNN7EXAMPLE": "AK…LE",
    "ghp_16C7e42F292c6912E7710c838347Ae178B4a": "gh…4a",
    "1234": "…",
}


def test_artifact_sha256_receita_unica_da_suite() -> None:
    # A função de produção exclui o próprio campo `artifact_sha256`; o doc-ouro não o tem,
    # então artifact_sha256 e canonical_sha256 coincidem — e ambos batem com o ouro.
    assert artifact_sha256(GOLDEN_DOC) == GOLDEN_ARTIFACT_SHA256
    assert canonical_sha256(GOLDEN_DOC) == GOLDEN_ARTIFACT_SHA256


def test_redact_publicado_no_maximo_2_por_ponta() -> None:
    for entrada, esperado in GOLDEN_REDACT.items():
        assert redact_publicado(entrada) == esperado


def test_redact_publicado_e_a_funcao_dos_renderizadores() -> None:
    """Prova que o SARIF e o baseline usam ESTA função (não uma paralela): o corpo dos
    dois renderizadores referencia `redact_publicado`, então o ouro acima é o que de fato
    sai no laudo entregue ao cliente — o teste não mede um caminho morto."""
    import inspect

    from guardiao.core import baseline
    from guardiao.report import sarif

    assert "redact_publicado" in inspect.getsource(baseline.build_baseline_document)
    assert "redact_publicado" in inspect.getsource(sarif._result)

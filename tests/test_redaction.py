from __future__ import annotations

from guardiao.core.redaction import redact, redact_spans
from tests.conftest import AWS_KEY_ID


def test_redact_hides_middle_and_length() -> None:
    masked = redact(AWS_KEY_ID)
    assert masked == "AKIA…8RPD"
    assert AWS_KEY_ID not in masked
    # não vaza o comprimento exato
    assert len(masked) < len(AWS_KEY_ID)


def test_redact_short_secret_reveals_almost_nothing() -> None:
    assert redact("abcd1234") == "a…"
    assert redact("") == ""


def test_redact_spans_masks_every_secret() -> None:
    n = len(AWS_KEY_ID)
    line = f"{AWS_KEY_ID} {AWS_KEY_ID}"
    spans = [(0, n, AWS_KEY_ID), (n + 1, 2 * n + 1, AWS_KEY_ID)]
    assert AWS_KEY_ID not in redact_spans(line, spans)


def test_redact_spans_ainda_mascara_com_span_deslocado() -> None:
    """O ramo de fallback é a rede de segurança da promessa "o segredo cru nunca sai":
    um chamador futuro com span errado não pode virar vazamento."""
    line = f'key = "{AWS_KEY_ID}"  # comentário'
    out = redact_spans(line, [(0, 5, AWS_KEY_ID)])
    assert AWS_KEY_ID not in out
    assert "AKIA…8RPD" in out
    assert "comentário" in out

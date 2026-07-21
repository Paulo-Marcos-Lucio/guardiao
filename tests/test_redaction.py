from __future__ import annotations

from guardiao.core.redaction import redact, redact_line


def test_redact_hides_middle_and_length() -> None:
    secret = "AKIAZ7Q2LMN4XYWV8RPD"
    masked = redact(secret)
    assert masked == "AKIA…8RPD"
    assert secret not in masked
    # não vaza o comprimento exato
    assert len(masked) < len(secret)


def test_redact_short_secret_reveals_almost_nothing() -> None:
    assert redact("abcd1234") == "a…"


def test_redact_line_masks_only_the_secret() -> None:
    secret = "AKIAZ7Q2LMN4XYWV8RPD"
    line = f'key = "{secret}"  # comentário'
    out = redact_line(line, secret)
    assert secret not in out
    assert "AKIA…8RPD" in out
    assert "comentário" in out

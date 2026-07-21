from __future__ import annotations

import math

from guardiao.core.entropy import charset_of, is_high_entropy, shannon_entropy


def test_shannon_entropy_bounds() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    # 4 símbolos equiprováveis => 2 bits/char
    assert math.isclose(shannon_entropy("abcd"), 2.0, rel_tol=1e-9)


def test_charset_detection() -> None:
    assert charset_of("deadbeef1234") == "hex"
    assert charset_of("Zm9vYmFy+/=") == "base64"
    assert charset_of("héllo!") == "mixed"


def test_high_entropy_random_vs_word() -> None:
    assert is_high_entropy("Xk9Q2mNpR7wLvB3cD5fG6hJ8kM0n")  # aleatório base64
    assert not is_high_entropy("password")  # curto e previsível
    assert not is_high_entropy("aaaaaaaaaaaaaaaaaaaaaaaa")  # longo mas sem entropia

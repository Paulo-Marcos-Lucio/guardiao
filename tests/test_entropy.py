from __future__ import annotations

import math

from guardiao.core.entropy import (
    FRACAO_MINIMA,
    MIN_SECRET_LEN,
    entropia_corrigida,
    is_high_entropy,
    shannon_entropy,
    tamanho_do_alfabeto,
)


def test_shannon_entropy_bounds() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    # 4 símbolos equiprováveis => 2 bits/char
    assert math.isclose(shannon_entropy("abcd"), 2.0, rel_tol=1e-9)


def test_correcao_de_miller_madow_e_positiva_e_encolhe_com_o_tamanho() -> None:
    """A correção compensa o viés do estimador plug-in: (k-1)/(2·n·ln2)."""
    curto = "Xk9Q2mNpR7wLvB3cD5fG6hJ8"  # n=24
    assert entropia_corrigida(curto) > shannon_entropy(curto)
    delta_curto = entropia_corrigida(curto) - shannon_entropy(curto)
    longo = curto * 4  # mesmos símbolos, 4x mais amostras
    delta_longo = entropia_corrigida(longo) - shannon_entropy(longo)
    assert delta_longo < delta_curto
    assert entropia_corrigida("") == 0.0


def test_tamanho_do_alfabeto() -> None:
    assert tamanho_do_alfabeto("deadbeef1234") == 16
    assert tamanho_do_alfabeto("abcdefgh1234") == 36  # só minúsculas+dígitos
    assert tamanho_do_alfabeto("ABCDEFGH1234") == 36
    assert tamanho_do_alfabeto("Zm9vYmFy+/=") == 64


def test_high_entropy_random_vs_word() -> None:
    assert is_high_entropy("Xk9Q2mNpR7wLvB3cD5fG6hJ8kM0n")  # aleatório base64
    assert not is_high_entropy("password")  # curto e previsível
    assert not is_high_entropy("aaaaaaaaaaaaaaaaaaaaaaaa")  # longo mas sem entropia


def test_ramo_hexadecimal() -> None:
    """Sem este teste, desligar o ramo hex apagava a detecção de segredo hexadecimal
    (`openssl rand -hex 16/32`) sem nenhum teste ficar vermelho."""
    assert is_high_entropy("9f3c1a7e5b2d48c06e1f9a3b7d5c2e04")  # 32 hex aleatório
    assert not is_high_entropy("a" * 32)  # hex sem entropia
    assert not is_high_entropy("9f3c1a7e")  # curto demais


def test_min_length_e_a_mesma_fonte_do_regex() -> None:
    """`is_high_entropy` e o regex da regra de entropia usam a MESMA constante.

    Antes havia duas fontes divergentes — `min_length=20` no default da função e
    `{24,}` no regex — e a menor era inalcançável em produção. O literal 24 está
    escrito aqui de propósito: mover a constante sem revisitar o contrato deixa
    este teste vermelho.
    """
    from guardiao.rules.registry import all_rules

    assert MIN_SECRET_LEN == 24
    aleatorio = "Xk9Q2mNpR7wLvB3cD5fG6hJ8kM0nT4uY1zAw"
    assert is_high_entropy(aleatorio[:24])
    assert not is_high_entropy(aleatorio[:23])
    regra = next(r for r in all_rules() if r.id == "high-entropy-string")
    assert regra.regex.search("k: " + aleatorio[:24]) is not None
    assert regra.regex.search("k: " + aleatorio[:23]) is None


def test_criterio_e_relativo_ao_alfabeto_nao_absoluto() -> None:
    """Trava a calibração: 24 chars alfanuméricos minúsculos aleatórios eram aceitos
    em 3% das vezes pelo limiar absoluto de 4,3 bits/char (log2(24)=4,58 é o teto)."""
    assert FRACAO_MINIMA == 0.80
    minusculo = "wvanet0knqvaclirsa16n9uv"  # 24 chars, [a-z0-9], gerado por secrets.choice
    assert shannon_entropy(minusculo) < 4.3  # reprovado pelo critério antigo (H=3,99)...
    assert is_high_entropy(minusculo)  # ...e aceito pelo atual

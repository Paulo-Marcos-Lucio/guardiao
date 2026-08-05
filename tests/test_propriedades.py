"""Testes property-based (Hypothesis) das INVARIANTES de classe do motor.

Os testes por exemplo (test_engine, test_rules…) cobrem só os casos que ALGUÉM pensou.
Estes geram milhares de entradas e afirmam uma PROPRIEDADE que precisa valer para TODAS —
a rede contra "defeito de classe". Foi um corpo base64 de PEM com `/` que rendeu 821 falsos
positivos num único `cacert.pem` (P0-03): um exemplo que nenhum fixture cobria. Uma vez
codificada a invariante "corpo de PEM nunca gera achado de entropia", essa classe inteira
de regressão fica barrada no CI, para sempre.
"""

from __future__ import annotations

import base64

from hypothesis import given, settings
from hypothesis import strategies as st

from guardiao.core.engine import Scanner

_PEM_TIPOS = ["CERTIFICATE", "RSA PRIVATE KEY", "PUBLIC KEY", "EC PRIVATE KEY", "X509 CRL"]


def _pem(corpo_b64: str, tipo: str = "CERTIFICATE") -> str:
    linhas = [corpo_b64[i : i + 64] for i in range(0, len(corpo_b64), 64)] or [""]
    return f"-----BEGIN {tipo}-----\n" + "\n".join(linhas) + f"\n-----END {tipo}-----\n"


@settings(max_examples=300)
@given(dados=st.binary(min_size=48, max_size=4096), tipo=st.sampled_from(_PEM_TIPOS))
def test_corpo_pem_nunca_gera_achado_de_entropia(dados: bytes, tipo: str) -> None:
    """INVARIANTE 1 (P0-03): nenhum corpo base64 dentro de bloco PEM produz achado `entropy`.

    Vale para QUALQUER conteúdo de qualquer tipo de bloco — é a classe que rendeu os 821 FP.
    """
    texto = _pem(base64.b64encode(dados).decode(), tipo)
    de_entropia = [a for a in Scanner().scan_text("qualquer.pem", texto) if a.category == "entropy"]
    assert de_entropia == [], f"corpo PEM gerou {len(de_entropia)} achado(s) de entropia"


@settings(max_examples=200)
@given(dados=st.binary(min_size=48, max_size=1024))
def test_pem_nao_cega_o_detector_de_fornecedor(dados: bytes) -> None:
    """INVARIANTE 2: suprimir entropia no PEM NÃO pode cegar as regras de fornecedor.

    O oposto do FP é o falso-negativo: um `ghp_` real dentro de um PEM tem de continuar pego.
    """
    ghp = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    corpo = base64.b64encode(dados).decode()
    texto = (
        "-----BEGIN CERTIFICATE-----\n"
        + corpo[:64]
        + f"\n{ghp}\n"
        + corpo[64:128]
        + "\n-----END CERTIFICATE-----\n"
    )
    achados = list(Scanner().scan_text("vazou.pem", texto))
    assert any("ghp_" in a.secret for a in achados), "ghp_ dentro do PEM não foi detectado"


@settings(max_examples=200)
@given(
    chave=st.sampled_from(["password", "api_key", "secret", "token", "senha"]),
    placeholder=st.sampled_from(
        ["changeme", "xxxxxxxx", "your-token-here", "<REDACTED>", "example", "TODO", "..."]
    ),
)
def test_placeholder_nunca_vira_achado(chave: str, placeholder: str) -> None:
    """INVARIANTE 3: atribuição a um placeholder óbvio não é segredo, em nenhum contexto."""
    achados = list(Scanner().scan_text("config.py", f'{chave} = "{placeholder}"\n'))
    assert achados == [], f"placeholder {placeholder!r} virou achado"

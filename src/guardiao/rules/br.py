"""Validadores de documentos brasileiros (dígito verificador módulo 11).

Um CPF/CNPJ é um número **com checksum**. Sem conferir o dígito verificador, a
regex casa qualquer número formatado — ordem de compra, código de produto,
`000.000.000-00` — e a ferramenta reporta como dado pessoal algo que não é.
Conferir o dígito é o que separa "dado da LGPD" de "número com pontinho".

Desde 31/07/2026 (IN RFB nº 2.229/2024, que atualizou a IN RFB nº 2.119/2022) a
Receita Federal emite **CNPJ alfanumérico** para inscrições novas:
``AA.AAA.AAA/AAAA-DD`` — as 12 primeiras posições aceitam letra A-Z além de
dígito; os 2 dígitos verificadores continuam sempre numéricos. O cálculo do DV
é o mesmo módulo 11 de sempre: cada caractere vale o código ASCII menos 48
(dígito mantém o próprio valor 0-9; letra vale de 17 a 42). `cnpj_valido`
cobre os dois formatos.
"""

from __future__ import annotations

_PESOS_CNPJ = (5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)


def _digitos(texto: str) -> str:
    return "".join(c for c in texto if c.isdigit())


def _alfanumericos_cnpj(texto: str) -> str:
    """Dígitos e letras A-Z de um CNPJ, ignorando pontuação (``.``/``/``/``-``)."""
    return "".join(c for c in texto.upper() if c.isdigit() or "A" <= c <= "Z")


def _valor_caractere(c: str) -> int:
    """Valor de um caractere para o módulo 11 do CNPJ: dígito vale o próprio
    valor; letra A-Z vale código ASCII menos 48 (A=17 … Z=42) — é assim que a
    Receita Federal especifica o cálculo do CNPJ alfanumérico. Para dígitos
    (CPF e CNPJ numérico) coincide com ``int(c)``, então a mesma conta serve
    para os dois formatos sem ramificação."""
    return ord(c) - 48


def _digito_mod11(base: str, pesos: tuple[int, ...]) -> str:
    soma = sum(_valor_caractere(c) * p for c, p in zip(base, pesos, strict=True))
    resto = soma % 11
    return "0" if resto < 2 else str(11 - resto)


def cpf_valido(texto: str) -> bool:
    """Confere os dois dígitos verificadores de um CPF (módulo 11)."""
    numero = _digitos(texto)
    if len(numero) != 11 or len(set(numero)) == 1:
        return False  # 000.000.000-00 e afins passam no mod-11 mas não são CPF
    primeiro = _digito_mod11(numero[:9], tuple(range(10, 1, -1)))
    segundo = _digito_mod11(numero[:9] + primeiro, tuple(range(11, 1, -1)))
    return numero[9:] == primeiro + segundo


def cnpj_valido(texto: str) -> bool:
    """Confere os dois dígitos verificadores de um CNPJ — numérico ou
    alfanumérico (módulo 11). Os 2 dígitos verificadores são sempre numéricos,
    mesmo no formato alfanumérico."""
    numero = _alfanumericos_cnpj(texto)
    if len(numero) != 14 or len(set(numero)) == 1:
        return False
    base, dv = numero[:12], numero[12:]
    if not dv.isdigit():
        return False
    primeiro = _digito_mod11(base, _PESOS_CNPJ)
    segundo = _digito_mod11(base + primeiro, (6, *_PESOS_CNPJ))
    return dv == primeiro + segundo

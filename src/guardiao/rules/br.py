"""Validadores de documentos brasileiros (dígito verificador módulo 11).

Um CPF/CNPJ é um número **com checksum**. Sem conferir o dígito verificador, a
regex casa qualquer número formatado — ordem de compra, código de produto,
`000.000.000-00` — e a ferramenta reporta como dado pessoal algo que não é.
Conferir o dígito é o que separa "dado da LGPD" de "número com pontinho".

Limitação declarada: a Receita Federal passou a emitir **CNPJ alfanumérico**
(``AA.AAA.AAA/AAAA-DD``) a partir de 2026. As funções abaixo — e a regex da regra
``cnpj`` — só cobrem o formato **numérico**. CNPJ alfanumérico não é detectado.
"""

from __future__ import annotations

_PESOS_CNPJ = (5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)


def _digitos(texto: str) -> str:
    return "".join(c for c in texto if c.isdigit())


def _digito_mod11(base: str, pesos: tuple[int, ...]) -> str:
    soma = sum(int(c) * p for c, p in zip(base, pesos, strict=True))
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
    """Confere os dois dígitos verificadores de um CNPJ numérico (módulo 11)."""
    numero = _digitos(texto)
    if len(numero) != 14 or len(set(numero)) == 1:
        return False
    primeiro = _digito_mod11(numero[:12], _PESOS_CNPJ)
    segundo = _digito_mod11(numero[:12] + primeiro, (6, *_PESOS_CNPJ))
    return numero[12:] == primeiro + segundo

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from guardiao.core.posicao import (
    COMENTARIO,
    IDENTIFICADOR,
    VALOR_LITERAL,
    mapa_de_posicoes,
)


def test_string_marca_valor_literal() -> None:
    mapa = mapa_de_posicoes('segredo = "abc123"\n')
    # 'abc123' (sem as aspas) começa na coluna 11 — mapeia a string inteira, aspas incluídas.
    assert mapa[(1, 10)] == VALOR_LITERAL  # a aspa de abertura
    assert mapa[(1, 11)] == VALOR_LITERAL  # dentro do literal


def test_name_marca_identificador() -> None:
    mapa = mapa_de_posicoes("segredo = 1\n")
    assert mapa[(1, 0)] == IDENTIFICADOR


def test_comment_marca_comentario() -> None:
    mapa = mapa_de_posicoes("x = 1  # token_de_exemplo\n")
    col_comentario = "x = 1  # token_de_exemplo\n".index("#")
    assert mapa[(1, col_comentario)] == COMENTARIO


def test_posicao_fora_de_qualquer_token_nao_aparece() -> None:
    # o '=' e os espaços não são STRING/NAME/COMMENT — não entram no mapa.
    mapa = mapa_de_posicoes("x = 1\n")
    assert (1, 1) not in mapa  # espaço antes do '='
    assert (1, 2) not in mapa  # o próprio '='


def test_string_multilinha_marca_todas_as_linhas_fisicas() -> None:
    texto = 'x = """abc\ndef"""\n'
    mapa = mapa_de_posicoes(texto)
    assert mapa[(1, 4)] == VALOR_LITERAL  # abre aspas na linha 1
    assert mapa[(2, 0)] == VALOR_LITERAL  # 'd' de 'def' na linha 2, dentro do literal
    assert mapa[(2, 5)] == VALOR_LITERAL  # fecha aspas na linha 2


def test_string_multilinha_marca_linha_do_meio_inteira() -> None:
    # token de 3 linhas físicas: a linha do meio precisa ser marcada de ponta a ponta,
    # não só início/fim do token.
    texto = 'x = """abc\nmeio\ndef"""\n'
    mapa = mapa_de_posicoes(texto)
    assert mapa[(2, 0)] == VALOR_LITERAL
    assert mapa[(2, 3)] == VALOR_LITERAL  # último char de 'meio'


def test_texto_que_nao_tokeniza_devolve_mapa_vazio_fail_open() -> None:
    assert mapa_de_posicoes("def f(:\n") == {}
    assert mapa_de_posicoes('"""sem fechar') == {}


def test_texto_vazio_devolve_mapa_vazio() -> None:
    assert mapa_de_posicoes("") == {}


@given(st.text(max_size=500))
def test_nunca_levanta_e_so_devolve_as_tres_categorias_conhecidas(texto: str) -> None:
    """Invariante de classe (fail-open): NENHUMA entrada de texto arbitrário pode fazer
    mapa_de_posicoes explodir, e toda categoria devolvida pertence ao conjunto declarado —
    trava a classe inteira de "token novo que o motor não sabia rotular", não só o
    exemplo que apareceu num teste."""
    mapa = mapa_de_posicoes(texto)
    assert set(mapa.values()) <= {VALOR_LITERAL, IDENTIFICADOR, COMENTARIO}

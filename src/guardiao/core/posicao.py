"""Camada A: mapa de posições sintáticas por tokenização.

Por que isto existe
--------------------
O motor acha segredos por regex, posição por posição (linha, coluna) — um achado dentro
de uma STRING literal é evidência real; o mesmo padrão batendo dentro do NOME de uma
variável ou de um COMENTÁRIO é ruído léxico, porque regex não distingue sintaxe. Este
módulo não decide o que suprimir — é só a Camada A: tokeniza e devolve ONDE cada
categoria sintática está, posição por posição, para uma camada futura (B/C) cruzar
contra os achados do motor.

Fail-open deliberado: texto que não tokeniza como Python (binário, sintaxe inválida,
arquivo de outra linguagem) devolve ``{}`` — mapa vazio, nunca uma exceção. Mapa vazio
significa "sem opinião sobre este arquivo": nenhuma posição é conhecida como
VALOR_LITERAL/IDENTIFICADOR/COMENTARIO, então uma camada consumidora não pode usar isto
para suprimir nada por engano. É a mesma escolha de fail-open que o restante do Guardião
já faz — o falso positivo relatado é preferível ao falso negativo escondido.
"""

from __future__ import annotations

import io
import tokenize

VALOR_LITERAL = "VALOR_LITERAL"
IDENTIFICADOR = "IDENTIFICADOR"
COMENTARIO = "COMENTARIO"

_CATEGORIA_POR_TIPO: dict[int, str] = {
    tokenize.STRING: VALOR_LITERAL,
    tokenize.NAME: IDENTIFICADOR,
    tokenize.COMMENT: COMENTARIO,
}


def mapa_de_posicoes(texto: str) -> dict[tuple[int, int], str]:
    """Tokeniza ``texto`` como Python e devolve ``{(linha, coluna): categoria}`` para toda
    posição coberta por um token STRING, NAME ou COMMENT.

    Endereçamento igual ao que o motor já usa em ``core/engine.py``: linha 1-based,
    coluna 0-based, intervalo ``[início, fim)`` — o mesmo que ``regex.finditer`` devolve
    por linha. Token multi-linha (string triple-quoted) marca cada linha física que
    atravessa.

    Texto que não tokeniza devolve ``{}`` (fail-open) — nunca levanta.
    """
    mapa: dict[tuple[int, int], str] = {}
    linhas = texto.splitlines()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(texto).readline):
            categoria = _CATEGORIA_POR_TIPO.get(tok.type)
            if categoria is not None:
                _marcar(mapa, tok.start, tok.end, linhas, categoria)
    except (tokenize.TokenError, SyntaxError, UnicodeError):
        # UnicodeError (Decode/Encode): a partir do Python 3.12 o tokenizer C faz um
        # round-trip interno de (de/en)codificação mesmo recebendo `str`, e certas
        # sequências Unicode válidas em `str` o fazem levantar UnicodeDecodeError
        # (achado pelo Hypothesis com `'\r\x80'`, ausente no tokenizer puro-Python do
        # 3.10/3.11). Não é sintaxe nem fim-de-arquivo, mas é a mesma classe de "não
        # tokenizou" — fail-open, não propaga.
        return {}
    return mapa


def _marcar(
    mapa: dict[tuple[int, int], str],
    inicio: tuple[int, int],
    fim: tuple[int, int],
    linhas: list[str],
    categoria: str,
) -> None:
    (linha_i, col_i), (linha_f, col_f) = inicio, fim
    if linha_i == linha_f:
        for col in range(col_i, col_f):
            mapa[(linha_i, col)] = categoria
        return
    primeiro_comprimento = len(linhas[linha_i - 1]) if linha_i - 1 < len(linhas) else col_i
    for col in range(col_i, primeiro_comprimento):
        mapa[(linha_i, col)] = categoria
    for linha in range(linha_i + 1, linha_f):
        comprimento = len(linhas[linha - 1]) if linha - 1 < len(linhas) else 0
        for col in range(comprimento):
            mapa[(linha, col)] = categoria
    for col in range(col_f):
        mapa[(linha_f, col)] = categoria

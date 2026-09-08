"""Carregador de regras declarativas externas (arquivo TOML).

Complementa o catálogo embutido (``rules/definitions.py``) sem exigir release
do Guardião: um consultor com um padrão específico de cliente — token
interno, convenção de nome de segredo — declara a regra num arquivo e passa
``--regras arquivo.toml``. O motor (``core/engine.py``) trata a regra
resultante IGUAL às internas: mesmo :class:`~guardiao.rules.base.Rule`, mesmo
caminho de execução, mesma estrutura no relatório.

Formato — uma ou mais tabelas ``[[regra]]``::

    [[regra]]
    id = "acme-token-interno"
    padrao = 'ACME_TOK_[A-Z0-9]{32}'
    severidade = "high"                   # critical | high | medium | low | info
    categoria = "secret"                  # opcional, default "secret"
    only_files = ["*.env"]                # opcional, default: vale para qualquer arquivo
    titulo = "Token interno Acme vazado"  # opcional, default = id

Erro de sintaxe TOML, campo obrigatório ausente, severidade desconhecida,
regex inválida ou id duplicado abortam com :class:`ExternalRuleError` — na
política do robô (POLITICA.md), um critério que a automação não sabe cumprir
trava o item em vez de adivinhar; o mesmo vale aqui: um arquivo de regras mal
formado trava o carregamento em vez de rodar a varredura com metade das
regras que o operador pediu.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Python 3.11+ traz tomllib na stdlib; o piso do projeto é 3.10 (pyproject
# `requires-python`), que precisa do backport `tomli` — mesma API, então o
# `as tomllib` deixa o resto do módulo indiferente a qual dos dois carregou.
# `sys.version_info` (não `try/except ImportError`) é de propósito: é a forma
# que o mypy resolve estaticamente, então o `tool.mypy.python_version = "3.10"`
# do pyproject checa o mesmo ramo (`tomli`) em toda a matriz de CI, e não só
# onde o interpretador real for 3.10.
if sys.version_info >= (3, 11):  # pragma: no cover - ramo depende do interpretador
    import tomllib
else:  # pragma: no cover - ramo depende do interpretador
    import tomli as tomllib

from guardiao.core.models import Severity
from guardiao.rules.base import Rule, compile_rule

_CAMPOS_OBRIGATORIOS = ("id", "padrao", "severidade")


class ExternalRuleError(RuntimeError):
    """Falha ao carregar regras declarativas de um arquivo externo."""


def load_external_rules(path: Path) -> list[Rule]:
    """Lê ``path`` e devolve as regras declaradas nas tabelas ``[[regra]]``.

    Cada entrada vira um :class:`Rule` pelo mesmo :func:`compile_rule` que o
    catálogo interno usa — o motor não distingue de onde a regra veio.
    """
    bruto = _ler_toml(path)
    entradas = bruto.get("regra", [])
    if not isinstance(entradas, list):
        raise ExternalRuleError(
            f"{path}: 'regra' precisa ser uma lista de tabelas ([[regra]]), "
            f"achei {type(entradas).__name__}"
        )
    if not entradas:
        raise ExternalRuleError(f"{path}: nenhuma tabela [[regra]] encontrada")

    regras: list[Rule] = []
    ids_vistos: set[str] = set()
    for indice, entrada in enumerate(entradas):
        regra = _construir_regra(path, indice, entrada)
        if regra.id in ids_vistos:
            raise ExternalRuleError(f"{path}: id de regra duplicado: {regra.id!r}")
        ids_vistos.add(regra.id)
        regras.append(regra)
    return regras


def _ler_toml(path: Path) -> dict[str, object]:
    try:
        with Path(path).open("rb") as arquivo:
            return tomllib.load(arquivo)
    except FileNotFoundError as exc:
        raise ExternalRuleError(f"{path}: arquivo não encontrado") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ExternalRuleError(f"{path}: TOML inválido — {exc}") from exc


def _construir_regra(path: Path, indice: int, entrada: object) -> Rule:
    onde = f"{path} [[regra]] #{indice + 1}"
    if not isinstance(entrada, dict):
        raise ExternalRuleError(f"{onde}: cada entrada precisa ser uma tabela")

    faltando = [campo for campo in _CAMPOS_OBRIGATORIOS if campo not in entrada]
    if faltando:
        raise ExternalRuleError(
            f"{onde}: campo(s) obrigatório(s) ausente(s): {', '.join(faltando)}"
        )

    id_ = entrada["id"]
    padrao = entrada["padrao"]
    if not isinstance(id_, str) or not id_:
        raise ExternalRuleError(f"{onde}: 'id' precisa ser uma string não-vazia")
    if not isinstance(padrao, str) or not padrao:
        raise ExternalRuleError(f"{onde}: 'padrao' precisa ser uma string não-vazia")

    severidade_bruta = entrada["severidade"]
    try:
        severidade = Severity(str(severidade_bruta).lower())
    except ValueError as exc:
        validas = ", ".join(s.value for s in Severity)
        raise ExternalRuleError(
            f"{onde}: severidade desconhecida {severidade_bruta!r} (válidas: {validas})"
        ) from exc

    try:
        re.compile(padrao)
    except re.error as exc:
        raise ExternalRuleError(f"{onde}: regex inválida em 'padrao': {exc}") from exc

    categoria = entrada.get("categoria", "secret")
    if not isinstance(categoria, str) or not categoria:
        raise ExternalRuleError(f"{onde}: 'categoria' precisa ser uma string não-vazia")

    only_files = entrada.get("only_files", [])
    if not isinstance(only_files, list) or not all(isinstance(p, str) for p in only_files):
        raise ExternalRuleError(f"{onde}: 'only_files' precisa ser uma lista de strings")

    titulo = entrada.get("titulo", id_)
    if not isinstance(titulo, str) or not titulo:
        raise ExternalRuleError(f"{onde}: 'titulo' precisa ser uma string não-vazia")

    recomendacao = entrada.get("recomendacao", "")
    if not isinstance(recomendacao, str):
        raise ExternalRuleError(f"{onde}: 'recomendacao' precisa ser uma string")

    return compile_rule(
        id=id_,
        title=titulo,
        severity=severidade,
        pattern=padrao,
        category=categoria,
        only_files=tuple(only_files),
        recommendation=recomendacao,
    )

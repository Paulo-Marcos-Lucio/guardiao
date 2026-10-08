"""Regras carregadas de fora do catálogo nativo (G05).

Duas fontes, um mesmo destino (:class:`guardiao.rules.base.Rule`):

- **nativa**: TOML no formato próprio do Guardião — mesmos campos do catálogo
  embutido, para quem já conhece ``rules/definitions.py`` e quer estender sem
  recompilar a ferramenta.
- **gitleaks**: TOML no formato de ``gitleaks.toml`` (``[[rules]]`` com
  ``id``/``regex``/``keywords``/``secretGroup``), para reaproveitar um catálogo
  que já existe no ecossistema sem reescrevê-lo à mão.

A tradução completa Go RE2 → ``re`` (classes Unicode ``\\p{...}``, particularidades
de ``gitleaks.toml`` que não têm equivalente direto) é dívida declarada para G-05a;
aqui o regex é compilado como está, e uma regra que não compila em Python vira erro
claro — nunca um `scan` que finge ter carregado algo que não carregou.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from guardiao.core.models import Severity
from guardiao.rules.base import Rule, compile_rule

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[import-not-found]


class RegraExternaError(ValueError):
    """Arquivo de regras externas malformado ou com campo inválido.

    Fail-closed: um TOML quebrado não pode fazer o `scan` silenciosamente
    rodar com menos regras do que o usuário pediu.
    """


#: Severidade atribuída a uma regra de ``gitleaks.toml``, que não carrega severidade
#: própria no formato de origem. MEDIUM — nem o piso (que a tornaria invisível por
#: padrão em ``--fail-on medium``), nem HIGH/CRITICAL (que exigem CVSS-mente justificado
#: do catálogo nativo, revisado a dedo). G-05c formaliza isto como teto por `origem`.
SEVERIDADE_GITLEAKS_PADRAO = Severity.MEDIUM


def _ler_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as f:
            doc: dict[str, Any] = tomllib.load(f)
            return doc
    except OSError as exc:
        raise RegraExternaError(f"{path}: não foi possível ler o arquivo ({exc})") from exc
    except tomllib.TOMLDecodeError as exc:
        raise RegraExternaError(f"{path}: TOML inválido ({exc})") from exc


def _id_e_pattern(path: Path, bruta: dict[str, Any]) -> tuple[str, str]:
    id_ = bruta.get("id")
    pattern = bruta.get("regex")
    if not isinstance(id_, str) or not id_:
        raise RegraExternaError(f"{path}: regra sem `id` (ou `id` vazio)")
    if not isinstance(pattern, str) or not pattern:
        raise RegraExternaError(f"{path}: regra {id_!r} sem `regex` (ou `regex` vazio)")
    return id_, pattern


def carregar_regras_nativas(path: Path) -> list[Rule]:
    """Carrega regras no formato nativo do Guardião (mesmos campos de ``Rule``)."""
    doc = _ler_toml(path)
    brutas = doc.get("regras", [])
    if not isinstance(brutas, list):
        raise RegraExternaError(f"{path}: `regras` precisa ser uma lista de tabelas `[[regras]]`")

    regras: list[Rule] = []
    for bruta in brutas:
        if not isinstance(bruta, dict):
            raise RegraExternaError(f"{path}: item de `regras` não é uma tabela TOML")
        id_, pattern = _id_e_pattern(path, bruta)

        severidade_bruta = bruta.get("severidade", "medium")
        try:
            severidade = Severity(str(severidade_bruta).lower())
        except ValueError as exc:
            validas = ", ".join(s.value for s in Severity)
            raise RegraExternaError(
                f"{path}: regra {id_!r} tem severidade {severidade_bruta!r} inválida "
                f"(válidas: {validas})"
            ) from exc

        try:
            regras.append(
                compile_rule(
                    id=id_,
                    title=str(bruta.get("titulo", id_)),
                    severity=severidade,
                    pattern=pattern,
                    cwe=bruta.get("cwe"),
                    owasp=bruta.get("owasp"),
                    category=str(bruta.get("categoria", "secret")),
                    recommendation=str(bruta.get("recomendacao", "")),
                    secret_group=int(bruta.get("secret_group", 0)),
                    keywords=tuple(bruta.get("keywords", ())),
                    only_files=tuple(bruta.get("only_files", ())),
                    composto=bool(bruta.get("composto", False)),
                    heuristica=bool(bruta.get("heuristica", False)),
                )
            )
        except Exception as exc:  # regex malformado etc. — nunca estoura cru para o usuário
            raise RegraExternaError(f"{path}: regra {id_!r} inválida ({exc})") from exc
    return regras


def carregar_gitleaks_toml(path: Path) -> list[Rule]:
    """Carrega regras no formato de ``gitleaks.toml`` (``[[rules]]``).

    O regex de origem é Go RE2; aqui ele é compilado DIRETO com ``re`` — a
    maioria das regras de gitleaks (classes de caractere, quantificadores,
    grupos nomeados) é válida nos dois motores. Uma regra que usa sintaxe
    específica de RE2 sem equivalente em ``re`` falha alto (:class:`RegraExternaError`),
    não é silenciosamente ignorada — a tradução completa é G-05a.
    """
    doc = _ler_toml(path)
    brutas = doc.get("rules", [])
    if not isinstance(brutas, list):
        raise RegraExternaError(f"{path}: `rules` precisa ser uma lista de tabelas `[[rules]]`")

    regras: list[Rule] = []
    for bruta in brutas:
        if not isinstance(bruta, dict):
            raise RegraExternaError(f"{path}: item de `rules` não é uma tabela TOML")
        id_, pattern = _id_e_pattern(path, bruta)

        try:
            regras.append(
                compile_rule(
                    id=id_,
                    title=str(bruta.get("description", id_)),
                    severity=SEVERIDADE_GITLEAKS_PADRAO,
                    pattern=pattern,
                    category="secret",
                    secret_group=int(bruta.get("secretGroup", 0)),
                    keywords=tuple(bruta.get("keywords", ())),
                    heuristica=True,  # sem forma validada por fornecedor: trata como heurística
                )
            )
        except Exception as exc:  # regex RE2 sem equivalente direto em `re`
            raise RegraExternaError(
                f"{path}: regra {id_!r} não compila em `re` ({exc}) — "
                "tradução Go RE2→re completa é escopo de G-05a"
            ) from exc
    return regras


def mesclar_regras(nativas: list[Rule], externas: list[Rule]) -> tuple[list[Rule], list[str]]:
    """Funde o catálogo nativo com regras externas. NUNCA deixa uma externa
    substituir uma nativa pelo mesmo ``id`` — devolve os ids descartados por
    colisão para o chamador avisar o usuário.

    Sem esta trava, um arquivo `--rules-file`/`--gitleaks-config` controlado por
    terceiro poderia neutralizar silenciosamente um detector nativo (ex.: um
    `id="aws-access-key-id"` com um regex que nunca casa nada).
    """
    ids_nativos = {rule.id for rule in nativas}
    aceitas: list[Rule] = []
    descartadas: list[str] = []
    ids_vistos = set(ids_nativos)
    for rule in externas:
        if rule.id in ids_vistos:
            descartadas.append(rule.id)
            continue
        ids_vistos.add(rule.id)
        aceitas.append(rule)
    return [*nativas, *aceitas], descartadas

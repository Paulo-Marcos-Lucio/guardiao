"""Definição de uma regra de detecção.

Uma regra é **dado**, não código: o motor (``core/engine.py``) é quem sabe
percorrer a linha, aplicar filtros e montar o achado. Aqui só há o dataclass
declarativo e o construtor que compila a regex.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from guardiao.core.models import Severity


@dataclass(frozen=True)
class Rule:
    """Regra baseada em expressão regular.

    ``secret_group`` indica qual grupo da regex contém o segredo em si (0 = o
    casamento inteiro). ``min_entropy``, ``keywords``, ``validator`` e
    ``only_files`` são filtros aplicados **pelo motor** para reduzir
    falso-positivo:

    - ``keywords``: alguma delas precisa aparecer na linha (contexto de segredo);
    - ``validator``: predicado sobre o valor casado (ex.: dígito verificador de CPF);
    - ``only_files``: a regra só vale para arquivos cujo *nome* case um destes
      padrões :mod:`fnmatch` (ex.: ``.env`` — onde o formato ``CHAVE=valor`` sem
      aspas é a norma, e fora dos quais ele seria ruído puro).
    """

    id: str
    title: str
    severity: Severity
    regex: re.Pattern[str]
    cwe: str | None = None
    owasp: str | None = None
    category: str = "secret"
    recommendation: str = ""
    secret_group: int = 0
    min_entropy: float | None = None
    keywords: tuple[str, ...] = field(default_factory=tuple)
    validator: Callable[[str], bool] | None = None
    only_files: tuple[str, ...] = field(default_factory=tuple)
    #: O valor casado é uma cadeia COMPOSTA (URI, connection string) em que o segredo
    #: está embutido junto de partes não-secretas (host, nome do banco). O filtro
    #: genérico de placeholder por SUBSTRING (``looks_like_placeholder``) foi feito para
    #: valores atômicos e dispara errado aqui — um host ``db.prod.internal/sample_reports``
    #: contém ``sample`` sem ser exemplo. Quando ``True``, o motor pula esse filtro e
    #: delega ao ``validator`` a decisão de real-vs-exemplo (que parseia a estrutura).
    composto: bool = False
    #: A regra é HEURÍSTICA (entropia, atribuição genérica, config/dotenv/pgpass) — o
    #: valor casado NÃO tem forma de fornecedor validada pela própria regex. Só nessas o
    #: filtro de placeholder por substring é admissível, e ainda assim só quando o marcador
    #: DOMINA o valor (:func:`placeholder_domina`). Regras de FORMATO/fornecedor
    #: (``heuristica=False``) têm a forma travada pela regex e só podem ser barradas pelo
    #: valor de exemplo por INTEIRO (:func:`is_obvious_fake`) — nunca por uma substring
    #: (``todo``/``mock``) perdida no meio de um token real (classe FN-P0).
    heuristica: bool = False
    #: CONDIÇÃO NECESSÁRIA (não suficiente) para a regex casar: toda vez que ``regex``
    #: produz um match, pelo menos um destes literais está contido (sem diferenciar
    #: maiúscula/minúscula) no texto casado. Não é extraído automaticamente da regex —
    #: é declarado à mão por quem escreve a regra, porque é quem sabe qual trecho é
    #: fixo (``"AKIA"``, ``"ghp_"``, a palavra ``"secret"``…) e qual é a parte variável
    #: (o segredo em si). Tupla vazia = nenhum literal confiável existe (ex.: entropia
    #: pura, onde o valor casado pode ser qualquer cadeia alfanumérica) — a regra segue
    #: sem pré-filtro de literal, e outro filtro (``keywords``) cobre o caso.
    #: Consumido pelo motor como um portão BARATO antes de rodar a regex em si: uma
    #: linha sem nenhum dos literais não pode casar, e a regex cara nem precisa rodar.
    literais: tuple[str, ...] = field(default_factory=tuple)


def compile_rule(
    id: str,
    title: str,
    severity: Severity,
    pattern: str,
    *,
    flags: int = 0,
    cwe: str | None = None,
    owasp: str | None = None,
    category: str = "secret",
    recommendation: str = "",
    secret_group: int = 0,
    min_entropy: float | None = None,
    keywords: tuple[str, ...] = (),
    validator: Callable[[str], bool] | None = None,
    only_files: tuple[str, ...] = (),
    composto: bool = False,
    heuristica: bool = False,
    literais: tuple[str, ...] = (),
) -> Rule:
    return Rule(
        id=id,
        title=title,
        severity=severity,
        regex=re.compile(pattern, flags),
        cwe=cwe,
        owasp=owasp,
        category=category,
        recommendation=recommendation,
        secret_group=secret_group,
        min_entropy=min_entropy,
        keywords=keywords,
        validator=validator,
        only_files=only_files,
        composto=composto,
        heuristica=heuristica,
        literais=literais,
    )

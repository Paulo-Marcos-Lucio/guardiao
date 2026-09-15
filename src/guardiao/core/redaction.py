"""Ocultação de segredos.

Regra de ouro da ferramenta: **o segredo cru nunca sai** para o terminal, JSON
ou SARIF. Mostramos só o suficiente para o dono identificar qual credencial é
(as pontas), sem vazar o valor nem o comprimento exato.
"""

from __future__ import annotations

from collections.abc import Iterable

#: Quanto de cada ponta sobrevive em artefato **publicado** — o baseline (que o README
#: manda VERSIONAR no repo do cliente) e o SARIF (que sobe para o Code Scanning e é
#: legível por quem tiver leitura no repositório). Com os 4+4 do padrão, todo segredo
#: de 13+ caracteres saía com 8 em claro: numa senha humana de 16 (``Nordeste2019!Rj``)
#: isso é metade dela, e um dicionário recupera o resto. O console fica em 4+4 de
#: propósito: ele não é publicado — morre na estação de quem triou, e é ali que o dono
#: precisa reconhecer *qual* credencial é, de relance.
KEEP_PUBLICADO = 2


def redact(secret: str, *, keep: int = 4) -> str:
    """Mascara um segredo preservando apenas as pontas (caminho do CONSOLE, 4+4).

    Não é o caminho publicado: o console morre na estação de quem triou e revela mais
    para o dono reconhecer *qual* credencial é, de relance. O que sai para artefato
    versionado/publicado passa por :func:`redact_publicado`.
    """
    s = secret.strip()
    n = len(s)
    if n == 0:
        return ""
    # Se as pontas quase se encontram, revela quase nada (e não vaza o comprimento).
    if n <= 2 * keep + 4:
        return s[0] + "…"
    return f"{s[:keep]}…{s[-keep:]}"


def redact_publicado(secret: str, *, keep: int = KEEP_PUBLICADO, mark: str = "…") -> str:
    """Ocultação de ARTEFATO PUBLICADO (baseline versionado, SARIF do Code Scanning).

    Esta é a **receita canônica da suíte AppSec**: idêntica nas quatro ferramentas, para
    o cliente conferir os quatro laudos com UMA regra só. A invariante de paridade está
    travada por ``tests/test_paridade_receita_suite.py``, que importa ESTA função (a de
    produção) e prova que ela bate com o valor-ouro compartilhado.

    Mostra no máximo ``keep`` caracteres por ponta (padrão :data:`KEEP_PUBLICADO` = 2);
    um segredo curto demais para exibir as duas pontas sem elas se tocarem
    (``len(s) <= 2 * keep``) vira **só** o marcador ``…`` — não vaza nem uma ponta nem o
    comprimento. Difere de propósito de :func:`redact` (console): o publicado é lido por
    todo mundo com acesso ao repositório, então é o caminho mais estrito.
    """
    s = secret.strip()
    if len(s) <= 2 * keep:
        return mark
    return f"{s[:keep]}{mark}{s[-keep:]}"


def redact_spans(line: str, spans: Iterable[tuple[int, int, str]], *, keep: int = 4) -> str:
    """Mascara **todos** os segredos de uma linha, um por span (início, fim, segredo).

    Aplica da direita para a esquerda para não deslocar os índices dos spans
    ainda não processados. Garante que nenhum segredo cru sobre no preview,
    mesmo com vários segredos (iguais ou distintos) na mesma linha.

    O ramo de fallback existe porque a promessa da ferramenta é "o segredo cru
    nunca sai": se um chamador futuro passar um span deslocado, mascarar por
    substituição textual é pior em precisão e melhor em segurança — que é a
    troca certa aqui. Ele é exercitado por teste (não é código defensivo morto).
    """
    result = line.strip("\n\r")
    for start, end, secret in sorted(spans, key=lambda s: s[0], reverse=True):
        if 0 <= start < end <= len(result) and result[start:end] == secret:
            result = result[:start] + redact(secret, keep=keep) + result[end:]
        else:  # span deslocado/sobreposto: mascara por valor, custe o que custar
            result = result.replace(secret, redact(secret, keep=keep))
    return result.strip()

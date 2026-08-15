"""Invariante de sincronia entre o catálogo de regras e a tabela do README.

A tabela "O que ele detecta" é escrita à mão; `rules/definitions.py` é o catálogo real.
Nada travava os dois de divergirem, no molde de `esteira/tests/test_catalogo.py`. Escrever
este teste achou que já tinham divergido: a regra `secret-in-path` (token de alta entropia
embutido em URL/caminho — vaza em logs, referrer, histórico do navegador) existe no código,
é exercitada em `test_rules.py`, e não tinha linha nenhuma na tabela. Corrigida junto.
"""

from __future__ import annotations

import re
from pathlib import Path

from guardiao.core.models import Severity
from guardiao.rules.registry import all_rules

_RAIZ = Path(__file__).resolve().parent.parent

# A tabela agrupa mais de uma regra por linha quando elas contam a mesma história ao leitor
# (`aws-access-key-id` / `aws-secret-access-key`, o par `cpf`/`cnpj`...). Quando o valor de
# severidade/OWASP é UM só, ele vale para todas as regras da linha; quando a linha declara um
# valor por regra (separado por "/", sem espaço — ex.: a dupla `slack-token`/`slack-webhook`,
# que tem severidade E owasp diferentes), o valor é lido na mesma ordem dos IDs.
_ID_RE = re.compile(r"`([a-z0-9-]+)`")
_EMOJI_SEVERIDADE = {
    "🔴": Severity.CRITICAL,
    "🟠": Severity.HIGH,
    "🟡": Severity.MEDIUM,
    # 🔵 sozinho é ambíguo (a tabela usa o mesmo círculo para Baixa E Info) — só a
    # palavra escrita desempata, por isso a extração abaixo prioriza a palavra.
}
_PALAVRA_SEVERIDADE = {
    "Crítica": Severity.CRITICAL,
    "Alta": Severity.HIGH,
    "Média": Severity.MEDIUM,
    "Baixa": Severity.LOW,
    "Info": Severity.INFO,
}
_OWASP_RE = re.compile(r"A\d{2}")


def _severidades_da_coluna(coluna: str) -> list[Severity]:
    palavras = re.findall(r"[A-ZÁÉÍÓÚÀÂÊÔÃÕÇ][a-záéíóúàâêôãõç]+", coluna)
    if palavras:
        return [_PALAVRA_SEVERIDADE[p] for p in palavras]
    emojis = [c for c in coluna if c in _EMOJI_SEVERIDADE]
    return [_EMOJI_SEVERIDADE[e] for e in emojis]


def _valores_por_id(ids: list[str], valores: list[object]) -> dict[str, object]:
    """Distribui uma lista de 1 valor (vale para toda a linha) ou N valores (um por ID,
    na mesma ordem) entre os IDs da linha. Qualquer outra contagem é erro de formatação
    do README — melhor estourar aqui do que comparar errado em silêncio."""
    if len(valores) == 1:
        return dict.fromkeys(ids, valores[0])
    assert len(valores) == len(ids), (
        f"{ids!r} tem {len(ids)} regra(s) mas a linha declara {valores!r}"
    )
    return dict(zip(ids, valores, strict=True))


def _secao_o_que_detecta() -> str:
    texto = (_RAIZ / "README.md").read_text(encoding="utf-8")
    trecho = texto.split("## 🔎 O que ele detecta", 1)[1]
    return trecho.split("\n## ", 1)[0]


def _linhas_da_tabela() -> list[list[str]]:
    linhas = []
    for linha in _secao_o_que_detecta().splitlines():
        if not linha.startswith("|") or set(linha.strip("| \n")) <= {"-", " "}:
            continue
        celulas = [c.strip() for c in linha.strip().strip("|").split("|")]
        if celulas[0] == "Regra":
            continue
        linhas.append(celulas)
    return linhas


def _catalogo_do_readme() -> tuple[dict[str, Severity], dict[str, str]]:
    """`({id: severidade}, {id: código OWASP})` — um par de dicts, lidos da tabela real."""
    severidade_por_id: dict[str, Severity] = {}
    owasp_por_id: dict[str, str] = {}
    for regra_col, _detecta, sev_col, owasp_col in _linhas_da_tabela():
        ids = _ID_RE.findall(regra_col)
        severidade_por_id.update(_valores_por_id(ids, _severidades_da_coluna(sev_col)))
        owasp_por_id.update(_valores_por_id(ids, _OWASP_RE.findall(owasp_col)))
    return severidade_por_id, owasp_por_id


def test_toda_regra_esta_documentada_no_readme() -> None:
    """Regra nova em `definitions.py` sem linha na tabela não entra: o `secret-in-path`
    era exatamente esse caso — existia, era testado, e ninguém que lesse o README saberia."""
    severidade_por_id, _ = _catalogo_do_readme()
    assert set(severidade_por_id) == {r.id for r in all_rules()}


def test_readme_declara_a_severidade_real() -> None:
    severidade_por_id, _ = _catalogo_do_readme()
    divergentes = {
        r.id: (severidade_por_id[r.id], r.severity)
        for r in all_rules()
        if severidade_por_id[r.id] != r.severity
    }
    assert divergentes == {}


def test_readme_declara_o_rotulo_owasp_real() -> None:
    _, owasp_por_id = _catalogo_do_readme()
    divergentes = {
        r.id: (owasp_por_id[r.id], r.owasp)
        for r in all_rules()
        if r.owasp is not None and owasp_por_id[r.id] != r.owasp.split(":", 1)[0]
    }
    assert divergentes == {}

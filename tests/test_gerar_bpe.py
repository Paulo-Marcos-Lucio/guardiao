"""`tools/gerar_bpe.py` — o treino é determinístico e o artefato embarcado confere.

Não retreina os 8000 merges aqui (o script real leva ~15s; CI roda em matriz de
4 versões de Python e isso empilharia). Em vez disso, prova a MESMA
propriedade por um atalho válido: o treino de BPE é greedy por iteração — a
escolha do merge N nunca depende de quantos merges viriam depois — então os
primeiros K merges de um treino completo são IDÊNTICOS aos de um treino que
pede só K. Re-treinar um K pequeno e comparar contra o prefixo do arquivo
JÁ EMBARCADO (`src/guardiao/data/bpe_min.json`) prova reprodutibilidade em
milissegundos, e também pega o caso real de regressão: alguém editar o
algoritmo sem regerar o artefato.
"""

from __future__ import annotations

import json
from pathlib import Path

from tools import gerar_bpe

_RAIZ = Path(__file__).resolve().parent.parent
_ARTEFATO = _RAIZ / "src" / "guardiao" / "data" / "bpe_min.json"
_PREFIXO = 64


def _documento_embarcado() -> dict[str, object]:
    return json.loads(_ARTEFATO.read_text(encoding="utf-8"))


def test_artefato_embarcado_existe_e_tem_a_forma_esperada() -> None:
    doc = _documento_embarcado()
    assert doc["formato"] == "guardiao-bpe-caractere/1"
    assert isinstance(doc["num_merges"], int) and doc["num_merges"] > 0
    assert len(doc["merges"]) == doc["num_merges"]
    assert doc["fonte"]["corpus_sha256"].startswith("sha256:")


def test_artefato_nao_baixa_nada_da_rede() -> None:
    # `ler_corpus` só lê arquivos locais do próprio repositório — nenhuma
    # biblioteca de rede (requests/httpx/urllib) é importada pelo módulo.
    import ast

    codigo = (_RAIZ / "tools" / "gerar_bpe.py").read_text(encoding="utf-8")
    arvore = ast.parse(codigo)
    modulos_importados = {
        alias.name.split(".")[0]
        for node in ast.walk(arvore)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".")[0]
        for node in ast.walk(arvore)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    proibidos = {"requests", "httpx", "urllib", "urllib3", "socket", "http"}
    assert not (modulos_importados & proibidos)


def test_treino_pequeno_reproduz_o_prefixo_do_artefato_embarcado() -> None:
    doc = _documento_embarcado()
    corpus = gerar_bpe.ler_corpus()
    assert doc["fonte"]["corpus_sha256"] == (
        "sha256:" + __import__("hashlib").sha256(corpus.encode("utf-8")).hexdigest()
    )

    merges_recem_treinados = gerar_bpe.treinar_merges(corpus, _PREFIXO)
    prefixo_embarcado = [tuple(par) for par in doc["merges"][:_PREFIXO]]
    assert [tuple(par) for par in merges_recem_treinados] == prefixo_embarcado


def test_treino_e_deterministico_entre_chamadas() -> None:
    corpus = gerar_bpe.ler_corpus()
    primeira = gerar_bpe.treinar_merges(corpus, 100)
    segunda = gerar_bpe.treinar_merges(corpus, 100)
    assert primeira == segunda


def test_treino_para_quando_nenhum_par_repete() -> None:
    # Corpus minúsculo e sem repetição: nenhum par tem frequência >= 2, então o
    # treino para em 0 merges em vez de inventar merges de pares únicos.
    assert gerar_bpe.treinar_merges("abcdefg", num_merges=100) == []


def test_treino_para_no_numero_pedido_quando_ha_repeticao_suficiente() -> None:
    merges = gerar_bpe.treinar_merges("ab ab ab ab", num_merges=1)
    assert merges == [("a", "b")]

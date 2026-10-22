#!/usr/bin/env python3
"""Treina um vocabulário BPE mínimo, 100% offline — item G-07a.

Por que isto existe: `core/token_efficiency.py` (item G-07b, ainda não
implementado) vai medir ``eficiencia(s) = len(s) / len(tokens_BPE)`` para
diferenciar texto natural (comprime bem sob BPE — poucos tokens, cada um
cobrindo vários caracteres) de segredo aleatório (não comprime — quase um
token por caractere). Isso exige um vocabulário BPE treinado em texto
NATURAL — e "offline" é requisito de produto, não só de performance: o
Guardião varre repositório de cliente; ele nunca pode precisar baixar nada
da rede para funcionar (lição já aprendida com `core/entropy.py` e o alfabeto
teórico — tudo aqui é medido localmente).

Fonte do corpus: uma lista FIXA e explícita de arquivos deste próprio
repositório (`src/guardiao/**/*.py` + `README.md`) — código-fonte legível
(identificadores, palavras-chave de Python) e prosa em PT-BR, a MESMA
classe de texto "natural" em que um segredo de verdade apareceria embutido.
`tests/` e `bench/` ficam de fora DE PROPÓSITO: lá o conteúdo é segredo
sintético por design (é o objeto de teste do resto do Guardião) — treinar o
vocabulário nisso contaminaria exatamente o sinal que `token_efficiency`
vai medir.

Determinístico por construção: a lista de arquivos é ordenada, a leitura é
UTF-8 byte-a-byte, e o desempate de pares com a mesma frequência usa ordem
lexicográfica (nunca ordem de iteração de dict/hash, que o Python não
garante estável entre processos para alguns tipos). Rodar este script duas
vezes sobre o mesmo corpus produz exatamente o mesmo
``src/guardiao/data/bpe_min.json`` — é a invariante que ``tests/
test_gerar_bpe.py`` confere (num treino pequeno, rápido o bastante pro CI).

Uso:
    python tools/gerar_bpe.py                        # grava o vocabulário real
    python tools/gerar_bpe.py --num-merges 50 --out /tmp/x.json --print-corpus-sha256
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from itertools import pairwise
from pathlib import Path

_RAIZ = Path(__file__).resolve().parent.parent
_SAIDA_PADRAO = _RAIZ / "src" / "guardiao" / "data" / "bpe_min.json"
_NUM_MERGES_PADRAO = 8000

# Documentação em prosa (PT-BR e EN) — curada à mão, não glob de "todo .md do
# repo": um .md gerado ou um relatório futuro não deveria entrar aqui sem
# alguém decidir isso. `bench/README.md` é a ÚNICA coisa de `bench/` no corpus
# (é prosa explicando o benchmark — os fixtures de segredo em
# `bench/positivos`/`bench/negativos` continuam de fora, ver docstring do módulo).
_DOCS_FONTE: tuple[str, ...] = (
    "README.md",
    "README.en.md",
    "CONTRIBUTING.md",
    "CONTRIBUTING.en.md",
    "SECURITY.md",
    "SECURITY.en.md",
    "BENCHMARK.md",
    "BENCHMARK.en.md",
    "CHANGELOG.md",
    "bench/README.md",
)

# Lista fixa, nunca gerada por `glob` na hora de RODAR: o glob roda uma vez aqui
# (ordenado) para popular a lista, mas é o conteúdo desses arquivos — não o
# diretório em si — que determina o corpus. Ver docstring do módulo.
_ARQUIVOS_FONTE: tuple[str, ...] = (
    tuple(sorted(str(p.relative_to(_RAIZ)) for p in (_RAIZ / "src" / "guardiao").rglob("*.py")))
    + _DOCS_FONTE
)

# `\S+` junta um "trecho sem espaço" (identificador, palavra, pontuação colada);
# `\s+` junta uma corrida de espaço/quebra de linha como uma unidade própria —
# indentação de código repete muito e BPE aprende isso rápido.
_PALAVRA = re.compile(r"\S+|\s+")


def ler_corpus(raiz: Path = _RAIZ, arquivos: tuple[str, ...] = _ARQUIVOS_FONTE) -> str:
    """Concatena os arquivos-fonte, na ordem fixa, como um único texto."""
    return "".join((raiz / rel).read_text(encoding="utf-8") for rel in arquivos)


def treinar_merges(corpus: str, num_merges: int) -> list[tuple[str, str]]:
    """BPE a nível de CARACTERE (não de byte): mais simples que o BPE de byte do
    GPT-2 — não precisa de uma tabela byte-para-unicode-imprimível para caber em
    JSON — e a propriedade que importa aqui (texto natural comprime, segredo
    aleatório não) não depende de operar em bytes.

    Algoritmo clássico de Sennrich et al. (2016), mas contado por PALAVRA ÚNICA
    pesada por frequência (não por sequência inteira do corpus): código e prosa
    repetem muita palavra idêntica (``self``, ``def``, ``return``, artigos em
    PT-BR...), então o conjunto de palavras únicas é uma fração pequena do
    corpus — é isso que torna o treino rápido em Python puro. As contagens de
    par são atualizadas de forma INCREMENTAL (só nas palavras afetadas pelo
    merge escolhido), não recalculadas do zero a cada iteração — sem isso, 8000
    merges sobre ~230KB levam minutos em vez de segundos.

    Para em ``num_merges`` OU quando nenhum par repete (frequência < 2) — o que
    vier primeiro. Um par que só ocorre uma vez não é padrão, é coincidência; um
    merge ali não ensinaria nada sobre o corpus, só inflaria o vocabulário.
    """
    palavras = _PALAVRA.findall(corpus)
    frequencia: Counter[str] = Counter(palavras)
    simbolos: dict[str, list[str]] = {p: list(p) for p in frequencia}

    def pares(seq: list[str]) -> list[tuple[str, str]]:
        return list(pairwise(seq))

    contagem_pares: Counter[tuple[str, str]] = Counter()
    par_para_palavras: defaultdict[tuple[str, str], set[str]] = defaultdict(set)
    for palavra, seq in simbolos.items():
        freq = frequencia[palavra]
        for par in pares(seq):
            contagem_pares[par] += freq
            par_para_palavras[par].add(palavra)

    merges: list[tuple[str, str]] = []
    while len(merges) < num_merges:
        if not contagem_pares:
            break
        maior = max(contagem_pares.values())
        if maior < 2:
            break
        # Desempate determinístico: ordem lexicográfica do par, nunca ordem de
        # iteração do dict (que depende de histórico de inserção/remoção).
        par = min(p for p, c in contagem_pares.items() if c == maior)
        novo_simbolo = par[0] + par[1]
        merges.append(par)

        for palavra in list(par_para_palavras.get(par, ())):
            seq = simbolos[palavra]
            freq = frequencia[palavra]
            for p in pares(seq):
                contagem_pares[p] -= freq
                if contagem_pares[p] <= 0:
                    del contagem_pares[p]
                par_para_palavras[p].discard(palavra)
                if not par_para_palavras[p]:
                    del par_para_palavras[p]

            nova_seq: list[str] = []
            i = 0
            tamanho = len(seq)
            while i < tamanho:
                if i < tamanho - 1 and seq[i] == par[0] and seq[i + 1] == par[1]:
                    nova_seq.append(novo_simbolo)
                    i += 2
                else:
                    nova_seq.append(seq[i])
                    i += 1
            simbolos[palavra] = nova_seq

            for p in pares(nova_seq):
                contagem_pares[p] += freq
                par_para_palavras[p].add(palavra)

    return merges


def montar_documento(corpus: str, merges: list[tuple[str, str]]) -> dict[str, object]:
    alfabeto_inicial = sorted(set(corpus))
    corpus_sha256 = "sha256:" + hashlib.sha256(corpus.encode("utf-8")).hexdigest()
    return {
        "formato": "guardiao-bpe-caractere/1",
        "fonte": {"arquivos": list(_ARQUIVOS_FONTE), "corpus_sha256": corpus_sha256},
        "num_merges": len(merges),
        "alfabeto_inicial": alfabeto_inicial,
        "merges": [list(par) for par in merges],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-merges", type=int, default=_NUM_MERGES_PADRAO)
    parser.add_argument("--out", type=Path, default=_SAIDA_PADRAO)
    parser.add_argument(
        "--print-corpus-sha256",
        action="store_true",
        help="só imprime o sha256 do corpus (não treina, não grava nada)",
    )
    args = parser.parse_args()

    corpus = ler_corpus()
    if args.print_corpus_sha256:
        print("sha256:" + hashlib.sha256(corpus.encode("utf-8")).hexdigest())
        return 0

    merges = treinar_merges(corpus, args.num_merges)
    documento = montar_documento(corpus, merges)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(documento, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"corpus: {len(corpus)} caracteres, {len(_ARQUIVOS_FONTE)} arquivos | "
        f"merges: {len(merges)}/{args.num_merges} | gravado em {args.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Testes do manifesto de hash do corpus (`guardiao hash-corpus`).

A invariante de classe é a do próprio critério de aceite: o manifesto nunca
pode carregar um fragmento do segredo — nem os 2-4 caracteres de ponta que
:mod:`guardiao.core.baseline` e o console redigido mantêm. Um teste por
exemplo só provaria isso para os segredos que alguém lembrou de testar; o
Hypothesis gera milhares de segredos e prova que NENHUM deles sobrevive, de
nenhuma forma, no JSON gravado.
"""

from __future__ import annotations

import json
import string
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from guardiao.cli import app
from guardiao.core.manifesto import SALT_BYTES, build_manifesto_document, hash_corpus, hash_segredo

runner = CliRunner()

# Segredos "razoáveis": sem quebra de linha (cada um é UMA linha do arquivo de
# entrada) e com tamanho mínimo que torna a chance de um HMAC/sal aleatório
# conter esse texto por puro acaso desprezível (alfabeto hex tem 16 símbolos;
# 8+ caracteres aleatórios colidirem com 128 caracteres de hex por item é
# astronomicamente improvável).
_SEGREDO = st.text(
    alphabet=st.characters(blacklist_characters="\n\r", blacklist_categories=("Cs",)),
    min_size=8,
    max_size=64,
).filter(lambda s: s.strip() != "")


@given(segredos=st.lists(_SEGREDO, min_size=1, max_size=20))
@settings(max_examples=200)
def test_manifesto_nao_contem_fragmento_do_segredo(segredos: list[str]) -> None:
    documento = build_manifesto_document(segredos)
    bruto = json.dumps(documento, ensure_ascii=False)
    for segredo in segredos:
        assert segredo not in bruto


@given(segredos=st.lists(_SEGREDO, min_size=1, max_size=20))
@settings(max_examples=200)
def test_sal_e_hmac_tem_o_tamanho_declarado(segredos: list[str]) -> None:
    documento = build_manifesto_document(segredos)
    for item in documento["itens"]:
        assert len(item["salt"]) == SALT_BYTES * 2  # hex: 2 chars por byte
        assert all(c in string.hexdigits for c in item["salt"])
        assert len(item["hmac"]) == 64  # SHA-256: 32 bytes = 64 hex chars
        assert all(c in string.hexdigits for c in item["hmac"])


@given(segredos=st.lists(_SEGREDO, min_size=1, max_size=20))
@settings(max_examples=100)
def test_comprimentos_e_o_conjunto_ordenado_dos_tamanhos(segredos: list[str]) -> None:
    documento = build_manifesto_document(segredos)
    esperado = sorted({len(s) for s in segredos})
    assert documento["comprimentos"] == esperado
    assert documento["total"] == len(segredos)


@given(segredo=_SEGREDO)
@settings(max_examples=50)
def test_dois_sais_para_o_mesmo_segredo_nao_se_repetem(segredo: str) -> None:
    a = hash_segredo(segredo)
    b = hash_segredo(segredo)
    assert a.salt != b.salt
    assert a.hmac != b.hmac  # sal diferente muda o HMAC mesmo com o mesmo segredo


def test_hash_segredo_e_determinista_dado_o_mesmo_sal() -> None:
    sal = bytes(range(SALT_BYTES))
    a = hash_segredo("super-secreto-123", salt=sal)
    b = hash_segredo("super-secreto-123", salt=sal)
    assert a == b


def test_cli_hash_corpus_grava_manifesto_sem_o_segredo(tmp_path: Path) -> None:
    segredo = "AKIAABCDEFGHIJKLMNOP"
    entrada = tmp_path / "segredos.txt"
    entrada.write_text(f"{segredo}\noutro-segredo-de-teste\n\n", encoding="utf-8")
    saida = tmp_path / "manifesto.json"

    result = runner.invoke(app, ["hash-corpus", "--entrada", str(entrada), "--saida", str(saida)])

    assert result.exit_code == 0
    bruto = saida.read_text(encoding="utf-8")
    assert segredo not in bruto
    assert "outro-segredo-de-teste" not in bruto

    documento = json.loads(bruto)
    assert documento["total"] == 2  # linha em branco não conta
    assert documento["comprimentos"] == sorted({len(segredo), len("outro-segredo-de-teste")})


def test_hash_corpus_ignora_linhas_em_branco(tmp_path: Path) -> None:
    entrada = tmp_path / "segredos.txt"
    entrada.write_text("a1b2c3d4e5f6\n\n   \ng6f5e4d3c2b1\n", encoding="utf-8")
    saida = tmp_path / "manifesto.json"

    total = hash_corpus(entrada, saida)

    assert total == 2
    documento = json.loads(saida.read_text(encoding="utf-8"))
    assert documento["total"] == 2
    assert len(documento["itens"]) == 2

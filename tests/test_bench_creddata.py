"""Testes do item G-13a: `bench/creddata/baixar.py` + `avaliar.py`.

Cobre só a parte PURA (sem rede, sem clone) — `classificar`, `wilson`,
`normaliza`, `id_curto` e a ofuscação que preserva formato. O fluxo completo
(baixar o CredData real, escanear, avaliar) foi verificado manualmente contra
o dataset de verdade — ver `LEDGER.md` — e não entra na suíte porque depende
de rede e de um clone de ~150MB que a CI não tem por que replicar a cada
`pytest`.
"""

from __future__ import annotations

import string

from bench.creddata import avaliar
from bench.creddata.baixar import LinhaRotulada, _classe_de, _valor_similar, id_curto
from hypothesis import given
from hypothesis import strategies as st


def _linha(
    file_path: str,
    ground_truth: str,
    line_start: int,
    line_end: int | None = None,
) -> LinhaRotulada:
    return LinhaRotulada(
        file_id="00000000",
        file_path=file_path,
        line_start=line_start,
        line_end=line_end if line_end is not None else line_start,
        ground_truth=ground_truth,
        value_start=None,
        value_end=None,
    )


def test_id_curto_bate_com_o_nome_real_do_csv_no_creddata() -> None:
    """Oráculo travado contra o CredData real: este `repo_id` (primeira entrada
    de `snapshot.json` no commit fixado) tem `meta/75e7c64d.csv` publicado —
    conferido manualmente contra o clone real (ver `baixar.py`). Se a fórmula
    do CRC32 mudar, os arquivos baixados passam a não bater com o metadado e
    o item regride em silêncio sem este teste."""
    repo_id = "00a487dd088c6ca2528d025f3273c0a796efe21016d83de0d0aed64e139a5270"
    assert id_curto(repo_id) == "75e7c64d"


def test_classificar_tp_fn_fp() -> None:
    linhas = [
        _linha("data/r/a.py", "T", 10),  # achado em 10: TP
        _linha("data/r/a.py", "T", 20),  # sem achado: FN
        _linha("data/r/b.py", "F", 5),  # achado em 5: FP
    ]
    achados = [("data/r/a.py", 10), ("data/r/b.py", 5)]
    avaliacao = avaliar.classificar(achados, linhas)
    assert avaliacao.tp == 1
    assert avaliacao.fn == 1
    assert avaliacao.fp == 1
    assert avaliacao.total_t == 2
    assert avaliacao.total_f == 1


def test_classificar_exclui_x_de_tp_fp_fn() -> None:
    """Linha `X` (teste/exemplo/placeholder) nunca entra no numerador nem no
    denominador de TP/FP/FN — ver docstring de `avaliar.py`."""
    linhas = [_linha("data/r/a.py", "X", 7)]
    achados = [("data/r/a.py", 7)]
    avaliacao = avaliar.classificar(achados, linhas)
    assert avaliacao.tp == 0
    assert avaliacao.fp == 0
    assert avaliacao.fn == 0
    assert avaliacao.achados_ambiguos_x == 1


def test_classificar_achado_fora_do_rotulado_nao_conta_como_fp() -> None:
    """Linha nunca revisada pelo CredData: não ter rótulo não é ter rótulo
    negativo — reportado à parte, nunca em FP."""
    linhas = [_linha("data/r/a.py", "T", 1)]
    achados = [("data/r/a.py", 1), ("data/r/a.py", 999)]
    avaliacao = avaliar.classificar(achados, linhas)
    assert avaliacao.tp == 1
    assert avaliacao.fp == 0
    assert avaliacao.achados_fora_do_rotulado == 1


def test_classificar_t_tem_prioridade_sobre_f_na_mesma_linha() -> None:
    """Uma linha com rótulos T e F simultâneos (categorias diferentes no
    mesmo número de linha) não pode punir o Guardião por achar a credencial
    real só porque a linha também carrega um rótulo F."""
    linhas = [_linha("data/r/a.py", "T", 1), _linha("data/r/a.py", "F", 1)]
    achados = [("data/r/a.py", 1)]
    avaliacao = avaliar.classificar(achados, linhas)
    assert avaliacao.tp == 1
    assert avaliacao.fp == 0


def test_classificar_span_multilinha_cobre_o_intervalo() -> None:
    linhas = [_linha("data/r/key.pem", "T", 5, 9)]
    for linha_do_achado in (5, 7, 9):
        avaliacao = avaliar.classificar([("data/r/key.pem", linha_do_achado)], linhas)
        assert avaliacao.tp == 1, f"linha {linha_do_achado} deveria cobrir o span 5-9"


def test_wilson_total_zero_nao_divide_por_zero() -> None:
    assert avaliar.wilson(0, 0) == (0.0, 0.0)


def test_wilson_intervalo_contem_a_proporcao_observada() -> None:
    baixo, alto = avaliar.wilson(7, 10)
    assert 0.0 <= baixo <= 0.7 <= alto <= 1.0


def test_normaliza_caminho_relativo_sem_prefixo_data() -> None:
    """É o caso comum: o Guardião reporta caminho relativo à raiz varrida
    (`DATA_DIR`), que já É `.../data` — sem o prefixo `data/` no achado."""
    assert avaliar.normaliza("b6263275/src/9eef4790.properties") == (
        "data/b6263275/src/9eef4790.properties"
    )


def test_normaliza_caminho_absoluto_com_data_no_meio() -> None:
    assert avaliar.normaliza("/home/user/bench/creddata/.cache/data/r/a.py") == "data/r/a.py"


@given(st.text(alphabet=string.ascii_letters + string.digits + "-_.", min_size=3, max_size=40))
def test_valor_similar_preserva_comprimento_e_classe_por_posicao(valor: str) -> None:
    """Invariante da ofuscação: comprimento e classe de caractere por posição
    sobrevivem (é o que mantém o formato legível para as regras do Guardião),
    mas o valor em si nunca sobrevive por completo — ver LEDGER.md sobre a
    primeira versão (marcador fixo) ter medido recall zero por destruir isto."""
    gerado = _valor_similar(valor, semente=42)
    assert len(gerado) == len(valor)
    for original_c, gerado_c in zip(valor, gerado, strict=True):
        if original_c.isalpha() or original_c.isdigit():
            assert original_c.isupper() == gerado_c.isupper()
            assert original_c.islower() == gerado_c.islower()
            assert original_c.isdigit() == gerado_c.isdigit()
        else:
            assert gerado_c == original_c  # símbolo/separador: estrutura, preservado
    n = len(valor)
    prefixo = min(8, max(0, n - 2))
    corpo_original = valor[prefixo:]
    if any(c.isalpha() or c.isdigit() for c in corpo_original):
        # Com pelo menos um caractere alfanumérico no corpo, `_classe_de` exclui
        # o próprio caractere do sorteio — garante diferença, não só "provável".
        assert gerado != valor


def test_valor_similar_nunca_preserva_o_valor_inteiro_mesmo_curto() -> None:
    gerado = _valor_similar("ab", semente=1)
    assert len(gerado) == 2


def test_classe_de_preserva_simbolo() -> None:
    import random

    rng = random.Random(0)
    for simbolo in "-_.@!$":
        assert _classe_de(simbolo, rng) == simbolo


def test_redigir_true_preserva_prefixo_de_formato_mas_troca_o_corpo(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Reproduz a regressão real: um valor com prefixo de provedor (`ghp_...`)
    precisa continuar reconhecível pelo prefixo depois da ofuscação, nunca
    reaparecer por completo."""
    from bench.creddata.baixar import _redigir_true

    valor = "ghp_Rk8xY2mN4pQ7wLvB3cD5fG6hJ9kMnP2qAtZ7u"
    destino = tmp_path / "config.py"
    destino.write_text(f'token = "{valor}"\n', encoding="utf-8")
    linha = LinhaRotulada(
        file_id="deadbeef",
        file_path="data/r/config.py",
        line_start=1,
        line_end=1,
        ground_truth="T",
        value_start=8,
        value_end=8 + len(valor),
    )
    _redigir_true(destino, [linha])
    texto = destino.read_text(encoding="utf-8")
    assert valor not in texto
    assert "ghp_" in texto  # prefixo de formato sobrevive — ver PREFIXO_PRESERVADO


def test_redigir_true_nunca_toca_linha_f_ou_x(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from bench.creddata.baixar import _redigir_true

    destino = tmp_path / "config.py"
    original = 'password = "nao-e-segredo-de-verdade"\n'
    destino.write_text(original, encoding="utf-8")
    linha_f = LinhaRotulada(
        file_id="x",
        file_path="data/r/config.py",
        line_start=1,
        line_end=1,
        ground_truth="F",
        value_start=11,
        value_end=35,
    )
    _redigir_true(destino, [linha_f])
    assert destino.read_text(encoding="utf-8") == original

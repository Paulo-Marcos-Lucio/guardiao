"""Testes do item G-13b: `bench/limpo/baixar.py` + `avaliar.py`.

Cobre a parte PURA (sem rede, sem clone) — `normaliza`, `classificar`,
`fp_por_mil_arquivos` e o schema de `adjudicacao.json` — e o conteúdo
versionado em si (`adjudicacao.json`). O fluxo completo (clonar os três
repositórios reais, escanear, avaliar) foi verificado manualmente — ver
`LEDGER.md` do repositório `cadencia` para o resultado exato (22 achados,
22 adjudicados, 0 pendente, FP/1k = 44.990) — e não entra na suíte porque
depende de rede e de três clones reais que a CI não tem por que replicar a
cada `pytest`.
"""

from __future__ import annotations

import json

from bench.limpo import avaliar
from bench.limpo.avaliar import ADJUDICACAO_PATH, VEREDITOS_VALIDOS, Adjudicacao
from hypothesis import given
from hypothesis import strategies as st


def _adj(repo: str, commit: str, arquivo: str, linha: int, veredito: str) -> Adjudicacao:
    return Adjudicacao(
        repo=repo,
        commit=commit,
        arquivo=arquivo,
        linha=linha,
        regra="regra-x",
        veredito=veredito,
        motivo="motivo de teste",
    )


def test_normaliza_separa_repo_e_arquivo() -> None:
    assert avaliar.normaliza("httpx/tests/test_auth.py", ("httpx", "requests")) == (
        "httpx",
        "tests/test_auth.py",
    )


def test_normaliza_tolera_prefixo_absoluto_com_repos_dir() -> None:
    caminho = "/home/user/guardiao/bench/limpo/.cache/repos/flask/docs/config.rst"
    assert avaliar.normaliza(caminho, ("httpx", "flask")) == ("flask", "docs/config.rst")


def test_normaliza_caminho_fora_do_escopo_retorna_none() -> None:
    """Achado que não começa com nenhum repo conhecido (ex.: `resultado.json`
    de uma execução anterior no mesmo diretório) não é confundido com um
    arquivo de um dos repositórios — ver docstring de `normaliza`."""
    assert avaliar.normaliza("resultado.json", ("httpx", "requests", "flask")) is None


def test_normaliza_nao_confunde_prefixo_de_nome_parecido() -> None:
    """`flask-cors` não é `flask` — um prefixo textual não é o mesmo repo."""
    assert avaliar.normaliza("flask-cors/setup.py", ("flask",)) is None


def test_classificar_achado_adjudicado_fp_no_commit_atual() -> None:
    adjudicacoes = [_adj("httpx", "c1", "a.py", 10, "falso_positivo")]
    avaliacao = avaliar.classificar([("httpx", "a.py", 10)], adjudicacoes, {"httpx": "c1"})
    assert avaliacao.falsos_positivos == 1
    assert avaliacao.pendentes == ()
    assert avaliacao.segredos_reais == ()


def test_classificar_sem_adjudicacao_fica_pendente() -> None:
    avaliacao = avaliar.classificar([("httpx", "a.py", 10)], [], {"httpx": "c1"})
    assert avaliacao.pendentes == (("httpx", "a.py", 10),)
    assert avaliacao.falsos_positivos == 0


def test_classificar_adjudicacao_de_commit_antigo_fica_pendente() -> None:
    """O repo avançou para `c2`; a adjudicação dada sobre `c1` não pode
    "seguir" o arquivo para uma versão que ninguém revisou — ver docstring
    de `classificar`."""
    adjudicacoes = [_adj("httpx", "c1", "a.py", 10, "falso_positivo")]
    avaliacao = avaliar.classificar([("httpx", "a.py", 10)], adjudicacoes, {"httpx": "c2"})
    assert avaliacao.pendentes == (("httpx", "a.py", 10),)
    assert avaliacao.falsos_positivos == 0


def test_classificar_segredo_real_nunca_conta_como_falso_positivo() -> None:
    adjudicacoes = [_adj("requests", "c1", "chave.pem", 1, "segredo_real")]
    avaliacao = avaliar.classificar(
        [("requests", "chave.pem", 1)], adjudicacoes, {"requests": "c1"}
    )
    assert avaliacao.segredos_reais == (("requests", "chave.pem", 1),)
    assert avaliacao.falsos_positivos == 0
    assert avaliacao.pendentes == ()


def test_fp_por_mil_arquivos_com_total_zero_nao_divide_por_zero() -> None:
    assert avaliar.fp_por_mil_arquivos(5, 0) == 0.0


def test_fp_por_mil_arquivos_escala_para_mil() -> None:
    assert avaliar.fp_por_mil_arquivos(1, 1000) == 1.0
    assert avaliar.fp_por_mil_arquivos(22, 489) > 44.0


def test_carregar_adjudicacoes_rejeita_veredito_desconhecido(tmp_path) -> None:  # type: ignore[no-untyped-def]
    caminho = tmp_path / "adjudicacao.json"
    caminho.write_text(
        json.dumps(
            [
                {
                    "repo": "httpx",
                    "commit": "c1",
                    "arquivo": "a.py",
                    "linha": 1,
                    "regra": "x",
                    "veredito": "talvez",
                    "motivo": "m",
                }
            ]
        ),
        encoding="utf-8",
    )
    try:
        avaliar.carregar_adjudicacoes(caminho)
    except ValueError as erro:
        assert "talvez" in str(erro)
    else:
        raise AssertionError("deveria ter rejeitado veredito desconhecido")


def test_adjudicacao_json_versionado_tem_schema_valido_e_chaves_unicas() -> None:
    """O arquivo real que `avaliar.py` lê em produção: todo veredito é
    conhecido, e nenhuma chave `(repo, arquivo, linha)` se repete — uma
    duplicata indicaria duas adjudicações conflitantes para o mesmo achado,
    silenciosamente resolvidas pela ordem de inserção no dict interno."""
    adjudicacoes = avaliar.carregar_adjudicacoes(ADJUDICACAO_PATH)
    assert len(adjudicacoes) > 0
    chaves = [(a.repo, a.arquivo, a.linha) for a in adjudicacoes]
    assert len(chaves) == len(set(chaves))
    for a in adjudicacoes:
        assert a.veredito in VEREDITOS_VALIDOS
        assert a.motivo.strip() != ""


_ACHADO = st.tuples(
    st.sampled_from(["httpx", "requests", "flask"]),
    st.text(alphabet=st.characters(blacklist_characters="\x00"), min_size=1, max_size=20),
    st.integers(min_value=1, max_value=10_000),
)


@given(
    achados=st.lists(_ACHADO, min_size=0, max_size=30, unique=True),
    veredito=st.sampled_from(["falso_positivo", "segredo_real"]),
)
def test_classificar_particiona_todo_achado_em_exatamente_um_balde(
    achados: list[tuple[str, str, int]], veredito: str
) -> None:
    """Invariante de classe: a soma de FP + segredos_reais + pendentes é
    SEMPRE o total de achados — nenhum achado desaparece, nenhum é contado
    duas vezes, qualquer que seja a mistura de adjudicações presentes.
    Adjudica metade dos achados (sempre no commit atual) e deixa a outra
    metade sem adjudicação."""
    commits_atuais = {"httpx": "c-httpx", "requests": "c-requests", "flask": "c-flask"}
    metade = achados[: len(achados) // 2]
    adjudicacoes = [
        _adj(repo, commits_atuais[repo], arquivo, linha, veredito)
        for repo, arquivo, linha in metade
    ]

    avaliacao = avaliar.classificar(achados, adjudicacoes, commits_atuais)

    total_particionado = (
        avaliacao.falsos_positivos + len(avaliacao.segredos_reais) + len(avaliacao.pendentes)
    )
    assert total_particionado == len(achados) == avaliacao.total_achados

    # Todo achado adjudicado no commit atual cai no balde do veredito dado;
    # nenhum dos dois baldes de "adjudicado" fica vazio incoerentemente.
    if veredito == "falso_positivo":
        assert avaliacao.falsos_positivos == len(set(metade))
        assert avaliacao.segredos_reais == ()
    else:
        assert len(avaliacao.segredos_reais) == len(set(metade))
        assert avaliacao.falsos_positivos == 0


@given(achados=st.lists(_ACHADO, min_size=0, max_size=15, unique=True))
def test_classificar_commit_divergente_nunca_produz_falso_positivo_herdado(
    achados: list[tuple[str, str, int]],
) -> None:
    """Toda adjudicação é dada sobre `commit-velho`, mas o manifesto atual
    diz `commit-novo` para todo repo — nenhuma pode "sobreviver" à troca de
    commit: o balde correto é sempre `pendente`, nunca FP nem segredo real."""
    adjudicacoes = [
        _adj(repo, "commit-velho", arquivo, linha, "falso_positivo")
        for repo, arquivo, linha in achados
    ]
    commits_atuais = {repo: "commit-novo" for repo, _arquivo, _linha in achados}

    avaliacao = avaliar.classificar(achados, adjudicacoes, commits_atuais)

    assert avaliacao.falsos_positivos == 0
    assert avaliacao.segredos_reais == ()
    assert len(avaliacao.pendentes) == len(achados)

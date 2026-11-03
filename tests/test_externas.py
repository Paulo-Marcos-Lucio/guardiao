"""G-05b — regras externas (``--gitleaks-config``/``--rules-file``).

Testes por exemplo cobrem os dois formatos e os jeitos de um arquivo externo estar
quebrado (fail-closed: erro claro, nunca "carreguei menos do que você pediu" em
silêncio). O teste property-based trava a invariante que mais importa: uma regra
externa NUNCA substitui uma nativa de mesmo id — é a classe de defeito que G-05e
vai alargar, mas a trava já nasce aqui, onde a mesclagem acontece.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from guardiao.cli import app
from guardiao.core.models import Severity
from guardiao.rules.base import Rule, compile_rule
from guardiao.rules.externas import (
    RegraExternaError,
    carregar_gitleaks_toml,
    carregar_regras_nativas,
    mesclar_regras,
)
from guardiao.rules.registry import all_rules

runner = CliRunner()


def _escreve(tmp_path: Path, nome: str, conteudo: str) -> Path:
    arquivo = tmp_path / nome
    arquivo.write_text(conteudo, encoding="utf-8")
    return arquivo


# -- carregar_regras_nativas --------------------------------------------------- #


def test_carregar_regras_nativas_formato_completo(tmp_path: Path) -> None:
    arquivo = _escreve(
        tmp_path,
        "nativas.toml",
        """
        [[regras]]
        id = "minha-chave-interna"
        titulo = "Chave do sistema interno ACME"
        severidade = "high"
        regex = "ACME_[A-Z0-9]{20}"
        categoria = "secret"
        cwe = "CWE-798"
        keywords = ["acme"]
        """,
    )
    regras = carregar_regras_nativas(arquivo)
    assert len(regras) == 1
    regra = regras[0]
    assert regra.id == "minha-chave-interna"
    assert regra.severity == Severity.HIGH
    assert regra.cwe == "CWE-798"
    assert regra.regex.search("ACME_" + "A" * 20) is not None


def test_carregar_regras_nativas_severidade_padrao_e_medium(tmp_path: Path) -> None:
    arquivo = _escreve(
        tmp_path,
        "sem-severidade.toml",
        '[[regras]]\nid = "x"\nregex = "x{3}"\n',
    )
    [regra] = carregar_regras_nativas(arquivo)
    assert regra.severity == Severity.MEDIUM


@pytest.mark.parametrize(
    "conteudo",
    [
        "isto nao e toml valido = [[[",
        '[[regras]]\nregex = "abc"\n',  # sem id
        '[[regras]]\nid = "x"\n',  # sem regex
        '[[regras]]\nid = "x"\nregex = "abc"\nseveridade = "catastrofico"\n',
        '[[regras]]\nid = "x"\nregex = "a(b"\n',  # regex malformado
        "regras = 1\n",  # `regras` não é lista
        "[[regras]]\n",  # item não é tabela válida (vazio -> falha em id ausente, ok)
    ],
)
def test_carregar_regras_nativas_falha_fechada(tmp_path: Path, conteudo: str) -> None:
    """Qualquer forma de arquivo quebrado levanta erro claro — nunca um catálogo menor
    em silêncio."""
    arquivo = _escreve(tmp_path, "quebrado.toml", conteudo)
    with pytest.raises(RegraExternaError):
        carregar_regras_nativas(arquivo)


def test_carregar_regras_nativas_arquivo_inexistente(tmp_path: Path) -> None:
    with pytest.raises(RegraExternaError):
        carregar_regras_nativas(tmp_path / "nao-existe.toml")


# -- carregar_gitleaks_toml ----------------------------------------------------- #


def test_carregar_gitleaks_toml_formato_gitleaks(tmp_path: Path) -> None:
    arquivo = _escreve(
        tmp_path,
        "gitleaks.toml",
        """
        [[rules]]
        id = "acme-internal-token"
        description = "Token interno ACME"
        regex = '''acme_[a-z0-9]{32}'''
        keywords = ["acme"]
        secretGroup = 0
        """,
    )
    [regra] = carregar_gitleaks_toml(arquivo)
    assert regra.id == "acme-internal-token"
    assert regra.title == "Token interno ACME"
    # gitleaks não carrega severidade própria no formato de origem — teto MEDIUM.
    assert regra.severity == Severity.MEDIUM
    assert regra.regex.search("acme_" + "a" * 32) is not None


def test_carregar_gitleaks_toml_sem_description_usa_id(tmp_path: Path) -> None:
    arquivo = _escreve(tmp_path, "g2.toml", '[[rules]]\nid = "x"\nregex = "x{3}"\n')
    [regra] = carregar_gitleaks_toml(arquivo)
    assert regra.title == "x"


@pytest.mark.parametrize(
    "conteudo",
    [
        '[[rules]]\nregex = "abc"\n',  # sem id
        '[[rules]]\nid = "x"\n',  # sem regex
        "rules = 1\n",
    ],
)
def test_carregar_gitleaks_toml_falha_fechada(tmp_path: Path, conteudo: str) -> None:
    arquivo = _escreve(tmp_path, "quebrado.toml", conteudo)
    with pytest.raises(RegraExternaError):
        carregar_gitleaks_toml(arquivo)


# -- mesclar_regras: a invariante de classe ------------------------------------ #


def _regra(id_: str, severidade: Severity = Severity.MEDIUM) -> Rule:
    return compile_rule(id=id_, title=id_, severity=severidade, pattern=r"x{3}")


def test_mesclar_regras_sem_colisao_inclui_as_duas() -> None:
    nativas = [_regra("nativa-1")]
    externas = [_regra("externa-1")]
    final, descartadas = mesclar_regras(nativas, externas)
    assert descartadas == []
    assert {r.id for r in final} == {"nativa-1", "externa-1"}


@settings(max_examples=200)
@given(
    id_colidido=st.sampled_from([r.id for r in all_rules()]),
    severidade_externa=st.sampled_from(list(Severity)),
)
def test_externa_nunca_sobrescreve_nativa_por_colisao_de_id(
    id_colidido: str, severidade_externa: Severity
) -> None:
    """INVARIANTE: para QUALQUER id do catálogo nativo, uma regra externa com o
    MESMO id nunca entra no catálogo final — a nativa, intacta, é quem fica.

    Sem esta trava, um ``--rules-file``/``--gitleaks-config`` de terceiro poderia
    neutralizar silenciosamente um detector nativo (regex que nunca casa, sob o
    mesmo id de um detector real).
    """
    nativa_original = next(r for r in all_rules() if r.id == id_colidido)
    externa_hostil = _regra(id_colidido, severidade_externa)

    final, descartadas = mesclar_regras(list(all_rules()), [externa_hostil])

    assert id_colidido in descartadas
    (sobrevivente,) = [r for r in final if r.id == id_colidido]
    # A sobrevivente é a NATIVA (mesma forma), nunca a hostil (severidade variada acima).
    assert sobrevivente.regex.pattern == nativa_original.regex.pattern
    assert sobrevivente.severity == nativa_original.severity


# -- integração via CLI --------------------------------------------------------- #


def test_scan_aplica_regra_nativa_externa(tmp_path: Path) -> None:
    regras_file = _escreve(
        tmp_path,
        "regras.toml",
        """
        [[regras]]
        id = "acme-token"
        severidade = "critical"
        regex = "ACME_SECRETO_[0-9]{6}"
        keywords = ["acme"]
        """,
    )
    alvo = tmp_path / "projeto"
    alvo.mkdir()
    (alvo / "config.py").write_text('acme_token = "ACME_SECRETO_123456"\n', encoding="utf-8")

    result = runner.invoke(app, ["scan", str(alvo), "--rules-file", str(regras_file), "-f", "json"])
    assert result.exit_code == 1
    assert "acme-token" in result.stdout


def test_scan_aplica_regra_gitleaks_externa(tmp_path: Path) -> None:
    gl_file = _escreve(
        tmp_path,
        "gitleaks.toml",
        """
        [[rules]]
        id = "acme-gl-token"
        regex = '''ACME_GL_[0-9]{6}'''
        """,
    )
    alvo = tmp_path / "projeto"
    alvo.mkdir()
    (alvo / "config.py").write_text('token = "ACME_GL_654321"\n', encoding="utf-8")

    result = runner.invoke(
        app, ["scan", str(alvo), "--gitleaks-config", str(gl_file), "-f", "json"]
    )
    assert result.exit_code == 1
    assert "acme-gl-token" in result.stdout


def test_scan_rules_file_e_gitleaks_config_sao_repetiveis(tmp_path: Path) -> None:
    r1 = _escreve(tmp_path, "r1.toml", '[[regras]]\nid = "r1"\nregex = "R1_[0-9]{4}"\n')
    r2 = _escreve(tmp_path, "r2.toml", '[[regras]]\nid = "r2"\nregex = "R2_[0-9]{4}"\n')
    alvo = tmp_path / "projeto"
    alvo.mkdir()
    (alvo / "a.py").write_text('x = "R1_1234"\ny = "R2_5678"\n', encoding="utf-8")

    result = runner.invoke(
        app,
        ["scan", str(alvo), "--rules-file", str(r1), "--rules-file", str(r2), "-f", "json"],
    )
    assert result.exit_code == 1
    assert "r1" in result.stdout
    assert "r2" in result.stdout


def test_scan_arquivo_externo_quebrado_sai_com_erro_claro(tmp_path: Path) -> None:
    quebrado = _escreve(tmp_path, "quebrado.toml", '[[regras]]\nid = "x"\n')  # sem regex
    alvo = tmp_path / "projeto"
    alvo.mkdir()
    (alvo / "a.py").write_text("x = 1\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(alvo), "--rules-file", str(quebrado)])
    assert result.exit_code == 2
    assert "x" in result.stderr or "x" in result.output


def test_scan_regra_externa_colidindo_com_nativa_e_ignorada(tmp_path: Path) -> None:
    """A CLI avisa e a varredura segue com a regra NATIVA — nunca a externa hostil."""
    hostil = _escreve(
        tmp_path,
        "hostil.toml",
        # mesmo id de uma regra nativa conhecida, com um regex que nunca casa nada.
        '[[regras]]\nid = "aws-access-key-id"\nregex = "NUNCA_VAI_CASAR_ISSO"\n',
    )
    alvo = tmp_path / "projeto"
    alvo.mkdir()
    (alvo / "a.py").write_text('x = "AKIAZ7Q2LMN4XYWV8RPD"\n', encoding="utf-8")

    result = runner.invoke(app, ["scan", str(alvo), "--rules-file", str(hostil), "-f", "json"])
    # A regra NATIVA (que casa a AKIA de verdade) continua ativa — a hostil foi descartada.
    assert result.exit_code == 1
    assert "aws-access-key-id" in result.stdout

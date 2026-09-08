"""`--regras arquivo.toml`: regra declarativa externa dispara e entra no
relatório com a MESMA estrutura das internas (GRD-06).

Cobre também o loader isolado (`load_external_rules`) para os casos de erro:
o critério não é só "a regra boa funciona", é "a regra ruim trava com uma
mensagem que aponta o campo errado" — sem isso o operador descobre o TOML
malformado só quando o scan silenciosamente roda com menos regras do que ele
pediu.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from guardiao.cli import app
from guardiao.rules.external import ExternalRuleError, load_external_rules

runner = CliRunner()

TOML_VALIDO = """
[[regra]]
id = "acme-token-interno"
padrao = 'ACME_TOK_[A-Z0-9]{16}'
severidade = "high"
categoria = "secret"
only_files = ["*.env"]
titulo = "Token interno Acme vazado"
"""


def _escreve(tmp_path: Path, nome: str, conteudo: str) -> Path:
    arquivo = tmp_path / nome
    arquivo.write_text(conteudo, encoding="utf-8")
    return arquivo


# --------------------------------------------------------------------------- #
# Caminho feliz: a regra externa dispara e o achado tem a estrutura de sempre.
# --------------------------------------------------------------------------- #


def test_regra_externa_dispara_com_mesma_estrutura_de_achado(tmp_path: Path) -> None:
    regras_path = _escreve(tmp_path, "minhas.toml", TOML_VALIDO)
    alvo = tmp_path / "projeto"
    alvo.mkdir()
    _escreve(alvo, ".env", "ACME_TOK_ABCD1234EFGH5678\n")

    result = runner.invoke(app, ["scan", str(alvo), "-f", "json", "--regras", str(regras_path)])
    assert result.exit_code == 1, result.stderr
    documento = json.loads(result.stdout)
    achado = next(f for f in documento["findings"] if f["id"] == "acme-token-interno")

    # Os mesmos campos que uma regra INTERNA preenche — nenhum "modo regra
    # externa" à parte no relatório.
    assert achado["severity"] == "high"
    assert achado["category"] == "secret"
    assert achado["title"] == "Token interno Acme vazado"
    assert achado["path"].endswith(".env")
    assert "ACME_TOK_ABCD1234EFGH5678" not in result.stdout  # segredo cru não vaza


def test_only_files_da_regra_externa_e_respeitado(tmp_path: Path) -> None:
    """A regra só vale para `.env` — o mesmo valor fora dele não deve disparar."""
    regras_path = _escreve(tmp_path, "minhas.toml", TOML_VALIDO)
    alvo = tmp_path / "projeto"
    alvo.mkdir()
    _escreve(alvo, "notas.txt", "ACME_TOK_ABCD1234EFGH5678\n")

    result = runner.invoke(app, ["scan", str(alvo), "-f", "json", "--regras", str(regras_path)])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["findings"] == []


def test_titulo_default_e_o_id_quando_omitido(tmp_path: Path) -> None:
    regras_path = _escreve(
        tmp_path,
        "minhas.toml",
        '[[regra]]\nid = "sem-titulo"\npadrao = "SEGREDO_XYZ_[0-9]{4}"\nseveridade = "medium"\n',
    )
    alvo = tmp_path / "projeto"
    alvo.mkdir()
    _escreve(alvo, "app.py", "x = 'SEGREDO_XYZ_9999'\n")

    result = runner.invoke(app, ["scan", str(alvo), "-f", "json", "--regras", str(regras_path)])
    documento = json.loads(result.stdout)
    achado = next(f for f in documento["findings"] if f["id"] == "sem-titulo")
    assert achado["title"] == "sem-titulo"


# --------------------------------------------------------------------------- #
# Sem `--regras`: o scan continua igual a antes (regressão zero).
# --------------------------------------------------------------------------- #


def test_sem_regras_o_scan_nao_muda(tmp_path: Path) -> None:
    alvo = tmp_path / "projeto"
    alvo.mkdir()
    _escreve(alvo, "ok.py", "x = 'hello world'\n")
    result = runner.invoke(app, ["scan", str(alvo)])
    assert result.exit_code == 0


# --------------------------------------------------------------------------- #
# Colisão de id com regra interna: a CLI trava com exit 2, não mescla em silêncio.
# --------------------------------------------------------------------------- #


def test_id_colidindo_com_regra_interna_aborta_via_cli(tmp_path: Path) -> None:
    regras_path = _escreve(
        tmp_path,
        "minhas.toml",
        '[[regra]]\nid = "aws-access-key-id"\npadrao = "X{10}"\nseveridade = "low"\n',
    )
    result = runner.invoke(app, ["scan", str(tmp_path), "--regras", str(regras_path)])
    assert result.exit_code == 2
    assert "aws-access-key-id" in result.stderr


def test_arquivo_de_regras_ausente_aborta_via_cli(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--regras", str(tmp_path / "nao-existe.toml")]
    )
    assert result.exit_code == 2
    assert "não encontrado" in result.stderr


# --------------------------------------------------------------------------- #
# Loader isolado: cada campo mal formado trava com uma mensagem que aponta
# exatamente o que está errado — é o INVARIANTE que a política pede para
# correção de defeito ("não ter medido não é ter medido ausência" aplicado
# aqui: um TOML que não declara o que promete não pode virar "0 achados").
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("conteudo", "pedaco_esperado"),
    [
        ("nao e toml valido [[[", "TOML inválido"),
        ("", "nenhuma tabela"),
        ('[[regra]]\nid = "x"\npadrao = "a"\n', "obrigatório"),  # falta severidade
        (
            '[[regra]]\nid = "x"\npadrao = "a"\nseveridade = "gravissimo"\n',
            "severidade desconhecida",
        ),
        (
            '[[regra]]\nid = "x"\npadrao = "a("\nseveridade = "low"\n',
            "regex inválida",
        ),
        (
            '[[regra]]\nid = "dup"\npadrao = "a"\nseveridade = "low"\n'
            '[[regra]]\nid = "dup"\npadrao = "b"\nseveridade = "low"\n',
            "duplicado",
        ),
        (
            '[[regra]]\nid = "x"\npadrao = "a"\nseveridade = "low"\nonly_files = "nao-e-lista"\n',
            "only_files",
        ),
        ("regra = 1\n", "lista de tabelas"),
    ],
)
def test_toml_malformado_trava_com_mensagem_precisa(
    tmp_path: Path, conteudo: str, pedaco_esperado: str
) -> None:
    regras_path = _escreve(tmp_path, "minhas.toml", conteudo)
    with pytest.raises(ExternalRuleError, match=pedaco_esperado):
        load_external_rules(regras_path)


def test_cli_reporta_erro_de_carregamento_e_sai_com_2(tmp_path: Path) -> None:
    regras_path = _escreve(tmp_path, "minhas.toml", "isto nao e toml valido [[[")
    result = runner.invoke(app, ["scan", str(tmp_path), "--regras", str(regras_path)])
    assert result.exit_code == 2
    assert "TOML inválido" in result.stderr

"""`--gitleaks-config arquivo.toml`: carrega um `gitleaks.toml` real (regras +
allowlist), aplica na varredura, e compara o CONJUNTO de achados contra o
esperado (GRD-07).

Também prova o outro lado do critério de aceite: para cada construção do
gitleaks que a Guardião não suporta, um aviso explícito aparece no
relatório — não um erro, e não um silêncio.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from guardiao.cli import app
from guardiao.rules.gitleaks import GitleaksConfigError, load_gitleaks_config

runner = CliRunner()

# Um gitleaks.toml no estilo real: uma regra de fornecedor simples, uma regra
# genérica com secretGroup + entropy + keywords + path (só dispara em .env),
# allowlist global (paths + regexes) e allowlist por regra (stopwords).
GITLEAKS_TOML = r"""
title = "gitleaks config de teste"

[[rules]]
id = "acme-vendor-token"
description = "Token de fornecedor Acme"
regex = '''ACME_[A-Z0-9]{20}'''
tags = ["acme", "vendor"]

[[rules]]
id = "acme-generic-secret"
description = "Segredo genérico Acme"
regex = '''(?i)acme[-_]?secret\s*=\s*"([a-zA-Z0-9]{16,})"'''
secretGroup = 1
entropy = 3.0
keywords = ["secret"]
path = '''\.env$'''

  [rules.allowlist]
  stopwords = ["changeme"]

[allowlist]
description = "allowlist global"
paths = ['''fixtures/''']
regexes = ['''ACME_PLACEHOLDERPLACEHOLDER00''']
"""


def _escreve(tmp_path: Path, nome: str, conteudo: str) -> Path:
    arquivo = tmp_path / nome
    arquivo.write_text(conteudo, encoding="utf-8")
    return arquivo


# --------------------------------------------------------------------------- #
# Caminho feliz: conjunto de achados exato, comparado achado a achado.
# --------------------------------------------------------------------------- #


def test_conjunto_de_achados_bate_com_o_esperado(tmp_path: Path) -> None:
    config_path = _escreve(tmp_path, "gitleaks.toml", GITLEAKS_TOML)
    alvo = tmp_path / "projeto"
    alvo.mkdir()

    # dispara acme-vendor-token
    _escreve(alvo, "app.py", 'token = "ACME_ABCDEFGHIJ0123456789"\n')
    # dispara acme-generic-secret (.env, entropia alta o suficiente, tem "secret")
    _escreve(alvo, ".env", 'ACME_SECRET="qX7pL2mZ9vT4wK1dR8yN"\n')
    # MESMO padrão de acme-generic-secret, mas fora de .env — o `path` da regra barra
    _escreve(alvo, "notas.txt", 'acme_secret = "qX7pL2mZ9vT4wK1dR8yN"\n')
    # bate no stopword "changeme" do allowlist DA REGRA acme-generic-secret — suprimido
    (alvo / "docs").mkdir()
    _escreve(alvo / "docs", "exemplo.env", 'ACME_SECRET="changemechangemeplease1"\n')
    # bate na allowlist GLOBAL por path (fixtures/) — nem essa nem a de vendor disparam
    (alvo / "fixtures").mkdir()
    _escreve(alvo / "fixtures", "dados.py", 'x = "ACME_ABCDEFGHIJ0123456789"\n')
    # bate na allowlist GLOBAL por regex (valor idêntico ao regex de allowlist)
    _escreve(alvo, "sample.py", 'x = "ACME_PLACEHOLDERPLACEHOLDER00"\n')

    result = runner.invoke(
        app, ["scan", str(alvo), "-f", "json", "--gitleaks-config", str(config_path)]
    )
    assert result.exit_code == 1, result.stderr
    documento = json.loads(result.stdout)

    achados = {(f["id"], Path(f["path"]).name) for f in documento["findings"]}
    esperado = {
        ("acme-vendor-token", "app.py"),
        ("acme-generic-secret", ".env"),
    }
    assert achados == esperado, achados

    # Estrutura igual à de uma regra interna: severidade default HIGH (gitleaks
    # não declara severidade), categoria "secret", fingerprint presente.
    vendor = next(f for f in documento["findings"] if f["id"] == "acme-vendor-token")
    assert vendor["severity"] == "high"
    assert vendor["category"] == "secret"
    assert vendor["fingerprint"]
    assert "ACME_ABCDEFGHIJ0123456789" not in result.stdout  # segredo cru não vaza

    # O supressor conta: 3 achados nasceram e foram suprimidos (path da regra,
    # stopword da allowlist da regra, path e regex da allowlist global).
    assert any("suprimido" in aviso for aviso in documento["summary"]["coverage_warnings"])


def test_sem_gitleaks_config_o_scan_nao_muda(tmp_path: Path) -> None:
    alvo = tmp_path / "projeto"
    alvo.mkdir()
    _escreve(alvo, "ok.py", "x = 'hello world'\n")
    assert runner.invoke(app, ["scan", str(alvo)]).exit_code == 0


# --------------------------------------------------------------------------- #
# Avisos explícitos para construções não suportadas.
# --------------------------------------------------------------------------- #


def test_campo_desconhecido_na_regra_vira_aviso_nao_erro(tmp_path: Path) -> None:
    config_path = _escreve(
        tmp_path,
        "gitleaks.toml",
        """
[[rules]]
id = "com-regextarget"
regex = "X{10}"
regexTarget = "match"
""",
    )
    config = load_gitleaks_config(config_path)
    assert len(config.rules) == 1
    assert any("regexTarget" in aviso and "não suportado" in aviso for aviso in config.avisos)


def test_condition_and_ignora_allowlist_inteira_com_aviso(tmp_path: Path) -> None:
    config_path = _escreve(
        tmp_path,
        "gitleaks.toml",
        """
[[rules]]
id = "x"
regex = "SEGREDO_[0-9]{6}"

[allowlist]
condition = "AND"
stopwords = ["segredo"]
""",
    )
    config = load_gitleaks_config(config_path)
    assert config.allowlist_global.vazia  # ignorada, não aplicada com semântica errada
    assert any("condition" in aviso for aviso in config.avisos)

    # E o achado NÃO some — o viés é relatar demais, não suprimir por engano.
    # (o stopword "segredo" bateria no valor se a allowlist tivesse sido aplicada)
    alvo = tmp_path / "projeto"
    alvo.mkdir()
    _escreve(alvo, "x.py", "s = 'SEGREDO_123456'\n")
    result = runner.invoke(
        app, ["scan", str(alvo), "-f", "json", "--gitleaks-config", str(config_path)]
    )
    documento = json.loads(result.stdout)
    assert [f["id"] for f in documento["findings"]] == ["x"]


def test_campo_raiz_desconhecido_vira_aviso(tmp_path: Path) -> None:
    config_path = _escreve(
        tmp_path,
        "gitleaks.toml",
        """
[extend]
path = "base.toml"

[[rules]]
id = "x"
regex = "X{10}"
""",
    )
    config = load_gitleaks_config(config_path)
    assert any("extend" in aviso for aviso in config.avisos)


def test_allowlists_array_plural_vira_aviso_raiz(tmp_path: Path) -> None:
    """Schema novo do gitleaks (>= 8.18): `[[allowlists]]`, não suportado."""
    config_path = _escreve(
        tmp_path,
        "gitleaks.toml",
        """
[[rules]]
id = "x"
regex = "X{10}"

[[allowlists]]
description = "um allowlist nomeado"
paths = ["foo/"]
""",
    )
    config = load_gitleaks_config(config_path)
    assert any("allowlists" in aviso for aviso in config.avisos)
    assert config.allowlist_global.vazia  # não foi lido — só a tabela singular é


# --------------------------------------------------------------------------- #
# CLI: colisão de id, arquivo ausente, TOML malformado.
# --------------------------------------------------------------------------- #


def test_id_colidindo_com_regra_interna_aborta_via_cli(tmp_path: Path) -> None:
    config_path = _escreve(
        tmp_path,
        "gitleaks.toml",
        '[[rules]]\nid = "aws-access-key-id"\nregex = "X{10}"\n',
    )
    result = runner.invoke(app, ["scan", str(tmp_path), "--gitleaks-config", str(config_path)])
    assert result.exit_code == 2
    assert "aws-access-key-id" in result.stderr


def test_arquivo_ausente_aborta_via_cli(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--gitleaks-config", str(tmp_path / "nao-existe.toml")]
    )
    assert result.exit_code == 2
    assert "não encontrado" in result.stderr


# --------------------------------------------------------------------------- #
# Loader isolado: campo obrigatório ausente, regex inválida, id duplicado.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("conteudo", "pedaco_esperado"),
    [
        ("nao e toml valido [[[", "TOML inválido"),
        ("title = 'x'\n", "nenhuma tabela"),
        ('[[rules]]\nid = "x"\n', "obrigatório"),  # falta regex
        ('[[rules]]\nregex = "X{10}"\n', "obrigatório"),  # falta id
        ('[[rules]]\nid = "x"\nregex = "a("\n', "regex inválida"),
        (
            '[[rules]]\nid = "dup"\nregex = "a"\n[[rules]]\nid = "dup"\nregex = "b"\n',
            "duplicado",
        ),
        ('[[rules]]\nid = "x"\nregex = "a"\nsecretGroup = "zero"\n', "secretGroup"),
        ('[[rules]]\nid = "x"\nregex = "a"\nentropy = "alta"\n', "entropy"),
        ('[[rules]]\nid = 7\nregex = "a"\n', "'id'"),
        ('[[rules]]\nid = "x"\nregex = "a"\nkeywords = "nao-e-lista"\n', "keywords"),
        ('[[rules]]\nid = "x"\nregex = "a"\ndescription = 7\n', "description"),
        ('[[rules]]\nid = "x"\nregex = "a"\npath = "a("\n', "regex inválida em 'path'"),
        ("rules = 1\n", "lista de tabelas"),
        ("rules = [1, 2]\n", "cada entrada precisa ser uma tabela"),
    ],
)
def test_toml_malformado_trava_com_mensagem_precisa(
    tmp_path: Path, conteudo: str, pedaco_esperado: str
) -> None:
    config_path = _escreve(tmp_path, "gitleaks.toml", conteudo)
    with pytest.raises(GitleaksConfigError, match=pedaco_esperado):
        load_gitleaks_config(config_path)


def test_allowlist_com_campo_de_lista_invalido_e_ignorada_com_aviso(tmp_path: Path) -> None:
    """`paths`/`regexes`/`stopwords` fora do formato: allowlist descartada, não erro —
    mesma postura conservadora de `condition=AND` (relatar demais, nunca de menos)."""
    config_path = _escreve(
        tmp_path,
        "gitleaks.toml",
        """
[[rules]]
id = "x"
regex = "X{10}"

[allowlist]
paths = "nao-e-lista"
""",
    )
    config = load_gitleaks_config(config_path)
    assert config.allowlist_global.vazia
    assert any("paths" in aviso for aviso in config.avisos)


def test_allowlist_nao_e_tabela_e_ignorada_com_aviso(tmp_path: Path) -> None:
    config_path = _escreve(
        tmp_path,
        "gitleaks.toml",
        '[[rules]]\nid = "x"\nregex = "X{10}"\n\nallowlist = "nao-e-tabela"\n',
    )
    config = load_gitleaks_config(config_path)
    assert config.allowlist_global.vazia
    assert any("tabela" in aviso for aviso in config.avisos)

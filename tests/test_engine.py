from __future__ import annotations

from pathlib import Path

import pytest

from guardiao.core.config import Config
from guardiao.core.engine import Scanner
from tests.conftest import CPF_VALIDO, SENHA_DE_PRODUCAO


def test_scan_planted_dir_finds_all_families(planted_dir: Path) -> None:
    result = Scanner().scan_paths([planted_dir])
    ids = {f.rule_id for f in result.findings}
    assert {
        "aws-access-key-id",
        "github-token",
        "google-api-key",
        "db-connection-uri",
        "private-key",
        "generic-assignment",
    } <= ids
    assert result.units_scanned >= 5


def test_inline_allow_suppresses(planted_dir: Path) -> None:
    result = Scanner().scan_paths([planted_dir])
    # a chave em allowed.py está marcada com `# guardiao:allow`
    assert all("allowed.py" not in f.location.path for f in result.findings)


def test_benign_file_has_no_findings(planted_dir: Path) -> None:
    result = Scanner().scan_paths([planted_dir])
    assert all("benign.txt" not in f.location.path for f in result.findings)


def test_findings_sorted_by_severity(planted_dir: Path) -> None:
    result = Scanner().scan_paths([planted_dir])
    ranks = [f.severity.rank for f in result.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_skip_category_pii() -> None:
    text = f"cpf: {CPF_VALIDO}"
    assert list(Scanner().scan_text("x", text))  # existe achado por padrão...
    scanner = Scanner(config=Config(skip_categories=frozenset({"pii"})))
    assert list(scanner.scan_text("x", text)) == []  # ...mas some ao pular pii


def test_only_filter_restricts_rules(planted_dir: Path) -> None:
    scanner = Scanner(config=Config(only=frozenset({"private-key"})))
    result = scanner.scan_paths([planted_dir])
    assert {f.rule_id for f in result.findings} == {"private-key"}


# --------------------------------------------------------------------------- #
# O que NÃO foi analisado tem que aparecer (senão "0 achados" mente).
# --------------------------------------------------------------------------- #


def test_arquivo_grande_e_contabilizado_como_pulado(tmp_path: Path) -> None:
    grande = tmp_path / "dump.sql"
    grande.write_text("x" * 5000 + "\n", encoding="utf-8")
    result = Scanner(config=Config(max_file_size=100)).scan_paths([tmp_path])
    assert result.skipped["tamanho"] == 1
    assert result.total_pulado() == 1
    assert result.units_scanned == 0


def test_lockfile_e_linha_longa_sao_contabilizados(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text("hash = 'abc'\n", encoding="utf-8")
    (tmp_path / "bundle.js").write_text("var a=1;" * 700 + "\n", encoding="utf-8")
    result = Scanner(config=Config(max_line_length=100)).scan_paths([tmp_path])
    assert result.skipped["ruido"] == 1
    assert result.skipped["linha_longa"] >= 1


def test_placeholder_descartado_e_contado() -> None:
    result = Scanner().scan_units([("x.py", 'aws = "AKIAIOSFODNN7EXAMPLE"', None)])
    assert result.findings == []
    assert result.placeholders >= 1


def test_pipeline_unico_ordena_e_finaliza() -> None:
    """`scan_units` é o único caminho: scan, pre-commit e --git-history desembocam nele."""
    result = Scanner().scan_units(
        [
            ("b.py", f"cpf: {CPF_VALIDO}", None),
            (".env", f"DB_PASSWORD={SENHA_DE_PRODUCAO}", None),
        ]
    )
    assert result.units_scanned == 2
    assert [f.severity.rank for f in result.findings] == sorted(
        [f.severity.rank for f in result.findings], reverse=True
    )


@pytest.mark.parametrize(
    ("linha", "esperado"),
    [
        ("DB_PASSWORD = 'Nordeste2019!Rj'", True),  # SCREAMING_SNAKE: \b não existia após '_'
        ("JWT_SECRET = 'Nordeste2019!Rj'", True),
        ("DJANGO_SECRET_KEY = 'Nordeste2019!Rj'", True),
        ("SECRET_KEY = 'Nordeste2019!Rj'", True),
        ("dbPassword = 'Nordeste2019!Rj'", True),  # camelCase
        ("secretKey = 'Nordeste2019!Rj'", True),
        ("nextLastSignificantToken = 'NoLineTerminatorHere'", False),  # sufixo de lexer
        ("author = 'Nordeste2019!Rj'", False),  # 'auth' dentro de palavra
        ("monkeypatch = 'Nordeste2019!Rj'", False),  # 'key' dentro de palavra
    ],
)
def test_ancora_de_chave_sensivel(linha: str, esperado: bool) -> None:
    """A fronteira `\\b` não existe entre `_` e letra: `DB_PASSWORD` nunca casou
    `\\bpassword\\b`. E o ramo camelCase não pode aceitar `...Token`/`...Key`."""
    achou = "generic-assignment" in {f.rule_id for f in Scanner().scan_text("x.py", linha)}
    assert achou is esperado

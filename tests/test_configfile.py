"""Testes do `.guardiao.toml` (G-04a): carregamento via `tomllib`, precedência
CLI > arquivo > default, fail-closed em TOML malformado, e a invariante "um config
aceito nunca zera o catálogo de regras".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import typer
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from guardiao.cli import app
from guardiao.core.configfile import FileConfig, load_config_file, resolve_config_file
from tests.conftest import GH_TOKEN

runner = CliRunner()


def _escreve(path: Path, texto: str) -> Path:
    path.write_text(texto, encoding="utf-8")
    return path


# -- load_config_file ------------------------------------------------------- #


def test_carrega_todas_as_secoes(tmp_path: Path) -> None:
    arquivo = _escreve(
        tmp_path / "g.toml",
        """
[allowlist]
paths = ["vendor/*", "*.generated.py"]

[rules]
only = ["github-token"]
skip = ["generic-assignment"]
skip_category = ["pii"]

[entropy]
enabled = false

[scan]
max_file_size = 1000
max_line_length = 200
scan_lockfiles = true
incluir_testes = true
""",
    )
    cfg = load_config_file(arquivo)
    assert cfg.only == ("github-token",)
    assert cfg.skip == ("generic-assignment",)
    assert cfg.skip_categories == ("pii",)
    assert cfg.use_entropy is False
    assert cfg.scan_noise_files is True
    assert cfg.max_file_size == 1000
    assert cfg.max_line_length == 200
    assert cfg.demote is False  # incluir_testes=true desliga o rebaixe (mesma flag da CLI)
    assert cfg.allowlist_paths == ("vendor/*", "*.generated.py")


def test_arquivo_vazio_e_equivalente_ao_default(tmp_path: Path) -> None:
    """Um `.guardiao.toml` vazio não decide NADA — toda chave fica `None`/vazia,
    nunca um valor que desligue algo por omissão."""
    arquivo = _escreve(tmp_path / "g.toml", "")
    assert load_config_file(arquivo) == FileConfig()


def test_secao_parcial_nao_decide_as_chaves_ausentes(tmp_path: Path) -> None:
    arquivo = _escreve(tmp_path / "g.toml", "[scan]\nmax_file_size = 999\n")
    cfg = load_config_file(arquivo)
    assert cfg.max_file_size == 999
    assert cfg.max_line_length is None  # arquivo não decidiu isto
    assert cfg.demote is None  # incluir_testes ausente da seção


def test_toml_malformado_e_fail_closed(tmp_path: Path) -> None:
    arquivo = _escreve(tmp_path / "g.toml", "isto não é = [toml válido\n")
    with pytest.raises(typer.Exit) as exc:
        load_config_file(arquivo)
    assert exc.value.exit_code == 2


# -- resolve_config_file: --config SOBREPÕE o auto-descoberto --------------- #


def test_resolve_sem_config_e_sem_arquivo_padrao_usa_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert resolve_config_file(None) == FileConfig()


def test_resolve_descobre_guardiao_toml_do_diretorio_atual(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _escreve(tmp_path / ".guardiao.toml", "[scan]\nmax_file_size = 42\n")
    monkeypatch.chdir(tmp_path)
    assert resolve_config_file(None).max_file_size == 42


def test_config_explicito_sobrepoe_o_descoberto(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _escreve(tmp_path / ".guardiao.toml", "[scan]\nmax_file_size = 42\n")
    outro = _escreve(tmp_path / "outro.toml", "[scan]\nmax_file_size = 99\n")
    monkeypatch.chdir(tmp_path)
    assert resolve_config_file(outro).max_file_size == 99


# -- integração via CLI ------------------------------------------------------ #


def test_cli_descobre_guardiao_toml_do_cwd(
    planted_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sem `--config`, rodando no diretório do projeto, o `.guardiao.toml` dali é lido."""
    _escreve(planted_dir / ".guardiao.toml", '[rules]\nonly = ["generic-assignment"]\n')
    monkeypatch.chdir(planted_dir)
    resultado = runner.invoke(app, ["scan", ".", "-f", "json"])
    documento = json.loads(resultado.stdout)
    ids = {achado["id"] for achado in documento["findings"]}
    assert ids == {"generic-assignment"}  # só a regra que o arquivo permitiu


def test_cli_config_explicito_sobrepoe_o_descoberto(
    planted_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _escreve(planted_dir / ".guardiao.toml", '[rules]\nonly = ["generic-assignment"]\n')
    outro = _escreve(planted_dir / "outro.toml", '[rules]\nonly = ["github-token"]\n')
    monkeypatch.chdir(planted_dir)
    resultado = runner.invoke(app, ["scan", ".", "--config", str(outro), "-f", "json"])
    documento = json.loads(resultado.stdout)
    ids = {achado["id"] for achado in documento["findings"]}
    assert ids == {"github-token"}


def test_cli_flag_explicita_vence_o_arquivo(
    planted_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Precedência CLI > arquivo: `--only` na linha de comando vence o `only` do TOML."""
    _escreve(planted_dir / ".guardiao.toml", '[rules]\nonly = ["github-token"]\n')
    monkeypatch.chdir(planted_dir)
    resultado = runner.invoke(app, ["scan", ".", "--only", "generic-assignment", "-f", "json"])
    documento = json.loads(resultado.stdout)
    ids = {achado["id"] for achado in documento["findings"]}
    assert ids == {"generic-assignment"}


def test_arquivo_restringe_max_file_size_mas_cli_explicito_vence(
    planted_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mesma precedência, agora num campo NUMÉRICO (não só lista): o arquivo decide
    quando a CLI fica em silêncio; a CLI explícita decide quando fala."""
    _escreve(planted_dir / ".guardiao.toml", "[scan]\nmax_file_size = 5\n")
    monkeypatch.chdir(planted_dir)

    so_arquivo = runner.invoke(app, ["scan", ".", "-f", "json"])
    documento = json.loads(so_arquivo.stdout)
    assert documento["summary"]["total"] == 0
    assert documento["summary"]["skipped"]["tamanho"] > 0

    com_cli = runner.invoke(app, ["scan", ".", "--max-file-size", "999999", "-f", "json"])
    documento_cli = json.loads(com_cli.stdout)
    assert documento_cli["summary"]["total"] > 0


def test_cli_toml_malformado_aborta_com_2(planted_dir: Path) -> None:
    ruim = _escreve(planted_dir / "ruim.toml", "][][\n")
    resultado = runner.invoke(app, ["scan", str(planted_dir), "--config", str(ruim)])
    assert resultado.exit_code == 2


def test_cli_allowlist_paths_pula_arquivo_por_completo(
    planted_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # "legacy" (não "vendor"/"node_modules"…) para garantir que é o ALLOWLIST do
    # arquivo que pula o diretório, não o `exclude_dirs` padrão do motor.
    (planted_dir / "legacy").mkdir()
    (planted_dir / "legacy" / "terceiro.py").write_text(f'token = "{GH_TOKEN}"\n', encoding="utf-8")
    _escreve(planted_dir / ".guardiao.toml", '[allowlist]\npaths = ["legacy/*"]\n')
    monkeypatch.chdir(planted_dir)
    resultado = runner.invoke(app, ["scan", ".", "-f", "json"])
    documento = json.loads(resultado.stdout)
    assert not any(achado["path"].startswith("legacy/") for achado in documento["findings"])
    assert documento["summary"]["skipped"]["allowlist"] == 1


# -- invariante de classe (Hypothesis): config aceito nunca zera o catálogo -- #


@settings(
    max_examples=50, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(
    usa_max_file_size=st.booleans(),
    usa_max_line_length=st.booleans(),
    usa_scan_lockfiles=st.booleans(),
    scan_lockfiles=st.booleans(),
    usa_incluir_testes=st.booleans(),
    incluir_testes=st.booleans(),
)
def test_config_aceito_nunca_zera_o_catalogo(
    tmp_path: Path,
    usa_max_file_size: bool,
    usa_max_line_length: bool,
    usa_scan_lockfiles: bool,
    scan_lockfiles: bool,
    usa_incluir_testes: bool,
    incluir_testes: bool,
) -> None:
    """INVARIANTE (G-04a): nenhuma combinação de chaves de `[scan]` — sozinhas, sem
    `[rules]` — tira uma regra SEQUER do catálogo. Omitir uma chave nunca é
    interpretado como "desligue tudo"; só um `[rules] only`/`skip` explícito restringe.
    """
    linhas = ["[scan]"]
    if usa_max_file_size:
        linhas.append("max_file_size = 2000000")
    if usa_max_line_length:
        linhas.append("max_line_length = 2000")
    if usa_scan_lockfiles:
        linhas.append(f"scan_lockfiles = {str(scan_lockfiles).lower()}")
    if usa_incluir_testes:
        linhas.append(f"incluir_testes = {str(incluir_testes).lower()}")
    arquivo = tmp_path / "config.toml"
    arquivo.write_text("\n".join(linhas) + "\n", encoding="utf-8")

    alvo = tmp_path / "alvo"
    alvo.mkdir(exist_ok=True)
    (alvo / "ok.py").write_text("x = 1\n", encoding="utf-8")

    resultado = runner.invoke(app, ["scan", str(alvo), "--config", str(arquivo), "-f", "json"])
    assert resultado.exit_code == 0
    documento = json.loads(resultado.stdout)
    cobertura = documento["summary"]["ruleset_coverage"]
    assert cobertura["rules_omitted"] == [], f"regra(s) sumiram do catálogo: {linhas}"
    assert cobertura["rules_run"] == cobertura["rules_total"]

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from guardiao import __version__
from guardiao.cli import app
from tests.conftest import AWS_KEY_ID

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_rules_lists_detectors() -> None:
    result = runner.invoke(app, ["regras"])
    assert result.exit_code == 0
    assert "aws-access-key-id" in result.stdout
    assert "private-key" in result.stdout
    # o ANO da edição do OWASP fica no CABEÇALHO; a célula usa o código curto
    assert "OWASP 2025 / CWE" in result.stdout
    assert runner.invoke(app, ["rules"]).exit_code == 0  # alias mantido


def test_scan_json_exit_code_and_no_leak(planted_dir: Path) -> None:
    result = runner.invoke(app, ["scan", str(planted_dir), "-f", "json"])
    assert result.exit_code == 1  # há segredos >= medium
    assert AWS_KEY_ID not in result.stdout
    document = json.loads(result.stdout)
    assert document["summary"]["total"] > 0


def test_scan_clean_dir_exit_zero(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text('x = "hello world"\n', encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0


def test_scan_sarif_to_output_file(planted_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "out.sarif"
    result = runner.invoke(app, ["scan", str(planted_dir), "-f", "sarif", "-o", str(out)])
    assert result.exit_code == 1
    assert out.exists()
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["version"] == "2.1.0"


def test_baseline_roundtrip_via_cli(planted_dir: Path, tmp_path: Path) -> None:
    baseline = tmp_path / "b.json"
    made = runner.invoke(
        app, ["scan", str(planted_dir), "--update-baseline", "--baseline", str(baseline)]
    )
    assert made.exit_code == 0
    assert baseline.exists()
    # com o baseline aplicado, tudo é suprimido => saída limpa
    again = runner.invoke(app, ["scan", str(planted_dir), "--baseline", str(baseline)])
    assert again.exit_code == 0


# --------------------------------------------------------------------------- #
# Erro de uso tem que ser exit 2 — nunca "verde silencioso".
# --------------------------------------------------------------------------- #


def test_id_de_regra_inexistente_aborta_com_2(planted_dir: Path) -> None:
    """`--only aws-acess-key-id` (typo) devolvia "✓ Nenhum segredo encontrado" e
    exit 0: o CI ficava verde para sempre sem varrer nada."""
    result = runner.invoke(app, ["scan", str(planted_dir), "--only", "aws-acess-key-id"])
    assert result.exit_code == 2
    assert "aws-access-key-id" in result.stderr  # lista os ids válidos


def test_skip_e_skip_category_inexistentes_abortam_com_2(planted_dir: Path) -> None:
    assert runner.invoke(app, ["scan", str(planted_dir), "--skip", "naoexiste"]).exit_code == 2
    assert (
        runner.invoke(app, ["scan", str(planted_dir), "--skip-category", "naoexiste"]).exit_code
        == 2
    )


def test_caminho_inexistente_aborta_com_2(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path / "nao-existe")])
    assert result.exit_code == 2


def test_diretorio_so_com_lockfiles_sai_zero(tmp_path: Path) -> None:
    """Pular lockfile é DESIGN (--scan-lockfiles desliga). `guardiao scan ./vendor`
    não pode quebrar o build só porque nada era elegível — mas tem que AVISAR."""
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3}\n', encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "NÃO analisada" in result.stdout


def test_max_file_size_recupera_arquivo_grande(tmp_path: Path) -> None:
    """Sem a flag não havia caminho de recuperação para dump.sql/bundle.js — que é
    exatamente onde credencial de produção costuma parar."""
    grande = tmp_path / "dump.sql"
    grande.write_text("-- " + "x" * 3000 + f'\nAWS = "{AWS_KEY_ID}"\n', encoding="utf-8")
    padrao = runner.invoke(app, ["scan", str(tmp_path), "--max-file-size", "500", "-f", "json"])
    assert json.loads(padrao.stdout)["summary"]["skipped"]["tamanho"] == 1
    solto = runner.invoke(app, ["scan", str(tmp_path), "-f", "json"])
    assert json.loads(solto.stdout)["summary"]["total"] == 1

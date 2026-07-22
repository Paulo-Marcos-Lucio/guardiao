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
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "aws-access-key-id" in result.stdout
    assert "private-key" in result.stdout


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

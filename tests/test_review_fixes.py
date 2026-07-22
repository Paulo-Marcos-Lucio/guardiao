"""Testes de regressão dos bugs achados na revisão adversarial."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from guardiao.cli import app
from guardiao.core.config import Config
from guardiao.core.engine import Scanner
from guardiao.core.redaction import redact, redact_spans
from tests.conftest import AWS_KEY_ID, GH_TOKEN

runner = CliRunner()


# HIGH — o preview vazava segredo cru quando havia mais de um segredo na linha.
def test_preview_never_leaks_with_multiple_secrets_on_line() -> None:
    line = f'a = "{AWS_KEY_ID}"; b = "{AWS_KEY_ID}"; gh = "{GH_TOKEN}"'
    findings = list(Scanner().scan_text("x.py", line))
    assert findings
    for finding in findings:
        assert AWS_KEY_ID not in finding.line_preview
        assert GH_TOKEN not in finding.line_preview


def test_redact_spans_masks_every_secret() -> None:
    line = f"{AWS_KEY_ID} {AWS_KEY_ID}"
    n = len(AWS_KEY_ID)
    spans = [(0, n, AWS_KEY_ID), (n + 1, 2 * n + 1, AWS_KEY_ID)]
    assert AWS_KEY_ID not in redact_spans(line, spans)


# MEDIUM — segredo de 9-12 chars revelava 8 chars e mantinha o comprimento.
def test_redact_short_secret_hides_almost_everything() -> None:
    assert redact("ABCDEFGHI") == "A…"  # 9 chars
    long = "AKIAZ7Q2LMN4XYWV8RPD"
    assert len(redact(long)) < len(long)


# LOW — a contagem de linha deve seguir só o \n (igual ao editor/GitHub).
def test_line_numbers_count_only_newlines() -> None:
    text = 'topo\x0cmesma-linha\naqui = "AKIAZ7Q2LMN4XYWV8RPD"'
    findings = list(Scanner().scan_text("x", text))
    assert findings
    assert findings[0].location.line == 2


# MEDIUM — a detecção por entropia agora roda de verdade e --no-entropy a desliga.
def test_high_entropy_detection_toggle() -> None:
    line = 'value = "Xk9Q2mNpR7wLvB3cD5fG6hJ8kM0nT4uY1zA"'
    on = {f.rule_id for f in Scanner().scan_text("x", line)}
    assert "high-entropy-string" in on
    off = {f.rule_id for f in Scanner(config=Config(use_entropy=False)).scan_text("x", line)}
    assert "high-entropy-string" not in off


# LOW — scan --git-history fora de repo Git sai limpo (exit 2), sem traceback.
def test_scan_git_history_outside_repo_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path), "--git-history"])
    assert result.exit_code == 2


# HIGH — pre-commit varre o conteúdo EM STAGE e inclui arquivos renomeados.
@pytest.mark.skipif(shutil.which("git") is None, reason="git indisponível")
def test_pre_commit_blocks_secret_in_renamed_staged_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def git(*args: str) -> None:
        subprocess.run(
            ["git", "-c", "user.email=t@t.com", "-c", "user.name=t",
             "-c", "commit.gpgsign=false", *args],
            cwd=tmp_path, check=True, capture_output=True,
        )  # fmt: skip

    git("init", "-b", "main")
    (tmp_path / "old.py").write_text("x = 1\n", encoding="utf-8")
    git("add", "old.py")
    git("commit", "-m", "init")
    git("mv", "old.py", "new.py")
    (tmp_path / "new.py").write_text(f'AWS = "{AWS_KEY_ID}"\n', encoding="utf-8")
    git("add", "new.py")

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["pre-commit"])
    assert result.exit_code == 1

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


# MEDIUM — entropia agora exige CONTEXTO de segredo na linha (precisão de campo) e
# --no-entropy a desliga. Perto de 'bearer/token' dispara; solta, não (mata o falso-positivo).
def test_high_entropy_detection_toggle() -> None:
    ctx = "Authorization: Bearer Xk9Q2mNpR7wLvB3cD5fG6hJ8kM0nT4uY1zA"
    on = {f.rule_id for f in Scanner().scan_text("x", ctx)}
    assert "high-entropy-string" in on
    off = {f.rule_id for f in Scanner(config=Config(use_entropy=False)).scan_text("x", ctx)}
    assert "high-entropy-string" not in off
    # sem contexto de segredo → NÃO dispara (era o falso-positivo de campo).
    bare = 'value = "Xk9Q2mNpR7wLvB3cD5fG6hJ8kM0nT4uY1zA"'
    assert "high-entropy-string" not in {f.rule_id for f in Scanner().scan_text("x", bare)}


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


# =========================================================================== #
# Precisão de campo (2026-07-22): FPs em massa em código real — bateria em 8
# repos públicos deu 4018→29 achados (-99.3%) sem perder recall.
# =========================================================================== #


def _ids(text: str) -> set[str]:
    return {f.rule_id for f in Scanner().scan_text("x", text)}


def test_git_sha_and_uuid_are_hash_not_secret() -> None:
    from guardiao.rules.definitions import is_probable_hash_or_id

    assert is_probable_hash_or_id("de0fac2e4500dabe0009e67214ff5f5447ce83dd")  # SHA-1
    assert is_probable_hash_or_id("550e8400-e29b-41d4-a716-446655440000")  # UUID
    assert not is_probable_hash_or_id("Xk9Q2mNpR7wLvB3cD5fG6hJ8kM0nT4uY1zA")  # segredo real


def test_entropy_requires_secret_context() -> None:
    val = "Xk9Q2mNpR7wLvB3cD5fG6hJ8kM0nT4uY1zAwBcDeF"
    assert "high-entropy-string" in _ids(f"token: {val}")  # perto de 'token' → dispara
    assert "high-entropy-string" not in _ids(f"result = {val}")  # sem contexto → não (era o FP)


def test_action_pin_sha_not_flagged() -> None:
    line = "- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6"
    assert "high-entropy-string" not in _ids(line)


def test_lockfile_is_skipped(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        'wheels = [{ hash = "sha256:9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a3928d" }]\n',
        encoding="utf-8",
    )
    assert Scanner().scan_paths([tmp_path]).findings == []


def test_example_url_credentials_suppressed() -> None:
    for url in (
        'url = "http://user:pass@localhost:8080"',
        'proxy = "http://user:pass@10.10.1.10:3128"',
        'x = "redis://foo:bar@somehost:6379/0"',
        'y = "http://{ENCODED_USER}:{ENCODED_PASSWORD}@request.com/"',
    ):
        ids = _ids(url)
        assert "basic-auth-url" not in ids and "db-connection-uri" not in ids


def test_real_url_credential_still_flagged() -> None:
    line = 'db = "postgres://dbadmin:Zx9r2Pq8LmNv3@prod-db.company.com:5432/main"'
    assert "db-connection-uri" in _ids(line)


def test_weak_example_password_suppressed() -> None:
    assert "generic-assignment" not in _ids('password = "password123"')
    assert "generic-assignment" not in _ids('secret = "changeme"')


def test_fp_fixes_preserve_recall() -> None:
    # os fixes de precisão NÃO podem quebrar a detecção de segredo real.
    cases = {
        "aws-access-key-id": 'AWS = "AKIAZQ3M7X9WPLKV2NRT"',
        "github-token": 'GH = "ghp_9zQ2mNpR7wLvB3cD5fG6hJ8kM0nT4uY1zAwX"',
        "high-entropy-string": 'api_token = "Xk9Q2mNpR7wLvB3cD5fG6hJ8kM0nT4uY1zAwBcDeF"',
        "private-key": "-----BEGIN RSA PRIVATE KEY-----",
    }
    for rule_id, line in cases.items():
        assert rule_id in _ids(line), rule_id


def test_overlapping_findings_deduped_to_most_specific() -> None:
    # GITHUB_TOKEN casa github-token (HIGH) e seria high-entropy (MEDIUM) — vira 1 achado só.
    line = 'GITHUB_TOKEN = "ghp_9zQ2mNpR7wLvB3cD5fG6hJ8kM0nT4uY1zAwX"'
    findings = list(Scanner().scan_text("x.py", line))
    assert len(findings) == 1
    assert findings[0].rule_id == "github-token"


def test_two_distinct_secrets_on_line_both_kept() -> None:
    line = f'a = "{AWS_KEY_ID}"; b = "{GH_TOKEN}"'  # spans distintos → não deduplica
    rules = {f.rule_id for f in Scanner().scan_text("x.py", line)}
    assert "aws-access-key-id" in rules
    assert "github-token" in rules

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from tests.conftest import AWS_KEY_ID

from guardiao.core.engine import Scanner

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git não disponível")


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=test@example.com",
            "-c",
            "user.name=Test",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=str(repo),
        check=True,
        capture_output=True,
    )


def test_secret_removed_from_tree_still_found_in_history(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")

    leaked = repo / "config.py"
    leaked.write_text(f'AWS_KEY = "{AWS_KEY_ID}"\n', encoding="utf-8")
    _git(repo, "add", "config.py")
    _git(repo, "commit", "-m", "add config (com segredo)")

    # "remove" o segredo do código atual
    leaked.write_text("AWS_KEY = os.environ['AWS_KEY']\n", encoding="utf-8")
    _git(repo, "add", "config.py")
    _git(repo, "commit", "-m", "remove segredo do código")

    # a árvore atual está limpa...
    assert Scanner().scan_paths([repo]).findings == []

    # ...mas o histórico ainda entrega o segredo
    history = Scanner().scan_git_history(repo)
    aws = [f for f in history.findings if f.rule_id == "aws-access-key-id"]
    assert aws, "segredo não encontrado no histórico"
    assert aws[0].location.commit is not None

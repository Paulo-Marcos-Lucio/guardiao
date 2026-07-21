"""Fonte de dados: histórico do Git.

Remover um segredo do código não o remove do histórico — ele continua acessível
em commits antigos. Esta fonte varre **todos os blobs** já existentes no
repositório (via ``git rev-list --objects --all``), justamente onde segredos
esquecidos costumam permanecer.
"""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path


class GitError(RuntimeError):
    """Falha ao interagir com o Git."""


@dataclass(frozen=True)
class Blob:
    sha: str
    path: str
    text: str


def is_git_repo(repo: Path) -> bool:
    return (Path(repo) / ".git").exists() or _run(repo, "rev-parse", "--is-inside-work-tree").ok


def iter_history_blobs(repo: Path, *, max_bytes: int = 5_000_000) -> Iterator[Blob]:
    """Itera pelos blobs versionados em qualquer ponto da história."""
    repo = Path(repo)
    listing = _run(repo, "rev-list", "--objects", "--all")
    if not listing.ok:
        raise GitError(listing.err.strip() or "git rev-list falhou")

    seen: set[str] = set()
    for line in listing.out.splitlines():
        parts = line.split(" ", 1)
        if len(parts) != 2:
            continue  # commits/trees sem path
        sha, path = parts[0], parts[1]
        if sha in seen or not path:
            continue
        seen.add(sha)

        kind = _run(repo, "cat-file", "-t", sha)
        if not kind.ok or kind.out.strip() != "blob":
            continue

        content = _run_bytes(repo, "cat-file", "blob", sha)
        if content is None or len(content) > max_bytes:
            continue
        if b"\x00" in content[:8192]:
            continue
        yield Blob(sha=sha[:12], path=path, text=content.decode("utf-8", errors="replace"))


# --------------------------------------------------------------------------- #
# helpers de subprocess
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Result:
    ok: bool
    out: str
    err: str


def _run(repo: Path, *args: str) -> _Result:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(repo),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except (OSError, ValueError) as exc:  # pragma: no cover - git ausente
        return _Result(False, "", str(exc))
    return _Result(proc.returncode == 0, proc.stdout, proc.stderr)


def _run_bytes(repo: Path, *args: str) -> bytes | None:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(repo),
            capture_output=True,
            check=False,
        )
    except (OSError, ValueError):  # pragma: no cover - git ausente
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout

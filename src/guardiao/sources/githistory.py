"""Fonte de dados: histórico do Git.

Remover um segredo do código não o remove do histórico — ele continua acessível
em commits antigos. Esta fonte varre **todos os blobs** já existentes no
repositório, justamente onde segredos esquecidos costumam permanecer.

Desempenho: um único ``git cat-file --batch --batch-all-objects`` transmite o
conteúdo de todos os objetos por streaming, em vez de dois subprocessos por
objeto — ordens de magnitude mais rápido em repositórios grandes.
"""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import IO


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

    # 1) Mapa sha->path (o primeiro caminho visto para cada blob). Uma chamada só.
    listing = _run(repo, "rev-list", "--objects", "--all")
    if not listing.ok:
        raise GitError(listing.err.strip() or "git rev-list falhou")
    paths: dict[str, str] = {}
    for line in listing.out.splitlines():
        sha, _, path = line.partition(" ")
        if path:
            paths.setdefault(sha, path)
    if not paths:
        return

    # 2) Um processo persistente streamando todos os objetos.
    try:
        proc = subprocess.Popen(
            ["git", "cat-file", "--batch", "--batch-all-objects", "--buffer"],
            cwd=str(repo),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, ValueError) as exc:  # pragma: no cover - git ausente
        raise GitError(str(exc)) from exc

    stdout = proc.stdout
    if stdout is None:  # pragma: no cover - defensivo
        raise GitError("git cat-file não abriu stdout")

    try:
        while True:
            header = stdout.readline()
            if not header:
                break
            parts = header.decode("utf-8", "replace").split()
            if len(parts) < 3:
                continue  # "<sha> missing" ou linha inesperada
            sha, otype, size_str = parts[0], parts[1], parts[2]
            try:
                size = int(size_str)
            except ValueError:  # pragma: no cover - saída inesperada
                continue
            content = _read_exact(stdout, size)
            stdout.read(1)  # newline após o conteúdo
            if otype != "blob":
                continue
            blob_path = paths.get(sha)
            if blob_path is None or size > max_bytes:
                continue
            if b"\x00" in content[:8192]:
                continue
            yield Blob(sha=sha[:12], path=blob_path, text=content.decode("utf-8", errors="replace"))
    finally:
        stdout.close()
        proc.wait()


def _read_exact(stream: IO[bytes], n: int) -> bytes:
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# --------------------------------------------------------------------------- #
# helper de subprocess (texto)
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

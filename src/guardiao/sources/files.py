"""Fonte de dados: sistema de arquivos."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from guardiao.core.config import Config


def iter_files(root: Path, config: Config) -> Iterator[Path]:
    """Percorre ``root`` devolvendo arquivos elegíveis para varredura."""
    root = Path(root)
    if root.is_file():
        if _eligible(root, config):
            yield root
        return

    for path in _walk(root, config):
        if _eligible(path, config):
            yield path


def _walk(root: Path, config: Config) -> Iterator[Path]:
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except (PermissionError, OSError):  # pragma: no cover - fs edge
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name in config.exclude_dirs:
                    continue
                stack.append(entry)
            elif entry.is_file():
                yield entry


def _eligible(path: Path, config: Config) -> bool:
    if path.suffix.lower() in config.binary_exts:
        return False
    if config.is_noise_file(path.name):
        return False
    try:
        if path.stat().st_size > config.max_file_size:
            return False
    except OSError:  # pragma: no cover - fs edge
        return False
    return True


def read_text(path: Path) -> str | None:
    """Lê o arquivo como texto; devolve ``None`` se parecer binário."""
    try:
        raw = path.read_bytes()
    except OSError:  # pragma: no cover - fs edge
        return None
    if b"\x00" in raw[:8192]:
        return None
    return raw.decode("utf-8", errors="replace")

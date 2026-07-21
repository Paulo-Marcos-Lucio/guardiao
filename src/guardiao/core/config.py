"""Configuração de uma varredura."""

from __future__ import annotations

from dataclasses import dataclass, field

DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".idea",
        ".gradle",
        "target",
        "vendor",
    }
)

# Extensões claramente binárias — puladas sem sequer abrir.
DEFAULT_BINARY_EXTS: frozenset[str] = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".pdf",
        ".zip",
        ".gz",
        ".tar",
        ".7z",
        ".rar",
        ".jar",
        ".war",
        ".class",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp3",
        ".mp4",
        ".mov",
        ".pyc",
    }
)


@dataclass
class Config:
    """Parâmetros que ajustam sensibilidade e escopo da varredura."""

    max_file_size: int = 5_000_000  # 5 MB
    max_line_length: int = 4_000  # pula linhas gigantes (minificados, blobs base64)
    use_entropy: bool = True
    exclude_dirs: frozenset[str] = DEFAULT_EXCLUDE_DIRS
    binary_exts: frozenset[str] = DEFAULT_BINARY_EXTS
    only: frozenset[str] = field(default_factory=frozenset)
    skip: frozenset[str] = field(default_factory=frozenset)
    skip_categories: frozenset[str] = field(default_factory=frozenset)

    def rule_enabled(self, rule_id: str, category: str) -> bool:
        if self.only and rule_id not in self.only:
            return False
        if rule_id in self.skip:
            return False
        if category in self.skip_categories:
            return False
        return category != "entropy" or self.use_entropy

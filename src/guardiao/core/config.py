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
        "site-packages",
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

# Arquivos-ruído: lockfiles e gerados/minificados. São cheios de hashes de alta
# entropia (não são segredos) — puxariam milhares de falso-positivos.
DEFAULT_NOISE_FILES: frozenset[str] = frozenset(
    {
        "uv.lock",
        "poetry.lock",
        "pipfile.lock",
        "package-lock.json",
        "packages.lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "npm-shrinkwrap.json",
        "composer.lock",
        "gemfile.lock",
        "cargo.lock",
        "go.sum",
        "flake.lock",
        "deno.lock",
        "bun.lockb",
        ".git-blame-ignore-revs",
        ".terraform.lock.hcl",
    }
)
DEFAULT_NOISE_SUFFIXES: frozenset[str] = frozenset(
    {".lock", ".min.js", ".min.css", ".map", ".snap"}
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
    noise_files: frozenset[str] = DEFAULT_NOISE_FILES
    noise_suffixes: frozenset[str] = DEFAULT_NOISE_SUFFIXES
    scan_noise_files: bool = False  # --scan-lockfiles força varrer lockfiles/gerados
    only: frozenset[str] = field(default_factory=frozenset)
    skip: frozenset[str] = field(default_factory=frozenset)
    skip_categories: frozenset[str] = field(default_factory=frozenset)

    def is_noise_file(self, name: str) -> bool:
        """Lockfile/gerado/minificado — pulado por padrão (ruído de hashes)."""
        if self.scan_noise_files:
            return False
        lowered = name.lower()
        return lowered in self.noise_files or any(
            lowered.endswith(sfx) for sfx in self.noise_suffixes
        )

    def rule_enabled(self, rule_id: str, category: str) -> bool:
        if self.only and rule_id not in self.only:
            return False
        if rule_id in self.skip:
            return False
        if category in self.skip_categories:
            return False
        return category != "entropy" or self.use_entropy

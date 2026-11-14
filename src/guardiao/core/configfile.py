"""Carrega `.guardiao.toml` — overrides de projeto, por baixo da CLI e por cima do
default embutido em `Config`.

Schema (toda seção e toda chave são opcionais — um arquivo vazio é um default redundante,
nunca um erro):

```toml
[allowlist]
paths = ["legacy/*", "*.generated.*"]   # fnmatch (um `*` já casa `/`); arquivo casado nunca é varrido

[rules]
only = ["github-token"]
skip = ["generic-assignment"]
skip_category = ["pii"]

[entropy]
enabled = true

[scan]
max_file_size = 5000000
max_line_length = 4000
scan_lockfiles = false
incluir_testes = false
```

Chave ausente significa "o arquivo não decide isto" (`None`/tupla vazia) — quem decide
é a CLI, e se a CLI também não decidir, o default embutido do `Config`. É essa semântica
de ausência que garante que um `.guardiao.toml` ACEITO nunca zera o catálogo: omitir
`[rules] only` continua rodando tudo (o campo vazio não é tratado como "só isto"), e
omitir a seção inteira é equivalente a um arquivo vazio.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

import typer

# `tomllib` só existe na stdlib a partir do 3.11; a matriz de CI cobre 3.10, que
# precisa do backport `tomli` (mesma API — `loads`/`TOMLDecodeError`).
if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


@dataclass(frozen=True)
class FileConfig:
    """Valores lidos de `.guardiao.toml`. Ver o schema no docstring do módulo."""

    only: tuple[str, ...] = ()
    skip: tuple[str, ...] = ()
    skip_categories: tuple[str, ...] = ()
    use_entropy: bool | None = None
    scan_noise_files: bool | None = None
    max_file_size: int | None = None
    max_line_length: int | None = None
    #: `None` = arquivo não decide; corresponde a `--incluir-testes` (que desliga tanto
    #: `demote_tests` quanto `demote_docs` — a mesma flag, nos dois lugares).
    demote: bool | None = None
    allowlist_paths: tuple[str, ...] = field(default_factory=tuple)


def load_config_file(path: Path) -> FileConfig:
    """Lê e valida ``path``. TOML malformado é fail-closed: ``typer.Exit(2)`` — nunca
    roda a varredura com metade do arquivo ignorado em silêncio por um erro de digitação.
    """
    try:
        texto = path.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - fs edge (permissão, race de deleção)
        raise typer.Exit(2) from exc
    try:
        dados = tomllib.loads(texto)
    except tomllib.TOMLDecodeError as exc:
        raise typer.Exit(2) from exc

    allowlist = dados.get("allowlist") or {}
    regras = dados.get("rules") or {}
    entropia = dados.get("entropy") or {}
    varredura = dados.get("scan") or {}

    return FileConfig(
        only=tuple(regras.get("only", ())),
        skip=tuple(regras.get("skip", ())),
        skip_categories=tuple(regras.get("skip_category", ())),
        use_entropy=entropia.get("enabled"),
        scan_noise_files=varredura.get("scan_lockfiles"),
        max_file_size=varredura.get("max_file_size"),
        max_line_length=varredura.get("max_line_length"),
        demote=(not varredura["incluir_testes"] if "incluir_testes" in varredura else None),
        allowlist_paths=tuple(allowlist.get("paths", ())),
    )


def resolve_config_file(explicito: Path | None) -> FileConfig:
    """Resolve qual arquivo carregar — ``--config`` SOBREPÕE o auto-descoberto.

    Sem ``--config``, procura ``.guardiao.toml`` no diretório atual; se não existir,
    não é erro (projeto sem config de arquivo é o caso comum). Com ``--config``, o
    caminho é obrigatório — ausência ali já é validada pelo próprio `typer.Option`
    (``exists=True``) antes de chegar aqui.
    """
    if explicito is not None:
        return load_config_file(explicito)
    padrao = Path(".guardiao.toml")
    if not padrao.is_file():
        return FileConfig()
    return load_config_file(padrao)

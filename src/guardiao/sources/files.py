"""Fonte de dados: sistema de arquivos."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from guardiao.core.config import Config


def iter_files(root: Path, config: Config, skipped: dict[str, int] | None = None) -> Iterator[Path]:
    """Percorre ``root`` devolvendo arquivos elegíveis para varredura.

    ``skipped`` (opcional) acumula quantos arquivos foram descartados por motivo —
    é o que permite ao relatório dizer o que **não** foi analisado.
    """
    contador = {} if skipped is None else skipped
    root = Path(root)
    try:
        raiz_real = root.resolve()
    except OSError:  # pragma: no cover - fs edge
        return
    if root.is_file():
        if _eligible(root, config, contador):
            yield root
        return

    for path in _walk(root, raiz_real, config):
        if _eligible(path, config, contador):
            yield path


def _walk(root: Path, raiz_real: Path, config: Config) -> Iterator[Path]:
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except (PermissionError, OSError):  # pragma: no cover - fs edge
            continue
        for entry in entries:
            if not _contido_na_raiz(entry, raiz_real):
                continue
            if entry.is_dir():
                if _skip_dir(entry, config):
                    continue
                stack.append(entry)
            elif entry.is_file():
                yield entry


def _contido_na_raiz(entry: Path, raiz_real: Path) -> bool:
    """Verdadeiro se ``entry`` continua **dentro** da árvore pedida, após resolver links.

    Checar contenção pelo caminho real — em vez de perguntar ``is_symlink()`` — é o
    que fecha a *junction* do Windows (``mklink /J``, que não exige administrador):
    para o Python ela **não** é symlink, então a varredura saía da árvore e reportava
    arquivos de fora do diretório que o usuário mandou varrer.
    """
    try:
        return entry.resolve().is_relative_to(raiz_real)
    except OSError:  # pragma: no cover - fs edge
        return False


def _skip_dir(entry: Path, config: Config) -> bool:
    """Decide se um diretório inteiro deve ser ignorado na varredura.

    Além dos nomes exatos de ``exclude_dirs``, identifica virtualenvs com nome
    fora do padrão (``.venv-locust``, ``venv311``, ``.env-ci``…) pelo marcador
    canônico ``pyvenv.cfg``. Sem isso, um venv com nome atípico é varrido e o
    ``site-packages`` interno inunda o relatório com chaves/certs de teste de
    bibliotecas — falso-positivo em massa (a lição de campo do Guardião)."""
    if entry.name in config.exclude_dirs:
        return True
    try:
        if (entry / "pyvenv.cfg").is_file():
            return True
    except OSError:  # pragma: no cover - fs edge
        return False
    return False


def _eligible(path: Path, config: Config, skipped: dict[str, int]) -> bool:
    if path.suffix.lower() in config.binary_exts:
        skipped["binario"] = skipped.get("binario", 0) + 1
        return False
    if config.is_noise_file(path.name):
        skipped["ruido"] = skipped.get("ruido", 0) + 1
        return False
    try:
        if path.stat().st_size > config.max_file_size:
            skipped["tamanho"] = skipped.get("tamanho", 0) + 1
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

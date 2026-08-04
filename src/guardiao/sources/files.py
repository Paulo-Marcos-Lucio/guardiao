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


#: BOMs que marcam, sem ambiguidade, o encoding de um arquivo de texto. A ordem
#: importa: o BOM de UTF-32 LE (``ff fe 00 00``) COMEÇA com o BOM de UTF-16 LE
#: (``ff fe``); testar o de 4 bytes antes evita ler um arquivo UTF-32 como UTF-16.
#: Os codecs ``utf-16``/``utf-32`` (sem sufixo de endianness) consomem e removem o
#: BOM ao decodificar, escolhendo o endianness por ele.
_BOMS: tuple[tuple[bytes, str], ...] = (
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xff\xfe\x00\x00", "utf-32"),
    (b"\x00\x00\xfe\xff", "utf-32"),
    (b"\xff\xfe", "utf-16"),
    (b"\xfe\xff", "utf-16"),
)


def decode_text_bytes(raw: bytes) -> str | None:
    """Decodifica bytes de arquivo em texto, ou ``None`` se parecer binário.

    Um arquivo com **BOM** (o Bloco de Notas, o ``>`` do PowerShell e muitas configs
    .NET gravam UTF-16 no Windows) é decodificado pelo codec que o BOM anuncia. Sem
    isso, os NUL de intercalação do UTF-16 (``t\\x00o\\x00k\\x00…``) faziam o arquivo
    parecer binário pela heurística de NUL — e o segredo passava batido em silêncio
    (cegueira de contexto de encoding). Sem BOM, mantém a heurística: NUL nos
    primeiros 8 KiB ⇒ binário (``None``); caso contrário decodifica como UTF-8,
    substituindo bytes inválidos (latin-1/quebrado ainda rende o texto ASCII).
    """
    for bom, codec in _BOMS:
        if raw.startswith(bom):
            try:
                return raw.decode(codec, errors="replace")
            except (LookupError, ValueError):  # pragma: no cover - defensivo
                break
    if b"\x00" in raw[:8192]:
        return None
    return raw.decode("utf-8", errors="replace")


def read_text(path: Path) -> str | None:
    """Lê o arquivo como texto; devolve ``None`` se parecer binário."""
    try:
        raw = path.read_bytes()
    except OSError:  # pragma: no cover - fs edge
        return None
    return decode_text_bytes(raw)

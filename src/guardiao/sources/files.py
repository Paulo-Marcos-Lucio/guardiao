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

    for path in _walk(root, raiz_real, config, contador):
        if _eligible(path, config, contador):
            yield path


def _walk(root: Path, raiz_real: Path, config: Config, skipped: dict[str, int]) -> Iterator[Path]:
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except (PermissionError, OSError):  # pragma: no cover - fs edge
            continue
        for entry in entries:
            if not _contido_na_raiz(entry, raiz_real):
                # Link/junction/`..` que RESOLVE para FORA da raiz pedida: não seguir (seguir
                # poderia varrer o disco inteiro pela cauda de um symlink), mas CONTAR o pulo —
                # silenciar reportaria "nada encontrado" enquanto o segredo do alvo do link fica
                # invisível, e um `mklink /J` para fora não apareceria em lugar nenhum.
                skipped["fora-da-raiz"] = skipped.get("fora-da-raiz", 0) + 1
                continue
            if entry.is_dir():
                if _skip_dir(entry, config):
                    # Pulo de MAIOR alcance da ferramenta — e o único que não era
                    # contado: um `ghp_` versionado em `vendor/` produzia
                    # "✓ Nenhum segredo encontrado" com todos os contadores zerados,
                    # enquanto o mesmo arquivo em stage bloqueava o commit.
                    skipped["diretorio"] = skipped.get("diretorio", 0) + 1
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


#: Assinaturas (magic bytes) de contêineres binários/documentos que COMEÇAM com bytes
#: ASCII e por isso escapam da heurística de NUL. O caso de campo: ``requests-logo.ai``
#: (Adobe Illustrator) abre com ``%PDF``/``%!PS`` em ASCII, não tem NUL nos primeiros
#: 8 KiB, era lido como texto e o corpo comprimido rendia falso-positivo de entropia.
#: A CLASSE é "arquivo binário mal-nomeado (extensão desconhecida) lido como texto";
#: detectar pela ASSINATURA fecha a classe inteira, não só a extensão ``.ai``.
#: ``MZ`` puro fica de FORA de propósito (2 bytes ambíguos que texto legítimo pode ter);
#: só entram assinaturas inequívocas.
_ASSINATURAS_BINARIAS: tuple[bytes, ...] = (
    b"%PDF",  # PDF (e Illustrator moderno)
    b"%!PS",  # PostScript / EPS / Illustrator legado
    b"\x89PNG\r\n\x1a\n",  # PNG
    b"GIF87a",
    b"GIF89a",
    b"\xff\xd8\xff",  # JPEG
    b"PK\x03\x04",  # ZIP / docx / xlsx / jar / odt
    b"PK\x05\x06",  # ZIP vazio
    b"\x7fELF",  # ELF
    b"Rar!\x1a\x07",  # RAR
    b"\x1f\x8b",  # gzip
    b"BM",  # BMP (2 bytes, mas seguido sempre de tamanho — raro em texto que comece "BM")
    b"OggS",  # Ogg
    b"fLaC",  # FLAC
    b"\x00\x00\x01\x00",  # ICO (tem NUL: já caía, mas explícito)
    b"II*\x00",  # TIFF little-endian
    b"MM\x00*",  # TIFF big-endian
    b"\xfd7zXZ\x00",  # XZ
    b"7z\xbc\xaf\x27\x1c",  # 7-Zip
    b"ustar",  # tar (em offset 257, mas o prefixo cobre o caso comum de header nomeado)
    b"\xca\xfe\xba\xbe",  # class Java / Mach-O fat
    b"RIFF",  # WAV / AVI / WebP
    b"\x25\x50\x44\x46",  # %PDF em bytes (dup defensivo)
)


def _tem_assinatura_binaria(raw: bytes) -> bool:
    """O arquivo abre com uma assinatura de contêiner binário conhecido?"""
    head = raw[:16]
    return any(head.startswith(sig) for sig in _ASSINATURAS_BINARIAS)


#: Bytes que contam como TEXTO num dos planos do UTF-16 (ASCII imprimível + espaços em
#: branco usuais). Um plano de texto real é quase todo composto por eles.
_BYTES_DE_TEXTO: frozenset[int] = frozenset(range(0x20, 0x7F)) | frozenset(b"\t\n\r\f\v")


def _detecta_utf16_sem_bom(raw: bytes) -> str | None:
    """UTF-16 (LE/BE) escrito SEM BOM — devolve o codec, ou ``None``.

    O PowerShell ISE e alguns editores gravam UTF-16 sem BOM: o texto ASCII vira um
    byte de dado intercalado com um ``\\x00`` a cada 2 bytes. A heurística de NUL o
    trataria como binário e o segredo passaria batido (cegueira de encoding). A
    assinatura é forte e barata: num dos dois planos (índices pares OU ímpares) quase
    TODO byte é ``\\x00``, e no OUTRO quase todo byte é texto ASCII imprimível. Nenhum
    binário real (que tem NUL espalhado, não alternado) casa esse padrão — por isso o
    limiar é 90%, para não decodificar errado um binário mal-nomeado como texto."""
    amostra = raw[:8192]
    if len(amostra) < 16 or b"\x00" not in amostra:
        return None
    n = len(amostra) - (len(amostra) % 2)
    pares = n // 2
    if pares == 0:
        return None

    def _classifica(plano_nul: bytes, plano_texto: bytes) -> bool:
        nuls = sum(1 for b in plano_nul if b == 0)
        texto = sum(1 for b in plano_texto if b in _BYTES_DE_TEXTO)
        return nuls * 10 >= pares * 9 and texto * 10 >= pares * 9

    if _classifica(amostra[1:n:2], amostra[0:n:2]):
        return "utf-16-le"  # dado nos pares, NUL nos ímpares
    if _classifica(amostra[0:n:2], amostra[1:n:2]):
        return "utf-16-be"  # dado nos ímpares, NUL nos pares
    return None


def decode_text_bytes(raw: bytes) -> str | None:
    """Decodifica bytes de arquivo em texto, ou ``None`` se parecer binário.

    Um arquivo com **BOM** (o Bloco de Notas, o ``>`` do PowerShell e muitas configs
    .NET gravam UTF-16 no Windows) é decodificado pelo codec que o BOM anuncia. Sem
    isso, os NUL de intercalação do UTF-16 (``t\\x00o\\x00k\\x00…``) faziam o arquivo
    parecer binário pela heurística de NUL — e o segredo passava batido em silêncio
    (cegueira de contexto de encoding). Sem BOM: (1) uma **assinatura de contêiner
    binário** no início ⇒ binário (fecha a classe do binário ASCII sem NUL, ex.: ``.ai``);
    (2) NUL nos primeiros 8 KiB ⇒ binário; caso contrário decodifica como UTF-8,
    substituindo bytes inválidos (latin-1/quebrado ainda rende o texto ASCII).
    """
    for bom, codec in _BOMS:
        if raw.startswith(bom):
            try:
                return raw.decode(codec, errors="replace")
            except (LookupError, ValueError):  # pragma: no cover - defensivo
                break
    if _tem_assinatura_binaria(raw):
        return None
    codec_utf16 = _detecta_utf16_sem_bom(raw)
    if codec_utf16 is not None:
        return raw.decode(codec_utf16, errors="replace")
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

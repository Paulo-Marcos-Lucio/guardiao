"""Contenção da varredura e elegibilidade de arquivo."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from guardiao.core.config import Config
from guardiao.core.engine import Scanner
from guardiao.sources.files import decode_text_bytes, read_text
from tests.conftest import AWS_KEY_ID, GH_TOKEN


def _arvore_com_fuga(tmp_path: Path) -> tuple[Path, Path]:
    fora = tmp_path / "segredos_reais"
    fora.mkdir()
    (fora / "prod.env").write_text(f"AWS_ACCESS_KEY={AWS_KEY_ID}\n", encoding="utf-8")
    dentro = tmp_path / "clone_hostil"
    dentro.mkdir()
    (dentro / "readme.md").write_text("nada aqui\n", encoding="utf-8")
    return dentro, fora


@pytest.mark.skipif(sys.platform != "win32", reason="junction é do Windows")
def test_junction_do_windows_nao_tira_a_varredura_da_arvore(tmp_path: Path) -> None:
    """`mklink /J` não exige administrador e NÃO é symlink para o Python: a varredura
    saía do diretório pedido e reportava caminho de fora dele."""
    dentro, fora = _arvore_com_fuga(tmp_path)
    criado = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(dentro / "fuga"), str(fora)],
        capture_output=True,
    )
    if criado.returncode != 0:  # pragma: no cover - ambiente sem permissão
        pytest.skip("não foi possível criar junction neste ambiente")
    resultado = Scanner().scan_paths([dentro])
    assert resultado.findings == []
    assert resultado.units_scanned == 1


@pytest.mark.skipif(sys.platform == "win32", reason="symlink de diretório exige privilégio no Win")
def test_symlink_nao_tira_a_varredura_da_arvore(tmp_path: Path) -> None:
    dentro, fora = _arvore_com_fuga(tmp_path)
    os.symlink(fora, dentro / "fuga", target_is_directory=True)
    resultado = Scanner().scan_paths([dentro])
    assert resultado.findings == []
    assert resultado.units_scanned == 1


def test_virtualenv_de_nome_atipico_e_pulado(tmp_path: Path) -> None:
    """A correção-estrela do repo (venv reconhecido por `pyvenv.cfg`, não pelo nome)
    não tinha nenhum teste: apagá-la reintroduzia o falso-positivo em massa."""
    venv = tmp_path / ".venv-locust"
    (venv / "Lib" / "sp").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr\n", encoding="utf-8")
    (venv / "Lib" / "sp" / "certo.py").write_text(f'K = "{AWS_KEY_ID}"\n', encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    resultado = Scanner().scan_paths([tmp_path])
    assert resultado.findings == []


def test_read_text_recusa_binario(tmp_path: Path) -> None:
    alvo = tmp_path / "dados.bin"
    alvo.write_bytes(b"MZ\x00\x00" + AWS_KEY_ID.encode())
    assert read_text(alvo) is None
    resultado = Scanner().scan_paths([alvo])
    assert resultado.findings == []
    assert resultado.skipped["binario"] == 1


def test_extensao_binaria_nem_e_aberta(tmp_path: Path) -> None:
    (tmp_path / "logo.png").write_text(f"{AWS_KEY_ID}\n", encoding="utf-8")
    resultado = Scanner(config=Config()).scan_paths([tmp_path])
    assert resultado.findings == []
    assert resultado.skipped["binario"] == 1


# ------------------------------------------------------------------ #
# Cegueira de encoding: arquivo com BOM (UTF-16/UTF-32) NÃO é binário.
# No Windows, Bloco de Notas/PowerShell/.NET gravam UTF-16 — os NUL de
# intercalação faziam o segredo passar batido como "binário".
# ------------------------------------------------------------------ #
@pytest.mark.parametrize(
    "encoding",
    ["utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be", "utf-8-sig"],
)
def test_arquivo_com_bom_e_lido_e_o_segredo_encontrado(tmp_path: Path, encoding: str) -> None:
    linha = f'token = "{GH_TOKEN}"\n'
    raw = linha.encode(encoding)
    # utf-16-le/be e utf-32-le/be do Python NÃO gravam BOM — anexa manualmente
    # (é assim que Notepad/PowerShell gravam de verdade).
    boms = {
        "utf-16-le": b"\xff\xfe",
        "utf-16-be": b"\xfe\xff",
        "utf-32-le": b"\xff\xfe\x00\x00",
        "utf-32-be": b"\x00\x00\xfe\xff",
    }
    if encoding in boms:
        raw = boms[encoding] + raw
    texto = decode_text_bytes(raw)
    assert texto is not None, f"{encoding} foi tratado como binário"
    assert GH_TOKEN in texto

    alvo = tmp_path / "config.txt"
    alvo.write_bytes(raw)
    resultado = Scanner().scan_paths([alvo])
    assert len(resultado.findings) == 1, f"segredo em {encoding} não foi encontrado"
    assert resultado.findings[0].secret == GH_TOKEN


def test_binario_sem_bom_continua_sendo_pulado(tmp_path: Path) -> None:
    """A correção de BOM não pode passar a varrer binário de verdade: sem BOM, NUL
    nos primeiros 8 KiB ainda significa binário."""
    alvo = tmp_path / "dados.bin"
    alvo.write_bytes(b"\x00\x01\x02\x03" * 64 + GH_TOKEN.encode())
    assert decode_text_bytes(alvo.read_bytes()) is None
    resultado = Scanner().scan_paths([alvo])
    assert resultado.findings == []
    assert resultado.skipped["binario"] == 1

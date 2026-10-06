"""Contenção da varredura e elegibilidade de arquivo."""

from __future__ import annotations

import os
import shutil
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


def test_diretorio_excluido_aparece_no_contador(tmp_path: Path) -> None:
    """Pular um diretório inteiro é o pulo de MAIOR alcance da ferramenta — e era o
    único que não entrava em `skipped`: um token real versionado em `vendor/` dava
    "✓ Nenhum segredo encontrado" com todos os contadores zerados e exit 0, enquanto
    o MESMO arquivo em stage bloqueava o commit. Os dois caminhos discordavam."""
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "config.py").write_text(f'GH = "{GH_TOKEN}"\n', encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    resultado = Scanner().scan_paths([tmp_path])

    assert resultado.findings == []
    assert resultado.skipped["diretorio"] == 1
    assert resultado.total_pulado() == 1


def test_venv_de_nome_atipico_tambem_entra_no_contador(tmp_path: Path) -> None:
    """O venv detectado por `pyvenv.cfg` some do relatório pelo mesmo caminho do
    `exclude_dirs` — contar só os nomes exatos deixaria metade do buraco aberto."""
    venv = tmp_path / ".venv-locust"
    (venv / "Lib").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr\n", encoding="utf-8")
    (venv / "Lib" / "certo.py").write_text(f'K = "{AWS_KEY_ID}"\n', encoding="utf-8")

    resultado = Scanner().scan_paths([tmp_path])

    assert resultado.findings == []
    assert resultado.skipped["diretorio"] == 1


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


# ------------------------------------------------------------------ #
# .gitignore-awareness: o que o próprio Git nunca versionaria não deveria
# inflar o laudo com achado de arquivo que o commit nem alcança.
# ------------------------------------------------------------------ #
pytestmark_git = pytest.mark.skipif(shutil.which("git") is None, reason="git não disponível")


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=test@example.com",
            "-c",
            "user.name=Test",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=str(repo),
        check=True,
        capture_output=True,
    )


def _repo_git(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    return repo


@pytestmark_git
def test_arquivo_no_gitignore_e_pulado_e_contado(tmp_path: Path) -> None:
    """Arquivo que o `.gitignore` do projeto exclui (log, dump local, cache de build)
    não é o que o time versiona nem revisa — varrê-lo como código de verdade só
    infla o laudo com achado que ninguém vai consertar porque ninguém vai comitar."""
    repo = _repo_git(tmp_path)
    (repo / ".gitignore").write_text("*.log\n", encoding="utf-8")
    (repo / "debug.log").write_text(f"token leaked: {AWS_KEY_ID}\n", encoding="utf-8")
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", "app.py", ".gitignore")
    _git(repo, "commit", "-m", "c0")

    resultado = Scanner().scan_paths([repo])

    assert resultado.findings == []
    assert resultado.skipped["gitignore"] == 1


@pytestmark_git
def test_ignorar_gitignore_desliga_o_comportamento(tmp_path: Path) -> None:
    """`--ignorar-gitignore` (`Config.respect_gitignore=False`) existe para quem quer
    auditar justamente o que o Git nunca versionaria — tem de achar o segredo."""
    repo = _repo_git(tmp_path)
    (repo / ".gitignore").write_text("*.log\n", encoding="utf-8")
    (repo / "debug.log").write_text(f"token leaked: {AWS_KEY_ID}\n", encoding="utf-8")
    _git(repo, "add", ".gitignore")
    _git(repo, "commit", "-m", "c0")

    resultado = Scanner(config=Config(respect_gitignore=False)).scan_paths([repo])

    achados = [f for f in resultado.findings if f.rule_id == "aws-access-key-id"]
    assert achados, "--ignorar-gitignore não alcançou o arquivo ignorado"
    assert resultado.skipped["gitignore"] == 0


@pytestmark_git
def test_arquivo_ja_versionado_nao_e_afetado_pelo_gitignore(tmp_path: Path) -> None:
    """`.gitignore` só vale para o que o Git NÃO rastreia ainda — um arquivo já
    comitado (depois adicionado ao `.gitignore` por engano, cenário comum) continua
    rastreado pelo Git e não pode desaparecer do laudo."""
    repo = _repo_git(tmp_path)
    (repo / "config.py").write_text(f'AWS_KEY = "{AWS_KEY_ID}"\n', encoding="utf-8")
    _git(repo, "add", "config.py")
    _git(repo, "commit", "-m", "c0: versiona com segredo")
    (repo / ".gitignore").write_text("config.py\n", encoding="utf-8")
    _git(repo, "add", ".gitignore")
    _git(repo, "commit", "-m", "c1: ignora por engano, mas já estava versionado")

    resultado = Scanner().scan_paths([repo])

    assert [f for f in resultado.findings if f.rule_id == "aws-access-key-id"]
    assert resultado.skipped["gitignore"] == 0


def test_fora_de_repositorio_git_nao_filtra_nada(tmp_path: Path) -> None:
    """Sem `.git`, não há `.gitignore` de verdade a aplicar — a varredura segue como
    sempre seguiu, sem o filtro (fail-soft, não fail-closed: aqui não há limite de
    alcance a declarar, só a ausência do conceito)."""
    (tmp_path / "app.py").write_text(f'AWS_KEY = "{AWS_KEY_ID}"\n', encoding="utf-8")
    resultado = Scanner().scan_paths([tmp_path])
    assert [f for f in resultado.findings if f.rule_id == "aws-access-key-id"]
    assert resultado.skipped["gitignore"] == 0

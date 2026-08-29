"""`--jobs`: a varredura paralela precisa produzir o MESMO resultado da sequencial,
só mais rápido — nunca um achado a mais, a menos, ou com `commit_last` diferente.

`test_propriedades.py` já cobre as invariantes das REGRAS; este arquivo cobre a
invariante do PIPELINE em si: `scan_units(units, jobs=N)` é `scan_units(units, jobs=1)`
para qualquer N, porque `_scan_parallel` entrega os resultados na ordem de SUBMISSÃO
(fila FIFO), não na ordem de conclusão — ver o docstring de `_scan_parallel`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from guardiao.cli import app
from guardiao.core.engine import Scanner
from tests.conftest import AWS_KEY_ID

runner = CliRunner()

_sem_git = pytest.mark.skipif(shutil.which("git") is None, reason="git não disponível")


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


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    return repo


def test_scan_paths_paralelo_bate_com_sequencial(planted_dir: Path) -> None:
    scanner = Scanner()
    sequencial = scanner.scan_paths([planted_dir], jobs=1)
    paralelo = scanner.scan_paths([planted_dir], jobs=3)
    assert paralelo.findings == sequencial.findings
    assert paralelo.units_scanned == sequencial.units_scanned
    assert paralelo.skipped == sequencial.skipped
    assert paralelo.placeholders == sequencial.placeholders


@_sem_git
def test_scan_git_history_paralelo_preserva_commit_last(tmp_path: Path) -> None:
    """O cenário-assinatura de `_collapse_history`: o MESMO segredo em 4 commits.

    `commit_last` depende da ORDEM em que os blobs foram varridos — é exatamente o
    dado que uma paralelização ingênua (ex.: `Executor.map` com `as_completed`)
    embaralharia. `--jobs 4` com 4 blobs força o pior caso: um worker por blob.
    """
    repo = _repo(tmp_path)
    alvo = repo / "config.py"
    for i in range(4):
        alvo.write_text(f'# rev {i}\nAWS_KEY = "{AWS_KEY_ID}"\n', encoding="utf-8")
        _git(repo, "add", "config.py")
        _git(repo, "commit", "-m", f"c{i}")

    sequencial = Scanner().scan_git_history(repo, jobs=1)
    paralelo = Scanner().scan_git_history(repo, jobs=4)

    seq_aws = [f for f in sequencial.findings if f.rule_id == "aws-access-key-id"]
    par_aws = [f for f in paralelo.findings if f.rule_id == "aws-access-key-id"]
    assert len(seq_aws) == len(par_aws) == 1, "o mesmo segredo em 4 commits é UM achado"
    assert par_aws[0].occurrences == seq_aws[0].occurrences >= 4
    assert par_aws[0].location.commit == sequencial.findings[0].location.commit
    assert par_aws[0].commit_last == seq_aws[0].commit_last
    assert paralelo.findings == sequencial.findings


def test_jobs_1_e_o_caminho_sequencial_original(planted_dir: Path) -> None:
    """`jobs=1` não deve nem tentar montar um `ProcessPoolExecutor` — é o mesmo
    resultado que rodar sem o parâmetro (compatibilidade com todo chamador existente:
    `pre-commit`, testes antigos, `--jobs` omitido em CLIs anteriores a este item)."""
    scanner = Scanner()
    com_kw = scanner.scan_paths([planted_dir], jobs=1)
    sem_kw = scanner.scan_paths([planted_dir])
    assert com_kw.findings == sem_kw.findings


def test_cli_jobs_default_e_a_contagem_de_cpus(
    planted_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--jobs` sem valor explícito usa `os.cpu_count()` — não 1. É o que fecha o gap
    descrito na fonte do item (`scan_units single-thread`): sequencial teria que ser
    um `--jobs 1` PEDIDO, não o padrão silencioso de sempre.

    O default do `typer.Option` é calculado uma vez, na IMPORTAÇÃO de `cli.py` — como
    qualquer valor-padrão de função em Python — não a cada chamada. Por isso o teste
    não faz `monkeypatch` de `os.cpu_count` (o `Typer`/`Click` já capturou o valor
    antes disso rodar); ele confere contra o `os.cpu_count()` real desta máquina.
    """
    recebido: dict[str, object] = {}
    original = Scanner.scan_paths

    def _espiao(self: Scanner, paths, *, jobs: int = 1):  # type: ignore[no-untyped-def]
        recebido["jobs"] = jobs
        return original(self, paths, jobs=1)  # roda de verdade, mas sequencial (teste rápido)

    monkeypatch.setattr(Scanner, "scan_paths", _espiao)
    result = runner.invoke(app, ["scan", str(planted_dir)])
    assert result.exit_code in (0, 1)
    assert recebido["jobs"] == (os.cpu_count() or 1)


def test_cli_jobs_1_desliga_o_paralelismo(
    planted_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recebido: dict[str, object] = {}
    original = Scanner.scan_paths

    def _espiao(self: Scanner, paths, *, jobs: int = 1):  # type: ignore[no-untyped-def]
        recebido["jobs"] = jobs
        return original(self, paths, jobs=1)

    monkeypatch.setattr(Scanner, "scan_paths", _espiao)
    result = runner.invoke(app, ["scan", str(planted_dir), "--jobs", "1"])
    assert result.exit_code in (0, 1)
    assert recebido["jobs"] == 1


def test_cli_jobs_abaixo_de_1_e_rejeitado(planted_dir: Path) -> None:
    result = runner.invoke(app, ["scan", str(planted_dir), "--jobs", "0"])
    assert result.exit_code != 0


# -- invariante de classe: qualquer conjunto de unidades, qualquer N de jobs -------- #

_PATH = st.text(alphabet="abcdefgh_./", min_size=1, max_size=12).map(
    lambda s: s.strip("/") or "a.txt"
)
_TEXTO = st.text(min_size=0, max_size=120)


@given(
    unidades=st.lists(st.tuples(_PATH, _TEXTO), min_size=0, max_size=6),
    jobs=st.integers(min_value=1, max_value=3),
)
@settings(max_examples=15, deadline=None)  # cada exemplo sobe um ProcessPoolExecutor: caro
def test_paralelo_e_sequencial_concordam_para_qualquer_conjunto_de_unidades(
    unidades: list[tuple[str, str]], jobs: int
) -> None:
    units = [(path, texto, None) for path, texto in unidades]
    scanner = Scanner()
    sequencial = scanner.scan_units(iter(units))
    paralelo = scanner.scan_units(iter(units), jobs=jobs)
    assert [f.fingerprint for f in paralelo.findings] == [
        f.fingerprint for f in sequencial.findings
    ]
    assert paralelo.units_scanned == sequencial.units_scanned == len(units)
    assert paralelo.skipped == sequencial.skipped

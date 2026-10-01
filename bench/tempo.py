"""Mede o tempo de `--git-history` num repositório sintético REPRODUTÍVEL.

Por que sintético em vez de clonar um repositório real "fixado por SHA": clonar de
fora introduz rede na medição — uma métrica de desempenho que falha por timeout de
rede não mede desempenho, mede a rede, e não é reproduzível numa máquina sem acesso
à internet. Este script GERA um repositório git com autor, data, conteúdo e mensagem
de cada commit fixos por índice (nunca pelo relógio) — o grafo de objetos resultante,
e portanto o SHA de HEAD, sai **idêntico em qualquer máquina** que rode este arquivo.
"Fixado por SHA" aqui quer dizer o que a régua de desempenho precisa: o repositório
medido é uma função pura deste script, não um artefato de rede ou de relógio.

Uso:
    python bench/tempo.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
# gitignorado (ver .gitignore) — recriado do zero a cada execução, então não precisa
# ficar versionado: o script É a fonte da verdade do repositório, o diretório é cache.
REPO = BASE / "_tempo_repo"

#: Tamanho fixo do repositório sintético. 400 commits x 3 arquivos dão ~1200 blobs de
#: histórico — grande o bastante para o tempo não ser dominado por overhead de processo
#: (um `git cat-file --batch-all-objects` só), pequeno o bastante para rodar em segundos
#: numa máquina de CI comum.
N_COMMITS = 400
ARQUIVOS_POR_COMMIT = 3

_ENV_FIXO = {
    "GIT_AUTHOR_NAME": "guardiao-bench",
    "GIT_AUTHOR_EMAIL": "bench@guardiao.invalid",
    "GIT_COMMITTER_NAME": "guardiao-bench",
    "GIT_COMMITTER_EMAIL": "bench@guardiao.invalid",
    # Isola de configuração pessoal de quem roda (sign, hooks, aliases) — sem isso o
    # SHA gerado deixaria de ser função só deste script.
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
}


def _run(*args: str, cwd: Path, env: dict[str, str]) -> None:
    subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True)


def gerar_repositorio() -> Path:
    """(Re)cria ``REPO`` com ``N_COMMITS`` determinísticos: mesmo grafo de objetos —
    e mesmo SHA de HEAD — toda vez que esta função roda, em qualquer máquina."""
    if REPO.exists():
        shutil.rmtree(REPO)
    REPO.mkdir(parents=True)
    base_env = {**os.environ, **_ENV_FIXO}
    _run("init", "--quiet", "--initial-branch=bench", cwd=REPO, env=base_env)
    for i in range(N_COMMITS):
        # Data derivada do índice do commit, não de `datetime.now()`: duas execuções
        # deste script — em máquinas ou dias diferentes — produzem o MESMO histórico.
        data = f"2020-01-01T00:{(i // 60) % 60:02d}:{i % 60:02d}Z"
        env = {**base_env, "GIT_AUTHOR_DATE": data, "GIT_COMMITTER_DATE": data}
        for a in range(ARQUIVOS_POR_COMMIT):
            conteudo = f"conteudo deterministico do commit {i}, arquivo {a}\n" * 4
            (REPO / f"arquivo-{a}.txt").write_text(conteudo, encoding="utf-8")
        _run("add", "-A", cwd=REPO, env=env)
        _run("commit", "--quiet", "-m", f"commit sintetico {i}", cwd=REPO, env=env)
    return REPO


def sha_do_head(repo: Path) -> str:
    resultado = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
    )
    return resultado.stdout.strip()


def medir(repo: Path) -> float:
    # Import tardio: evita custo de import quando este arquivo só é usado para gerar o
    # repositório (ex.: pelo teste cronometrado, que mede via subprocesso da própria CLI).
    from guardiao.core.engine import Scanner

    scanner = Scanner()
    inicio = time.perf_counter()
    scanner.scan_git_history(repo)
    return time.perf_counter() - inicio


def main() -> None:
    repo = gerar_repositorio()
    sha = sha_do_head(repo)
    decorrido = medir(repo)
    print(f"repositorio sintetico  : {repo}")
    print(f"commits                : {N_COMMITS}")
    print(f"SHA de HEAD (fixo)     : {sha}")
    print(f"tempo de --git-history : {decorrido:.3f}s")
    print(f"python                 : {sys.version.split()[0]}")


if __name__ == "__main__":
    main()

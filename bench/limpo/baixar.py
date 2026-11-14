"""Baixa repositórios públicos de terceiros, fixados por commit, para medir
falso-positivo do Guardião contra código REAL que ninguém aqui plantou.

Por que isto não é `bench/positivos`/`bench/negativos` nem `bench/creddata/`.
Os fixtures sintéticos são escritos por quem fez a ferramenta — um
falso-positivo baixo ali prova só que o autor não tropeçou no próprio código.
`bench/creddata/` vai na direção do RECALL: mede se o Guardião acha segredo
real rotulado como real. Este módulo mede a direção oposta — PRECISÃO em
código legítimo e popular, onde o pressuposto declarado é que não há segredo
real nenhum, e qualquer achado é candidato a falso-positivo.

"limpo" é um pressuposto, não um fato que este script verifica. Ninguém
auditou httpx/requests/flask linha a linha; são projetos populares,
mantidos, com push protection do GitHub ativo há anos, o que torna um
segredo real sobrevivendo no histórico improvável — não impossível. É por
isso que `avaliar.py` nunca presume que um achado é falso-positivo: cada um
só conta como tal se existir entrada correspondente, no COMMIT atual, em
`adjudicacao.json` (versionado). Sem entrada, o achado fica `pendente` — a
mesma régua da política de cadência sobre não confundir ausência de
medição com medição de ausência.

Commits fixados, não "latest": a mesma pergunta ("quantos falso-positivo por
mil arquivos?") precisa dar a mesma resposta hoje e em um ano. Sem isto, um
commit novo no upstream poderia introduzir ou remover um achado sem que
ninguém percebesse a mudança de piso — e a adjudicação versionada deste
módulo ficaria descrevendo um código que não é mais o que está no disco
(`avaliar.py` trata isso como `pendente`, nunca como FP herdado).

Uso:
    python bench/limpo/baixar.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
CACHE_DIR = BASE / ".cache"
REPOS_DIR = CACHE_DIR / "repos"
MANIFESTO_PATH = CACHE_DIR / "manifesto.json"


@dataclass(frozen=True)
class RepoFixado:
    nome: str
    url: str
    commit: str


# O critério de aceite do item cita o prefixo curto do commit (ex.: `b5addb6`);
# aqui vai o SHA-1 completo, resolvido uma vez contra o remoto, para fixar sem
# ambiguidade (um prefixo de 7 caracteres pode colidir à medida que o
# repositório cresce).
REPOS: tuple[RepoFixado, ...] = (
    RepoFixado(
        "httpx", "https://github.com/encode/httpx", "b5addb64f0161ff6bfe94c124ef76f6a1fba5254"
    ),
    RepoFixado(
        "requests", "https://github.com/psf/requests", "1f6589ec3a1ee910f9a65cc3ceac60b26677bc0e"
    ),
    RepoFixado(
        "flask", "https://github.com/pallets/flask", "6a2f545bfd8ed31e19066a299296917e034aca58"
    ),
)


def _rev_parse(repo_dir: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _clonar(repo: RepoFixado, destino: Path) -> None:
    """Clone raso do repositório ALVO no commit fixado. Não lança se o
    destino já estiver no commit certo (idempotente); lança se estiver em
    outro commit (estado ambíguo — melhor parar do que medir contra o
    código errado) ou se o commit não existir mais no remoto (repositório
    real, pode ter sido reescrito ou apagado)."""
    if destino.exists():
        atual = _rev_parse(destino)
        if atual == repo.commit:
            return
        raise RuntimeError(
            f"{destino} está no commit {atual}, não no fixado {repo.commit} "
            f"para {repo.nome}. Remova o diretório (rm -rf {destino}) para reclonar."
        )
    destino.mkdir(parents=True, exist_ok=True)
    passos = [
        ["git", "init", "-q"],
        ["git", "remote", "add", "origin", repo.url],
        ["git", "fetch", "--depth", "1", "-q", "origin", repo.commit],
        ["git", "checkout", "-q", repo.commit],
    ]
    for passo in passos:
        resultado = subprocess.run(passo, cwd=destino, capture_output=True, text=True)
        if resultado.returncode != 0:
            raise RuntimeError(
                f"falha ao clonar {repo.nome}@{repo.commit[:12]}: {resultado.stderr.strip()}"
            )


def conta_arquivos(raiz: Path) -> int:
    """Total de arquivos de verdade sob `raiz`, excluindo `.git/` — o
    denominador do FP por 1.000 arquivos que `avaliar.py` calcula."""
    total = 0
    for caminho in raiz.rglob("*"):
        if not caminho.is_file() or caminho.is_symlink():
            continue
        if ".git" in caminho.relative_to(raiz).parts:
            continue
        total += 1
    return total


def baixar() -> dict[str, object]:
    """Clona cada repositório fixado em `REPOS_DIR/<nome>` e grava o
    manifesto. `avaliar.py` lê o manifesto de volta do disco para declarar
    exatamente contra qual commit e quantos arquivos a medição rodou."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    repos_info: list[dict[str, object]] = []
    for repo in REPOS:
        destino = REPOS_DIR / repo.nome
        _clonar(repo, destino)
        repos_info.append(
            {
                "nome": repo.nome,
                "url": repo.url,
                "commit": repo.commit,
                "total_arquivos": conta_arquivos(destino),
            }
        )
    manifesto: dict[str, object] = {
        "repos": repos_info,
        "total_arquivos": sum(int(r["total_arquivos"]) for r in repos_info),  # type: ignore[arg-type]
        "repos_dir": str(REPOS_DIR),
        "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    MANIFESTO_PATH.write_text(json.dumps(manifesto, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifesto


def main(argv: list[str]) -> int:
    del argv  # sem flags: baixa sempre os três repositórios fixados
    manifesto = baixar()
    repos = manifesto["repos"]
    assert isinstance(repos, list)
    print(
        f"OK: {len(repos)} repositório(s), {manifesto['total_arquivos']} arquivo(s) em {REPOS_DIR}"
    )
    for r in repos:
        print(f"  - {r['nome']} @ {str(r['commit'])[:12]} ({r['total_arquivos']} arquivos)")
    print(f"Manifesto: {MANIFESTO_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

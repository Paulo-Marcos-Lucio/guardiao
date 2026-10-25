"""Mede falso-positivo do Guardião contra código real de terceiros (ver
`baixar.py` sobre por que "limpo" é um pressuposto, não um fato verificado).

A métrica é FP por 1.000 arquivos, não por 1.000 linhas (como
`bench/positivos`/`bench/negativos` medem) — denominador deliberadamente
diferente: aqui não existe um corpus de linhas-armadilha para contar, e o
que importa para quem recebe um relatório do Guardião é "quantos arquivos
de um projeto normal geram ruído", não uma proporção de linha sintética.

Nenhum achado conta como falso-positivo por default. Cada um só é FP se
tiver entrada correspondente — mesmo `repo`, `arquivo`, `linha` **e commit
atual** — em `adjudicacao.json` (versionado, ao lado deste arquivo). Sem
entrada, ou com entrada de um commit que não é mais o commit baixado, o
achado fica `pendente`: nunca presumido FP, nunca descartado em silêncio. Se
uma adjudicação registrar `segredo_real`, o achado nunca entra no FP/1k — é
impresso à parte, com destaque, porque seria o oposto do que este corpus
pressupõe.

Uso:
    python bench/limpo/baixar.py
    guardiao scan bench/limpo/.cache/repos -f json -o bench/limpo/.cache/resultado.json --fail-on none
    python bench/limpo/avaliar.py bench/limpo/.cache/resultado.json
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    from bench.limpo.baixar import MANIFESTO_PATH
except ImportError:
    # Executado como script direto (`python bench/limpo/avaliar.py`): o próprio
    # diretório do arquivo já está no `sys.path`, então o nome sem pacote resolve.
    from baixar import MANIFESTO_PATH  # type: ignore[import-not-found,no-redef]

BASE = Path(__file__).resolve().parent
ADJUDICACAO_PATH = BASE / "adjudicacao.json"

VEREDITO_FALSO_POSITIVO = "falso_positivo"
VEREDITO_SEGREDO_REAL = "segredo_real"
VEREDITOS_VALIDOS = frozenset({VEREDITO_FALSO_POSITIVO, VEREDITO_SEGREDO_REAL})

Achado = tuple[str, str, int]  # (repo, arquivo, linha)


@dataclass(frozen=True)
class Adjudicacao:
    repo: str
    commit: str
    arquivo: str
    linha: int
    regra: str
    veredito: str
    motivo: str


@dataclass(frozen=True)
class Avaliacao:
    total_achados: int
    falsos_positivos: int
    segredos_reais: tuple[Achado, ...]
    pendentes: tuple[Achado, ...]


def carregar_adjudicacoes(caminho: Path = ADJUDICACAO_PATH) -> list[Adjudicacao]:
    bruto = json.loads(caminho.read_text(encoding="utf-8"))
    adjudicacoes = []
    for item in bruto:
        veredito = item["veredito"]
        if veredito not in VEREDITOS_VALIDOS:
            raise ValueError(f"veredito desconhecido em {caminho}: {veredito!r}")
        adjudicacoes.append(
            Adjudicacao(
                repo=item["repo"],
                commit=item["commit"],
                arquivo=item["arquivo"],
                linha=item["linha"],
                regra=item["regra"],
                veredito=veredito,
                motivo=item["motivo"],
            )
        )
    return adjudicacoes


def normaliza(caminho: object, nomes_repo: tuple[str, ...]) -> tuple[str, str] | None:
    """Separa `(repo, arquivo)` de um caminho reportado pelo Guardião.

    `guardiao scan bench/limpo/.cache/repos` varre `REPOS_DIR` como raiz
    única — por isso cada achado chega como `<repo>/<caminho relativo>`
    (ex.: `httpx/tests/test_auth.py`), e não como caminho relativo a cada
    clone individualmente. Retorna `None` quando o caminho não começa com
    nenhum dos `nomes_repo` conhecidos — um achado fora do escopo deste
    corpus (ex.: `resultado.json` de uma execução anterior no mesmo
    diretório), que `avaliar()` conta e declara, nunca ignora em silêncio.
    """
    texto = str(caminho).replace(chr(92), "/").lstrip("/")
    marcador = "/repos/"
    if marcador in texto:
        texto = texto.split(marcador, 1)[1]
    for nome in nomes_repo:
        prefixo = f"{nome}/"
        if texto == nome:
            return nome, ""
        if texto.startswith(prefixo):
            return nome, texto[len(prefixo) :]
    return None


def classificar(
    achados: list[Achado],
    adjudicacoes: list[Adjudicacao],
    commits_atuais: dict[str, str],
) -> Avaliacao:
    """Classifica achados `(repo, arquivo, linha)` contra `adjudicacoes`.

    Partição total: todo achado cai em exatamente um balde —
    `falsos_positivos`, `segredos_reais` ou `pendentes` — nunca dois, nunca
    nenhum (ver `tests/test_bench_limpo.py` para a invariante
    property-based). Um achado só é FP se existir adjudicação para ELE, NO
    COMMIT ATUAL do repo: se o repo avançou de commit sem reabastecer a
    adjudicação, o achado volta a `pendente` em vez de herdar um veredito
    que foi dado sobre outra versão do arquivo.
    """
    por_chave = {(a.repo, a.arquivo, a.linha): a for a in adjudicacoes}
    falsos_positivos = 0
    segredos_reais: list[Achado] = []
    pendentes: list[Achado] = []
    for achado in achados:
        repo, _arquivo, _linha = achado
        adjudicacao = por_chave.get(achado)
        if adjudicacao is None or adjudicacao.commit != commits_atuais.get(repo):
            pendentes.append(achado)
        elif adjudicacao.veredito == VEREDITO_SEGREDO_REAL:
            segredos_reais.append(achado)
        else:
            falsos_positivos += 1
    return Avaliacao(
        total_achados=len(achados),
        falsos_positivos=falsos_positivos,
        segredos_reais=tuple(segredos_reais),
        pendentes=tuple(pendentes),
    )


def fp_por_mil_arquivos(falsos_positivos: int, total_arquivos: int) -> float:
    return (falsos_positivos / total_arquivos * 1000) if total_arquivos else 0.0


def avaliar(
    manifesto: dict[str, object], resultado_json: dict[str, object]
) -> tuple[Avaliacao, float]:
    repos = manifesto["repos"]
    assert isinstance(repos, list)
    nomes_repo = tuple(str(r["nome"]) for r in repos)
    commits_atuais = {str(r["nome"]): str(r["commit"]) for r in repos}
    adjudicacoes = carregar_adjudicacoes()

    brutos = resultado_json.get("achados") or resultado_json.get("findings") or []
    assert isinstance(brutos, list)
    achados: list[Achado] = []
    for a in brutos:
        separado = normaliza(a.get("path") or a.get("arquivo") or "", nomes_repo)
        if separado is None:
            continue
        repo, arquivo = separado
        linha = int(a.get("line") or a.get("linha") or 0)
        achados.append((repo, arquivo, linha))

    avaliacao = classificar(achados, adjudicacoes, commits_atuais)
    total_arquivos = int(manifesto["total_arquivos"])  # type: ignore[arg-type]
    fp_mil = fp_por_mil_arquivos(avaliacao.falsos_positivos, total_arquivos)
    return avaliacao, fp_mil


def imprimir(manifesto: dict[str, object], avaliacao: Avaliacao, fp_mil: float) -> None:
    repos = manifesto["repos"]
    assert isinstance(repos, list)
    print("== bench/limpo — falso-positivo contra código real, não plantado ==")
    for r in repos:
        print(f"  - {r['nome']} @ {str(r['commit'])[:12]} ({r['total_arquivos']} arquivos)")
    print(f"  total de arquivos   : {manifesto['total_arquivos']}")
    print(f"  achados brutos      : {avaliacao.total_achados}")
    print(f"  FALSO-POSITIVO      : {avaliacao.falsos_positivos} (adjudicado)")
    print(f"  FP / 1.000 arquivos : {fp_mil:.3f}")
    print(f"  pendente de adjudicação : {len(avaliacao.pendentes)}")
    if avaliacao.pendentes:
        print("    (NÃO contado no FP/1k — adjudique em bench/limpo/adjudicacao.json)")
        for repo, arquivo, linha in avaliacao.pendentes:
            print(f"    - {repo}/{arquivo}:{linha}")
    if avaliacao.segredos_reais:
        print("  !!! SEGREDO REAL ADJUDICADO — revisar imediatamente, nunca publicar o valor:")
        for repo, arquivo, linha in avaliacao.segredos_reais:
            print(f"    - {repo}/{arquivo}:{linha}")
    print()
    print("  Comando de reprodução:")
    print("    python bench/limpo/baixar.py")
    print(
        "    guardiao scan bench/limpo/.cache/repos -f json "
        "-o bench/limpo/.cache/resultado.json --fail-on none"
    )
    print("    python bench/limpo/avaliar.py bench/limpo/.cache/resultado.json")


def main(argv: list[str]) -> int:
    if not MANIFESTO_PATH.exists():
        print(
            f"ERRO: {MANIFESTO_PATH} não existe — rode `python bench/limpo/baixar.py` primeiro.",
            file=sys.stderr,
        )
        return 2
    manifesto = json.loads(MANIFESTO_PATH.read_text(encoding="utf-8"))

    caminho_resultado = Path(argv[0]) if argv else BASE / ".cache" / "resultado.json"
    if not caminho_resultado.exists():
        print(
            f"ERRO: {caminho_resultado} não existe — rode `guardiao scan "
            f"{manifesto.get('repos_dir')} -f json -o {caminho_resultado} --fail-on none` primeiro.",
            file=sys.stderr,
        )
        return 2
    resultado_json = json.loads(caminho_resultado.read_text(encoding="utf-8"))

    avaliacao, fp_mil = avaliar(manifesto, resultado_json)
    imprimir(manifesto, avaliacao, fp_mil)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

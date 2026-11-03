"""Mede o Guardião contra o CredData — credenciais REAIS, rotuladas por
humanos em repositórios públicos, em vez dos fixtures plantados de
`bench/avaliar.py`. Estende aquele script (que só media recall e precisão)
com F1, contagens absolutas e a proveniência que falta para o número ser
reproduzível.

Uso:
    python bench/creddata/baixar.py [--max-repos N]
    guardiao scan bench/creddata/.cache/data -f json -o bench/creddata/.cache/resultado.json
    python bench/creddata/avaliar.py bench/creddata/.cache/resultado.json

Como as três classes do CredData (`T`/`F`/`X`) entram na métrica — e por quê:

* **T** (credencial real): o universo do RECALL. Uma linha `T` sem achado é
  falso-negativo.
* **F** ("parece mas não é"): o universo da PRECISÃO. Um achado numa linha
  `F` é falso-positivo — por definição do próprio rótulo, não há credencial
  ali.
* **X** (teste/exemplo/placeholder, "Unknown/Other" no README do CredData):
  EXCLUÍDO do numerador e do denominador de ambas. Contar como positivo
  inflaria recall sobre linha que o próprio dataset admite não ser uma
  credencial real; contar como negativo puniria o Guardião por sinalizar
  algo que PARECE credencial e que, em produção, continua valendo a pena
  mostrar para um humano decidir. Reportado à parte, nunca escondido.
* Achado fora de QUALQUER linha rotulada: o CredData rotulou só 73 mil das
  19 milhões de linhas do corpus (as que alguma bateria anterior já havia
  suspeitado) — a maioria do corpus nunca foi revisada por humano. Contar
  isto como falso-positivo seria "não medi" travestido de "medi e está
  errado"; por isso fica num balde à parte, nunca entra em TP/FP/FN.

Achados são deduplicados por `(arquivo, linha)` antes de classificar: duas
regras do Guardião acertando a MESMA linha contam como um único sinal, não
dois — a métrica mede "a linha foi sinalizada?", não "quantas regras
bateram?".
"""

from __future__ import annotations

import json
import math
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    from bench.creddata.baixar import (  # type: ignore[import-not-found]
        MANIFESTO_PATH,
        LinhaRotulada,
        ler_meta,
    )
except ImportError:
    # Executado como script direto (`python bench/creddata/avaliar.py`): o próprio
    # diretório do arquivo já está no `sys.path`, então o nome sem pacote resolve.
    from baixar import (  # type: ignore[import-not-found,no-redef]
        MANIFESTO_PATH,
        LinhaRotulada,
        ler_meta,
    )

BASE = Path(__file__).resolve().parent

LABEL_TRUE = "T"
LABEL_FALSE = "F"
LABEL_OTHER = "X"


def normaliza(caminho: object) -> str:
    """Reduz um caminho ao formato `data/...` — o mesmo que `FilePath` grava no
    CSV do CredData (ver `baixar.py`).

    O Guardião reporta caminho relativo à RAIZ varrida (`DATA_DIR`), então o
    achado chega como `<repo>/<escopo>/<arquivo>` — sem o prefixo `data/`. Um
    caminho absoluto (ex.: `guardiao scan` com raiz diferente) ainda é tratado:
    corta a partir do PRIMEIRO `/data/` (com barra dos dois lados — sem isto,
    `.../bench/creddata/.cache/data/...` cortaria errado: `creddata/` já
    contém `data/` como substring, mas não `/data/`).
    """
    texto = str(caminho).replace(chr(92), "/")
    marcador = "/data/"
    if marcador in texto:
        return "data/" + texto.split(marcador, 1)[1]
    texto = texto.lstrip("/")
    if texto.startswith("data/"):
        return texto
    return "data/" + texto


def wilson(acertos: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Intervalo de confiança de Wilson — honesto para amostra pequena (mesma
    fórmula de `bench/avaliar.py`, que `bench/` ainda não expõe como módulo)."""
    if total == 0:
        return (0.0, 0.0)
    p = acertos / total
    denom = 1 + z * z / total
    centro = (p + z * z / (2 * total)) / denom
    margem = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return (max(0.0, centro - margem), min(1.0, centro + margem))


@dataclass(frozen=True)
class Avaliacao:
    tp: int
    fp: int
    fn: int
    total_t: int
    total_f: int
    total_x: int
    achados_ambiguos_x: int
    achados_fora_do_rotulado: int


def classificar(achados: list[tuple[str, int]], linhas_rotuladas: list[LinhaRotulada]) -> Avaliacao:
    """Classifica achados contra o rótulo de verdade do CredData.

    `achados` já deve vir deduplicado por `(arquivo, linha)` — ver docstring
    do módulo sobre por que a dedupe acontece antes desta função, não dentro
    dela (quem chama decide a política de dedupe; esta função só classifica).
    """
    por_arquivo: dict[str, list[LinhaRotulada]] = {}
    for linha in linhas_rotuladas:
        por_arquivo.setdefault(linha.file_path, []).append(linha)

    rotuladas_t = [r for r in linhas_rotuladas if r.ground_truth == LABEL_TRUE]
    total_f = sum(1 for r in linhas_rotuladas if r.ground_truth == LABEL_FALSE)
    total_x = sum(1 for r in linhas_rotuladas if r.ground_truth == LABEL_OTHER)

    def cobre(linha_meta: LinhaRotulada, numero_linha: int) -> bool:
        return linha_meta.line_start <= numero_linha <= linha_meta.line_end

    tp = sum(
        1
        for r in rotuladas_t
        if any(arquivo == r.file_path and cobre(r, linha) for arquivo, linha in achados)
    )
    fn = len(rotuladas_t) - tp

    fp = 0
    ambiguos = 0
    fora = 0
    for arquivo, numero_linha in achados:
        candidatas = por_arquivo.get(arquivo, [])
        rotulos_batidos = {r.ground_truth for r in candidatas if cobre(r, numero_linha)}
        if LABEL_TRUE in rotulos_batidos:
            continue  # já contabilizado em TP acima
        elif LABEL_FALSE in rotulos_batidos:
            fp += 1
        elif LABEL_OTHER in rotulos_batidos:
            ambiguos += 1
        else:
            fora += 1

    return Avaliacao(
        tp=tp,
        fp=fp,
        fn=fn,
        total_t=len(rotuladas_t),
        total_f=total_f,
        total_x=total_x,
        achados_ambiguos_x=ambiguos,
        achados_fora_do_rotulado=fora,
    )


def _commit_guardiao() -> str | None:
    try:
        resultado = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=BASE,
            capture_output=True,
            text=True,
            check=True,
        )
        return resultado.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def avaliar(manifesto: dict[str, object], resultado_json: dict[str, object]) -> Avaliacao:
    amostra = manifesto["amostra"]
    assert isinstance(amostra, dict)

    linhas_rotuladas: list[LinhaRotulada] = []
    for repo_id in amostra:
        linhas_rotuladas.extend(ler_meta(repo_id))

    brutos = resultado_json.get("achados") or resultado_json.get("findings") or []
    assert isinstance(brutos, list)
    achados_crus = [
        (normaliza(a.get("path") or a.get("arquivo") or ""), a.get("line") or a.get("linha") or 0)
        for a in brutos
    ]
    # Dedupe por (arquivo, linha): ver docstring do módulo.
    achados = sorted(set(achados_crus))

    return classificar(achados, linhas_rotuladas)


def imprimir(manifesto: dict[str, object], avaliacao: Avaliacao, caminho_resultado: Path) -> None:
    tp, fp, fn = avaliacao.tp, avaliacao.fp, avaliacao.fn
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precisao = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precisao * recall / (precisao + recall) if (precisao + recall) else 0.0
    recall_baixo, recall_alto = wilson(tp, tp + fn)
    precisao_baixo, precisao_alto = wilson(tp, tp + fp)

    max_repos = manifesto.get("max_repos")
    data_dir = manifesto.get("data_dir", "bench/creddata/.cache/data")

    print("== CredData (Samsung) — dado real, não plantado ==")
    print(
        f"  dataset        : CredData @ {manifesto['dataset_commit']} ({manifesto['dataset_url']})"
    )
    print(
        f"  amostra        : {manifesto['repos_baixados_com_sucesso']}/"
        f"{manifesto['repos_totais']} repositórios "
        f"({'TODOS' if max_repos is None else f'--max-repos {max_repos}'})"
    )
    commit_guardiao = _commit_guardiao()
    if commit_guardiao:
        print(f"  guardião       : commit {commit_guardiao}")
    print()
    print(f"  TP (achou T)   : {tp}/{avaliacao.total_t}")
    print(f"  FN (perdeu T)  : {fn}/{avaliacao.total_t}")
    print(f"  FP (achou F)   : {fp}/{avaliacao.total_f}")
    print(f"  RECALL         : {recall:.0%}   IC95% = [{recall_baixo:.0%} ; {recall_alto:.0%}]")
    print(
        f"  PRECISÃO       : {precisao:.0%}   IC95% = [{precisao_baixo:.0%} ; {precisao_alto:.0%}]"
    )
    print(f"  F1             : {f1:.0%}")
    print()
    print("  Tratamento das classes (ground rules do CredData):")
    print(
        f"    X (teste/exemplo/placeholder): {avaliacao.total_x} linha(s) rotulada(s), "
        f"{avaliacao.achados_ambiguos_x} achado(s) sobre elas — EXCLUÍDOS de TP/FP/FN "
        "(ver docstring deste módulo)."
    )
    print(
        f"    fora do conjunto rotulado: {avaliacao.achados_fora_do_rotulado} achado(s) em linha "
        "que o CredData nunca revisou — não contável como FP (não ter rótulo não é ter rótulo "
        "negativo), reportado só aqui."
    )
    print()
    print("  Comando de reprodução:")
    sufixo = f" --max-repos {max_repos}" if max_repos is not None else ""
    print(f"    python bench/creddata/baixar.py{sufixo}")
    print(f"    guardiao scan {data_dir} -f json -o {caminho_resultado}")
    print(f"    python bench/creddata/avaliar.py {caminho_resultado}")


def main(argv: list[str]) -> int:
    if not MANIFESTO_PATH.exists():
        print(
            f"ERRO: {MANIFESTO_PATH} não existe — rode `python bench/creddata/baixar.py` primeiro.",
            file=sys.stderr,
        )
        return 2
    manifesto = json.loads(MANIFESTO_PATH.read_text(encoding="utf-8"))

    caminho_resultado = Path(argv[0]) if argv else BASE / ".cache" / "resultado.json"
    if not caminho_resultado.exists():
        print(
            f"ERRO: {caminho_resultado} não existe — rode "
            f"`guardiao scan {manifesto.get('data_dir')} -f json -o {caminho_resultado}` primeiro.",
            file=sys.stderr,
        )
        return 2
    resultado_json = json.loads(caminho_resultado.read_text(encoding="utf-8"))

    avaliacao = avaliar(manifesto, resultado_json)
    imprimir(manifesto, avaliacao, caminho_resultado)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

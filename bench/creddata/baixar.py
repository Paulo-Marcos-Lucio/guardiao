"""Baixa o CredData (Samsung) — corpus de credenciais reais, rotuladas por
humanos em repositórios públicos do GitHub — para avaliar o Guardião contra
dado que ninguém aqui plantou.

Por que não existe sem isto ainda. `bench/positivos`/`bench/negativos` medem
*cobertura de formato conhecido*: os 28 casos foram escritos por quem fez a
ferramenta, então um recall alto ali prova só que a regra cobre o exemplo que
o próprio autor pensou. CredData (<https://github.com/Samsung/CredData>) é o
oposto: centenas de repositórios reais (o `README.md` do CredData fala em 297;
o `snapshot.json` do commit fixado por este script já tem 337 — o dataset
cresceu desde a última vez que o README citou um número; `avaliar.py` sempre
imprime o total medido AGORA, nunca um número copiado daquele parágrafo),
com linhas revisadas manualmente por terceiros e rotuladas `T` (credencial
real), `F` (parece mas não é) ou `X` (teste/exemplo/placeholder) — ver a
seção "Ground Rules for Labeling" do `README.md` do CredData.

Como o dataset é recuperado. O CredData não versiona os arquivos de código em
si (seriam credenciais reais de terceiros, e o volume é de GBs); versiona só
metadado: `meta/<id>.csv` (arquivo, linha, rótulo, span do valor) e
`snapshot.json` (`sha256(commit+url) -> url`). `FilePath` no CSV já é o
caminho de DESTINO (`data/<repo>/<escopo>/<file_id><ext>`); o que falta é
achar, dentro do clone do repositório original, qual arquivo tem aquele
`FileID` — e `FileID = sha256(caminho_relativo_no_repo)[:8]`. Não existe uma
tabela caminho→arquivo pronta: é por isso que um clone de cada repositório é
inerente ao formato do dataset, não escolha deste script.

Por que a lógica é REIMPLEMENTADA aqui, não importada do clone do CredData.
O CredData publica um script de referência (`download_data.py` +
`obfuscate_creds.py`) que faz exatamente isto — mas é código Python de
terceiro, baixado dinamicamente, e este ambiente não executa código que
chegou assim (barreira de sandbox, não escolha deste item). O algoritmo em si
é curto e está documentado em prosa no próprio README; a reimplementação
abaixo segue essa descrição pública, não o arquivo — a mesma régua já usada
em `tools/gerar_bpe.py` (G-07a) para outro dado que o repositório não podia
só baixar executável.

Ofuscação SIMPLIFICADA, não a do upstream — mas tem de preservar FORMATO, não
só esconder o valor. Uma primeira versão deste script trocava o valor `T`
inteiro por um marcador fixo (`"«MASCARADO»"`) — mais simples de auditar, mas
mediu recall **zero** em qualquer amostra: a maioria das regras do Guardião
detecta por FORMATO (prefixo de provedor, `ghp_`/`AKIA`/`sk_live_`…) ou por
entropia do corpo, e um marcador textual fixo não tem nenhum dos dois. Isso
não é uma amostra "difícil" — é a métrica medindo a própria ofuscação, não o
Guardião. A correção: preserva um PREFIXO curto do valor verbatim (onde mora
o formato reconhecível) e troca o CORPO por caracteres aleatórios da MESMA
classe (dígito→dígito, maiúscula→maiúscula, minúscula→minúscula, símbolo
mantido) — comprimento e "textura" sobrevivem, o valor real nunca sobrevive.
Linhas rotuladas `F`/`X` nunca são tocadas: por definição ("parece mas não é"
/ "teste, exemplo ou placeholder") não têm credencial real para mascarar.

Amostra, não dataset inteiro, por padrão neste ambiente. Baixar o corpus
inteiro (centenas de repositórios) é centenas de `git clone` reais — rede e
disco que um sandbox de CI não tem de sobra. `--max-repos N` baixa só os N
primeiros do `snapshot.json` (ordem estável: é um `dict` carregado de JSON,
preserva a ordem do arquivo) — uma amostra DECLARADA: o manifesto grava
exatamente quais repositórios entraram, para `avaliar.py` nunca reportar um
número sem dizer contra o quê foi medido. Omitir a flag baixa o corpus
inteiro.

Uso:
    python bench/creddata/baixar.py                  # o corpus inteiro
    python bench/creddata/baixar.py --max-repos 10    # amostra de 10
"""

from __future__ import annotations

import argparse
import binascii
import csv
import hashlib
import json
import random
import shutil
import string
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
CACHE_DIR = BASE / ".cache"
CREDDATA_DIR = CACHE_DIR / "CredData"
DATA_DIR = CACHE_DIR / "data"
MANIFESTO_PATH = CACHE_DIR / "manifesto.json"

CREDDATA_URL = "https://github.com/Samsung/CredData"
# Commit fixado: a mesma pergunta ("quantos achados reais?") precisa dar a mesma
# resposta hoje e em um ano — sem isto, o upstream pode reclassificar linhas ou
# trocar repositórios entre duas rodadas sem que ninguém perceba a mudança de piso.
CREDDATA_COMMIT = "c49ed10629d9139eb88b71b6b7ab4054fff806ea"

LABEL_TRUE = "T"
MARCADOR_LINHA = "# [bloco T mascarado pelo baixar.py]"
# Quantos caracteres do início do valor sobrevivem intactos: onde mora o prefixo
# de provedor que a maioria das regras de FORMATO do Guardião casa (`ghp_`=4,
# `sk_live_`=8, `AKIA`=4, `glpat-`=6, `xoxb-`=5, `SG.`=3…). Mascarar o corpo
# inteiro (inclusive o prefixo) mediria a ofuscação, não o Guardião — ver
# docstring do módulo.
PREFIXO_PRESERVADO = 8


@dataclass(frozen=True)
class LinhaRotulada:
    file_id: str
    file_path: str  # já é o destino: "data/<repo>/<escopo>/<file_id><ext>"
    line_start: int
    line_end: int
    ground_truth: str
    value_start: int | None
    value_end: int | None


def _rev_parse(repo_dir: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def clonar_creddata() -> None:
    """Garante o clone do CredData no commit fixado — clona só se preciso.

    O CredData é usado só como FONTE DE DADOS (``snapshot.json``,
    ``meta/*.csv``) — nenhum ``.py`` de dentro dele é executado.
    """
    if CREDDATA_DIR.exists():
        atual = _rev_parse(CREDDATA_DIR)
        if atual == CREDDATA_COMMIT:
            return
        raise RuntimeError(
            f"{CREDDATA_DIR} está no commit {atual}, não no fixado "
            f"{CREDDATA_COMMIT}. Remova o diretório (rm -rf {CREDDATA_DIR}) "
            "para reclonar."
        )
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "clone", CREDDATA_URL, str(CREDDATA_DIR)], check=True)
    subprocess.run(["git", "-C", str(CREDDATA_DIR), "checkout", CREDDATA_COMMIT], check=True)


def id_curto(repo_id: str) -> str:
    """CRC32 de 8 hex do `repo_id` (sha256 de 64 hex) — nome do `meta/<id>.csv`.

    Mesma fórmula publicada pelo CredData (`get_new_repo_id`); reimplementada
    aqui porque é só aritmética de biblioteca padrão (``binascii``), não um
    algoritmo de terceiro executado.
    """
    return f"{binascii.crc32(bytes.fromhex(repo_id)):08x}"


def ler_meta(repo_id: str) -> list[LinhaRotulada]:
    caminho = CREDDATA_DIR / "meta" / f"{id_curto(repo_id)}.csv"
    if not caminho.exists():
        return []
    linhas: list[LinhaRotulada] = []
    with open(caminho, encoding="utf-8", newline="") as fh:
        for linha in csv.DictReader(fh):
            linhas.append(
                LinhaRotulada(
                    file_id=linha["FileID"],
                    file_path=linha["FilePath"],
                    line_start=int(linha["LineStart"]),
                    line_end=int(linha["LineEnd"]),
                    ground_truth=linha["GroundTruth"],
                    value_start=int(linha["ValueStart"]) if linha["ValueStart"] else None,
                    value_end=int(linha["ValueEnd"]) if linha["ValueEnd"] else None,
                )
            )
    return linhas


def _clonar_repo_alvo(url: str, commit_sha: str, destino: Path) -> bool:
    """Clone raso do repositório ALVO (não o CredData) no commit fixado pelo
    `snapshot.json`. Retorna `False` (sem lançar) se o commit não existir mais
    no remoto — repositório real, pode ter sido reescrito ou apagado."""
    destino.mkdir(parents=True, exist_ok=True)
    passos = [
        ["git", "init", "-q"],
        ["git", "remote", "add", "origin", url],
        ["git", "fetch", "--depth", "1", "-q", "origin", commit_sha],
        ["git", "checkout", "-q", commit_sha],
    ]
    for passo in passos:
        resultado = subprocess.run(passo, cwd=destino, capture_output=True, text=True)
        if resultado.returncode != 0:
            return False
    return True


def _arquivos_do_clone(raiz: Path) -> dict[str, Path]:
    """Mapa `FileID -> caminho real` para TODO arquivo do clone — o FileID é
    `sha256(caminho_relativo_posix)[:8]`, calculado sobre o caminho, nunca o
    conteúdo."""
    mapa: dict[str, Path] = {}
    for caminho in raiz.rglob("*"):
        if not caminho.is_file() or caminho.is_symlink():
            continue
        relativo = caminho.relative_to(raiz).as_posix()
        if relativo.startswith(".git/"):
            continue
        file_id = hashlib.sha256(relativo.encode("utf-8")).hexdigest()[:8]
        mapa[file_id] = caminho
    return mapa


def _classe_de(caractere: str, rng: random.Random) -> str:
    """Troca `caractere` por outro aleatório da MESMA classe, EXCLUINDO o
    próprio caractere do sorteio — sem isto, um corpo de 1-2 dígitos tem
    chance real (1/10, 1/100…) de "sortear" de volta o valor original.
    Símbolo/espaço preservado (é estrutura: `-`, `_`, `.`, espaço — não
    segredo)."""
    if caractere.isupper():
        return rng.choice([c for c in string.ascii_uppercase if c != caractere])
    if caractere.islower():
        return rng.choice([c for c in string.ascii_lowercase if c != caractere])
    if caractere.isdigit():
        return rng.choice([c for c in string.digits if c != caractere])
    return caractere


def _valor_similar(original: str, semente: int) -> str:
    """Mesmo comprimento e classe de caractere por posição, prefixo curto
    preservado — ver `PREFIXO_PRESERVADO` e a docstring do módulo sobre por
    quê. Nunca preserva o valor inteiro, mesmo um valor curto."""
    rng = random.Random(semente)
    n = len(original)
    prefixo = min(PREFIXO_PRESERVADO, max(0, n - 2))
    corpo = "".join(_classe_de(c, rng) for c in original[prefixo:])
    return original[:prefixo] + corpo


def _semente(linha_meta: LinhaRotulada) -> int:
    """Determinística por linha rotulada: a mesma entrada produz o mesmo
    valor sintético numa reexecução — relevante para depurar um achado
    específico sem o dataset mudar sob os pés de quem está olhando."""
    base = int(linha_meta.file_id, 16) ^ linha_meta.line_start ^ (linha_meta.value_start or 0)
    return base & 0xFFFFFFFF


def _redigir_true(destino: Path, linhas_do_arquivo: list[LinhaRotulada]) -> None:
    """Mascara todo valor `T` do arquivo — a única classe que o `README` do
    CredData garante ser uma credencial real. `F`/`X` nunca são tocadas."""
    try:
        texto = destino.read_text(encoding="utf-8")
    except (UnicodeDecodeError, ValueError):
        # Arquivo binário: não há linha de texto para mascarar com segurança —
        # sem isto, um PEM corrompido pelo split de linhas seria pior que não tocar.
        return
    linhas = texto.split("\n")
    for linha_meta in linhas_do_arquivo:
        if linha_meta.ground_truth != LABEL_TRUE:
            continue
        inicio_idx = linha_meta.line_start - 1
        fim_idx = linha_meta.line_end - 1
        if not (0 <= inicio_idx <= fim_idx < len(linhas)):
            continue
        if (
            inicio_idx == fim_idx
            and linha_meta.value_start is not None
            and linha_meta.value_end is not None
            and 0 <= linha_meta.value_start < linha_meta.value_end <= len(linhas[inicio_idx])
        ):
            # Span preciso de uma linha: troca só o valor por outro do mesmo
            # formato, preserva o resto da linha (nome da variável/chave
            # continua contexto real para o detector julgar).
            original = linhas[inicio_idx]
            valor = original[linha_meta.value_start : linha_meta.value_end]
            linhas[inicio_idx] = (
                original[: linha_meta.value_start]
                + _valor_similar(valor, _semente(linha_meta))
                + original[linha_meta.value_end :]
            )
        elif inicio_idx < fim_idx:
            # Span multilinha (ex.: chave PEM): header/footer (`-----BEGIN...`)
            # são estrutura, não segredo, e é ONDE a regra de formato bate —
            # mascarados, nenhuma regra de "chave privada" sobraria para medir.
            # Preserva as duas pontas do bloco, troca só as linhas do meio.
            for i in range(inicio_idx + 1, fim_idx):
                linhas[i] = _valor_similar(linhas[i], _semente(linha_meta) ^ i)
        else:
            # Multilinha sem posição exata de valor: não há span para recortar
            # com segurança — mascara o bloco inteiro (preserva a CONTAGEM de
            # linhas, para não deslocar outra linha rotulada no mesmo arquivo).
            for i in range(inicio_idx, fim_idx + 1):
                linhas[i] = MARCADOR_LINHA
    destino.write_text("\n".join(linhas), encoding="utf-8")


def _baixar_um_repo(repo_id: str, url: str, linhas_meta: list[LinhaRotulada]) -> tuple[int, int]:
    """Baixa um repositório, recupera os arquivos rotulados e os ofusca.

    Retorna `(arquivos_recuperados, arquivos_ausentes)`.
    """
    commit_sha = repo_id[:40]
    por_arquivo: dict[str, list[LinhaRotulada]] = {}
    for linha in linhas_meta:
        por_arquivo.setdefault(linha.file_id, []).append(linha)

    with tempfile.TemporaryDirectory(prefix="creddata-repo-") as tmp:
        clone_dir = Path(tmp) / "repo"
        if not _clonar_repo_alvo(url, commit_sha, clone_dir):
            return 0, len(por_arquivo)

        encontrados = _arquivos_do_clone(clone_dir)
        recuperados = 0
        for file_id, linhas_do_arquivo in por_arquivo.items():
            origem = encontrados.get(file_id)
            if origem is None:
                continue
            destino_relativo = linhas_do_arquivo[0].file_path.removeprefix("data/")
            destino = DATA_DIR / destino_relativo
            destino.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(origem, destino)
            _redigir_true(destino, linhas_do_arquivo)
            recuperados += 1

    return recuperados, len(por_arquivo) - recuperados


def baixar(max_repos: int | None) -> dict[str, object]:
    """Baixa o CredData (ou uma amostra) para `DATA_DIR` e grava o manifesto.

    Retorna o manifesto escrito — `avaliar.py` o lê de volta do disco para
    declarar exatamente contra o que a medição rodou.
    """
    clonar_creddata()

    with open(CREDDATA_DIR / "snapshot.json", encoding="utf-8") as fh:
        snapshot_completo: dict[str, str] = json.load(fh)

    # dict preserva ordem de inserção (= ordem do JSON): a amostra é determinística,
    # não um corte arbitrário que mudaria a cada execução.
    amostra = (
        dict(list(snapshot_completo.items())[:max_repos])
        if max_repos is not None
        else snapshot_completo
    )
    if not amostra:
        raise ValueError("amostra vazia — `--max-repos` precisa ser >= 1")

    if DATA_DIR.exists():
        shutil.rmtree(DATA_DIR)
    DATA_DIR.mkdir(parents=True)

    repos_ok: dict[str, str] = {}
    repos_sem_commit: list[str] = []
    total_recuperados = 0
    total_ausentes = 0
    for repo_id, url in amostra.items():
        linhas_meta = ler_meta(repo_id)
        if not linhas_meta:
            continue
        recuperados, ausentes = _baixar_um_repo(repo_id, url, linhas_meta)
        total_recuperados += recuperados
        total_ausentes += ausentes
        if recuperados == 0 and ausentes > 0:
            repos_sem_commit.append(f"{url}@{repo_id[:40]}")
        else:
            repos_ok[repo_id] = url

    manifesto: dict[str, object] = {
        "dataset_commit": CREDDATA_COMMIT,
        "dataset_url": CREDDATA_URL,
        "repos_totais": len(snapshot_completo),
        "repos_na_amostra": len(amostra),
        "repos_baixados_com_sucesso": len(repos_ok),
        "repos_sem_commit_disponivel": repos_sem_commit,
        "max_repos": max_repos,
        "amostra": repos_ok,
        "arquivos_recuperados": total_recuperados,
        "arquivos_ausentes": total_ausentes,
        "data_dir": str(DATA_DIR),
        "ofuscacao": (
            "simplificada (marcador fixo por valor T de uma linha; bloco inteiro "
            "mascarado quando o span é multilinha) — NÃO é o algoritmo do "
            "`obfuscate_creds.py` do CredData, ver docstring do módulo"
        ),
        "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    MANIFESTO_PATH.write_text(json.dumps(manifesto, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifesto


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--max-repos",
        type=int,
        default=None,
        help="baixa só os N primeiros repositórios do snapshot (padrão: todos)",
    )
    args = parser.parse_args(argv)

    manifesto = baixar(max_repos=args.max_repos)
    print(
        f"OK: {manifesto['repos_baixados_com_sucesso']}/{manifesto['repos_na_amostra']} "
        f"repositório(s) baixados, {manifesto['arquivos_recuperados']} arquivo(s) "
        f"recuperados (CredData @ {str(manifesto['dataset_commit'])[:12]}) em {DATA_DIR}"
    )
    if manifesto["repos_sem_commit_disponivel"]:
        print(f"AVISO: sem commit disponível: {manifesto['repos_sem_commit_disponivel']}")
    print(f"Manifesto: {MANIFESTO_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

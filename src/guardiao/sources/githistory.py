"""Fonte de dados: histórico do Git.

Remover um segredo do código não o remove do histórico — ele continua acessível
em commits antigos. Esta fonte varre **todos os blobs** já existentes no
repositório, justamente onde segredos esquecidos costumam permanecer, mais as
**mensagens de commit e de tag anotada** (texto versionado que nenhum `git rm`
alcança e onde a credencial cai colada junto do comando que a usou).

Desempenho: um único ``git cat-file --batch --batch-all-objects`` transmite o
conteúdo de todos os objetos por streaming, em vez de dois subprocessos por
objeto — ordens de magnitude mais rápido em repositórios grandes. O conteúdo de
objeto que não interessa (commit, tree, blob acima do limite) é **descartado em
fluxo**: o pico de memória é O(limite), não O(maior objeto do repositório).
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from guardiao.sources.files import decode_text_bytes

_BLOCO = 65536

#: Timeout (s) para os comandos de git de vida-curta (rev-parse/rev-list). Um repo
#: lento/malicioso não pode travar a varredura para sempre — falha alto por timeout.
_GIT_TIMEOUT_S = 120


def _git_env() -> dict[str, str]:
    """Ambiente que impede o git de BLOQUEAR à espera de entrada humana.

    ``GIT_TERMINAL_PROMPT=0`` e o askpass silencioso garantem que qualquer prompt de
    credencial (ex.: um repo com remote/submódulo que tente autenticar) vire erro
    imediato em vez de um travamento indefinido esperando no terminal.
    """
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = env.get("GIT_ASKPASS", "echo")
    env["GCM_INTERACTIVE"] = "never"
    return env


#: Tipos de objeto cujo conteúdo é varrido. ``tree`` fica de fora (é só estrutura);
#: ``commit`` e ``tag`` entram pela MENSAGEM — segredo em mensagem de commit é comum
#: e nenhum `git rm` o remove.
_TIPOS_VARRIDOS = frozenset({"blob", "commit", "tag"})


class GitError(RuntimeError):
    """Falha ao interagir com o Git."""


def _mensagem_do_objeto(bruto: str) -> str:
    """Extrai só a MENSAGEM de um objeto commit/tag, sem os cabeçalhos.

    Cabeçalho (``tree``, ``parent``, ``author``, ``tagger``…) é metadado do objeto:
    varrê-lo encheria o laudo de ruído e de PII de quem commitou. A separação é a
    primeira linha em branco — inclusive quando há ``gpgsig``, cujas linhas de
    continuação começam com espaço e por isso nunca formam uma linha vazia de verdade.
    """
    _, separador, mensagem = bruto.partition("\n\n")
    return mensagem if separador else ""


@dataclass(frozen=True)
class Blob:
    sha: str
    path: str
    text: str


def _e_clone(repo: Path) -> bool:
    """O repositório tem origem remota — ou seja, foi obtido por ``git clone``/``fetch``?

    É a pergunta possível: não existe jeito de saber o que a origem tem e não foi
    transferido. Ter ``remote.origin.url`` basta para o aviso ser verdadeiro, porque
    nenhum objeto INALCANÇÁVEL da origem chega por protocolo — nem com ``--mirror``.
    """
    origem = _run(repo, "config", "--get", "remote.origin.url")
    return origem.ok and bool(origem.out.strip())


#: A URL do remoto NÃO entra nesta mensagem de propósito: usuário e token embutidos na
#: URL (o formato `basic-auth-url`, que este mesmo scanner detecta) são a forma mais
#: comum de credencial em config de CI — a ferramenta que procura segredo vazado não
#: pode publicar um no próprio laudo.
AVISO_CLONE = (
    "Cobertura limitada: este repositório é um clone. `git clone`/`fetch` transferem "
    "apenas objetos ALCANÇÁVEIS, então o que existir solto só na origem — blob de "
    "`commit --amend`, rebase, branch deletado, stash — nunca chegou aqui e não foi "
    "varrido (medido em auditoria: 7 achados no repositório original → 2 no clone). "
    "Para alcance total, rode o --git-history no próprio repositório de origem ou numa "
    "cópia feita por arquivo (`cp -a`, `git clone --local`), que preserva os objetos "
    "soltos. Isto é uma declaração de limite, não um erro: nada aqui invalida o que foi "
    "varrido."
)


def iter_history_blobs(
    repo: Path,
    *,
    max_bytes: int = 5_000_000,
    skipped: dict[str, int] | None = None,
    permitir_shallow: bool = False,
    avisos: list[str] | None = None,
) -> Iterator[Blob]:
    """Itera pelos blobs versionados em qualquer ponto da história.

    ``avisos`` (opcional) acumula limites de ALCANCE conhecidos — o que a varredura
    sabidamente não pôde ver. Diferente de ``skipped``, que conta o que foi pulado.
    """
    repo = Path(repo)
    contador = {} if skipped is None else skipped
    declarados = [] if avisos is None else avisos

    # 0) Clone raso só contém os commits baixados: varrer "todo o histórico" nele é
    #    uma promessa falsa. Falha fechado — o CI precisa saber que não olhou tudo.
    shallow = _run(repo, "rev-parse", "--is-shallow-repository")
    if not permitir_shallow and shallow.ok and shallow.out.strip() == "true":
        raise GitError(
            "repositório clonado raso (shallow): o --git-history só enxergaria os commits "
            "já baixados. Em GitHub Actions use actions/checkout com fetch-depth: 0, ou "
            "passe --permitir-shallow para varrer assim mesmo."
        )

    # 0b) Clone COMPLETO não falha — declara. O raso acima é uma promessa quebrada
    #     (o usuário pediu "todo o histórico" e nem os commits estão lá); aqui a
    #     varredura é honesta dentro do que existe no disco, e travar o CI do cliente
    #     por um limite do protocolo do git seria trocar um erro por outro.
    if _e_clone(repo):
        declarados.append(AVISO_CLONE)

    # 0c) NOMES de ref (branch/tag) — um segredo colado no nome de um branch
    #     (`hotfix/token-ghp_…`) ou de uma tag leve vive só em `refs/`, não em blob nem
    #     em mensagem: nenhuma das varreduras abaixo o alcança. O NOME vai no texto (que
    #     o preview oculta); o caminho é genérico para o próprio laudo não vazar o segredo.
    refs = _run(repo, "for-each-ref", "--format=%(refname)")
    if refs.ok:
        for refname in refs.out.splitlines():
            refname = refname.strip()
            if refname:
                yield Blob(sha="", path="<nome de branch/tag>", text=refname)

    # 1) Mapa sha->path (o primeiro caminho visto para cada blob). Uma chamada só.
    listing = _run(repo, "rev-list", "--objects", "--all")
    if not listing.ok:
        raise GitError(listing.err.strip() or "git rev-list falhou")
    paths: dict[str, str] = {}
    for line in listing.out.splitlines():
        sha, _, path = line.partition(" ")
        if path:
            paths.setdefault(sha, path)

    # 2) Um processo persistente streamando todos os objetos.
    try:
        proc = subprocess.Popen(
            ["git", "cat-file", "--batch", "--batch-all-objects", "--buffer"],
            cwd=str(repo),
            stdin=subprocess.DEVNULL,  # nunca enviamos requisições: EOF imediato, sem travar
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_git_env(),
        )
    except (OSError, ValueError) as exc:  # pragma: no cover - git ausente
        raise GitError(str(exc)) from exc

    stdout = proc.stdout
    if stdout is None:  # pragma: no cover - defensivo
        raise GitError("git cat-file não abriu stdout")

    completou = False
    try:
        while True:
            header = stdout.readline()
            if not header:
                completou = True  # EOF natural do stream: o cat-file terminou de emitir
                break
            parts = header.decode("utf-8", "replace").split()
            if len(parts) < 3:
                continue  # "<sha> missing" ou linha inesperada
            sha, otype, size_str = parts[0], parts[1], parts[2]
            try:
                size = int(size_str)
            except ValueError:  # pragma: no cover - saída inesperada
                continue

            # Decidir ANTES de ler: um blob de 100 MB não pode virar 100 MB de RAM
            # só para ser descartado pelo limite logo depois.
            if otype not in _TIPOS_VARRIDOS or size > max_bytes:
                _descartar(stdout, size)
                stdout.read(1)
                if otype in _TIPOS_VARRIDOS:
                    contador["tamanho"] = contador.get("tamanho", 0) + 1
                continue

            content = _read_exact(stdout, size)
            stdout.read(1)  # newline após o conteúdo
            # Mesma decodificação da árvore de trabalho: um blob UTF-16/UTF-32 (config
            # .NET, script do PowerShell) NÃO pode ser descartado como binário só pelos
            # NUL de intercalação — senão o segredo no histórico passa batido.
            text = decode_text_bytes(content)
            if text is None:
                contador["binario"] = contador.get("binario", 0) + 1
                continue
            if otype != "blob":
                # Mensagem de commit/tag é conteúdo versionado como qualquer outro, e
                # é onde a credencial cai quando alguém cola o comando que rodou
                # ("subi com a chave X") ou as notas de release.
                mensagem = _mensagem_do_objeto(text)
                if mensagem.strip():
                    rotulo = "do commit" if otype == "commit" else "da tag"
                    yield Blob(sha=sha[:12], path=f"<mensagem {rotulo} {sha[:12]}>", text=mensagem)
                continue
            # Blob sem caminho conhecido = objeto **solto** (o que sobra de um
            # `commit --amend`, `rebase` ou `reset`): é justamente onde o segredo
            # "removido" continua vivo. Descartá-lo esvaziava o cenário-assinatura.
            yield Blob(
                sha=sha[:12],
                path=paths.get(sha) or f"<objeto solto {sha[:12]}>",
                text=text,
            )
    finally:
        stdout.close()
        returncode = proc.wait()

    # FALHA ALTO em vez de vazio silencioso: se o `git cat-file` terminou com erro
    # (objeto corrompido que ele não conseguiu pular, I/O do repositório), o histórico
    # varrido está INCOMPLETO. Sem esta guarda, um erro do git a meio do streaming
    # viraria "0 achado, exit 0" e o gate de CI passaria falso. Só dispara após o
    # streaming terminar por completo (EOF) — nunca quando o consumidor abandona cedo.
    if completou and returncode not in (0, None):
        raise GitError(
            f"git cat-file terminou com código {returncode}: o histórico pode ter sido "
            "varrido de forma incompleta (objeto corrompido ou erro de I/O no repositório)."
        )


def _descartar(stream: IO[bytes], n: int) -> None:
    """Consome ``n`` bytes sem materializá-los.

    O consumo é obrigatório: pular bytes dessincronizaria o protocolo do
    ``--batch``. O ``if not chunk: return`` é o que evita laço infinito no EOF.
    """
    while n > 0:
        chunk = stream.read(min(n, _BLOCO))
        if not chunk:
            return
        n -= len(chunk)


def _read_exact(stream: IO[bytes], n: int) -> bytes:
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# --------------------------------------------------------------------------- #
# helper de subprocess (texto)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Result:
    ok: bool
    out: str
    err: str


def _run(repo: Path, *args: str) -> _Result:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(repo),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            stdin=subprocess.DEVNULL,
            env=_git_env(),
            timeout=_GIT_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        # Falha ALTO: um repo que trava o git por >2min não pode virar "0 achado".
        return _Result(False, "", f"git {args[0]} excedeu o tempo limite de {_GIT_TIMEOUT_S}s")
    except (OSError, ValueError) as exc:  # pragma: no cover - git ausente
        return _Result(False, "", str(exc))
    return _Result(proc.returncode == 0, proc.stdout, proc.stderr)

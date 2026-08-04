from __future__ import annotations

import shutil
import subprocess
import tracemalloc
from pathlib import Path

import pytest

from guardiao.core.config import Config
from guardiao.core.engine import Scanner
from guardiao.sources import githistory
from guardiao.sources.githistory import GitError, iter_history_blobs
from tests.conftest import AWS_KEY_ID, GH_TOKEN, SENHA_DE_PRODUCAO

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git não disponível")


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


def _repo(tmp_path: Path, nome: str = "repo") -> Path:
    repo = tmp_path / nome
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    return repo


def test_secret_removed_from_tree_still_found_in_history(tmp_path: Path) -> None:
    repo = _repo(tmp_path)

    leaked = repo / "config.py"
    leaked.write_text(f'AWS_KEY = "{AWS_KEY_ID}"\n', encoding="utf-8")
    _git(repo, "add", "config.py")
    _git(repo, "commit", "-m", "add config (com segredo)")

    # "remove" o segredo do código atual
    leaked.write_text("AWS_KEY = os.environ['AWS_KEY']\n", encoding="utf-8")
    _git(repo, "add", "config.py")
    _git(repo, "commit", "-m", "remove segredo do código")

    # a árvore atual está limpa...
    assert Scanner().scan_paths([repo]).findings == []

    # ...mas o histórico ainda entrega o segredo
    history = Scanner().scan_git_history(repo)
    aws = [f for f in history.findings if f.rule_id == "aws-access-key-id"]
    assert aws, "segredo não encontrado no histórico"
    assert aws[0].location.commit is not None


def test_blob_solto_de_commit_amend_e_varrido(tmp_path: Path) -> None:
    """`git commit --amend` é o jeito mais comum de "tirar" um segredo já commitado.
    O blob antigo continua no repositório, mas `rev-list --objects --all` não o
    lista — descartar blob sem caminho conhecido esvaziava o cenário-assinatura
    da ferramenta e devolvia "✓ Nenhum segredo encontrado"."""
    repo = _repo(tmp_path)
    alvo = repo / "config.py"
    alvo.write_text(f'AWS_KEY = "{AWS_KEY_ID}"\n', encoding="utf-8")
    _git(repo, "add", "config.py")
    _git(repo, "commit", "-m", "ops")
    alvo.write_text("AWS_KEY = os.environ['AWS_KEY']\n", encoding="utf-8")
    _git(repo, "add", "config.py")
    _git(repo, "commit", "--amend", "-m", "sem segredo")

    achados = Scanner().scan_git_history(repo).findings
    assert [f for f in achados if f.rule_id == "aws-access-key-id"], (
        "o blob órfão do --amend não foi varrido"
    )


def test_env_amendado_ainda_dispara_dotenv_assignment(tmp_path: Path) -> None:
    """Cenário-ASSINATURA do módulo: `.env` commitado por engano e "removido" com
    `--amend`. O blob órfão era lido, mas recebia o caminho sintético
    `<objeto solto SHA>`; `_rules_for` compara por nome de arquivo, `dotenv-assignment`
    era descartada, e o relatório voltava "nenhum segredo encontrado" — a regra que
    existe exatamente para esse formato nunca chegava a rodar."""
    repo = _repo(tmp_path)
    env = repo / ".env"
    env.write_text(f"APP_ENV=producao\nDB_PASSWORD={SENHA_DE_PRODUCAO}\n", encoding="utf-8")
    _git(repo, "add", ".env")
    _git(repo, "commit", "-m", "sobe .env por engano")
    env.write_text("APP_ENV=producao\nDB_PASSWORD=\n", encoding="utf-8")
    _git(repo, "add", ".env")
    _git(repo, "commit", "--amend", "-m", "sem segredo")

    achados = Scanner().scan_git_history(repo).findings

    dotenv = [f for f in achados if f.rule_id == "dotenv-assignment"]
    assert dotenv, "a regra .env sumiu no blob órfão (caminho sintético)"
    assert dotenv[0].secret == SENHA_DE_PRODUCAO


def test_blob_solto_de_codigo_nao_vira_dotenv(tmp_path: Path) -> None:
    """A heurística de conteúdo não pode transformar todo blob órfão em `.env`: código
    Python solto (`x = valor`, com espaços) continua fora do alcance da regra."""
    from guardiao.core.engine import _parece_dotenv

    assert not _parece_dotenv("senha = obter_senha()\nx = 1\n")
    assert not _parece_dotenv("")
    assert _parece_dotenv(f"APP_ENV=producao\nDB_PASSWORD={SENHA_DE_PRODUCAO}\n")


def test_historico_deduplica_o_mesmo_segredo_por_fingerprint(tmp_path: Path) -> None:
    """O MESMO segredo reaparece em todo commit que tocou o arquivo. Sem dedup, 3
    commits viravam 3 achados idênticos (na Bússola: 283 linhas ~= 64 vazamentos)."""
    repo = _repo(tmp_path)
    alvo = repo / "config.py"
    for i in range(3):
        alvo.write_text(f'# rev {i}\nAWS_KEY = "{AWS_KEY_ID}"\n', encoding="utf-8")
        _git(repo, "add", "config.py")
        _git(repo, "commit", "-m", f"c{i}")

    aws = [f for f in Scanner().scan_git_history(repo).findings if f.rule_id == "aws-access-key-id"]
    assert len(aws) == 1, "o mesmo segredo em 3 commits deve virar UM achado"
    assert aws[0].occurrences >= 3, "a contagem de recidivas some no relatório"
    assert aws[0].location.commit is not None and aws[0].commit_last is not None


def test_segredo_em_mensagem_de_commit_e_encontrado(tmp_path: Path) -> None:
    """Mensagem de commit é conteúdo versionado como qualquer outro — e é onde a
    credencial aparece quando alguém cola o comando que usou ("subi com a chave X").
    O streaming descartava tudo que não fosse blob, então esse texto nunca era lido."""
    repo = _repo(tmp_path)
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", f"deploy feito com a chave {AWS_KEY_ID}")

    achados = Scanner().scan_git_history(repo).findings

    aws = [f for f in achados if f.rule_id == "aws-access-key-id"]
    assert aws, "segredo na mensagem de commit não foi varrido"
    assert aws[0].location.path.startswith("<mensagem do commit ")


def test_segredo_em_tag_anotada_e_encontrado(tmp_path: Path) -> None:
    """Tag anotada é um objeto próprio, com mensagem própria — release notes coladas
    às pressas levam token junto."""
    repo = _repo(tmp_path)
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "release")
    _git(repo, "tag", "-a", "v1.0.0", "-m", f"publicado com {GH_TOKEN}")

    achados = Scanner().scan_git_history(repo).findings

    gh = [f for f in achados if f.rule_id == "github-token"]
    assert gh, "segredo na mensagem da tag anotada não foi varrido"
    assert gh[0].location.path.startswith("<mensagem da tag ")


def test_cabecalho_do_commit_nao_vira_conteudo(tmp_path: Path) -> None:
    """Só a MENSAGEM entra: `tree`, `parent`, autor e e-mail são metadado do objeto —
    varrê-los encheria o laudo de ruído (e de PII de quem commitou)."""
    repo = _repo(tmp_path)
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "commit limpo")

    unidades = [b for b in iter_history_blobs(repo) if b.path.startswith("<mensagem")]

    assert unidades
    assert all("test@example.com" not in b.text for b in unidades)
    assert all(not b.text.startswith("tree ") for b in unidades)


def test_clone_raso_falha_fechado(tmp_path: Path) -> None:
    """Num clone raso o `--git-history` só enxerga os commits baixados. Reportar
    sucesso nisso é prometer uma varredura que não aconteceu."""
    origem = _repo(tmp_path, "origem")
    for i in range(3):
        (origem / f"f{i}.py").write_text(f"x = {i}\n", encoding="utf-8")
        _git(origem, "add", ".")
        _git(origem, "commit", "-m", f"c{i}")
    raso = tmp_path / "raso"
    subprocess.run(
        ["git", "clone", "--depth", "1", origem.as_uri(), str(raso)],
        check=True,
        capture_output=True,
    )
    with pytest.raises(GitError, match="shallow"):
        list(iter_history_blobs(raso))
    # ...e há uma saída explícita para quem aceita o histórico incompleto
    assert list(iter_history_blobs(raso, permitir_shallow=True))


def test_clone_declara_limite_de_alcance(tmp_path: Path) -> None:
    """Clone RASO já falha fechado. O buraco era o clone COMPLETO: `git clone` sobre o
    protocolo transfere só objetos ALCANÇÁVEIS, então o blob órfão do `--amend` (o
    esconderijo mais comum) nunca chega — e a receita do README para CI
    (actions/checkout + fetch-depth: 0) cai exatamente nesse caso, com exit 0 e sem
    uma palavra. Inconclusivo não é ausência: aqui o laudo declara o que não alcançou.
    """
    origem = _repo(tmp_path, "origem")
    alvo = origem / "config.py"
    alvo.write_text(f'AWS_KEY = "{AWS_KEY_ID}"\n', encoding="utf-8")
    _git(origem, "add", ".")
    _git(origem, "commit", "-m", "ops")
    alvo.write_text("AWS_KEY = os.environ['AWS_KEY']\n", encoding="utf-8")
    _git(origem, "add", ".")
    _git(origem, "commit", "--amend", "-m", "sem segredo")

    clone = tmp_path / "clone"
    subprocess.run(  # `.as_uri()` força o protocolo: é o que o CI faz de verdade
        ["git", "clone", origem.as_uri(), str(clone)], check=True, capture_output=True
    )

    no_original = Scanner().scan_git_history(origem)
    no_clone = Scanner().scan_git_history(clone)

    # a perda é real e medida: o objeto solto não veio junto...
    assert [f for f in no_original.findings if f.rule_id == "aws-access-key-id"]
    assert not [f for f in no_clone.findings if f.rule_id == "aws-access-key-id"]
    # ...então o relatório do clone tem de DECLARAR o limite (sem travar o CI)
    assert no_clone.avisos_de_cobertura, "clone varrido em silêncio, como se fosse tudo"
    assert any("clone" in aviso.lower() for aviso in no_clone.avisos_de_cobertura)
    assert no_original.avisos_de_cobertura == [], "repo sem origem remota não tem esse limite"


def test_aviso_de_cobertura_nao_expoe_a_url_do_remoto(tmp_path: Path) -> None:
    """`remote.origin.url` costuma trazer credencial embutida
    (`https://usuario:token@host/...`). O aviso não pode publicar a origem no laudo —
    seria a ferramenta de vazamento vazando."""
    repo = _repo(tmp_path)
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "c0")
    _git(repo, "remote", "add", "origin", f"https://maria:{GH_TOKEN}@git.example.com/x.git")

    resultado = Scanner().scan_git_history(repo)

    assert resultado.avisos_de_cobertura
    assert all(
        GH_TOKEN not in aviso and "git.example.com" not in aviso
        for aviso in resultado.avisos_de_cobertura
    )


def test_blob_gigante_nao_vira_memoria(tmp_path: Path) -> None:
    """O limite de tamanho era conferido DEPOIS de o blob inteiro estar na memória:
    um `.git` de 0,5 MB forçava 100 MB de RAM (amplificação de 217x)."""
    repo = _repo(tmp_path)
    (repo / "gigante.txt").write_text("A" * 12_000_000, encoding="utf-8")
    (repo / "pequeno.py").write_text(f'AWS = "{AWS_KEY_ID}"\n', encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "um blob de 12 MB e um pequeno")

    tracemalloc.start()
    try:
        resultado = Scanner(config=Config(max_file_size=1_000_000)).scan_git_history(repo)
        pico = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()

    assert [f for f in resultado.findings if f.rule_id == "aws-access-key-id"]
    assert resultado.skipped["tamanho"] >= 1
    assert pico < 4_000_000, f"pico de {pico / 1e6:.1f} MB para um limite de 1 MB"


def test_blob_utf16_no_historico_e_varrido(tmp_path: Path) -> None:
    """Config .NET / script PowerShell versionado é UTF-16: os NUL de intercalação
    o faziam ser descartado como binário, e o segredo no histórico sumia."""
    repo = _repo(tmp_path)
    linha = f'token = "{GH_TOKEN}"\n'
    (repo / "appsettings.txt").write_bytes(linha.encode("utf-16"))
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "config utf-16")
    achados = Scanner().scan_git_history(repo).findings
    assert [f for f in achados if f.rule_id == "github-token"], (
        "segredo em blob UTF-16 do histórico não foi encontrado"
    )


def test_cat_file_com_saida_de_erro_falha_alto_e_nao_vazio(tmp_path: Path, monkeypatch) -> None:
    """Fail-open é o pior caso: se o `git cat-file` morre a meio do streaming (objeto
    corrompido, I/O), o histórico foi varrido de forma INCOMPLETA. Sem a guarda de
    returncode isso virava "0 achado, exit 0" e o gate de CI passava falso — aqui tem
    de virar GitError (exit != 0)."""
    import io

    blob = f'token = "{GH_TOKEN}"\n'.encode()
    stream = b"%b blob %d\n%b\n" % (b"a" * 40, len(blob), blob)

    class FakeProc:
        def __init__(self) -> None:
            self.stdout = io.BytesIO(stream)
            self.returncode: int | None = None

        def wait(self) -> int:
            self.returncode = 128  # cat-file morreu: objeto corrompido
            return 128

    monkeypatch.setattr(githistory.subprocess, "Popen", lambda *a, **k: FakeProc())
    monkeypatch.setattr(
        githistory,
        "_run",
        lambda repo, *args: githistory._Result(True, "%s foo\n" % ("a" * 40), ""),
    )
    with pytest.raises(GitError, match="cat-file"):
        list(iter_history_blobs(tmp_path))

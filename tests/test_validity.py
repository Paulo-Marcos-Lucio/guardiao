"""G-09pub — contrapartida pública do G09: o laudo declara a validade do SEGREDO (vivo,
morto, não verificado), não só a presença do achado. Hoje nenhuma verificação ativa
existe (chamar a API do provedor para confirmar se o segredo ainda funciona), então todo
achado é ``unknown`` por construção — e o ponto do item é que isso fique DITO no laudo,
com uma frase que impeça um consumidor automatizado de ler ``unknown`` como "descartado".
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from guardiao.core.engine import Scanner
from guardiao.report.json_report import to_document


def test_validity_marca_todo_achado_como_unknown_sem_verificacao_ativa(planted_dir: Path) -> None:
    resultado = Scanner().scan_paths([planted_dir])
    doc = to_document(resultado)
    validity = doc["summary"]["validity"]

    assert validity["verified"] == 0
    assert validity["unverified"] == 0
    assert validity["requisicoes_emitidas"] == 0
    # `unknown` cobre TODOS os achados — nenhum é classificado como morto/vivo sem
    # verificação de fato ter rodado.
    assert validity["unknown"] == doc["summary"]["total"] == len(resultado.findings)
    assert validity["unknown"] > 0, "o fixture precisa ter achado para o teste valer algo"


def test_validity_sem_achado_fica_zerada_nao_ausente(tmp_path: Path) -> None:
    """Diretório limpo: `unknown` cai para 0, mas a chave continua presente — "nada a
    verificar" e "não contei" precisam ser distinguíveis, como em `coverage_warnings`."""
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    doc = to_document(Scanner().scan_paths([tmp_path]))
    assert doc["summary"]["validity"]["unknown"] == 0


def test_validity_nota_diz_que_unknown_nao_e_achado_descartado(planted_dir: Path) -> None:
    doc = to_document(Scanner().scan_paths([planted_dir]))
    nota = doc["summary"]["validity"]["nota"].lower()
    assert "unknown" in nota
    assert "descart" in nota, "a nota precisa negar explicitamente 'achado descartado'"


@pytest.mark.skipif(shutil.which("git") is None, reason="git não disponível")
def test_validity_tambem_aparece_no_git_history(tmp_path: Path) -> None:
    """O campo não é exclusivo de `scan_paths`: um achado de histórico também não foi
    verificado contra o provedor, e precisa do mesmo rótulo."""
    import subprocess

    def _git(repo: Path, *args: str) -> None:
        subprocess.run(
            ["git", "-c", "user.email=t@example.com", "-c", "user.name=T", *args],
            cwd=str(repo),
            check=True,
            capture_output=True,
        )

    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    (repo / "app.py").write_text('TOKEN = "ghp_Rk8xY2mN4pQ7wLvB3cD5fG6hJ9kMnP2qAtZ7u"\n')
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "c0")

    doc = to_document(Scanner().scan_git_history(repo))
    assert doc["summary"]["validity"]["unknown"] == doc["summary"]["total"] > 0

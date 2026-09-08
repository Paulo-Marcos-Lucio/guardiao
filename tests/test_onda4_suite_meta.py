"""Onda 4 — invariantes transversais da suíte (PROV-01 raiz + cobertura de ruleset).

Dois defeitos de CLASSE, não de exemplo:

1. **commit-por-raiz**: o ``commit`` da proveniência tem de vir do git da RAIZ VARRIDA,
   não do CWD do processo. Rodar da pasta da própria ferramenta varrendo ``../outro-repo``
   carimbava o HEAD da ferramenta — e é justamente a proveniência que existe para desmentir
   "o achado sumiu porque a regra mudou" vs "porque o código mudou".

2. **cobertura-de-ruleset**: ``--only``/``--skip``/``--skip-category``/``--no-entropy``
   reduzem o catálogo em silêncio. "Não rodei essa regra" e "rodei e passou" viravam a mesma
   saída ("0 achados"). Agora a varredura DECLARA o recorte no console, no JSON e no SARIF.

Cada teste fica VERMELHO se a correção for revertida (a asserção mira a causa-raiz, não o
sintoma pontual).
"""

from __future__ import annotations

import json
import os
import subprocess
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from guardiao.core.config import Config
from guardiao.core.engine import Scanner
from guardiao.report import console as console_report
from guardiao.report import provenance
from guardiao.report.json_report import to_document
from guardiao.report.sarif import to_sarif
from guardiao.rules.registry import all_rules

# --------------------------------------------------------------------------- #
# Utilidades de repositório git efêmero (identidade via env, sem tocar config global).
# --------------------------------------------------------------------------- #

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.test",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.test",
}


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        env={**os.environ, **_GIT_ENV},
        check=True,
    )


def _repo_com_commit(raiz: Path, conteudo: str) -> str:
    """Cria um repo git com um commit e devolve o SHA de 40-hex do HEAD."""
    raiz.mkdir(parents=True, exist_ok=True)
    _git(raiz, "init", "-q")
    (raiz / "seed.txt").write_text(conteudo, encoding="utf-8")
    _git(raiz, "add", "-A")
    _git(raiz, "commit", "-q", "-m", conteudo)
    return _git(raiz, "rev-parse", "HEAD").stdout.strip()


# --------------------------------------------------------------------------- #
# 1) commit-por-raiz
# --------------------------------------------------------------------------- #


def test_commit_vem_da_raiz_varrida_nao_do_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Varrer o repo A com o processo rodando dentro do repo B carimba o HEAD de A.

    Revert (commit sem cwd=root) → o carimbo vira o HEAD de B (o CWD): asserção vermelha.
    """
    monkeypatch.delenv("GUARDIAO_COMMIT", raising=False)
    repo_a = tmp_path / "codigo_auditado"
    repo_b = tmp_path / "ferramenta"
    head_a = _repo_com_commit(repo_a, "conteudo alfa do alvo")
    head_b = _repo_com_commit(repo_b, "conteudo beta, outro repo, outro HEAD")
    assert head_a != head_b  # dois repositórios git independentes

    (repo_a / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.chdir(repo_b)  # CWD = repositório da ferramenta, NÃO o alvo

    result = Scanner().scan_paths([repo_a])
    doc = to_document(result)
    assert doc["commit"] == head_a  # commit do CÓDIGO AUDITADO
    assert doc["commit"] != head_b  # nunca o do CWD

    run = json.loads(to_sarif(result))["runs"][0]
    assert run["properties"]["commit"] == head_a


def test_commit_root_resolve_git_do_alvo_e_none_fora_de_repo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``commit(root)`` usa o git de ``root`` (arquivo → pasta pai); sem repo, ``None``."""
    monkeypatch.delenv("GUARDIAO_COMMIT", raising=False)
    repo = tmp_path / "r"
    head = _repo_com_commit(repo, "algo versionado")
    fora = tmp_path / "sem_git"
    fora.mkdir()
    monkeypatch.chdir(fora)  # o CWD não é repo git nenhum

    assert provenance.commit(repo) == head
    assert provenance.commit(repo / "seed.txt") == head  # arquivo resolve pela pasta pai
    assert provenance.commit(fora) is None  # raiz fora de repo → None, não o HEAD da máquina


def test_env_malformado_nao_contamina_a_proveniencia(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``GUARDIAO_COMMIT`` inválido (typo/variável errada) é ignorado e cai para o git da raiz.

    Revert (aceitar o env cru) → o carimbo vira o lixo do env: asserção vermelha.
    """
    repo = tmp_path / "r"
    head = _repo_com_commit(repo, "algo")
    monkeypatch.setenv("GUARDIAO_COMMIT", "nao-e-um-sha")
    assert provenance.commit(repo) == head


# --------------------------------------------------------------------------- #
# 2) cobertura-de-ruleset
# --------------------------------------------------------------------------- #


def _dir_limpo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    return tmp_path


def test_ruleset_parcial_declara_regras_omitidas_mesmo_com_zero_achados(
    tmp_path: Path,
) -> None:
    """``--only`` de UMA regra que não casa → 0 achados, MAS o recorte é declarado.

    Este é o oráculo do plano: 0 achados de um ruleset de 1 regra não pode ser lido como
    a varredura completa. Revert (não rastrear cobertura) → ``regras_omitidas`` vazio.
    """
    total = len(all_rules())
    scanner = Scanner(config=Config(only=frozenset({"github-token"})))
    result = scanner.scan_paths([_dir_limpo(tmp_path)])

    assert result.findings == []  # nada casou
    assert result.ruleset_parcial() is True
    assert result.regras_total == total
    assert "github-token" not in result.regras_omitidas  # a única ativa
    assert "aws-access-key-id" in result.regras_omitidas  # desativada → declarada
    assert len(result.regras_omitidas) == total - 1


def test_ruleset_completo_nao_e_parcial(tmp_path: Path) -> None:
    result = Scanner().scan_paths([_dir_limpo(tmp_path)])
    assert result.ruleset_parcial() is False
    assert result.regras_omitidas == []
    assert result.regras_total == len(all_rules())
    assert result.entropia_desligada is False


def test_no_entropy_marca_flag_dedicada_e_omite_regras_de_entropia(tmp_path: Path) -> None:
    """``--no-entropy`` liga a flag explícita E lista as regras de entropia como omitidas."""
    result = Scanner(config=Config(use_entropy=False)).scan_paths([_dir_limpo(tmp_path)])
    assert result.entropia_desligada is True
    assert result.ruleset_parcial() is True
    assert "high-entropy-string" in result.regras_omitidas
    assert "secret-in-path" in result.regras_omitidas


def test_skip_category_entra_na_cobertura(tmp_path: Path) -> None:
    """``--skip-category pii`` omite cpf/cnpj e isso aparece na cobertura."""
    result = Scanner(config=Config(skip_categories=frozenset({"pii"}))).scan_paths(
        [_dir_limpo(tmp_path)]
    )
    assert result.ruleset_parcial() is True
    assert "cpf" in result.regras_omitidas
    assert "cnpj" in result.regras_omitidas


def test_json_e_sarif_declaram_ruleset_coverage_parcial(tmp_path: Path) -> None:
    result = Scanner(config=Config(only=frozenset({"github-token"}))).scan_paths(
        [_dir_limpo(tmp_path)]
    )
    cov = to_document(result)["summary"]["ruleset_coverage"]  # type: ignore[index]
    assert cov["partial"] is True
    assert cov["rules_run"] == 1
    assert cov["rules_total"] == len(all_rules())
    assert "aws-access-key-id" in cov["rules_omitted"]

    sarif_cov = json.loads(to_sarif(result))["runs"][0]["properties"]["rulesetCoverage"]
    assert sarif_cov["partial"] is True
    assert sarif_cov["rulesRun"] == 1
    assert sarif_cov["rulesTotal"] == len(all_rules())


def test_json_ruleset_coverage_completo_nao_e_parcial(tmp_path: Path) -> None:
    cov = to_document(Scanner().scan_paths([_dir_limpo(tmp_path)]))["summary"][  # type: ignore[index]
        "ruleset_coverage"
    ]
    assert cov["partial"] is False
    assert cov["rules_omitted"] == []
    assert cov["rules_run"] == cov["rules_total"] == len(all_rules())
    assert cov["entropy_disabled"] is False


def test_console_rebaixa_verde_e_declara_o_recorte(tmp_path: Path) -> None:
    """Ruleset parcial + zero achados: o console troca o tique verde pelo aviso e lista o
    que NÃO foi avaliado. Revert → volta o "✓ Nenhum segredo encontrado." enganoso."""
    result = Scanner(config=Config(only=frozenset({"github-token"}))).scan_paths(
        [_dir_limpo(tmp_path)]
    )
    buffer = StringIO()
    console_report.render(result, Console(file=buffer, width=400, no_color=True))
    saida = buffer.getvalue()

    assert "✓ Nenhum segredo encontrado." not in saida
    assert "Ruleset PARCIAL" in saida
    assert "não avaliado" in saida
    assert "aws-access-key-id" in saida


def test_console_no_entropy_anuncia_entropia_desligada(tmp_path: Path) -> None:
    result = Scanner(config=Config(use_entropy=False)).scan_paths([_dir_limpo(tmp_path)])
    buffer = StringIO()
    console_report.render(result, Console(file=buffer, width=400, no_color=True))
    saida = buffer.getvalue()
    assert "entropia DESLIGADA" in saida

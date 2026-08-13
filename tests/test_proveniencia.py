"""PROV-01 — o laudo precisa ser vinculável a um código, a um catálogo e a si mesmo.

Sem os três eixos o achado não é reauditável: seis meses depois ninguém prova se
ele sumiu porque o código foi corrigido ou porque a REGRA mudou de opinião.
Molde: ``esteira/tests/test_proveniencia.py`` (mesma suíte, mesmo defeito de
origem).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from guardiao.core.engine import Scanner
from guardiao.report import provenance
from guardiao.report.json_report import to_document, to_json
from guardiao.report.sarif import to_sarif


def _sem_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GUARDIAO_COMMIT", raising=False)


def test_relatorio_carrega_commit_e_ruleset_hash(
    planted_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """O topo do JSON e o mesmo trio no SARIF: falha se qualquer campo sumir."""
    monkeypatch.setenv("GUARDIAO_COMMIT", "0" * 40)
    result = Scanner().scan_paths([planted_dir])

    doc = json.loads(to_json(result))
    assert doc["commit"] == "0" * 40
    assert len(doc["ruleset_hash"]) == 64
    assert len(doc["artifact_sha256"]) == 64

    run = json.loads(to_sarif(result))["runs"][0]
    assert run["properties"]["commit"] == "0" * 40
    assert len(run["properties"]["ruleset_hash"]) == 64
    assert len(run["properties"]["artifact_sha256"]) == 64


def test_commit_e_none_fora_de_repositorio_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fora de um repo git a resposta honesta é ``None`` — não uma exceção, nem 'unknown'."""
    _sem_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    assert provenance.commit() is None


def test_commit_e_none_quando_o_git_nao_existe_na_maquina(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _sem_env(monkeypatch)

    def explode(*_a: object, **_k: object) -> None:
        raise FileNotFoundError("git")

    monkeypatch.setattr(subprocess, "run", explode)
    assert provenance.commit() is None


def test_env_vence_o_git(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDIAO_COMMIT", "a" * 40)
    assert provenance.commit() == "a" * 40


def test_ruleset_hash_muda_quando_uma_regra_muda_de_severidade(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """O hash existe para provar QUAL catálogo julgou o código. Se ele não se
    move quando o catálogo se move, não prova nada."""
    from dataclasses import replace

    from guardiao.core.models import Severity
    from guardiao.rules.registry import all_rules

    antes = provenance.ruleset_hash()
    original = all_rules()

    def alterado() -> list[object]:
        regras = list(original)
        regras[0] = replace(regras[0], severity=Severity.INFO)
        return regras

    # `provenance.ruleset_hash` chama o `all_rules` importado NO MÓDULO
    # `provenance` (binding próprio) — remendar `guardiao.rules.registry.all_rules`
    # não teria efeito nenhum aqui.
    monkeypatch.setattr(provenance, "all_rules", alterado)
    assert provenance.ruleset_hash() != antes


def test_artifact_sha256_e_verificavel_pela_receita_documentada(planted_dir: Path) -> None:
    """Um hash que o destinatário não consegue recalcular é enfeite. A receita:
    zere o campo, serialize canonicamente (sort_keys, separadores compactos, sem
    escapar não-ASCII)."""
    doc = to_document(Scanner().scan_paths([planted_dir]))
    declarado = doc["artifact_sha256"]
    del doc["artifact_sha256"]
    canonico = json.dumps(doc, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    assert hashlib.sha256(canonico.encode("utf-8")).hexdigest() == declarado

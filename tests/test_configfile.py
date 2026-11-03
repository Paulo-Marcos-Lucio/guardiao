"""Testes property-based (Hypothesis) do G-04: supressão sempre contabilizada
(`apply_baseline`) e baseline corrompido falha explicitamente (`ConfigInvalida`).

Mesma receita do `test_propriedades.py`: gera achados e baselines ARBITRÁRIOS, não
só o caso que o G-04c descreveu — a invariante tem de valer para a classe inteira,
não para o exemplo que apareceu primeiro.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from guardiao.core.baseline import Baseline, ConfigInvalida, apply_baseline, load_baseline
from guardiao.core.models import Finding, Location, Severity

_RULE_ID = st.text(alphabet=st.characters(whitelist_categories=("L", "N")), min_size=1, max_size=8)


def _finding(indice: int, rule_id: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="achado sintético",
        severity=Severity.HIGH,
        location=Location(path=f"arquivo{indice}.py", line=1),
        secret="segredo-sintetico",
        redacted=f"ocult{indice}",
        line_preview="linha sintética",
    )


@settings(max_examples=300)
@given(
    rule_ids=st.lists(_RULE_ID, min_size=0, max_size=12),
    no_baseline=st.lists(st.booleans(), min_size=0, max_size=12),
)
def test_supressao_sempre_contabilizada(rule_ids: list[str], no_baseline: list[bool]) -> None:
    """INVARIANTE (G-04): para qualquer lista de achados e qualquer baseline,
    ``len(entrada) == len(saída) + contador`` — nenhum achado desaparece sem ser
    contado, e o contador nunca soma mais do que a entrada continha.
    """
    tamanho = min(len(rule_ids), len(no_baseline))
    findings = [_finding(i, rid) for i, rid in enumerate(rule_ids[:tamanho])]
    baseline = Baseline(
        fingerprints=frozenset(
            f.fingerprint
            for f, esta_no_baseline in zip(findings, no_baseline[:tamanho], strict=True)
            if esta_no_baseline
        )
    )
    kept, suprimido = apply_baseline(findings, baseline)
    assert len(findings) == len(kept) + suprimido
    # a contagem é a CERTA, não só do tamanho certo: exatamente os do baseline saíram
    assert suprimido == sum(1 for f in findings if baseline.contains(f))
    assert all(not baseline.contains(f) for f in kept)


def _json_valido(texto: str) -> object:
    try:
        return json.loads(texto)
    except json.JSONDecodeError:
        return _INVALIDO


_INVALIDO = object()


@settings(max_examples=200, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    conteudo=st.one_of(
        st.text(),
        st.integers().map(json.dumps),
        st.booleans().map(json.dumps),
        st.none().map(json.dumps),
        st.lists(st.text()).map(json.dumps),
        # dict de string->string: se tiver a chave "findings", o valor é uma STRING,
        # nunca um objeto — portanto nunca um baseline válido.
        st.dictionaries(st.text(), st.text()).map(json.dumps),
    )
)
def test_config_corrompido_levanta_configinvalida(tmp_path: Path, conteudo: str) -> None:
    """INVARIANTE (G-04): baseline corrompido nunca passa batido como baseline vazio
    nem explode com uma exceção genérica — sempre `ConfigInvalida`, sempre alto.
    """
    documento = _json_valido(conteudo)
    if isinstance(documento, dict) and isinstance(documento.get("findings"), dict):
        return  # não é corrompido: é um baseline válido (findings vazio ou não)
    caminho = tmp_path / "baseline.json"
    caminho.write_text(conteudo, encoding="utf-8")
    with pytest.raises(ConfigInvalida):
        load_baseline(caminho)


def test_arquivo_ausente_levanta_configinvalida(tmp_path: Path) -> None:
    with pytest.raises(ConfigInvalida):
        load_baseline(tmp_path / "nao-existe.json")


def test_baseline_valido_nao_levanta(tmp_path: Path) -> None:
    caminho = tmp_path / "baseline.json"
    caminho.write_text(json.dumps({"findings": {}}), encoding="utf-8")
    assert load_baseline(caminho) == Baseline(fingerprints=frozenset())

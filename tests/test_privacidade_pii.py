"""Privacidade de PII no laudo (Classe E / G6) — invariante de CLASSE, não por-exemplo.

A regra de ouro do Guardião é "o segredo cru nunca sai". Para SEGREDO isso já é
pinado (``test_report``); o buraco que a auditoria cruzada apontou é o **dado
pessoal**: um CPF válido é, ele mesmo, o dado sensível — não pode chegar INTEIRO a
nenhum artefato renderizado (console, JSON, SARIF), nem na forma mascarada
``529.982.247-25`` nem na forma só-dígitos ``52998224725``.

Ataca a classe: a asserção corre sobre CPFs válidos GERADOS (Hypothesis), não sobre
um exemplo escolhido a dedo — se um renderizador futuro deixar de mascarar o span de
PII, a propriedade fica vermelha para toda a família, não só para o fixture.
"""

from __future__ import annotations

from io import StringIO
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st
from rich.console import Console

from guardiao.core.engine import Scanner
from guardiao.report import console as console_report
from guardiao.report.json_report import to_json
from guardiao.report.sarif import to_sarif
from guardiao.rules.br import cpf_valido
from tests.conftest import CPF_VALIDO

_PESOS_1 = tuple(range(10, 1, -1))
_PESOS_2 = tuple(range(11, 1, -1))
_TUTORIAL = {"123.456.789-09", "111.444.777-35"}


def _dv(base: str, pesos: tuple[int, ...]) -> str:
    resto = sum(int(c) * p for c, p in zip(base, pesos, strict=True)) % 11
    return "0" if resto < 2 else str(11 - resto)


def _cpf_mascarado(base9: str) -> str:
    """Fecha os dois dígitos verificadores e formata ``NNN.NNN.NNN-DD``."""
    d1 = _dv(base9, _PESOS_1)
    d2 = _dv(base9 + d1, _PESOS_2)
    n = base9 + d1 + d2
    return f"{n[0:3]}.{n[3:6]}.{n[6:9]}-{n[9:11]}"


def _render_console(result: object) -> str:
    buffer = StringIO()
    console_report.render(result, Console(file=buffer, width=400, no_color=True))  # type: ignore[arg-type]
    return buffer.getvalue()


def _laudos(pasta: Path) -> tuple[str, str, str, object]:
    resultado = Scanner().scan_paths([pasta])
    return (
        _render_console(resultado),
        to_json(resultado),
        to_sarif(resultado),
        resultado,
    )


def _cpf_inteiro_ausente(mascarado: str, *laudos: str) -> None:
    digitos = "".join(c for c in mascarado if c.isdigit())
    for laudo in laudos:
        assert mascarado not in laudo, "CPF mascarado inteiro vazou no laudo"
        assert digitos not in laudo, "dígitos completos do CPF vazaram no laudo"


def test_cpf_valido_conhecido_nunca_sai_inteiro(tmp_path: Path) -> None:
    """e2e pinado: o CPF válido do conftest é DETECTADO mas nunca renderizado inteiro."""
    (tmp_path / "clientes.py").write_text(f'cpf = "{CPF_VALIDO}"\n', encoding="utf-8")
    console, js, sarif, resultado = _laudos(tmp_path)

    ids = {f.rule_id for f in resultado.findings}  # type: ignore[attr-defined]
    assert "cpf" in ids, "o CPF válido tem de ser detectado (senão o teste é vácuo)"
    _cpf_inteiro_ausente(CPF_VALIDO, console, js, sarif)
    # A ponta ocultada aparece (é o que o dono usa para reconhecer o dado), mas só ela.
    assert "…" in console


@settings(max_examples=60, deadline=None)
@given(base=st.integers(min_value=0, max_value=999_999_999))
def test_nenhum_cpf_valido_sai_inteiro_no_laudo(base: int, tmp_path_factory: object) -> None:
    """Classe: qualquer CPF VÁLIDO plantado é detectado e jamais sai inteiro."""
    base9 = f"{base:09d}"
    if len(set(base9)) == 1:
        return  # 000000000… reprova o próprio validador; fora do escopo
    mascarado = _cpf_mascarado(base9)
    if mascarado in _TUTORIAL or not cpf_valido(mascarado):
        return
    pasta = tmp_path_factory.mktemp("pii")  # type: ignore[attr-defined]
    (pasta / "dados.py").write_text(f'cpf = "{mascarado}"\n', encoding="utf-8")

    console, js, sarif, resultado = _laudos(pasta)
    ids = {f.rule_id for f in resultado.findings}  # type: ignore[attr-defined]
    assert "cpf" in ids
    _cpf_inteiro_ausente(mascarado, console, js, sarif)

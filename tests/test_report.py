from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

from rich.console import Console

from guardiao.core.engine import Scanner
from guardiao.core.models import Severity
from guardiao.report import console as console_report
from guardiao.report.json_report import SCHEMA, to_document, to_json
from guardiao.report.sarif import to_sarif
from guardiao.rules.registry import all_rules
from tests.conftest import AWS_KEY_ID, DB_URI, GENERIC_SECRET, GH_TOKEN, GOOGLE_KEY

_NIVEIS_SARIF = {"error", "warning", "note", "none"}


def _render(result: object) -> str:
    buffer = StringIO()
    console_report.render(result, Console(file=buffer, width=400, no_color=True))  # type: ignore[arg-type]
    return buffer.getvalue()


def test_json_never_leaks_raw_secret(planted_dir: Path) -> None:
    payload = to_json(Scanner().scan_paths([planted_dir]))
    for raw in (AWS_KEY_ID, GH_TOKEN, GOOGLE_KEY, DB_URI):
        assert raw not in payload
    assert "AKIA…8RPD" in payload  # o valor ocultado aparece
    document = json.loads(payload)
    assert document["tool"] == "guardiao"
    assert document["summary"]["total"] == len(document["findings"])
    assert document["summary"]["total"] > 0


def test_contrato_json_da_suite(planted_dir: Path) -> None:
    """Formato `suite-appsec/1`: schema declarado, chave do achado é `id` e
    `by_severity` traz SEMPRE as 5 severidades (inclusive zeradas)."""
    document = to_document(Scanner().scan_paths([planted_dir]))
    assert document["schema"] == SCHEMA
    assert document["owasp_edition"] == "2025"
    summary = document["summary"]
    assert isinstance(summary, dict)
    assert set(summary["by_severity"]) == {s.value for s in Severity}
    assert set(summary["skipped"])  # motivos declarados mesmo zerados
    findings = document["findings"]
    assert isinstance(findings, list)
    for finding in findings:
        assert "id" in finding and "rule" not in finding
        assert finding["severity"] in {s.value for s in Severity}
        assert isinstance(finding["severity_rank"], int)


def test_console_nao_imprime_o_segredo_cru(planted_dir: Path) -> None:
    """O renderizador PADRÃO é o que o cliente vê. Sem este teste, imprimir
    `finding.secret` na tabela passava com a suíte inteira verde."""
    saida = _render(Scanner().scan_paths([planted_dir]))
    for raw in (AWS_KEY_ID, GH_TOKEN, GOOGLE_KEY, GENERIC_SECRET):
        assert raw not in saida
    assert "AKIA…8RPD" in saida
    assert "Plano de ação" in saida  # a correção é mostrada, não só o problema


def test_console_distingue_nao_olhei_de_esta_limpo(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text("hash = 'x'\n", encoding="utf-8")
    saida = _render(Scanner().scan_paths([tmp_path]))
    assert "NÃO analisada" in saida
    assert "✓ Nenhum segredo encontrado." not in saida
    # e num diretório de fato limpo, o tique verde continua aparecendo
    (tmp_path / "limpo.py").write_text("x = 1\n", encoding="utf-8")
    limpo = _render(Scanner(config=None).scan_paths([tmp_path / "limpo.py"]))
    assert "✓ Nenhum segredo encontrado." in limpo


def test_console_nao_interpreta_markup_do_alvo(tmp_path: Path) -> None:
    """Markup do Rich vindo do alvo derrubava o relatório inteiro (MarkupError) e
    permitiria esconder um achado com `[black on black]`."""
    alvo = tmp_path / "malicioso.py"
    alvo.write_text(f'x = "[/]"  # [bold red]{AWS_KEY_ID}\n', encoding="utf-8")
    saida = _render(Scanner().scan_paths([alvo]))
    assert "[/]" in saida
    assert "[bold red]" in saida
    assert AWS_KEY_ID not in saida


def test_sarif_is_valid_and_safe(planted_dir: Path) -> None:
    payload = to_sarif(Scanner().scan_paths([planted_dir]))
    for raw in (AWS_KEY_ID, GH_TOKEN, GOOGLE_KEY):
        assert raw not in payload
    document = json.loads(payload)
    assert document["version"] == "2.1.0"
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "guardiao"
    assert run["tool"]["driver"]["rules"]
    assert run["results"]
    # cada resultado referencia uma regra declarada e tem localização
    declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in declared
        assert res["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_sarif_respeita_as_restricoes_do_schema_2_1_0(planted_dir: Path) -> None:
    """Checagem de conformidade nos campos que o GitHub valida — NÃO é validação
    contra o schema completo, e o nome do teste não pode prometer isso.

    Campos verificados: `tags` com itens únicos (`uniqueItems`), `level` no enum,
    `security-severity` parseável de 0 a 10, catálogo completo declarado e um único
    `partialFingerprints` por resultado.
    """
    document = json.loads(to_sarif(Scanner().scan_paths([planted_dir])))
    run = document["runs"][0]
    regras = run["tool"]["driver"]["rules"]
    assert len(regras) == len(all_rules())  # catálogo COMPLETO, não só o que disparou
    for regra in regras:
        tags = regra["properties"]["tags"]
        assert len(tags) == len(set(tags)), f"tags repetidas em {regra['id']}"
        assert regra["defaultConfiguration"]["level"] in _NIVEIS_SARIF
        assert 0.0 <= float(regra["properties"]["security-severity"]) <= 10.0
    for res in run["results"]:
        assert res["level"] in _NIVEIS_SARIF
        assert list(res["partialFingerprints"]) == ["guardiaoSecretHash/v1"]


def test_sarif_mapeia_severidade_para_nivel_e_score(planted_dir: Path) -> None:
    """Sem este teste, trocar `error` por `note` (ou zerar o security-severity)
    silenciava a aba Security do GitHub com a suíte verde."""
    document = json.loads(to_sarif(Scanner().scan_paths([planted_dir])))
    por_id = {r["id"]: r for r in document["runs"][0]["tool"]["driver"]["rules"]}
    assert por_id["private-key"]["defaultConfiguration"]["level"] == "error"
    assert por_id["private-key"]["properties"]["security-severity"] == "9.5"
    assert por_id["generic-assignment"]["defaultConfiguration"]["level"] == "warning"
    assert por_id["cnpj"]["defaultConfiguration"]["level"] == "note"

from __future__ import annotations

from pathlib import Path

from guardiao.core.config import Config
from guardiao.core.engine import Scanner


def test_scan_planted_dir_finds_all_families(planted_dir: Path) -> None:
    result = Scanner().scan_paths([planted_dir])
    ids = {f.rule_id for f in result.findings}
    assert {
        "aws-access-key-id",
        "github-token",
        "google-api-key",
        "db-connection-uri",
        "private-key",
        "generic-assignment",
    } <= ids
    assert result.units_scanned >= 5


def test_inline_allow_suppresses(planted_dir: Path) -> None:
    result = Scanner().scan_paths([planted_dir])
    # a chave em allowed.py está marcada com `# guardiao:allow`
    assert all("allowed.py" not in f.location.path for f in result.findings)


def test_benign_file_has_no_findings(planted_dir: Path) -> None:
    result = Scanner().scan_paths([planted_dir])
    assert all("benign.txt" not in f.location.path for f in result.findings)


def test_findings_sorted_by_severity(planted_dir: Path) -> None:
    result = Scanner().scan_paths([planted_dir])
    ranks = [f.severity.rank for f in result.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_skip_category_pii() -> None:
    text = "cpf: 123.456.789-09"
    assert list(Scanner().scan_text("x", text))  # existe achado por padrão...
    scanner = Scanner(config=Config(skip_categories=frozenset({"pii"})))
    assert list(scanner.scan_text("x", text)) == []  # ...mas some ao pular pii


def test_only_filter_restricts_rules(planted_dir: Path) -> None:
    scanner = Scanner(config=Config(only=frozenset({"private-key"})))
    result = scanner.scan_paths([planted_dir])
    assert {f.rule_id for f in result.findings} == {"private-key"}

from __future__ import annotations

import json
from pathlib import Path

from guardiao.core.engine import Scanner
from guardiao.report.json_report import to_json
from guardiao.report.sarif import to_sarif
from tests.conftest import AWS_KEY_ID, DB_URI, GH_TOKEN, GOOGLE_KEY


def test_json_never_leaks_raw_secret(planted_dir: Path) -> None:
    payload = to_json(Scanner().scan_paths([planted_dir]))
    for raw in (AWS_KEY_ID, GH_TOKEN, GOOGLE_KEY, DB_URI):
        assert raw not in payload
    assert "AKIA…8RPD" in payload  # o valor ocultado aparece
    document = json.loads(payload)
    assert document["tool"] == "guardiao"
    assert document["summary"]["total"] == len(document["findings"])
    assert document["summary"]["total"] > 0


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

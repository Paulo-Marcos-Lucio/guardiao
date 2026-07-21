from __future__ import annotations

import json
from pathlib import Path

from guardiao.core.baseline import apply_baseline, load_baseline, save_baseline
from guardiao.core.engine import Scanner


def test_baseline_suppresses_known_but_keeps_new(planted_dir: Path, tmp_path: Path) -> None:
    scanner = Scanner()
    result = scanner.scan_paths([planted_dir])
    assert result.findings

    baseline_path = tmp_path / "baseline.json"
    save_baseline(baseline_path, result.findings)

    baseline = load_baseline(baseline_path)
    kept, suppressed = apply_baseline(result.findings, baseline)
    assert kept == []
    assert suppressed == len(result.findings)

    # um segredo novo (não no baseline) sobrevive
    new_finding = list(
        scanner.scan_text("novo.py", 'gh = "ghp_Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3h2G1f0"')
    )
    assert new_finding
    kept2, _ = apply_baseline(result.findings + new_finding, baseline)
    assert kept2 == new_finding


def test_baseline_file_has_no_raw_secret(planted_dir: Path, tmp_path: Path) -> None:
    result = Scanner().scan_paths([planted_dir])
    baseline_path = tmp_path / "baseline.json"
    save_baseline(baseline_path, result.findings)
    raw = baseline_path.read_text(encoding="utf-8")
    assert "AKIAZ7Q2LMN4XYWV8RPD" not in raw
    document = json.loads(raw)
    assert document["version"] == 1
    assert document["findings"]

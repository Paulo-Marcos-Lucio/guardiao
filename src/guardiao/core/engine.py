"""Motor de varredura: junta fontes + regras e produz achados."""

from __future__ import annotations

import functools
import re
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from guardiao.core.config import Config
from guardiao.core.entropy import is_high_entropy, shannon_entropy
from guardiao.core.models import Finding, Location, Severity
from guardiao.core.redaction import redact, redact_spans
from guardiao.rules.base import Rule
from guardiao.rules.definitions import is_probable_hash_or_id, looks_like_placeholder
from guardiao.rules.registry import all_rules
from guardiao.sources.files import iter_files, read_text
from guardiao.sources.githistory import iter_history_blobs

_ALLOW_MARKERS = ("guardiao:allow", "guardiao: allow", "pragma: allowlist secret")


@functools.cache
def _keyword_pattern(keywords: tuple[str, ...]) -> re.Pattern[str] | None:
    """Regex que casa qualquer keyword como palavra (evita 'author'→'auth', 'monkey'→'key')."""
    if not keywords:
        return None
    body = "|".join(re.escape(k) for k in keywords)
    return re.compile(rf"(?<![a-z0-9])(?:{body})(?![a-z0-9])", re.IGNORECASE)


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    units_scanned: int = 0
    duration_s: float = 0.0

    def counts(self) -> dict[Severity, int]:
        result: dict[Severity, int] = dict.fromkeys(Severity, 0)
        for finding in self.findings:
            result[finding.severity] += 1
        return result

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)


class Scanner:
    """Aplica as regras habilitadas a qualquer trecho de texto."""

    def __init__(self, config: Config | None = None, rules: list[Rule] | None = None) -> None:
        self.config = config or Config()
        self.rules = [
            rule
            for rule in (rules if rules is not None else all_rules())
            if self.config.rule_enabled(rule.id, rule.category)
        ]

    # -- unidade mínima: um texto ------------------------------------------- #

    def scan_text(self, path: str, text: str, *, commit: str | None = None) -> Iterator[Finding]:
        for lineno, line in enumerate(text.split("\n"), start=1):
            raw_line = line.removesuffix("\r")  # conta linhas só por \n (igual ao editor/GitHub)
            if len(raw_line) > self.config.max_line_length:
                continue
            if _is_allowlisted(raw_line):
                continue

            # 1) Coleta todos os matches da linha que sobrevivem aos filtros.
            hits: list[tuple[Rule, int, str, float]] = []
            for rule in self.rules:
                keyword_re = _keyword_pattern(rule.keywords)
                if keyword_re is not None and keyword_re.search(raw_line) is None:
                    continue
                for match in rule.find(raw_line):
                    secret = match.secret
                    if looks_like_placeholder(secret):
                        continue
                    entropy = shannon_entropy(secret)
                    if rule.min_entropy is not None and entropy < rule.min_entropy:
                        continue
                    if rule.category == "entropy":
                        if not is_high_entropy(secret):
                            continue
                        if is_probable_hash_or_id(secret):
                            continue  # UUID / SHA-1 de commit / pin não são segredos
                        if match.start > 0 and raw_line[match.start - 1] == "@":
                            continue  # 'action@sha' / 'image@digest' são pins, não segredos
                    hits.append((rule, match.start, secret, entropy))
            if not hits:
                continue

            # 1b) Dedup por trecho sobreposto: o MESMO segredo casado por várias regras
            #     (ex.: github-token HIGH + high-entropy MEDIUM) vira um achado só — a regra
            #     mais específica/severa. Evita ruído de "achado dobrado" no relatório.
            hits = _dedupe_overlapping(hits)

            # 2) Um preview compartilhado que mascara TODOS os segredos da linha —
            #    impede que um segundo segredo na mesma linha vaze cru.
            spans = [(start, start + len(secret), secret) for (_, start, secret, _) in hits]
            preview = redact_spans(raw_line, spans)

            # 3) Um Finding por match, todos com o mesmo preview seguro.
            for rule, start, secret, entropy in hits:
                yield Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    location=Location(path=path, line=lineno, column=start + 1, commit=commit),
                    secret=secret,
                    redacted=redact(secret),
                    line_preview=preview,
                    entropy=round(entropy, 2),
                    cwe=rule.cwe,
                    owasp=rule.owasp,
                    category=rule.category,
                    recommendation=rule.recommendation,
                )

    # -- varredura de arquivos ---------------------------------------------- #

    def scan_paths(self, paths: Iterable[Path | str]) -> ScanResult:
        started = time.perf_counter()
        findings: list[Finding] = []
        units = 0
        for raw in paths:
            for file_path in iter_files(Path(raw), self.config):
                text = read_text(file_path)
                if text is None:
                    continue
                units += 1
                findings.extend(self.scan_text(str(file_path), text))
        return _finalize(findings, units, started)

    # -- varredura de histórico Git ----------------------------------------- #

    def scan_git_history(self, repo: Path | str) -> ScanResult:
        started = time.perf_counter()
        findings: list[Finding] = []
        units = 0
        for blob in iter_history_blobs(Path(repo), max_bytes=self.config.max_file_size):
            units += 1
            findings.extend(self.scan_text(blob.path, blob.text, commit=blob.sha))
        return _finalize(findings, units, started)


def _dedupe_overlapping(
    hits: list[tuple[Rule, int, str, float]],
) -> list[tuple[Rule, int, str, float]]:
    """Mantém, entre matches que cobrem o mesmo trecho, o de maior severidade — e, no
    empate, a regra específica antes da genérica de entropia."""
    if len(hits) < 2:
        return hits
    ordered = sorted(hits, key=lambda h: (-h[0].severity.rank, h[0].category == "entropy", h[0].id))
    kept: list[tuple[Rule, int, str, float]] = []
    for hit in ordered:
        _, start, secret, _ = hit
        a1, a2 = start, start + len(secret)
        if any(a1 < ks + len(ksec) and ks < a2 for (_, ks, ksec, _) in kept):
            continue  # sobrepõe um já mantido (mais severo/específico)
        kept.append(hit)
    return kept


def _is_allowlisted(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in _ALLOW_MARKERS)


def _finalize(findings: list[Finding], units: int, started: float) -> ScanResult:
    findings.sort(key=lambda f: (-f.severity.rank, f.location.path, f.location.line))
    return ScanResult(
        findings=findings,
        units_scanned=units,
        duration_s=round(time.perf_counter() - started, 4),
    )


def redact_preview(secret: str) -> str:  # re-export utilitário p/ conveniência
    return redact(secret)

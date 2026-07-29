"""Motor de varredura: junta fontes + regras e produz achados."""

from __future__ import annotations

import functools
import re
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path, PurePath

from guardiao.core.config import Config
from guardiao.core.entropy import is_high_entropy, shannon_entropy
from guardiao.core.models import Finding, Location, Severity
from guardiao.core.redaction import redact, redact_spans
from guardiao.rules.base import Rule
from guardiao.rules.definitions import (
    HASH_CONTEXT,
    is_probable_hash_or_id,
    looks_like_placeholder,
)
from guardiao.rules.registry import all_rules
from guardiao.sources.files import iter_files, read_text
from guardiao.sources.githistory import iter_history_blobs

_ALLOW_MARKERS = ("guardiao:allow", "guardiao: allow", "pragma: allowlist secret")

#: Motivos pelos quais conteúdo deixa de ser analisado. Sempre reportados (mesmo
#: zerados) — "não olhei" e "olhei e está limpo" precisam ser distinguíveis.
MOTIVOS_DE_PULO: tuple[str, ...] = ("tamanho", "ruido", "binario", "linha_longa")

#: Uma unidade de varredura: (caminho, conteúdo, commit de origem ou None).
Unit = tuple[str, str, "str | None"]


@functools.cache
def _keyword_pattern(keywords: tuple[str, ...]) -> re.Pattern[str] | None:
    """Regex que casa qualquer keyword como palavra.

    Cobre três formas de nome que a fronteira ``\\b`` deixa passar ou barra errado:
    ``token`` solto, ``DB_PASSWORD``/``JWT_SECRET`` (``\\b`` não existe entre ``_`` e
    letra) e ``accessToken`` (camelCase). Continua rejeitando ``author``→``auth`` e
    ``monkey``→``key``, porque o ramo camelCase exige maiúscula literal.
    """
    if not keywords:
        return None
    body = "|".join(re.escape(k) for k in keywords)
    return re.compile(
        rf"(?:(?<![A-Za-z0-9])|(?<=[a-z0-9])(?=[A-Z]))(?:{body})(?![A-Za-z0-9])",
        re.IGNORECASE,
    )


_HASH_CONTEXT_RE = re.compile(
    rf"(?:(?<![A-Za-z0-9])|(?<=[a-z0-9])(?=[A-Z]))(?:{'|'.join(HASH_CONTEXT)})(?![A-Za-z0-9])",
    re.IGNORECASE,
)


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    units_scanned: int = 0
    duration_s: float = 0.0
    #: Conteúdo NÃO analisado, por motivo (ver :data:`MOTIVOS_DE_PULO`).
    skipped: dict[str, int] = field(default_factory=lambda: dict.fromkeys(MOTIVOS_DE_PULO, 0))
    #: Valores casados por uma regra e descartados como placeholder (auditabilidade
    #: da supressão: sem esse número, o descarte é silencioso).
    placeholders: int = 0

    def counts(self) -> dict[Severity, int]:
        result: dict[Severity, int] = dict.fromkeys(Severity, 0)
        for finding in self.findings:
            result[finding.severity] += 1
        return result

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def total_pulado(self) -> int:
        return sum(self.skipped.values())


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

    def scan_text(
        self,
        path: str,
        text: str,
        *,
        commit: str | None = None,
        contadores: dict[str, int] | None = None,
    ) -> Iterator[Finding]:
        """Produz os achados de um texto. ``contadores`` acumula pulos/descartes."""
        contadores = {} if contadores is None else contadores
        rules = self._rules_for(path)
        for lineno, line in enumerate(text.split("\n"), start=1):
            raw_line = line.removesuffix("\r")  # conta linhas só por \n (igual ao editor/GitHub)
            if len(raw_line) > self.config.max_line_length:
                contadores["linha_longa"] = contadores.get("linha_longa", 0) + 1
                continue
            if _is_allowlisted(raw_line):
                continue

            # 1) Coleta todos os matches da linha que sobrevivem aos filtros.
            hits: list[tuple[Rule, int, str, float]] = []
            contexto_de_hash: bool | None = None
            for rule in rules:
                keyword_re = _keyword_pattern(rule.keywords)
                if keyword_re is not None and keyword_re.search(raw_line) is None:
                    continue
                regex = rule.regex
                if regex.search(raw_line) is None:
                    continue  # barato: evita montar o iterador nas linhas que não casam
                group = rule.secret_group
                for match in regex.finditer(raw_line):
                    secret = match.group(group)
                    if secret is None:
                        continue
                    if looks_like_placeholder(secret):
                        contadores["placeholder"] = contadores.get("placeholder", 0) + 1
                        continue
                    if rule.validator is not None and not rule.validator(secret):
                        continue
                    entropy = shannon_entropy(secret)
                    if rule.min_entropy is not None and entropy < rule.min_entropy:
                        continue
                    start = match.start(group)
                    if rule.category == "entropy":
                        if not is_high_entropy(secret):
                            continue
                        if is_probable_hash_or_id(secret):
                            continue  # UUID / SHA-1 de commit / pin não são segredos
                        if start > 0 and raw_line[start - 1] == "@":
                            continue  # 'action@sha' / 'image@digest' são pins, não segredos
                        if contexto_de_hash is None:
                            contexto_de_hash = _HASH_CONTEXT_RE.search(raw_line) is not None
                        if contexto_de_hash:
                            continue  # 'md5'/'etag'/'integrity' na linha: é digest, não credencial
                    hits.append((rule, start, secret, entropy))
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

    def _rules_for(self, path: str) -> list[Rule]:
        """Regras válidas para este arquivo (algumas só valem em `.env` e afins)."""
        if not any(rule.only_files for rule in self.rules):
            return self.rules
        nome = PurePath(path).name.lower()
        return [r for r in self.rules if not r.only_files or _nome_casa(nome, r.only_files)]

    # -- pipeline único ----------------------------------------------------- #

    def scan_units(
        self, units: Iterable[Unit], skipped: dict[str, int] | None = None
    ) -> ScanResult:
        """Varre unidades já materializadas. Todo comando desemboca aqui.

        ``skipped`` é usado **por referência**: as fontes são preguiçosas e só
        contabilizam o que pularam enquanto o laço abaixo as consome.
        """
        started = time.perf_counter()
        contadores: dict[str, int] = skipped if skipped is not None else {}
        for motivo in MOTIVOS_DE_PULO:
            contadores.setdefault(motivo, 0)
        findings: list[Finding] = []
        units_scanned = 0
        for path, text, commit in units:
            units_scanned += 1
            findings.extend(self.scan_text(path, text, commit=commit, contadores=contadores))
        findings.sort(key=lambda f: (-f.severity.rank, f.location.path, f.location.line))
        placeholders = contadores.pop("placeholder", 0)
        return ScanResult(
            findings=findings,
            units_scanned=units_scanned,
            duration_s=round(time.perf_counter() - started, 4),
            skipped=contadores,
            placeholders=placeholders,
        )

    # -- varredura de arquivos ---------------------------------------------- #

    def scan_paths(self, paths: Iterable[Path | str]) -> ScanResult:
        skipped: dict[str, int] = dict.fromkeys(MOTIVOS_DE_PULO, 0)
        return self.scan_units(_file_units(paths, self.config, skipped), skipped)

    # -- varredura de histórico Git ----------------------------------------- #

    def scan_git_history(self, repo: Path | str, *, permitir_shallow: bool = False) -> ScanResult:
        skipped: dict[str, int] = dict.fromkeys(MOTIVOS_DE_PULO, 0)
        units = (
            (blob.path, blob.text, blob.sha)
            for blob in iter_history_blobs(
                Path(repo),
                max_bytes=self.config.max_file_size,
                skipped=skipped,
                permitir_shallow=permitir_shallow,
            )
        )
        return self.scan_units(units, skipped)


def _file_units(
    paths: Iterable[Path | str], config: Config, skipped: dict[str, int]
) -> Iterator[Unit]:
    for raw in paths:
        for file_path in iter_files(Path(raw), config, skipped):
            text = read_text(file_path)
            if text is None:
                skipped["binario"] += 1
                continue
            yield (str(file_path), text, None)


def _nome_casa(nome: str, padroes: tuple[str, ...]) -> bool:
    """Padrões :mod:`fnmatch` sobre o nome do arquivo; prefixo ``!`` nega."""
    if not any(fnmatch(nome, p) for p in padroes if not p.startswith("!")):
        return False
    return not any(fnmatch(nome, p[1:]) for p in padroes if p.startswith("!"))


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

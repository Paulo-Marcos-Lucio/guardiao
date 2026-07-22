"""Interface de linha de comando do Guardião."""

from __future__ import annotations

import contextlib
import subprocess
import sys
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from guardiao import __version__
from guardiao.core.baseline import apply_baseline, load_baseline, save_baseline
from guardiao.core.config import Config
from guardiao.core.engine import Scanner, ScanResult
from guardiao.core.models import Finding, Severity
from guardiao.report import console as console_report
from guardiao.report.json_report import to_json
from guardiao.report.sarif import to_sarif
from guardiao.rules.registry import all_rules
from guardiao.sources.githistory import GitError

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Guardião — encontra segredos vazados no código e no histórico Git.",
)
err_console = Console(stderr=True)


class Format(str, Enum):
    console = "console"
    json = "json"
    sarif = "sarif"


class FailOn(str, Enum):
    none = "none"
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    def rank(self) -> int:
        if self is FailOn.none:
            return 99
        return Severity(self.value).rank


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"guardiao {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    _version: bool = typer.Option(
        False, "--version", "-V", callback=_version_callback, is_eager=True, help="Mostra a versão."
    ),
) -> None:
    pass


def _build_config(
    only: list[str],
    skip: list[str],
    skip_category: list[str],
    no_entropy: bool,
    scan_lockfiles: bool = False,
) -> Config:
    return Config(
        only=frozenset(only),
        skip=frozenset(skip),
        skip_categories=frozenset(skip_category),
        use_entropy=not no_entropy,
        scan_noise_files=scan_lockfiles,
    )


def _exit_code(result: ScanResult, fail_on: FailOn) -> int:
    top = result.max_severity()
    if top is None:
        return 0
    return 1 if top.rank >= fail_on.rank() else 0


def _emit(result: ScanResult, formats: list[Format], output: Path | None) -> None:
    file_formats = [f for f in formats if f is not Format.console]
    if output is not None and len(file_formats) != 1:
        err_console.print(
            "[red]--output exige exatamente um formato de arquivo (json OU sarif).[/]"
        )
        raise typer.Exit(2)

    for fmt in formats:
        if fmt is Format.console:
            console_report.render(result)
        else:
            payload = to_json(result) if fmt is Format.json else to_sarif(result)
            if output is not None:
                output.write_text(payload + "\n", encoding="utf-8")
                err_console.print(f"[green]{fmt.value}[/] salvo em [bold]{output}[/]")
            else:
                typer.echo(payload)


@app.command()
def scan(
    path: list[Path] = typer.Argument(
        None, help="Arquivos/pastas a varrer (padrão: diretório atual)."
    ),
    formats: list[Format] = typer.Option(
        [Format.console], "--format", "-f", help="Formato de saída (repetível)."
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Arquivo de saída."),
    git_history: bool = typer.Option(
        False,
        "--git-history",
        help="Varre TODO o histórico Git (blobs antigos), não só a árvore atual.",
    ),
    baseline: Path | None = typer.Option(
        None, "--baseline", help="Suprime achados presentes neste baseline."
    ),
    update_baseline: bool = typer.Option(
        False, "--update-baseline", help="Grava/atualiza o baseline com os achados atuais e sai."
    ),
    fail_on: FailOn = typer.Option(
        FailOn.medium, "--fail-on", help="Severidade mínima que faz o comando sair com código 1."
    ),
    no_entropy: bool = typer.Option(False, "--no-entropy", help="Desliga a regra por entropia."),
    scan_lockfiles: bool = typer.Option(
        False,
        "--scan-lockfiles",
        help="Também varre lockfiles/gerados (uv.lock, package-lock.json, *.min.js). "
        "Por padrão são pulados (só hashes, geram ruído).",
    ),
    only: list[str] = typer.Option([], "--only", help="Roda apenas estas regras (por id)."),
    skip: list[str] = typer.Option([], "--skip", help="Pula estas regras (por id)."),
    skip_category: list[str] = typer.Option(
        [], "--skip-category", help="Pula categorias inteiras (ex.: pii)."
    ),
) -> None:
    """Varre um projeto em busca de segredos."""
    targets = path or [Path(".")]
    config = _build_config(only, skip, skip_category, no_entropy, scan_lockfiles)
    scanner = Scanner(config=config)

    if git_history:
        repo = targets[0]
        try:
            result = scanner.scan_git_history(repo)
        except GitError as exc:
            err_console.print(f"[red]Não foi possível ler o histórico Git:[/] {exc}")
            raise typer.Exit(2) from exc
    else:
        result = scanner.scan_paths(targets)

    if update_baseline:
        target = baseline or Path(".guardiao-baseline.json")
        save_baseline(target, result.findings)
        err_console.print(
            f"[green]Baseline gravado[/] em [bold]{target}[/] "
            f"({len(result.findings)} achado(s) aceito(s))."
        )
        raise typer.Exit(0)

    suppressed = 0
    if baseline is not None and baseline.exists():
        result.findings, suppressed = apply_baseline(result.findings, load_baseline(baseline))

    _emit(result, formats, output)
    if suppressed and Format.console in formats:
        err_console.print(f"[dim]{suppressed} achado(s) suprimido(s) pelo baseline.[/]")

    raise typer.Exit(_exit_code(result, fail_on))


@app.command()
def rules() -> None:
    """Lista todas as regras de detecção."""
    table = Table(title="Regras do Guardião", header_style="bold")
    table.add_column("ID", no_wrap=True)
    table.add_column("Severidade", no_wrap=True)
    table.add_column("Categoria", no_wrap=True)
    table.add_column("Descrição")
    table.add_column("OWASP / CWE", no_wrap=True)
    for rule in all_rules():
        table.add_row(
            rule.id,
            rule.severity.value,
            rule.category,
            rule.title,
            f"{rule.owasp or '—'} · {rule.cwe or '—'}",
        )
    Console().print(table)


@app.command("pre-commit")
def pre_commit(
    fail_on: FailOn = typer.Option(
        FailOn.medium, "--fail-on", help="Severidade que bloqueia o commit."
    ),
) -> None:
    """Varre o conteúdo **em stage** — para uso como hook de pre-commit."""
    paths = _staged_paths()
    if not paths:
        typer.echo("Nada em stage. Nada a verificar.")
        raise typer.Exit(0)

    scanner = Scanner()
    findings: list[Finding] = []
    scanned = 0
    for path in paths:
        content = _staged_content(path)
        if content is None:
            continue
        scanned += 1
        findings.extend(scanner.scan_text(path, content))
    findings.sort(key=lambda f: (-f.severity.rank, f.location.path, f.location.line))
    result = ScanResult(findings=findings, units_scanned=scanned)

    if result.findings:
        console_report.render(result)
        err_console.print(
            "\n[bold red]Commit bloqueado:[/] possível segredo em stage. "
            "Remova/rotacione, ou marque a linha com [bold]# guardiao:allow[/] se for falso-positivo."
        )
    else:
        typer.echo(f"✓ {scanned} arquivo(s) em stage sem segredos.")
    raise typer.Exit(_exit_code(result, fail_on))


def _staged_paths() -> list[str]:
    """Caminhos em stage — inclui renomeados (ACMR) e nomes com caracteres especiais (-z)."""
    out = _git("diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR")
    if out is None:
        return []
    return [p for p in out.split("\x00") if p]


def _staged_content(path: str) -> str | None:
    """Conteúdo do arquivo **como está em stage** (índice), não o do working tree."""
    raw = _git_bytes("show", f":{path}")
    if raw is None or b"\x00" in raw[:8192]:
        return None
    return raw.decode("utf-8", errors="replace")


def _git(*args: str) -> str | None:
    try:
        proc = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except (OSError, ValueError):  # pragma: no cover - git ausente
        return None
    return proc.stdout if proc.returncode == 0 else None


def _git_bytes(*args: str) -> bytes | None:
    try:
        proc = subprocess.run(["git", *args], capture_output=True, check=False)
    except (OSError, ValueError):  # pragma: no cover - git ausente
        return None
    return proc.stdout if proc.returncode == 0 else None


def _force_utf8() -> None:
    """Evita UnicodeEncodeError no console legado do Windows (cp1252)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):
                reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    _force_utf8()
    app()

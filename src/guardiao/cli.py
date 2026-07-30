"""Interface de linha de comando do Guardião."""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from guardiao import __version__
from guardiao.core.baseline import apply_baseline, load_baseline, save_baseline
from guardiao.core.config import Config
from guardiao.core.engine import Scanner, ScanResult
from guardiao.core.models import Severity
from guardiao.report import console as console_report
from guardiao.report.console import txt
from guardiao.report.json_report import to_json
from guardiao.report.sarif import to_sarif
from guardiao.rules.registry import all_rules
from guardiao.sources.files import decode_text_bytes
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


def _validar_selecao(only: list[str], skip: list[str], skip_category: list[str]) -> None:
    """Id inexistente em --only/--skip/--skip-category aborta com 2.

    Sem isto, um typo (`--only aws-acess-key-id`) devolve "✓ Nenhum segredo
    encontrado" e exit 0: o CI fica verde para sempre e ninguém percebe.
    """
    regras = all_rules()
    ids = {rule.id for rule in regras}
    categorias = {rule.category for rule in regras}
    for valores, validos, rotulo in (
        (set(only) | set(skip), ids, "Regra(s) desconhecida(s)"),
        (set(skip_category), categorias, "Categoria(s) desconhecida(s)"),
    ):
        desconhecidos = sorted(valores - validos)
        if desconhecidos:
            err_console.print(
                Text(f"{rotulo}: {', '.join(desconhecidos)}", style="bold red"),
            )
            err_console.print(f"[dim]Válidos: {', '.join(sorted(validos))}[/]")
            raise typer.Exit(2)


def _build_config(
    only: list[str],
    skip: list[str],
    skip_category: list[str],
    no_entropy: bool,
    scan_lockfiles: bool = False,
    max_file_size: int = Config.max_file_size,
    max_line_length: int = Config.max_line_length,
    incluir_testes: bool = False,
) -> Config:
    _validar_selecao(only, skip, skip_category)
    return Config(
        only=frozenset(only),
        skip=frozenset(skip),
        skip_categories=frozenset(skip_category),
        use_entropy=not no_entropy,
        scan_noise_files=scan_lockfiles,
        max_file_size=max_file_size,
        max_line_length=max_line_length,
        demote_tests=not incluir_testes,
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
        None,
        exists=True,
        help="Arquivos/pastas a varrer (padrão: diretório atual).",
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
    permitir_shallow: bool = typer.Option(
        False,
        "--permitir-shallow",
        help="Aceita rodar --git-history em clone raso (o histórico varrido fica incompleto).",
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
    incluir_testes: bool = typer.Option(
        False,
        "--incluir-testes",
        help="Não rebaixa a severidade de achados heurísticos em arquivos de teste "
        "(por padrão, tests/, test_*.py, conftest.py etc. são rebaixados — sinal suave).",
    ),
    scan_lockfiles: bool = typer.Option(
        False,
        "--scan-lockfiles",
        help="Também varre lockfiles/gerados (uv.lock, package-lock.json, *.min.js). "
        "Por padrão são pulados (só hashes, geram ruído).",
    ),
    max_file_size: int = typer.Option(
        Config.max_file_size, "--max-file-size", help="Tamanho máximo de arquivo varrido, em bytes."
    ),
    max_line_length: int = typer.Option(
        Config.max_line_length, "--max-line-length", help="Comprimento máximo de linha analisada."
    ),
    only: list[str] = typer.Option([], "--only", help="Roda apenas estas regras (por id)."),
    skip: list[str] = typer.Option([], "--skip", help="Pula estas regras (por id)."),
    skip_category: list[str] = typer.Option(
        [], "--skip-category", help="Pula categorias inteiras (ex.: pii)."
    ),
) -> None:
    """Varre um projeto em busca de segredos."""
    targets = path or [Path(".")]
    config = _build_config(
        only,
        skip,
        skip_category,
        no_entropy,
        scan_lockfiles,
        max_file_size,
        max_line_length,
        incluir_testes,
    )
    scanner = Scanner(config=config)

    if git_history:
        try:
            result = scanner.scan_git_history(targets[0], permitir_shallow=permitir_shallow)
        except GitError as exc:
            err_console.print("[red]Não foi possível ler o histórico Git:[/]", txt(exc))
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


@app.command("regras")
def regras() -> None:
    """Lista todas as regras de detecção."""
    table = Table(title="Regras do Guardião", header_style="bold")
    table.add_column("ID", no_wrap=True)
    table.add_column("Severidade", no_wrap=True)
    table.add_column("Categoria", no_wrap=True)
    table.add_column("Descrição")
    # O ANO da edição do OWASP vive no CABEÇALHO; a célula usa o código curto.
    # 'A03' significa coisas diferentes em 2021 e em 2025 — o ano não pode sumir.
    table.add_column("OWASP 2025 / CWE", no_wrap=True)
    for rule in all_rules():
        codigo = (rule.owasp or "—").split(" ")[0]
        table.add_row(
            rule.id,
            rule.severity.value,
            rule.category,
            rule.title,
            f"{codigo} · {rule.cwe or '—'}",
        )
    Console().print(table)


app.command("rules", help="Alias de `regras`.")(regras)


@app.command("pre-commit")
def pre_commit(
    fail_on: FailOn = typer.Option(
        FailOn.medium, "--fail-on", help="Severidade que bloqueia o commit."
    ),
    baseline: Path | None = typer.Option(
        None, "--baseline", help="Suprime achados presentes neste baseline."
    ),
    no_entropy: bool = typer.Option(False, "--no-entropy", help="Desliga a regra por entropia."),
    scan_lockfiles: bool = typer.Option(
        False, "--scan-lockfiles", help="Também varre lockfiles/gerados."
    ),
    only: list[str] = typer.Option([], "--only", help="Roda apenas estas regras (por id)."),
    skip: list[str] = typer.Option([], "--skip", help="Pula estas regras (por id)."),
    skip_category: list[str] = typer.Option(
        [], "--skip-category", help="Pula categorias inteiras (ex.: pii)."
    ),
) -> None:
    """Varre o conteúdo **em stage** — para uso como hook de pre-commit.

    Usa a MESMA `Config` e o mesmo motor do `scan`: um arquivo que o CI considera
    limpo não pode bloquear o commit (e vice-versa).
    """
    config = _build_config(only, skip, skip_category, no_entropy, scan_lockfiles)
    scanner = Scanner(config=config)
    skipped: dict[str, int] = {}
    result = scanner.scan_units(_staged_units(config, skipped), skipped)

    if baseline is not None and baseline.exists():
        result.findings, _ = apply_baseline(result.findings, load_baseline(baseline))

    if result.findings:
        console_report.render(result)
        err_console.print(
            "\n[bold red]Commit bloqueado:[/] possível segredo em stage. "
            "Remova/rotacione, ou marque a linha com [bold]# guardiao:allow[/] se for falso-positivo."
        )
    elif result.units_scanned == 0:
        typer.echo("Nada em stage. Nada a verificar.")
    else:
        typer.echo(f"✓ {result.units_scanned} arquivo(s) em stage sem segredos.")
    raise typer.Exit(_exit_code(result, fail_on))


def _staged_units(config: Config, skipped: dict[str, int]) -> list[tuple[str, str, str | None]]:
    """Unidades a partir do índice do Git, filtradas pela mesma Config do `scan`."""
    units: list[tuple[str, str, str | None]] = []
    for path in _staged_paths():
        if Path(path).suffix.lower() in config.binary_exts:
            skipped["binario"] = skipped.get("binario", 0) + 1
            continue
        if config.is_noise_file(Path(path).name):
            skipped["ruido"] = skipped.get("ruido", 0) + 1
            continue
        raw = _git_bytes("show", f":{path}")
        if raw is None:
            continue
        if len(raw) > config.max_file_size:
            skipped["tamanho"] = skipped.get("tamanho", 0) + 1
            continue
        text = decode_text_bytes(raw)  # BOM-aware: UTF-16/UTF-32 não é binário
        if text is None:
            skipped["binario"] = skipped.get("binario", 0) + 1
            continue
        units.append((path, text, None))
    return units


def _staged_paths() -> list[str]:
    """Caminhos em stage — inclui renomeados (ACMR) e nomes com caracteres especiais (-z)."""
    out = _git("diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR")
    if out is None:
        return []
    return [p for p in out.split("\x00") if p]


def _git_env() -> dict[str, str]:
    """Ambiente que impede o git de travar esperando entrada humana (prompt de
    credencial num hook de pre-commit vira erro imediato, não um travamento)."""
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = env.get("GIT_ASKPASS", "echo")
    env["GCM_INTERACTIVE"] = "never"
    return env


def _git(*args: str) -> str | None:
    try:
        proc = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            stdin=subprocess.DEVNULL,
            env=_git_env(),
            timeout=120,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired):  # pragma: no cover - git ausente/lento
        return None
    return proc.stdout if proc.returncode == 0 else None


def _git_bytes(*args: str) -> bytes | None:
    try:
        proc = subprocess.run(
            ["git", *args],
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
            env=_git_env(),
            timeout=120,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired):  # pragma: no cover - git ausente/lento
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

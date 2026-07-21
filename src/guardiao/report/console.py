"""Renderizador para terminal, com cores por severidade."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from guardiao.core.engine import ScanResult
from guardiao.core.models import Severity

_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()

    if not result.findings:
        console.print(
            f"[bold green]✓ Nenhum segredo encontrado.[/] "
            f"[dim]({result.units_scanned} unidades, {result.duration_s}s)[/]"
        )
        return

    table = Table(show_lines=False, expand=True, header_style="bold")
    table.add_column("Sev", no_wrap=True)
    table.add_column("Regra", no_wrap=True)
    table.add_column("Local", overflow="fold")
    table.add_column("Trecho (ocultado)", overflow="fold")

    for finding in result.findings:
        sev = finding.severity
        table.add_row(
            Text(sev.value.upper(), style=_STYLE[sev]),
            finding.rule_id,
            finding.location.as_str(),
            finding.line_preview,
        )

    console.print(table)
    _render_summary(result, console)


def _render_summary(result: ScanResult, console: Console) -> None:
    counts = result.counts()
    parts = [f"[{_STYLE[sev]}] {sev.value}: {counts[sev]} [/]" for sev in Severity if counts[sev]]
    console.print(
        f"\n[bold]{len(result.findings)} achado(s)[/] — "
        + "  ".join(parts)
        + f"  [dim]({result.units_scanned} unidades, {result.duration_s}s)[/]"
    )

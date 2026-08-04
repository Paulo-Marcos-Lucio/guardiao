"""Renderizador para terminal, com cores por severidade.

Todo dado que vem do alvo (caminho, trecho da linha, id de regra) é impresso como
:class:`rich.text.Text`, nunca interpolado em string com markup: um arquivo
contendo ``[/]`` derrubava o relatório inteiro com ``MarkupError``, e um contendo
``[black on black]`` conseguiria esconder o próprio achado.
"""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
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

_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "CRÍTICA",
    Severity.HIGH: "ALTA",
    Severity.MEDIUM: "MÉDIA",
    Severity.LOW: "BAIXA",
    Severity.INFO: "INFO",
}


def txt(valor: object) -> Text:
    """Texto literal: nada vindo do alvo é interpretado como markup do Rich."""
    return Text(str(valor))


def render(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()

    if not result.findings:
        if result.total_pulado():
            console.print(
                "[bold yellow]⚠ Nenhum segredo encontrado NO QUE FOI ANALISADO.[/] "
                f"[dim]({result.units_scanned} unidades, {result.duration_s}s)[/]"
            )
        else:
            console.print(
                "[bold green]✓ Nenhum segredo encontrado.[/] "
                f"[dim]({result.units_scanned} unidades, {result.duration_s}s)[/]"
            )
        _render_pulos(result, console)
        _render_cobertura(result, console)
        return

    table = Table(show_lines=False, expand=True, header_style="bold")
    table.add_column("Sev", no_wrap=True)
    table.add_column("Regra", no_wrap=True)
    table.add_column("Local", overflow="fold")
    table.add_column("Trecho (ocultado)", overflow="fold")

    for finding in result.findings:
        sev = finding.severity
        table.add_row(
            Text(_LABEL[sev], style=_STYLE[sev]),
            txt(finding.rule_id),
            txt(finding.location.as_str()),
            txt(finding.line_preview),
        )

    console.print(table)
    _render_summary(result, console)
    _render_plano(result, console)
    _render_pulos(result, console)
    _render_cobertura(result, console)


def _render_cobertura(result: ScanResult, console: Console) -> None:
    """Limites de ALCANCE declarados pela fonte — o que a varredura não pôde ver.

    Vem do alvo (nome de repositório, mensagem montada), então sai como `Text`: nada
    de markup do Rich interpretado. Aparece TAMBÉM quando não há achado — é aí que a
    ausência de achado corre o risco de ser lida como ausência de segredo.
    """
    for aviso in result.avisos_de_cobertura:
        console.print(Text("⚠ ", style="yellow") + txt(aviso))


def _render_summary(result: ScanResult, console: Console) -> None:
    counts = result.counts()
    parts = [f"[{_STYLE[sev]}] {_LABEL[sev]}: {counts[sev]} [/]" for sev in Severity if counts[sev]]
    console.print(
        f"\n[bold]{len(result.findings)} achado(s)[/] — "
        + "  ".join(parts)
        + f"  [dim]({result.units_scanned} unidades, {result.duration_s}s)[/]"
    )


def _render_plano(result: ScanResult, console: Console) -> None:
    """Mostra a CORREÇÃO dos piores achados — não só o problema."""
    piores = result.findings[:3]
    corpo = Text()
    for i, finding in enumerate(piores, start=1):
        if i > 1:
            corpo.append("\n\n")
        corpo.append(f"{i}. ", style="bold")
        corpo.append(_LABEL[finding.severity], style=_STYLE[finding.severity])
        corpo.append(f" · {finding.rule_id} · {finding.location.as_str()}\n", style="bold")
        corpo.append(f"   {finding.recommendation}")
    console.print(
        Panel(corpo, title="Plano de ação — comece por aqui", border_style="green", box=box.ROUNDED)
    )


def _render_pulos(result: ScanResult, console: Console) -> None:
    """Auditabilidade: o que a ferramenta deixou de olhar e o que ela descartou.

    Diretório pulado sai em linha PRÓPRIA e é declarado SEMPRE, mesmo zerado: ele não
    é uma unidade (é uma árvore inteira, de tamanho desconhecido), e era o buraco pelo
    qual um `ghp_` versionado em `vendor/` saía com tique verde e exit 0.
    """
    diretorios = result.skipped.get("diretorio", 0)
    por_unidade = {m: n for m, n in result.skipped.items() if m != "diretorio" and n}
    total_unidades = sum(por_unidade.values())
    if total_unidades:
        detalhe = ", ".join(f"{motivo}: {n}" for motivo, n in por_unidade.items())
        console.print(
            f"[yellow]⚠ {total_unidades} unidade(s)/linha(s) NÃO analisada(s)[/] "
            f"[dim]({detalhe})[/] — veja --scan-lockfiles, --max-file-size e --max-line-length."
        )
    if diretorios:
        console.print(
            f"[yellow]⚠ {diretorios} diretório(s) inteiro(s) NÃO varrido(s)[/] "
            "[dim](exclude_dirs: vendor, dist, node_modules, .git… + virtualenvs)[/] — "
            "nada do que estiver dentro deles foi analisado."
        )
    else:
        console.print("[dim]0 diretório(s) pulado(s): a árvore foi percorrida inteira.[/]")
    if result.placeholders:
        console.print(
            f"[dim]{result.placeholders} valor(es) descartado(s) como placeholder "
            f"(exemplo de documentação, template ou senha fraca canônica).[/]"
        )

"""
SafePush CLI — built with Typer and Rich.

The CLI is the primary human-facing interface to SafePush.  It is implemented
as a thin adapter over the :class:`~safepush.core.engine.ScanEngine` — it
handles argument parsing, output formatting, and process exit codes, but
delegates all business logic to the engine.

This separation means the entire scanning pipeline can be consumed
programmatically (by an MCP server, VS Code extension, or test suite) without
any CLI involvement.

Commands
--------
``safepush scan``
    Scan a target path, directory, or Git object and print a report.

``safepush version``
    Print the SafePush version and exit.

``safepush list-scanners``
    List all registered scanner plugins with their versions.
"""

from __future__ import annotations

import sys
from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from safepush import __version__
from safepush.core.engine import ScanEngine
from safepush.exceptions import SafePushError, ScanTargetNotFoundError
from safepush.models.report import ReportFormat
from safepush.models.scan import ScanRequest, ScanTarget, ScanTargetType
from safepush.plugins.registry import ScannerRegistry
from safepush.reports.dispatcher import ReportDispatcher
from safepush.scoring.engine import ScoringEngine

app = typer.Typer(
    name="safepush",
    help="SafePush -- Secure Every Push. Detect secrets and vulnerabilities before they reach production.",
    add_completion=True,
    rich_markup_mode="rich",
    pretty_exceptions_show_locals=False,
)

console = Console()
err_console = Console(stderr=True)


class OutputFormat(str, Enum):
    """CLI output format choices."""

    TEXT = "text"
    JSON = "json"


class TargetType(str, Enum):
    """CLI target type choices."""

    FILE = "file"
    DIRECTORY = "directory"
    GIT_STAGED = "git-staged"
    GIT_DIFF = "git-diff"
    GIT_COMMIT = "git-commit"


_TARGET_TYPE_MAP: dict[TargetType, ScanTargetType] = {
    TargetType.FILE: ScanTargetType.FILE,
    TargetType.DIRECTORY: ScanTargetType.DIRECTORY,
    TargetType.GIT_STAGED: ScanTargetType.GIT_STAGED,
    TargetType.GIT_DIFF: ScanTargetType.GIT_DIFF,
    TargetType.GIT_COMMIT: ScanTargetType.GIT_COMMIT,
}


def _build_engine() -> tuple[ScanEngine, ScannerRegistry]:
    """Construct and return the scan engine with auto-discovered plugins.

    Returns
    -------
    tuple[ScanEngine, ScannerRegistry]
        The constructed engine and registry.
    """
    registry = ScannerRegistry.discover()
    scoring_engine = ScoringEngine()
    engine = ScanEngine(registry=registry, scoring_engine=scoring_engine)
    return engine, registry


@app.command(name="scan")
def scan_command(
    path: Path = typer.Argument(
        ...,
        help="Path to scan: a file, directory, or Git repository root.",
        exists=False,  # We handle the error ourselves for better UX
        show_default=False,
    ),
    target_type: TargetType = typer.Option(
        TargetType.DIRECTORY,
        "--type",
        "-t",
        help="Type of scan target.",
        show_default=True,
    ),
    scanners: Optional[list[str]] = typer.Option(
        None,
        "--scanner",
        "-s",
        help="Scanner plugin ID(s) to run. Repeat to specify multiple. Default: all.",
        show_default=False,
    ),
    severity: str = typer.Option(
        "LOW",
        "--severity",
        help="Minimum severity level to report [INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL].",
        show_default=True,
    ),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Exit with code 1 if any finding at this severity or above is found.",
        show_default=False,
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TEXT,
        "--format",
        "-f",
        help="Output format.",
        show_default=True,
    ),
    max_findings: Optional[int] = typer.Option(
        None,
        "--max-findings",
        help="Maximum number of findings to display.",
        show_default=False,
    ),
    timeout: int = typer.Option(
        300,
        "--timeout",
        help="Maximum scan duration in seconds.",
        show_default=True,
    ),
    no_colour: bool = typer.Option(
        False,
        "--no-colour",
        "--no-color",
        help="Disable ANSI colour in output.",
        is_flag=True,
    ),
    ref: Optional[str] = typer.Option(
        None,
        "--ref",
        help="Git ref for GIT_COMMIT and GIT_DIFF target types.",
        show_default=False,
    ),
) -> None:
    """Scan a target for secrets, vulnerabilities, and insecure patterns.

    Examples:

    \b
      # Scan current directory (all registered scanners)
      safepush scan .

    \b
      # Scan only staged changes before committing
      safepush scan . --type git-staged

    \b
      # Fail CI if any HIGH or CRITICAL finding is found
      safepush scan . --fail-on HIGH

    \b
      # Output machine-readable JSON
      safepush scan . --format json
    """
    # Validate path exists
    if not path.exists():
        err_console.print(
            f"[bold red]Error:[/bold red] Path does not exist: [cyan]{path}[/cyan]"
        )
        raise typer.Exit(code=1)

    try:
        engine, _ = _build_engine()
    except Exception as exc:
        err_console.print(f"[bold red]Engine initialisation failed:[/bold red] {exc}")
        raise typer.Exit(code=1)

    # Build request
    scan_target = ScanTarget(
        target_type=_TARGET_TYPE_MAP[target_type],
        path=path,
        ref=ref,
    )
    request = ScanRequest(
        target=scan_target,
        scanner_ids=scanners or [],
        severity_threshold=severity.upper(),
        fail_on_severity=fail_on.upper() if fail_on else None,
        max_findings=max_findings,
        timeout_seconds=timeout,
    )

    # Map output format
    report_format = (
        ReportFormat.JSON
        if output_format == OutputFormat.JSON
        else ReportFormat.TEXT
    )

    # Execute scan
    try:
        report = engine.scan(request, report_format=report_format)
    except ScanTargetNotFoundError as exc:
        err_console.print(
            f"[bold red]Scan target not found:[/bold red] {exc.path}"
        )
        raise typer.Exit(code=1)
    except SafePushError as exc:
        err_console.print(f"[bold red]SafePush error:[/bold red] {exc.message}")
        raise typer.Exit(code=1)
    except Exception as exc:
        err_console.print(f"[bold red]Unexpected error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    # Render output
    dispatcher = ReportDispatcher()
    use_colour = not no_colour and output_format != OutputFormat.JSON
    if output_format == OutputFormat.TEXT:
        from safepush.reports.renderers import TextReportRenderer
        dispatcher.register(TextReportRenderer(use_colour=use_colour))

    output = dispatcher.render(report)
    console.print(output) if output_format == OutputFormat.TEXT else print(output)

    # Exit code for CI gate
    if not report.summary.passed:
        raise typer.Exit(code=1)


@app.command(name="version")
def version_command() -> None:
    """Print the SafePush version and exit."""
    console.print(
        Panel(
            f"[bold cyan]SafePush[/bold cyan] [bright_white]v{__version__}[/bright_white]\n"
            "[dim]Secure Every Push[/dim]",
            box=box.ROUNDED,
            expand=False,
        )
    )


@app.command(name="list-scanners")
def list_scanners_command() -> None:
    """List all registered scanner plugins with their versions and availability."""
    _, registry = _build_engine()

    table = Table(
        title="Registered Scanner Plugins",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("ID", style="bold")
    table.add_column("Version")
    table.add_column("Available")

    scanners = list(registry.all())
    if not scanners:
        console.print(
            "[yellow]No scanner plugins registered.[/yellow]\n"
            "Install a SafePush scanner package to get started.\n"
            "See: [cyan]https://github.com/safepush/safepush#plugins[/cyan]"
        )
        return

    for scanner in sorted(scanners, key=lambda s: s.scanner_id):
        available = scanner.is_available()
        avail_str = "[green]Yes[/green]" if available else "[red]No[/red]"
        table.add_row(scanner.scanner_id, scanner.version, avail_str)

    console.print(table)


def main() -> None:
    """Entry point for the SafePush CLI.

    This function is the ``console_scripts`` target defined in
    ``pyproject.toml``.  It delegates entirely to Typer.
    """
    app()


if __name__ == "__main__":
    main()

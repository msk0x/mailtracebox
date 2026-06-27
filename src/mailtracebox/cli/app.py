"""Typer-based CLI application — FIXED: single engine.run() call."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console
from rich.panel import Panel

from mailtracebox import __version__

app = typer.Typer(
    name="mailtracebox",
    help="Email Intelligence Framework — authorized OSINT collection.",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console(stderr=True)


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target email address or domain."),
    output: str = typer.Option("rich", "--output", "-o", help="Output format: rich, json, markdown, html, csv."),
    output_file: Optional[str] = typer.Option(None, "--output-file", "-f", help="Save report to this file path."),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="Path to a YAML configuration file."),
    plugins: Optional[str] = typer.Option(None, "--plugins", "-p", help="Comma-separated list of plugins to run."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output."),
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug logging."),
) -> None:
    """Run an email intelligence scan against [bold]TARGET[/bold]."""
    asyncio.run(_run_scan(target, output, output_file, config_file, plugins, verbose, debug))


async def _run_scan(
    target: str, output_format: str, output_file: str | None,
    config_file: str | None, plugins_filter: str | None,
    verbose: bool, debug: bool,
) -> None:
    from mailtracebox.config.manager import ConfigManager
    from mailtracebox.core.engine import Engine
    from mailtracebox.log.setup import setup_logging
    from mailtracebox.reports.csv_report import CsvReporter
    from mailtracebox.reports.html_report import HtmlReporter
    from mailtracebox.reports.json_report import JsonReporter
    from mailtracebox.reports.markdown_report import MarkdownReporter
    from mailtracebox.reports.rich_report import RichReporter

    overrides: dict[str, Any] = {
        "general": {"target": target, "output_format": output_format, "verbose": verbose, "debug": debug},
    }
    if output_file:
        overrides["general"]["output_file"] = output_file
    if plugins_filter:
        overrides["plugins"] = {"enabled": [p.strip() for p in plugins_filter.split(",") if p.strip()]}

    config_mgr = ConfigManager()
    cfg_path = Path(config_file) if config_file else None
    config = config_mgr.load(config_file=cfg_path, cli_overrides=overrides)

    log_config = config.logging
    if debug:
        log_config = log_config.model_copy(update={"level": "DEBUG"})
    elif verbose:
        log_config = log_config.model_copy(update={"level": "INFO"})
    setup_logging(log_config)

    _show_banner(target)

    engine = Engine(config)

    # ← SINGLE await call — no duplicate
    try:
        report = await engine.run()
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        console.print(f"[red]Scan failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    RichReporter(console).display(engine.context, config.reports)

    final_output_file = output_file or config.general.output_file
    if final_output_file:
        reporters = {
            "json": JsonReporter, "markdown": MarkdownReporter,
            "html": HtmlReporter, "csv": CsvReporter,
        }
        reporter_cls = reporters.get(output_format)
        if reporter_cls:
            reporter = reporter_cls()
            content = reporter.generate(engine.context, config.reports)
            path = Path(final_output_file)
            reporter.save(content, path)
            console.print(f"\n[green]Report saved to {path}[/green]")


def _show_banner(target: str) -> None:
    console.print(Panel(
        f"[bold cyan]mailtracebox[/bold cyan] v{__version__}\nTarget: [bold]{target}[/bold]",
        border_style="cyan", padding=(0, 2),
    ))


# ── plugins command group ────────────────────────────────────────────

plugins_app = typer.Typer(help="Manage plugins.")
app.add_typer(plugins_app, name="plugins")


@plugins_app.command("list")
def plugins_list(config_file: Optional[str] = typer.Option(None, "--config", "-c")) -> None:
    """List all available plugins."""
    from mailtracebox.config.manager import ConfigManager
    from mailtracebox.core.plugin_manager import PluginManager
    from rich.table import Table

    config = ConfigManager().load(config_file=Path(config_file) if config_file else None)

    async def _list() -> None:
        pm = PluginManager(config)
        await pm.discover()
        plugins = pm.list_plugins()
        if not plugins:
            console.print("[yellow]No plugins found.[/yellow]")
            return
        table = Table(title="Available Plugins")
        table.add_column("Name", style="bold cyan")
        table.add_column("Version")
        table.add_column("Description", ratio=3)
        table.add_column("Tags")
        for p in plugins:
            table.add_row(p["name"], p["version"], p["description"], ", ".join(p.get("tags", [])))
        console.print(table)

    asyncio.run(_list())


@plugins_app.command("info")
def plugins_info(name: str = typer.Argument(...), config_file: Optional[str] = typer.Option(None, "--config", "-c")) -> None:
    """Show detailed information about a specific plugin."""
    from mailtracebox.config.manager import ConfigManager
    from mailtracebox.core.plugin_manager import PluginManager

    config = ConfigManager().load(config_file=Path(config_file) if config_file else None)

    async def _info() -> None:
        pm = PluginManager(config)
        await pm.discover()
        plugin = pm.get_plugin(name)
        if not plugin:
            console.print(f"[red]Plugin '{name}' not found.[/red]")
            raise typer.Exit(code=1)
        for k, v in plugin.to_metadata().items():
            console.print(f"  [bold]{k}:[/bold] {v}")

    asyncio.run(_info())


# ── config command group ─────────────────────────────────────────────

config_app = typer.Typer(help="Manage configuration.")
app.add_typer(config_app, name="config")


@config_app.command("show")
def config_show(config_file: Optional[str] = typer.Option(None, "--config", "-c")) -> None:
    """Display the active configuration."""
    import json
    from mailtracebox.config.manager import ConfigManager
    config = ConfigManager().load(config_file=Path(config_file) if config_file else None)
    data = config.model_dump()
    data["api_keys"] = {k: "***" for k in data.get("api_keys", {})}
    console.print_json(json.dumps(data, indent=2, default=str))


@config_app.command("validate")
def config_validate(config_file: Optional[str] = typer.Option(None, "--config", "-c")) -> None:
    """Validate a configuration file."""
    from mailtracebox.config.manager import ConfigManager
    from mailtracebox.utils.exceptions import ConfigurationError
    try:
        ConfigManager().load(config_file=Path(config_file) if config_file else None)
        console.print("[green]Configuration is valid.[/green]")
    except ConfigurationError as exc:
        console.print(f"[red]Invalid configuration:[/red] {exc}")
        raise typer.Exit(code=1) from exc


def main() -> None:
    app()


if __name__ == "__main__":
    main()

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from core.llm_client import LLMClient
from .personas import get_persona, list_personas
from .honeypot import Honeypot
from . import reporter as rpt

console = Console()


@click.group()
def main():
    """LLM Honeypot — Deploy a convincing fake AI system to trap and analyze attackers."""
    pass


@main.command()
@click.option("--persona", "-p", default="adminBot", show_default=True,
              help="Honeypot persona to deploy")
@click.option("--analysis", "-a", is_flag=True,
              help="Show real-time attack detection overlay")
def start(persona: str, analysis: bool):
    """Start an interactive honeypot session."""
    try:
        p = get_persona(persona)
    except ValueError as e:
        console.print(f"[red]✗[/red] {e}")
        raise SystemExit(1)

    with LLMClient() as llm:
        honeypot = Honeypot(p, llm, show_analysis=analysis)
        honeypot.print_banner()

        while True:
            try:
                user_input = console.input("[bold cyan]>[/bold cyan] ").strip()
            except (KeyboardInterrupt, EOFError):
                break

            if not user_input:
                continue

            if user_input.lower() == "/quit":
                break

            if user_input.lower() == "/status":
                honeypot.print_status()
                continue

            response, turn_analysis = honeypot.respond(user_input)

            console.print()
            console.print(Panel(
                response,
                title=f"[bold]{p.display_name}[/bold]",
                border_style="dim",
            ))

            if analysis:
                honeypot.print_analysis_overlay(turn_analysis)

            console.print()

        # End session
        console.print("\n[dim]Session ended. Generating report...[/dim]")
        path = honeypot.finalize()
        console.print(f"[green]✓[/green] Session saved: [link]{path}[/link]")
        console.print(f"  Run [bold]honeypot report --session {path}[/bold] to view full analysis")


@main.command()
@click.option("--session", "-s", default=None,
              help="Path to session JSON file (defaults to most recent)")
def report(session: str | None):
    """Display a detailed analysis report for a honeypot session."""
    if session:
        from pathlib import Path
        path = Path(session)
        if not path.exists():
            console.print(f"[red]✗[/red] Session file not found: {session}")
            raise SystemExit(1)
    else:
        sessions = rpt.list_sessions()
        if not sessions:
            console.print("[yellow]No sessions found.[/yellow] Run [bold]honeypot start[/bold] first.")
            raise SystemExit(0)
        path = sessions[0]
        console.print(f"[dim]Loading most recent session: {path.name}[/dim]")

    rpt.print_session_report(path)


@main.command("list-sessions")
def list_sessions():
    """List all recorded honeypot sessions."""
    sessions = rpt.list_sessions()
    if not sessions:
        console.print("[yellow]No sessions recorded yet.[/yellow]")
        return

    table = Table(title="Recorded Sessions", box=box.ROUNDED, border_style="cyan")
    table.add_column("#", justify="right", width=3, style="dim")
    table.add_column("Session ID")
    table.add_column("Persona")
    table.add_column("Turns", justify="center")
    table.add_column("Risk", justify="center")
    table.add_column("File", style="dim")

    import json
    for i, path in enumerate(sessions[:20], 1):
        try:
            with open(path) as f:
                data = json.load(f)
            turns = len(data.get("turns", []))
            risk = sum(t.get("risk_score", 0) for t in data.get("turns", []))
            color = "red" if risk >= 80 else "yellow" if risk >= 40 else "green"
            table.add_row(
                str(i),
                data.get("session_id", "—"),
                data.get("persona", "—"),
                str(turns),
                f"[{color}]{risk}[/{color}]",
                path.name,
            )
        except Exception:
            table.add_row(str(i), "—", "—", "—", "—", path.name)

    console.print()
    console.print(table)


@main.command("list-personas")
def list_personas_cmd():
    """List all available honeypot personas."""
    table = Table(title="Available Personas", box=box.ROUNDED, border_style="cyan")
    table.add_column("Name", style="bold cyan")
    table.add_column("Display Name")
    table.add_column("Description", max_width=40)
    table.add_column("Vulnerability", justify="center")
    table.add_column("Lures")

    for p in list_personas():
        vuln_color = {"low": "green", "medium": "yellow", "high": "red"}.get(p.vulnerability_level, "white")
        table.add_row(
            p.name,
            p.display_name,
            p.description[:38] + "…" if len(p.description) > 40 else p.description,
            f"[{vuln_color}]{p.vulnerability_level.upper()}[/{vuln_color}]",
            "\n".join(f"• {l[:35]}" for l in p.lure_details),
        )

    console.print()
    console.print(table)

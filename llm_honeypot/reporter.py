import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.rule import Rule

from core.config import REPORTS_DIR

console = Console()

SESSIONS_DIR = REPORTS_DIR / "honeypot_sessions"

TECHNIQUE_COLORS = {
    "prompt_injection": "yellow",
    "jailbreak": "red",
    "system_prompt_extraction": "magenta",
    "credential_extraction": "bright_red",
    "privilege_escalation": "orange3",
    "social_engineering": "cyan",
    "reconnaissance": "blue",
    "data_exfiltration": "bright_red",
}


def _risk_color(score: int) -> str:
    if score >= 80:
        return "red"
    if score >= 50:
        return "orange3"
    if score >= 20:
        return "yellow"
    return "green"


def print_session_report(session_path: str | Path) -> None:
    with open(session_path) as f:
        data = json.load(f)

    profile = data.get("attacker_profile", {})
    turns = data.get("turns", [])
    total_risk = sum(t.get("risk_score", 0) for t in turns)

    # Header
    console.print()
    console.print(Rule("[bold cyan]LLM Honeypot — Session Report[/bold cyan]", style="cyan"))
    console.print()

    # Session metadata
    console.print(Panel(
        f"[bold]Session ID:[/bold]   {data['session_id']}\n"
        f"[bold]Persona:[/bold]      {data['persona']}\n"
        f"[bold]Started:[/bold]      {data['started_at'][:19].replace('T', ' ')}\n"
        f"[bold]Ended:[/bold]        {data.get('ended_at', 'N/A')[:19].replace('T', ' ')}\n"
        f"[bold]Total turns:[/bold]  {len(turns)}\n"
        f"[bold]Total risk:[/bold]   [{_risk_color(min(total_risk, 100))}]{total_risk}[/]",
        title="Session Metadata",
        border_style="cyan",
    ))
    console.print()

    # Attacker profile
    if profile:
        soph_color = {"Advanced": "red", "Intermediate": "yellow", "Novice": "green"}.get(
            profile.get("sophistication", ""), "white"
        )
        console.print(Panel(
            f"[bold]Sophistication:[/bold]    [{soph_color}]{profile.get('sophistication', 'N/A')}[/{soph_color}]\n"
            f"[bold]Primary objective:[/bold] {profile.get('primary_objective', 'N/A')}\n"
            f"[bold]MITRE tactics:[/bold]     {', '.join(profile.get('mitre_tactics', [])) or 'None observed'}",
            title="Attacker Profile",
            border_style="yellow",
        ))
        console.print()

    # Technique frequency
    freq = profile.get("technique_frequency", {})
    if freq:
        table = Table(title="Detected Techniques", box=box.ROUNDED, border_style="cyan")
        table.add_column("Technique", style="bold")
        table.add_column("Occurrences", justify="center")
        table.add_column("MITRE Mapping", max_width=50)

        from .analyzer import MITRE_ATLAS_TACTICS
        for tech, count in sorted(freq.items(), key=lambda x: -x[1]):
            color = TECHNIQUE_COLORS.get(tech, "white")
            atlas = MITRE_ATLAS_TACTICS.get(tech, {})
            table.add_row(
                f"[{color}]{tech}[/{color}]",
                str(count),
                atlas.get("technique", "—"),
            )
        console.print(table)
        console.print()

    # Turn timeline
    table = Table(title="Turn Timeline", box=box.SIMPLE_HEAVY, border_style="cyan", show_lines=True)
    table.add_column("#", justify="right", width=3, style="dim")
    table.add_column("User Message", max_width=45)
    table.add_column("Techniques", max_width=30)
    table.add_column("Risk", justify="center", width=8)

    for turn in turns:
        techs = turn.get("detected_techniques", [])
        risk = turn.get("risk_score", 0)
        color = _risk_color(risk)
        techs_str = ", ".join(
            f"[{TECHNIQUE_COLORS.get(t, 'white')}]{t}[/{TECHNIQUE_COLORS.get(t, 'white')}]"
            for t in techs
        ) if techs else "[dim]—[/dim]"

        msg = turn["user_message"]
        table.add_row(
            str(turn["turn_id"]),
            msg[:43] + "…" if len(msg) > 45 else msg,
            techs_str,
            f"[{color}]{risk}[/{color}]",
        )

    console.print(table)
    console.print()

    # LLM summary
    if profile.get("llm_summary"):
        console.print(Panel(
            profile["llm_summary"],
            title="[bold]Threat Intelligence Summary[/bold]",
            border_style="yellow",
        ))
        console.print()

    # Recommendations
    recs = profile.get("recommendations", [])
    if recs:
        console.print("[bold cyan]Security Recommendations:[/bold cyan]")
        for rec in recs:
            console.print(f"  [cyan]•[/cyan] {rec}")
        console.print()


def list_sessions() -> list[Path]:
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    return sorted(SESSIONS_DIR.glob("session_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)

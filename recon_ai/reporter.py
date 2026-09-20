from dataclasses import asdict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.config import REPORTS_DIR
from core.utils import save_json, save_markdown_report, timestamp
from .analyzer import HostAnalysis

console = Console()

RISK_COLORS = {"critical": "red bold", "high": "bright_red", "medium": "yellow", "low": "blue", "info": "dim"}


def print_analysis(analyses: list[HostAnalysis]) -> None:
    for analysis in analyses:
        risk_color = "red" if analysis.risk_score >= 70 else "yellow" if analysis.risk_score >= 30 else "green"

        console.print(
            Panel(
                f"[bold]IP:[/] {analysis.ip}\n"
                f"[bold]Hostname:[/] {analysis.hostname or 'N/A'}\n"
                f"[bold]Risk Score:[/] [{risk_color}]{analysis.risk_score}/100[/]",
                title=f"Host: {analysis.ip}",
            )
        )

        if analysis.findings:
            table = Table(title="Heuristic Findings", show_lines=True)
            table.add_column("Port", width=8)
            table.add_column("Service", width=12)
            table.add_column("Risk", width=10)
            table.add_column("Description")
            table.add_column("Recommendation")

            for f in analysis.findings:
                style = RISK_COLORS.get(f.risk_level, "white")
                table.add_row(
                    str(f.port), f.service,
                    f"[{style}]{f.risk_level}[/]",
                    f.description, f.recommendation,
                )
            console.print(table)

        if analysis.llm_analysis:
            console.print(Panel(analysis.llm_analysis, title="AI Analysis"))

        console.print()


def export_json(analyses: list[HostAnalysis]) -> str:
    ts = timestamp()
    path = REPORTS_DIR / f"recon_report_{ts}.json"

    report = {
        "timestamp": ts,
        "hosts": [
            {
                "ip": a.ip,
                "hostname": a.hostname,
                "risk_score": a.risk_score,
                "findings": [asdict(f) for f in a.findings],
                "llm_analysis": a.llm_analysis,
            }
            for a in analyses
        ],
    }
    save_json(report, path)
    console.print(f"[dim]JSON report saved to: {path}[/]")
    return str(path)


def export_markdown(analyses: list[HostAnalysis]) -> str:
    ts = timestamp()
    path = REPORTS_DIR / f"recon_report_{ts}.md"

    sections = []
    for a in analyses:
        content = f"**IP:** {a.ip}  \n**Hostname:** {a.hostname or 'N/A'}  \n**Risk Score:** {a.risk_score}/100\n\n"

        if a.findings:
            content += "### Findings\n\n"
            content += "| Port | Service | Risk | Description |\n|------|---------|------|-------------|\n"
            for f in a.findings:
                content += f"| {f.port} | {f.service} | {f.risk_level} | {f.description} |\n"

        if a.llm_analysis:
            content += f"\n### AI Analysis\n\n{a.llm_analysis}"

        sections.append((f"Host: {a.ip}", content))

    save_markdown_report("Recon AI — Security Assessment", sections, path)
    console.print(f"[dim]Markdown report saved to: {path}[/]")
    return str(path)

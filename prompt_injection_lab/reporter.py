from collections import Counter
from dataclasses import asdict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config import REPORTS_DIR
from core.utils import save_json, timestamp
from .evaluator import EvalResult

console = Console()

VERDICT_COLORS = {
    "jailbroken": "red bold",
    "safe": "green bold",
    "partial": "yellow bold",
}

SEVERITY_COLORS = {
    "critical": "red",
    "high": "bright_red",
    "medium": "yellow",
    "low": "blue",
}


def print_result(result: EvalResult) -> None:
    verdict_style = VERDICT_COLORS.get(result.verdict, "white")
    severity_style = SEVERITY_COLORS.get(result.severity, "white")

    console.print(
        f"  [{severity_style}]{result.severity:>8}[/] "
        f"[dim]{result.test_id:<20}[/] "
        f"[{verdict_style}]{result.verdict:>10}[/] "
        f"[dim]({result.confidence}%)[/] "
        f"{result.name}"
    )


def print_summary(results: list[EvalResult]) -> None:
    console.print()

    # Per-category breakdown
    categories = sorted(set(r.category for r in results))
    table = Table(title="Results by Category", show_lines=True)
    table.add_column("Category", style="cyan")
    table.add_column("Total", justify="center")
    table.add_column("Safe", justify="center", style="green")
    table.add_column("Partial", justify="center", style="yellow")
    table.add_column("Jailbroken", justify="center", style="red")
    table.add_column("Safety Rate", justify="center")

    for cat in categories:
        cat_results = [r for r in results if r.category == cat]
        total = len(cat_results)
        verdicts = Counter(r.verdict for r in cat_results)
        safe = verdicts.get("safe", 0)
        partial = verdicts.get("partial", 0)
        jailbroken = verdicts.get("jailbroken", 0)
        safety_rate = safe / total * 100 if total > 0 else 0

        rate_style = "green" if safety_rate >= 80 else "yellow" if safety_rate >= 50 else "red"
        table.add_row(
            cat, str(total), str(safe), str(partial), str(jailbroken),
            f"[{rate_style}]{safety_rate:.0f}%[/]",
        )

    console.print(table)

    # Overall summary
    total = len(results)
    verdicts = Counter(r.verdict for r in results)
    overall_safe = verdicts.get("safe", 0) / total * 100 if total > 0 else 0

    color = "green" if overall_safe >= 80 else "yellow" if overall_safe >= 50 else "red"
    console.print(
        Panel(
            f"[bold]Overall Safety Score: [{color}]{overall_safe:.1f}%[/][/]\n"
            f"Total tests: {total} | "
            f"[green]Safe: {verdicts.get('safe', 0)}[/] | "
            f"[yellow]Partial: {verdicts.get('partial', 0)}[/] | "
            f"[red]Jailbroken: {verdicts.get('jailbroken', 0)}[/]",
            title="Summary",
        )
    )


def export_results(results: list[EvalResult]) -> str:
    ts = timestamp()
    path = REPORTS_DIR / f"injection_report_{ts}.json"

    total = len(results)
    verdicts = Counter(r.verdict for r in results)

    report = {
        "timestamp": ts,
        "summary": {
            "total_tests": total,
            "safe": verdicts.get("safe", 0),
            "partial": verdicts.get("partial", 0),
            "jailbroken": verdicts.get("jailbroken", 0),
            "safety_rate": verdicts.get("safe", 0) / total * 100 if total > 0 else 0,
        },
        "results": [asdict(r) for r in results],
    }

    save_json(report, path)
    console.print(f"\n[dim]Report saved to: {path}[/]")
    return str(path)

from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel

from core.llm_client import LLMClient
from .store import VectorStore
from .poisoner import Poisoner, TECHNIQUE_DESCRIPTIONS
from .evaluator import RAGEvaluator
from . import reporter as rpt

DATASETS_DIR = Path(__file__).parent / "datasets"
console = Console()


@click.group()
def main():
    """RAG Poisoning Lab — Test knowledge base injection attacks against LLM-powered RAG systems."""
    pass


@main.command()
@click.option("--technique", "-t", default="all", show_default=True,
              help="Attack technique to use (or 'all')")
@click.option("--judge", is_flag=True, help="Use LLM as judge for poison evaluation")
@click.option("--verbose", "-v", is_flag=True, help="Show full LLM responses")
@click.option("--output", "-o", is_flag=True, help="Save JSON report to reports/")
def attack(technique: str, judge: bool, verbose: bool, output: bool):
    """Inject poison payloads into the knowledge base and run probe questions."""
    console.print(Panel(
        "[bold cyan]RAG Poisoning Lab[/bold cyan] — Attack Mode\n"
        "[dim]Injecting malicious documents into the vector store and probing the RAG system[/dim]",
        border_style="cyan",
    ))

    with LLMClient() as llm:
        store = VectorStore(collection_name="rag_attack_session", ephemeral=True)
        poisoner = Poisoner(store)
        evaluator = RAGEvaluator(store, llm)

        # Load clean knowledge base
        console.print("[cyan]►[/cyan] Loading legitimate knowledge base...")
        kb_path = DATASETS_DIR / "knowledge_base.json"
        count = store.load_from_json(kb_path)
        console.print(f"  [green]✓[/green] Loaded {count} legitimate documents")

        # Inject poison payloads
        console.print(f"[cyan]►[/cyan] Injecting poison payloads (technique: [bold]{technique}[/bold])...")
        poisoner.load_payloads()

        if technique == "all":
            result = poisoner.inject_all()
            probes = poisoner.get_all_probes()
        else:
            if technique not in poisoner.get_techniques():
                console.print(f"[red]✗[/red] Unknown technique: {technique}")
                console.print(f"  Available: {', '.join(poisoner.get_techniques())}")
                raise SystemExit(1)
            result = poisoner.inject_technique(technique)
            probes = poisoner.get_probes_for_technique(technique)

        console.print(f"  [red]✓[/red] Injected {result.payloads_injected} malicious documents")
        console.print(f"  [dim]Total documents in KB: {store.count()}[/dim]")
        console.print()

        # Run probes
        console.print(f"[cyan]►[/cyan] Running {len(probes)} probe questions...")
        if judge:
            console.print("  [dim]LLM-as-judge enabled for borderline cases[/dim]")
        console.print()

        report = evaluator.run_probes(probes, use_judge=judge)

        # Display results
        rpt.print_summary(report)
        rpt.print_technique_breakdown(report)
        rpt.print_probe_results(report.probe_results, verbose=verbose)

        if output:
            path = rpt.save_report(report)
            console.print(f"\n[green]✓[/green] Report saved: [link]{path}[/link]")


@main.command()
@click.option("--judge", is_flag=True, help="Use LLM as judge for evaluation")
@click.option("--output", "-o", is_flag=True, help="Save JSON report to reports/")
def benchmark(judge: bool, output: bool):
    """Benchmark all attack techniques and compare their success rates."""
    console.print(Panel(
        "[bold cyan]RAG Poisoning Lab[/bold cyan] — Benchmark Mode\n"
        "[dim]Testing each attack technique independently and comparing effectiveness[/dim]",
        border_style="cyan",
    ))

    with LLMClient() as llm:
        poisoner = Poisoner(VectorStore(ephemeral=True))
        poisoner.load_payloads()
        techniques = poisoner.get_techniques()

        all_reports = {}

        for technique in techniques:
            console.print(f"\n[cyan]►[/cyan] Testing technique: [bold]{technique}[/bold]")
            store = VectorStore(collection_name=f"bench_{technique}", ephemeral=True)
            store.load_from_json(DATASETS_DIR / "knowledge_base.json")

            p = Poisoner(store)
            p._payloads = poisoner._payloads
            p.inject_technique(technique)

            evaluator = RAGEvaluator(store, llm)
            probes = p.get_probes_for_technique(technique)
            report = evaluator.run_probes(probes, use_judge=judge)
            all_reports[technique] = report
            console.print(
                f"  Success rate: [{'red' if report.poison_rate > 50 else 'yellow' if report.poison_rate > 20 else 'green'}]"
                f"{report.poison_rate}%[/] ({report.poison_successes}/{report.total_probes})"
            )

        # Print combined summary
        console.print()
        from rich.table import Table
        from rich import box

        table = Table(title="Benchmark — All Techniques", box=box.ROUNDED, border_style="cyan")
        table.add_column("Technique", style="bold")
        table.add_column("Description", max_width=45)
        table.add_column("Success Rate", justify="center")
        table.add_column("Verdict", justify="center")

        for tech, rep in sorted(all_reports.items(), key=lambda x: -x[1].poison_rate):
            rate = rep.poison_rate
            color = "red" if rate > 60 else "yellow" if rate > 30 else "green"
            verdict = "CRITICAL" if rate > 60 else "HIGH" if rate > 40 else "MEDIUM" if rate > 20 else "LOW"
            table.add_row(
                tech,
                TECHNIQUE_DESCRIPTIONS.get(tech, ""),
                f"[{color}]{rate}%[/{color}]",
                f"[{color}]{verdict}[/{color}]",
            )

        console.print(table)


@main.command("list-techniques")
def list_techniques():
    """List all available attack techniques."""
    from rich.table import Table
    from rich import box
    from rich.panel import Panel as P

    table = Table(box=box.ROUNDED, border_style="cyan", show_header=True)
    table.add_column("Technique", style="bold cyan")
    table.add_column("Description")

    for tech, desc in TECHNIQUE_DESCRIPTIONS.items():
        table.add_row(tech, desc)

    console.print()
    console.print(table)


@main.command()
@click.argument("question")
def ask(question: str):
    """Ask a question to a clean (unpoisoned) RAG system for baseline comparison."""
    with LLMClient() as llm:
        store = VectorStore(collection_name="clean_demo", ephemeral=True)
        store.load_from_json(DATASETS_DIR / "knowledge_base.json")
        evaluator = RAGEvaluator(store, llm)

        console.print(f"\n[cyan]Question:[/cyan] {question}")
        console.print("[dim]Querying clean (unpoisoned) knowledge base...[/dim]\n")

        response, retrieved = evaluator.query_rag(question)

        console.print("[bold cyan]Retrieved Documents:[/bold cyan]")
        for i, doc in enumerate(retrieved, 1):
            console.print(f"  [dim]{i}.[/dim] [{doc['metadata'].get('source', 'Unknown')}] "
                          f"{doc['text'][:80]}…")

        console.print()
        console.print(Panel(response, title="[bold green]RAG Response (Clean)[/bold green]", border_style="green"))

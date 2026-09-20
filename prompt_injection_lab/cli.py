import click
from rich.console import Console

from core.llm_client import LLMClient
from core.config import LLMProvider
from .runner import run_all, list_categories, load_test_cases
from .reporter import print_result, print_summary, export_results

console = Console()


@click.group()
def main():
    """Prompt Injection Testing Lab — Test LLM robustness against injection attacks."""
    pass


@main.command()
@click.option("--category", "-c", default=None, help="Test category to run (default: all)")
@click.option("--provider", "-p", default=None, type=click.Choice(["ollama", "groq", "huggingface"]))
@click.option("--judge/--no-judge", default=False, help="Use LLM-as-judge for evaluation")
@click.option("--output", "-o", default=None, type=click.Choice(["json"]), help="Export format")
def run(category, provider, judge, output):
    """Run injection tests against an LLM."""
    provider_enum = LLMProvider(provider) if provider else None

    try:
        client = LLMClient(provider_enum)
    except RuntimeError as e:
        console.print(f"[red]Error:[/] {e}")
        raise SystemExit(1)

    console.print(f"[cyan]Provider:[/] {client.provider.value} ({client.config.model})")
    console.print(f"[cyan]Category:[/] {category or 'all'}")
    console.print(f"[cyan]LLM Judge:[/] {'enabled' if judge else 'disabled'}")
    console.print()

    with client:
        results = run_all(client, category, judge, on_result=print_result)

    print_summary(results)

    if output == "json":
        export_results(results)


@main.command(name="list")
def list_tests():
    """List available test categories and cases."""
    categories = list_categories()
    for cat in categories:
        cases = load_test_cases(cat)
        console.print(f"\n[cyan bold]{cat}[/] ({len(cases)} tests)")
        for case in cases:
            severity = case.get("severity", "medium")
            console.print(f"  [{severity}] {case['id']}: {case['name']}")


if __name__ == "__main__":
    main()

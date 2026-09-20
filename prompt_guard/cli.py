import click
from rich.console import Console

from core.llm_client import LLMClient
from core.config import LLMProvider
from .detector import PromptGuard
from .benchmark import run_benchmark

console = Console()


@click.group()
def main():
    """Prompt Guard — Detect and defend against prompt injection attacks."""
    pass


@main.command()
@click.option("--text", "-t", default=None, help="Text to scan for injection")
@click.option("--file", "-f", default=None, type=click.Path(exists=True), help="File to scan")
@click.option("--llm/--no-llm", default=False, help="Enable LLM-based detection")
@click.option("--provider", "-p", default=None, type=click.Choice(["ollama", "groq", "huggingface"]))
def scan(text, file, llm, provider):
    """Scan input text for prompt injection attempts."""
    if not text and not file:
        console.print("[red]Error:[/] Provide --text or --file")
        raise SystemExit(1)

    if file:
        with open(file, encoding="utf-8") as f:
            text = f.read()

    client = None
    if llm:
        provider_enum = LLMProvider(provider) if provider else None
        try:
            client = LLMClient(provider_enum)
        except RuntimeError as e:
            console.print(f"[yellow]Warning:[/] LLM unavailable ({e}), using pattern-only")
            llm = False

    guard = PromptGuard(llm_client=client)
    result = guard.scan(text, use_llm=llm)

    # Display results
    risk_color = "red" if result.risk_score >= 70 else "yellow" if result.risk_score >= 30 else "green"
    console.print(f"\n[bold]Risk Score:[/] [{risk_color}]{result.risk_score:.0f}/100[/]")
    console.print(f"[bold]Suspicious:[/] {'Yes' if result.is_suspicious else 'No'}")
    console.print(f"[bold]Recommendation:[/] {result.recommendation}")

    if result.pattern_matches:
        console.print(f"\n[bold]Pattern Matches ({len(result.pattern_matches)}):[/]")
        for m in result.pattern_matches:
            console.print(f"  [{m.severity}] {m.category}: \"{m.matched_text}\"")

    if result.llm_assessment:
        console.print(f"\n[bold]LLM Assessment:[/] {result.llm_assessment}")

    if client:
        client.close()


@main.command()
@click.option("--llm/--pattern-only", default=False, help="Include LLM-based detection in benchmark")
@click.option("--provider", "-p", default=None, type=click.Choice(["ollama", "groq", "huggingface"]))
def benchmark(llm, provider):
    """Run benchmark against known injection corpus."""
    client = None
    if llm:
        provider_enum = LLMProvider(provider) if provider else None
        try:
            client = LLMClient(provider_enum)
        except RuntimeError as e:
            console.print(f"[yellow]Warning:[/] LLM unavailable ({e}), using pattern-only")
            llm = False

    guard = PromptGuard(llm_client=client)
    run_benchmark(guard, use_llm=llm)

    if client:
        client.close()


if __name__ == "__main__":
    main()

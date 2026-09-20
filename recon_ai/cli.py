import click
from rich.console import Console

from core.llm_client import LLMClient
from core.config import LLMProvider
from .parser import parse_nmap_xml, parse_nmap_text
from .analyzer import analyze_scan
from .reporter import print_analysis, export_json, export_markdown

console = Console()


@click.group()
def main():
    """Recon AI — AI-powered network reconnaissance analysis."""
    pass


@main.command()
@click.option("--input", "-i", "input_file", required=True, type=click.Path(exists=True), help="nmap output file")
@click.option("--format", "-f", "fmt", default="xml", type=click.Choice(["xml", "text"]), help="Input format")
@click.option("--provider", "-p", default=None, type=click.Choice(["ollama", "groq", "huggingface"]))
@click.option("--output", "-o", default=None, type=click.Choice(["json", "markdown", "both"]))
def analyze(input_file, fmt, provider, output):
    """Analyze nmap scan results with AI."""
    provider_enum = LLMProvider(provider) if provider else None
    try:
        client = LLMClient(provider_enum)
    except RuntimeError as e:
        console.print(f"[red]Error:[/] {e}")
        raise SystemExit(1)

    console.print(f"[cyan]Provider:[/] {client.provider.value} ({client.config.model})")
    console.print(f"[cyan]Input:[/] {input_file} ({fmt})\n")

    # Parse scan data
    if fmt == "xml":
        scan_data = parse_nmap_xml(input_file)
    else:
        with open(input_file, encoding="utf-8") as f:
            scan_data = parse_nmap_text(f.read())

    console.print(f"[cyan]Found {len(scan_data.hosts)} host(s)[/]\n")

    # Analyze
    with client:
        analyses = analyze_scan(client, scan_data)

    # Display
    print_analysis(analyses)

    # Export
    if output in ("json", "both"):
        export_json(analyses)
    if output in ("markdown", "both"):
        export_markdown(analyses)


if __name__ == "__main__":
    main()

import click
from rich.console import Console

from core.llm_client import LLMClient
from core.config import LLMProvider
from core.utils import load_json
from .classifier import classify_message, classify_batch
from .generator import generate_phishing_email, SCENARIOS, DIFFICULTIES
from .reporter import print_classification, print_batch_summary, export_results

console = Console()


@click.group()
def main():
    """Phishing Detector — AI-powered phishing email classification and simulation."""
    pass


@main.command()
@click.option("--input", "-i", "input_file", default=None, type=click.Path(exists=True), help="Email text file to classify")
@click.option("--dataset", "-d", default=None, type=click.Path(exists=True), help="JSON dataset to classify in batch")
@click.option("--provider", "-p", default=None, type=click.Choice(["ollama", "groq", "huggingface"]))
@click.option("--output", "-o", default=None, type=click.Choice(["json"]))
def classify(input_file, dataset, provider, output):
    """Classify emails as phishing or legitimate."""
    if not input_file and not dataset:
        console.print("[red]Error:[/] Provide --input (single file) or --dataset (JSON batch)")
        raise SystemExit(1)

    provider_enum = LLMProvider(provider) if provider else None
    try:
        client = LLMClient(provider_enum)
    except RuntimeError as e:
        console.print(f"[red]Error:[/] {e}")
        raise SystemExit(1)

    console.print(f"[cyan]Provider:[/] {client.provider.value} ({client.config.model})\n")

    with client:
        if input_file:
            with open(input_file, encoding="utf-8") as f:
                body = f.read()
            result = classify_message(client, body)
            print_classification(result)

        elif dataset:
            messages = load_json(dataset)
            results = classify_batch(client, messages)
            true_labels = [m.get("label") for m in messages]

            for msg, result in zip(messages, results):
                print_classification(result, msg.get("id", ""))

            has_labels = all(l in ("phishing", "legitimate") for l in true_labels)
            print_batch_summary(results, true_labels if has_labels else None)

            if output == "json":
                export_results(results, messages)


@main.command()
@click.option("--scenario", "-s", default="banking", type=click.Choice(SCENARIOS))
@click.option("--difficulty", "-d", default="moderate", type=click.Choice(DIFFICULTIES))
@click.option("--provider", "-p", default=None, type=click.Choice(["ollama", "groq", "huggingface"]))
def generate(scenario, difficulty, provider):
    """Generate a simulated phishing email for security awareness training."""
    provider_enum = LLMProvider(provider) if provider else None
    try:
        client = LLMClient(provider_enum)
    except RuntimeError as e:
        console.print(f"[red]Error:[/] {e}")
        raise SystemExit(1)

    console.print(f"[cyan]Generating {difficulty} {scenario} phishing email...[/]\n")

    with client:
        email = generate_phishing_email(client, scenario, difficulty)

    console.print(f"[bold]From:[/] {email.sender}")
    console.print(f"[bold]Subject:[/] {email.subject}")
    console.print(f"\n[bold]Body:[/]\n{email.body}")
    console.print(f"\n[yellow bold]Indicators:[/] {', '.join(email.indicators)}")
    console.print(f"[cyan bold]Training Notes:[/] {email.training_notes}")


if __name__ == "__main__":
    main()

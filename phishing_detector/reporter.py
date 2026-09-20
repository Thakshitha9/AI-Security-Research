from collections import Counter

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.config import REPORTS_DIR
from core.utils import save_json, timestamp
from .classifier import ClassificationResult

console = Console()


def print_classification(result: ClassificationResult, message_id: str = "") -> None:
    color = "red" if result.label == "phishing" else "green"
    prefix = f"[dim]{message_id:<12}[/] " if message_id else ""
    console.print(
        f"  {prefix}"
        f"[{color} bold]{result.label:>11}[/] "
        f"[dim]({result.confidence}%)[/] "
        f"{result.reasoning}"
    )


def print_batch_summary(
    results: list[ClassificationResult],
    true_labels: list[str] | None = None,
) -> None:
    console.print()

    if true_labels:
        # Accuracy metrics
        correct = sum(
            1
            for r, t in zip(results, true_labels)
            if r.label == t
        )
        total = len(results)
        accuracy = correct / total * 100 if total > 0 else 0

        # Confusion matrix
        tp = sum(1 for r, t in zip(results, true_labels) if r.label == "phishing" and t == "phishing")
        fp = sum(1 for r, t in zip(results, true_labels) if r.label == "phishing" and t == "legitimate")
        tn = sum(1 for r, t in zip(results, true_labels) if r.label == "legitimate" and t == "legitimate")
        fn = sum(1 for r, t in zip(results, true_labels) if r.label == "legitimate" and t == "phishing")

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        console.print(
            Panel(
                f"[bold]Accuracy:[/]  {accuracy:.1f}% ({correct}/{total})\n"
                f"[bold]Precision:[/] {precision:.2%}\n"
                f"[bold]Recall:[/]    {recall:.2%}\n"
                f"[bold]F1 Score:[/]  {f1:.2%}\n\n"
                f"TP: {tp} | FP: {fp} | TN: {tn} | FN: {fn}",
                title="Classification Metrics",
            )
        )
    else:
        labels = Counter(r.label for r in results)
        console.print(
            Panel(
                f"Total: {len(results)} | "
                f"[red]Phishing: {labels.get('phishing', 0)}[/] | "
                f"[green]Legitimate: {labels.get('legitimate', 0)}[/]",
                title="Summary",
            )
        )


def export_results(results: list[ClassificationResult], messages: list[dict]) -> str:
    ts = timestamp()
    path = REPORTS_DIR / f"phishing_report_{ts}.json"

    report = {
        "timestamp": ts,
        "total": len(results),
        "results": [
            {
                "message_id": msg.get("id", f"msg_{i}"),
                "label": r.label,
                "confidence": r.confidence,
                "indicators": r.indicators,
                "reasoning": r.reasoning,
            }
            for i, (r, msg) in enumerate(zip(results, messages))
        ],
    }

    save_json(report, path)
    console.print(f"\n[dim]Report saved to: {path}[/]")
    return str(path)

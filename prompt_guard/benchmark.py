from pathlib import Path
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.utils import load_json, save_json, timestamp
from core.config import REPORTS_DIR
from .detector import PromptGuard

console = Console()
CORPUS_PATH = Path(__file__).parent / "known_injections" / "injection_corpus.json"


@dataclass
class BenchmarkMetrics:
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        total = self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        return (self.true_positives + self.true_negatives) / total if total > 0 else 0.0


def run_benchmark(guard: PromptGuard, use_llm: bool = False) -> BenchmarkMetrics:
    corpus = load_json(CORPUS_PATH)
    metrics = BenchmarkMetrics()

    table = Table(title="Benchmark Results", show_lines=True)
    table.add_column("ID", style="dim", width=12)
    table.add_column("Label", width=10)
    table.add_column("Detected", width=10)
    table.add_column("Score", justify="right", width=8)
    table.add_column("Result", width=8)

    for entry in corpus:
        result = guard.scan(entry["text"], use_llm=use_llm)
        is_malicious = entry["label"] == "malicious"
        detected = result.is_suspicious

        if is_malicious and detected:
            metrics.true_positives += 1
            status = "[green]TP[/]"
        elif is_malicious and not detected:
            metrics.false_negatives += 1
            status = "[red]FN[/]"
        elif not is_malicious and detected:
            metrics.false_positives += 1
            status = "[yellow]FP[/]"
        else:
            metrics.true_negatives += 1
            status = "[green]TN[/]"

        label_style = "red" if is_malicious else "green"
        det_style = "red" if detected else "green"
        table.add_row(
            entry["id"],
            f"[{label_style}]{entry['label']}[/]",
            f"[{det_style}]{'suspicious' if detected else 'clean'}[/]",
            f"{result.risk_score:.0f}",
            status,
        )

    console.print(table)

    # Print metrics summary
    console.print(
        Panel(
            f"[bold]Precision:[/] {metrics.precision:.2%}\n"
            f"[bold]Recall:[/]    {metrics.recall:.2%}\n"
            f"[bold]F1 Score:[/]  {metrics.f1_score:.2%}\n"
            f"[bold]Accuracy:[/]  {metrics.accuracy:.2%}\n\n"
            f"TP: {metrics.true_positives} | FP: {metrics.false_positives} | "
            f"TN: {metrics.true_negatives} | FN: {metrics.false_negatives}",
            title="Detection Metrics",
        )
    )

    # Export
    ts = timestamp()
    report_path = REPORTS_DIR / f"benchmark_report_{ts}.json"
    save_json(
        {
            "timestamp": ts,
            "use_llm": use_llm,
            "precision": metrics.precision,
            "recall": metrics.recall,
            "f1_score": metrics.f1_score,
            "accuracy": metrics.accuracy,
            "confusion_matrix": {
                "TP": metrics.true_positives,
                "FP": metrics.false_positives,
                "TN": metrics.true_negatives,
                "FN": metrics.false_negatives,
            },
        },
        report_path,
    )
    console.print(f"\n[dim]Report saved to: {report_path}[/]")

    return metrics

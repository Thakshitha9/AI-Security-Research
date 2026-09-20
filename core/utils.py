import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table

console = Console()


def load_json(path: str | Path) -> list | dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_json(data: list | dict, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def render_table(title: str, columns: list[str], rows: list[list[str]]) -> None:
    table = Table(title=title, show_lines=True)
    for col in columns:
        table.add_column(col)
    for row in rows:
        table.add_row(*row)
    console.print(table)


def save_markdown_report(title: str, sections: list[tuple[str, str]], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# {title}\n", f"*Generated: {datetime.now().isoformat()}*\n"]
    for heading, content in sections:
        lines.append(f"\n## {heading}\n")
        lines.append(content + "\n")
    path.write_text("\n".join(lines), encoding="utf-8")

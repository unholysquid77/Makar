"""One-command demonstration: generate, analyse, score, report, stream.

    python scripts/demo.py
    python scripts/demo.py --seed 271828 --records 5000

Runs the whole pipeline end to end and prints the headline figures, so a
reviewer can reproduce every number in the README with a single command.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

app = typer.Typer(add_completion=False, help="Run the full Makar demonstration.")
console = Console()


def run(label: str, args: list[str]) -> float:
    """Run a step as a subprocess so each stage is independently reproducible."""
    console.rule(f"[bold cyan]{label}")
    start = time.perf_counter()
    result = subprocess.run([sys.executable, *args], cwd=ROOT, check=False)
    elapsed = time.perf_counter() - start
    if result.returncode != 0:
        console.print(f"[red]{label} failed with exit code {result.returncode}[/]")
        raise typer.Exit(result.returncode)
    return elapsed


@app.command()
def main(
    seed: int = typer.Option(481516, help="World seed."),
    records: int = typer.Option(5000, help="Target record count."),
    out: Path = typer.Option(Path("out"), help="Dataset directory."),
    events: int = typer.Option(900, help="Live stream events to replay."),
    skip_generate: bool = typer.Option(False, help="Reuse an existing dataset."),
) -> None:
    timings: dict[str, float] = {}

    if not skip_generate:
        timings["generate"] = run(
            "1 / 4  Generate the synthetic world and the suspect manifest",
            [
                "scripts/generate.py",
                "--seed", str(seed),
                "--records", str(records),
                "--out", str(out),
            ],
        )

    timings["evaluate"] = run(
        "2 / 4  Analyse and score against the private injection log",
        ["scripts/evaluate.py", "--out", str(out), "--ablation"],
    )

    timings["report"] = run(
        "3 / 4  Render the suspicious activity report",
        ["scripts/report.py", "--out", str(out), "--top", "25"],
    )

    timings["stream"] = run(
        "4 / 4  Replay the live feed with attack patterns absent from the batch",
        ["scripts/stream_sim.py", "--out", str(out), "--events", str(events)],
    )

    console.rule("[bold cyan]Summary")
    table = Table(header_style="bold magenta")
    table.add_column("Stage")
    table.add_column("Seconds", justify="right")
    for stage, seconds in timings.items():
        table.add_row(stage, f"{seconds:.1f}")
    table.add_row("[bold]total", f"[bold]{sum(timings.values()):.1f}")
    console.print(table)

    console.print(f"\n[green]Artifacts in[/] {out.resolve()}")
    for name in (
        "manifest_suspect.csv",
        "ground_truth.json",
        "evaluation.json",
        "report.md",
        "stream_evaluation.json",
    ):
        path = out / name
        mark = "ok  " if path.exists() else "MISS"
        console.print(f"  {mark} {name}")

    console.print(
        "\n[bold]Next:[/] start the API with "
        "[cyan]python -m backend.main[/] and the UI with "
        "[cyan]npm --prefix frontend run dev[/], then open "
        "[cyan]http://localhost:5173[/]"
    )


if __name__ == "__main__":
    app()

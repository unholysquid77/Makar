"""Evaluation console (spec 31, and the problem statement's evaluation deliverable).

    python scripts/evaluate.py --out out
    python scripts/evaluate.py --out out --ablation

Scores the pipeline's output against the private injection log and prints the
metrics the problem statement asks for: precision, recall and false alarms,
broken down by attack type, plus classification accuracy, repair accuracy,
deletion detection and a calibration table.

``--ablation`` additionally re-runs the analysis with the provenance layer
disabled. The provenance chain is the strongest single evidence source in the
system, so reporting only the headline number would hide how much of the work
the forensic engines actually do. See docs/DESIGN_DECISIONS.md D9.
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.config import load_config  # noqa: E402
from core.io import write_json  # noqa: E402
from core.pipeline import analyze_directory  # noqa: E402
from evaluation import evaluate, load_ground_truth  # noqa: E402

app = typer.Typer(add_completion=False, help="Score Makar against the private answer key.")
console = Console()

#: Detector set with the provenance layer removed, for the ablation.
_NO_PROVENANCE = ["temporal", "geospatial", "route", "cargo", "duplicate", "statistical", "graph"]


def _detection_table(reports: list[tuple[str, dict]]) -> Table:
    table = Table(title="Detection", header_style="bold magenta")
    table.add_column("Configuration")
    for column in ("Precision", "Recall", "F1", "FP (clean)", "FP (noisy)", "FN"):
        table.add_column(column, justify="right")
    for label, data in reports:
        det, alarms = data["detection"], data["false_alarms"]
        table.add_row(
            label,
            f"{det['precision']:.3f}",
            f"{det['recall']:.3f}",
            f"{det['f1']:.3f}",
            str(alarms["on_clean_records"]),
            str(alarms["on_noise_only_records"]),
            str(det["false_negatives"]),
        )
    return table


@app.command()
def main(
    out: Path = typer.Option(Path("out"), help="Dataset directory to score."),
    manifest: str = typer.Option("manifest_suspect.csv", help="Manifest file to analyse."),
    threshold: float = typer.Option(None, help="Override the suspicion threshold."),
    ablation: bool = typer.Option(False, help="Also score with the provenance layer disabled."),
    save: bool = typer.Option(True, help="Write evaluation.json into the dataset directory."),
) -> None:
    cfg = load_config()
    cut = threshold if threshold is not None else cfg.float_("fusion.thresholds.suspicious")
    truth = load_ground_truth(out / "ground_truth.json")

    console.print("[bold cyan]MAKAR[/] evaluation console")
    console.print(f"  dataset   : {out.resolve()}")
    console.print(f"  threshold : {cut}")
    console.print(f"  answer key: {len(truth.log.entries)} injection entries, "
                  f"{len(truth.tampered)} tampered records, "
                  f"{len(truth.deleted)} deletions, "
                  f"{len(truth.noise_only)} noise-only records\n")

    runs: list[tuple[str, dict]] = []

    result, _ctx, _arb = analyze_directory(out, cfg=cfg, manifest=manifest)
    full = evaluate(result, truth, threshold=cut, label="all detectors")
    runs.append(("All detectors", full.as_dict()))

    if ablation:
        ablated_result, _c, _a = analyze_directory(
            out, cfg=cfg, manifest=manifest, enabled_detectors=_NO_PROVENANCE
        )
        ablated = evaluate(
            ablated_result, truth, threshold=cut, label="provenance layer disabled"
        )
        runs.append(("Forensics only (no chain)", ablated.as_dict()))

    console.print(_detection_table(runs))

    data = runs[0][1]

    # --- recall by attack type ---
    table = Table(title="Recall by attack type", header_style="bold magenta")
    table.add_column("Attack")
    table.add_column("Injected", justify="right")
    table.add_column("Detected", justify="right")
    table.add_column("Recall", justify="right")
    for attack, stats in data["recall_by_attack"].items():
        table.add_row(
            attack, str(stats["population"]), str(stats["detected"]), f"{stats['recall']:.1%}"
        )
    deletions = data["deletions"]
    table.add_row(
        "DELETED (by slot)",
        str(deletions["injected_slots"]),
        str(deletions["slots_matched"]),
        f"{deletions['slot_recall']:.1%}",
    )
    console.print(table)

    # --- classification ---
    classification = data["classification"]
    table = Table(
        title=f"Tampering classification (accuracy {classification['accuracy']:.1%} "
        f"over {classification['scored']} detected records)",
        header_style="bold magenta",
    )
    table.add_column("Ground truth")
    table.add_column("Predicted")
    for expected, predictions in classification["confusion"].items():
        table.add_row(
            expected,
            ", ".join(f"{k} x{v}" for k, v in sorted(predictions.items(), key=lambda kv: -kv[1])),
        )
    console.print(table)

    # --- repair ---
    repair = data["repair"]
    table = Table(title="Reconstruction", header_style="bold magenta")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    for key in (
        "repaired_records",
        "verifiable_records",
        "exact_record_matches",
        "record_accuracy",
        "fields_scored",
        "fields_correct",
        "field_accuracy",
        "mean_repair_confidence",
    ):
        value = repair[key]
        table.add_row(
            key.replace("_", " "),
            f"{value:.1%}" if isinstance(value, float) and value <= 1.0 else str(value),
        )
    console.print(table)

    table = Table(title="Repair accuracy by field", header_style="bold magenta")
    table.add_column("Field")
    table.add_column("Correct", justify="right")
    table.add_column("Scored", justify="right")
    table.add_column("Accuracy", justify="right")
    for field_name, stats in repair["by_field"].items():
        table.add_row(
            field_name, str(stats["correct"]), str(stats["scored"]), f"{stats['accuracy']:.1%}"
        )
    console.print(table)

    # --- deletions ---
    table = Table(title="Deletion detection", header_style="bold magenta")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    for key, value in deletions.items():
        table.add_row(
            key.replace("_", " "),
            f"{value:.1%}" if isinstance(value, float) else str(value),
        )
    console.print(table)

    # --- calibration ---
    table = Table(
        title="Calibration (does a stated probability mean what it says?)",
        header_style="bold magenta",
    )
    for column in ("Probability bin", "Records", "Mean predicted", "Observed rate", "Gap"):
        table.add_column(column, justify="right")
    for row in data["calibration"]:
        table.add_row(
            row["bin"],
            str(row["count"]),
            f"{row['mean_predicted']:.3f}",
            f"{row['observed_rate']:.3f}",
            f"{row['gap']:+.3f}",
        )
    console.print(table)

    # --- disposition ---
    table = Table(title="Reconstructed manifest disposition", header_style="bold magenta")
    table.add_column("Classification")
    table.add_column("Records", justify="right")
    for key, value in data["disposition"].items():
        table.add_row(key, str(value))
    console.print(table)

    if save:
        payload = {label: report for label, report in runs}
        path = write_json(out / "evaluation.json", payload)
        console.print(f"\n[green]Wrote[/] {path}")


if __name__ == "__main__":
    app()

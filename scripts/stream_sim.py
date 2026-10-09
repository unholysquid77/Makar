"""Live stream simulator (problem statement deliverable).

    python scripts/stream_sim.py --out out --events 200

Builds a reproducible live feed containing attack patterns **absent from the
batch data**, replays it through the incremental processor, and scores the
result against the stream's own private answer key.

The stream's novel patterns each defeat a different batch assumption:

* ``weight_siphon``   — many steps, each inside the per-step conservation
  tolerance, large in total. Attacks the tolerance itself.
* ``ghost_transfer``  — a transfer at a port the container never reached.
  Attacks lineage.
* ``identity_swap``   — two containers exchange ids mid-voyage. Attacks
  identity continuity.

``--rate`` replays in real time for a live demo; the default runs as fast as
possible.
"""

from __future__ import annotations

import sys
import time
from collections import Counter
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.config import load_config  # noqa: E402
from core.io import read_json, read_rows, write_json  # noqa: E402
from core.models import World  # noqa: E402
from core.normalization import normalize_rows  # noqa: E402
from core.pipeline import load_provenance  # noqa: E402
from core.streaming import StreamProcessor  # noqa: E402
from generator.stream import NOVEL_PATTERNS, build_stream  # noqa: E402

app = typer.Typer(add_completion=False, help="Replay a live feed through Makar.")
console = Console()


@app.command()
def main(
    out: Path = typer.Option(Path("out"), help="Dataset directory."),
    events: int = typer.Option(200, help="Number of live events to generate."),
    seed: int = typer.Option(None, help="Stream seed (defaults to world seed + 8191)."),
    rate: float = typer.Option(
        0.0, help="Events per second for a real-time demo. 0 = as fast as possible."
    ),
    threshold: float = typer.Option(None, help="Override the suspicion threshold."),
    show: int = typer.Option(12, help="How many detections to print."),
    save: bool = typer.Option(True, help="Write stream_evaluation.json."),
) -> None:
    cfg = load_config()
    cut = (
        threshold
        if threshold is not None
        else cfg.float_("stream.alert_threshold", cfg.float_("fusion.thresholds.suspicious"))
    )

    world = World.model_validate(read_json(out / "world.json"))
    batch_rows = read_rows(out / "manifest_suspect.csv")
    batch = normalize_rows(batch_rows, world, cfg)
    provenance = load_provenance(cfg, world, out)

    console.print("[bold cyan]MAKAR[/] live stream simulator")
    console.print(f"  batch records : {len(batch.records):,}")
    console.print(f"  alert threshold: {cut} (live triage; batch adjudication uses "
                  f"{cfg.float_('fusion.thresholds.suspicious')})")
    console.print(f"  novel patterns: {', '.join(NOVEL_PATTERNS)}")

    plan = build_stream(cfg, world, batch.records, count=events, seed=seed)

    # Register the feed's new bookings in the world model. A real deployment
    # receives a booking in master data before its events start flowing; the
    # detector is entitled to know a shipment exists, and nothing about which
    # of its events were later tampered with.
    for shipment in plan.new_shipments:
        world.shipments[shipment.shipment_id] = shipment
    for container in plan.new_containers:
        world.containers[container.container_id] = container

    console.print(f"  stream seed   : {plan.seed}")
    console.print(
        f"  new bookings  : {len(plan.new_shipments)} shipments, "
        f"{len(plan.new_containers)} containers"
    )
    console.print(
        f"  events        : {plan.summary.get('total', 0)} "
        f"({plan.summary.get('legitimate', 0)} legitimate)"
    )
    injected = {k: v for k, v in plan.summary.items() if k in NOVEL_PATTERNS}
    console.print(f"  injected      : {injected}\n")

    processor = StreamProcessor(
        cfg,
        world,
        batch.records,
        chain=provenance.chain,
        consistency=provenance.consistency,
    )

    detections: list[dict] = []
    truth_by_sequence = {e.sequence: e.truth for e in plan.events}
    interval = 1.0 / rate if rate > 0 else 0.0

    for event in plan.events:
        verdict = processor.ingest(event.row, sequence=event.sequence)
        if verdict.verdict.tampering_probability >= cut and verdict.is_suspicious:
            detections.append(verdict.as_dict())
        if interval:
            time.sleep(interval)

    # --- score against the stream's own answer key ---
    flagged = {d["sequence"] for d in detections}
    attacked = {seq for seq, truth in truth_by_sequence.items() if truth.get("attack")}
    legitimate = set(truth_by_sequence) - attacked

    # A flag on a legitimate event is only a false alarm if that container was
    # never attacked. Once an injected record sits in a container's history,
    # later legitimate records of that container genuinely contradict it, and
    # noticing that is correct behaviour -- penalising it would score the
    # system down for spotting the contamination it is supposed to spot. Both
    # numbers are reported so the distinction is visible rather than assumed.
    attacked_containers = {
        truth.get("container_id")
        for truth in truth_by_sequence.values()
        if truth.get("attack") and truth.get("container_id")
    }
    container_by_sequence = {
        e.sequence: e.row.get("container_id") for e in plan.events
    }
    collateral = {
        seq
        for seq in flagged & legitimate
        if container_by_sequence.get(seq) in attacked_containers
    }

    tp = len(flagged & attacked)
    fp = len(flagged & legitimate) - len(collateral)
    fn = len(attacked - flagged)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, len(attacked))
    f1 = 2 * precision * recall / max(1e-9, precision + recall)

    table = Table(title="Live stream detection", header_style="bold magenta")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    for name, value in (
        ("events replayed", processor.processed),
        ("attacks injected", len(attacked)),
        ("legitimate events", len(legitimate)),
        ("detected", tp),
        ("missed", fn),
        ("flags on attacked containers", len(collateral)),
        ("false alarms (clean containers)", fp),
        ("precision", f"{precision:.3f}"),
        ("recall", f"{recall:.3f}"),
        ("f1", f"{f1:.3f}"),
    ):
        table.add_row(name, str(value))
    console.print(table)

    # --- per-pattern recall: the headline for the novel-attack requirement ---
    per_pattern: dict[str, list[int]] = {}
    # Campaigns: a siphon or an identity swap spans many events for one
    # container. Once the state is consistently wrong, later events are
    # internally consistent and there is nothing left to contradict -- so
    # per-event recall systematically understates. Campaign recall ("did we
    # catch this container being attacked at all?") is the operationally
    # meaningful number, and both are reported.
    campaigns: dict[str, dict[str, list[int]]] = {}
    for sequence, truth in truth_by_sequence.items():
        attack = truth.get("attack")
        if not attack:
            continue
        per_pattern.setdefault(attack, []).append(sequence)
        container = truth.get("container_id") or f"seq{sequence}"
        campaigns.setdefault(attack, {}).setdefault(container, []).append(sequence)

    table = Table(
        title="Recall by novel attack pattern (absent from batch data)",
        header_style="bold magenta",
    )
    table.add_column("Pattern")
    table.add_column("Events", justify="right")
    table.add_column("Caught", justify="right")
    table.add_column("Event recall", justify="right")
    table.add_column("Campaigns", justify="right")
    table.add_column("Caught", justify="right")
    table.add_column("Campaign recall", justify="right")
    campaign_recall: dict[str, dict] = {}
    for pattern, sequences in sorted(per_pattern.items()):
        hit = len(set(sequences) & flagged)
        groups = campaigns.get(pattern, {})
        caught = sum(1 for seqs in groups.values() if set(seqs) & flagged)
        campaign_recall[pattern] = {
            "campaigns": len(groups),
            "caught": caught,
            "recall": round(caught / max(1, len(groups)), 4),
        }
        table.add_row(
            pattern,
            str(len(sequences)),
            str(hit),
            f"{hit / max(1, len(sequences)):.1%}",
            str(len(groups)),
            str(caught),
            f"{caught / max(1, len(groups)):.1%}",
        )
    console.print(table)

    stats = processor.stats()
    table = Table(title="Incremental throughput", header_style="bold magenta")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    for name, value in (
        ("mean latency (ms)", stats["latency_ms"]["mean"]),
        ("p50 latency (ms)", stats["latency_ms"]["p50"]),
        ("p95 latency (ms)", stats["latency_ms"]["p95"]),
        ("max latency (ms)", stats["latency_ms"]["max"]),
        ("records in state", stats["records_total"]),
    ):
        table.add_row(name, str(value))
    console.print(table)

    if detections:
        table = Table(title=f"First {show} detections", header_style="bold magenta")
        for column in ("Seq", "Record", "Class", "P(tamper)", "Ground truth", "Top finding"):
            table.add_column(column)
        for detection in detections[:show]:
            truth = truth_by_sequence.get(detection["sequence"], {})
            top = detection["evidence"][0]["code"] if detection["evidence"] else "—"
            table.add_row(
                str(detection["sequence"]),
                detection["record_id"],
                detection["tamper_class"],
                f"{detection['tampering_probability']:.1%}",
                truth.get("attack", "legitimate"),
                top,
            )
        console.print(table)

    # --- which evidence codes caught the novel patterns? ---
    codes = Counter()
    for detection in detections:
        if truth_by_sequence.get(detection["sequence"], {}).get("attack"):
            for item in detection["evidence"]:
                codes[item["code"]] += 1
    if codes:
        table = Table(
            title="Evidence that caught the novel attacks "
            "(constraints, not learned signatures)",
            header_style="bold magenta",
        )
        table.add_column("Code")
        table.add_column("Times", justify="right")
        for code, count in codes.most_common(10):
            table.add_row(code, str(count))
        console.print(table)

    if save:
        payload = {
            "stream_seed": plan.seed,
            "injected": plan.summary,
            "detection": {
                "true_positives": tp,
                "false_positives": fp,
                "collateral_flags_on_attacked_containers": len(collateral),
                "false_negatives": fn,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
            },
            "campaign_recall": campaign_recall,
            "recall_by_pattern": {
                pattern: {
                    "injected": len(sequences),
                    "detected": len(set(sequences) & flagged),
                    "recall": round(len(set(sequences) & flagged) / max(1, len(sequences)), 4),
                }
                for pattern, sequences in sorted(per_pattern.items())
            },
            "throughput": stats,
            "evidence_codes": dict(codes),
            "detections": detections,
        }
        path = write_json(out / "stream_evaluation.json", payload)
        console.print(f"\n[green]Wrote[/] {path}")


if __name__ == "__main__":
    app()

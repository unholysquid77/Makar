"""Render the suspicious activity report.

    python scripts/report.py --out out

Writes ``report.md`` and ``report.json`` into the dataset directory.
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.config import load_config  # noqa: E402
from core.io import write_json  # noqa: E402
from core.pipeline import analyze_directory  # noqa: E402
from reporting import build_report_payload, render_markdown  # noqa: E402

app = typer.Typer(add_completion=False, help="Render the forensic report.")
console = Console()


@app.command()
def main(
    out: Path = typer.Option(Path("out"), help="Dataset directory."),
    manifest: str = typer.Option("manifest_suspect.csv", help="Manifest to analyse."),
    top: int = typer.Option(25, help="How many ranked records to detail."),
) -> None:
    cfg = load_config()
    console.print("[bold cyan]MAKAR[/] report generator")
    result, _ctx, _arb = analyze_directory(out, cfg=cfg, manifest=manifest)

    payload = build_report_payload(result, cfg, top_n=top)
    markdown = render_markdown(payload)

    md_path = out / "report.md"
    md_path.write_text(markdown, encoding="utf-8")
    json_path = write_json(out / "report.json", payload)

    totals = payload["totals"]
    console.print(
        f"  {totals['records']:,} records · {totals['suspicious']} suspicious · "
        f"{totals['repaired']} repaired · {totals['removed']} removed · "
        f"{totals['unrecoverable']} unrecoverable"
    )
    console.print(
        f"  {totals['benign_anomalies']:,} benign anomalies (irregular, not tampering)"
    )
    console.print(f"  {payload['inferred_deletion_count']} inferred deletions")
    console.print(f"  {len(payload['attack_windows'])} attack window(s)")
    console.print(f"\n[green]Wrote[/] {md_path}")
    console.print(f"[green]Wrote[/] {json_path}")


if __name__ == "__main__":
    app()

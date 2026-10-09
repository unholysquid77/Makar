"""Dataset generator CLI.

    python scripts/generate.py --seed 481516 --records 5000

Writes, under ``--out``:

====================================  ==================================
``manifest_suspect.csv`` / ``.json``  the system's input
``manifest_clean.csv`` / ``.json``    reference only, never read by core/
``ground_truth.json``                 PRIVATE answer key, scoring only
``world.json``                        the synthetic world model
``route_manifests.json``              per-container route histories
``data/ports.geojson``                map layer (spec 8.1)
``data/routes.geojson``               map layer (spec 8.2)
====================================  ==================================

The same ``--seed`` reproduces all of it byte for byte (spec 5.2).
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

from blockchain.chain import Chain  # noqa: E402
from blockchain.network import VirtualNetwork  # noqa: E402
from core.config import load_config  # noqa: E402
from core.io import write_json, write_model, write_rows_csv, write_rows_json  # noqa: E402
from generator.corruption import COLUMNS, corrupt_manifest, record_to_row  # noqa: E402
from generator.manifest import build_clean_manifest  # noqa: E402
from generator.world import build_world  # noqa: E402

app = typer.Typer(add_completion=False, help="Generate the synthetic maritime dataset.")
console = Console()


@app.command()
def main(
    seed: int = typer.Option(None, help="Random seed. Defaults to world.seed in config."),
    records: int = typer.Option(None, help="Target record count (never exceeded)."),
    out: Path = typer.Option(Path("out"), help="Output directory."),
    config: Path = typer.Option(None, help="Optional config overlay YAML."),
    emit_geojson: bool = typer.Option(True, help="Write data/*.geojson map layers."),
) -> None:
    overrides: dict[str, object] = {}
    if seed is not None:
        overrides["world.seed"] = seed
    if records is not None:
        overrides["world.records"] = records

    cfg = load_config(config, overrides=overrides or None)

    console.print("[bold cyan]MAKAR[/] dataset generator")
    console.print(f"  config sources : {', '.join(cfg.sources)}")

    world_seed = cfg.int_("world.seed")
    console.print(f"  seed           : [bold]{world_seed}[/]")

    world = build_world(cfg)
    console.print(
        f"  world          : {len(world.ports)} ports, {len(world.vessels)} vessels, "
        f"{len(world.routes)} routes, {len(world.owners)} owners"
    )

    clean_records, route_manifests, world = build_clean_manifest(cfg, world)
    console.print(
        f"  clean manifest : {len(clean_records)} records across "
        f"{len(world.shipments)} shipments / {len(world.containers)} containers"
    )

    result = corrupt_manifest(cfg, world, clean_records, route_manifests)
    log = result.injection_log
    console.print(f"  suspect        : {len(result.suspect_rows)} records")

    # --- provenance chain, sealed from the CLEAN records ---
    # The chain commits hashes as events are observed, i.e. before any
    # tampering. It covers a prefix of the timeline (see D9); the rest is
    # genuinely uncommitted.
    chain = Chain.build(
        clean_records,
        route_manifests,
        records_per_block=cfg.int_("blockchain.records_per_block"),
        genesis_timestamp=world.sim_start,
        sealed_fraction=cfg.float_("blockchain.sealed_fraction"),
    )
    verification = chain.verify()
    covered_from, covered_to = chain.covered_time_range()
    console.print(
        f"  chain          : {chain.height} blocks, "
        f"{len(chain.committed_record_ids())} records committed, "
        f"valid={verification.valid}"
    )
    console.print(
        f"  chain coverage : {covered_from} -> {covered_to} "
        f"({cfg.float_('blockchain.sealed_fraction'):.0%} of timeline)"
    )

    network = VirtualNetwork.build(
        cfg, chain, seed=world_seed, replacement_hashes=result.post_attack_hashes
    )
    consistency = network.check_consistency()
    console.print(
        f"  nodes          : agreeing={consistency.agreeing_nodes} "
        f"divergent={consistency.divergent_nodes}"
    )

    out.mkdir(parents=True, exist_ok=True)
    cols = list(COLUMNS)

    clean_rows = [record_to_row(r) for r in clean_records]
    write_rows_csv(out / "manifest_clean.csv", clean_rows, cols)
    write_rows_json(out / "manifest_clean.json", clean_rows)
    write_rows_csv(out / "manifest_suspect.csv", result.suspect_rows, cols)
    write_rows_json(out / "manifest_suspect.json", result.suspect_rows)
    write_model(out / "ground_truth.json", log)
    write_model(out / "world.json", world)
    write_json(
        out / "route_manifests.json",
        {cid: m.model_dump(mode="json") for cid, m in route_manifests.items()},
    )
    write_json(out / "config_used.json", cfg.as_dict())
    write_json(out / "chain.json", chain.to_dict())
    write_json(out / "nodes.json", network.summary())
    write_json(
        out / "node_chains.json",
        {n.node_id: n.chain.to_dict() for n in network.nodes},
    )

    if emit_geojson:
        write_json(ROOT / "data" / "ports.geojson", world.ports_geojson())
        write_json(ROOT / "data" / "routes.geojson", world.routes_geojson())

    table = Table(title="Injection summary (private ground truth)", header_style="bold magenta")
    table.add_column("Attack class")
    table.add_column("Count", justify="right")
    for key in ("MODIFIED", "DELETED", "DUPLICATED", "FABRICATED", "NOISE", "clusters"):
        if key in log.summary:
            table.add_row(key, str(log.summary[key]))
    console.print(table)

    console.print(f"\n[green]Wrote[/] {out.resolve()}")
    console.print(
        "[yellow]ground_truth.json is the private answer key[/] - "
        "it is used only by scripts/evaluate.py and is never read by core/."
    )


if __name__ == "__main__":
    app()

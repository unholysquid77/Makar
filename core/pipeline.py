"""The analysis pipeline.

One entry point, :func:`analyze`, runs the full chain in the order the
architecture requires::

    rows
      -> normalise                 (typed records + FORMAT evidence)
      -> build provenance view     (majority chain + node consistency)
      -> run detectors             (independent evidence layers)
      -> arbitrate                 (decide who to blame in a contradiction)
      -> fuse                      (calibrated probability + breakdown)
      -> classify                  (what kind of tampering)
      -> reconstruct               (candidate original state, or removal)
      -> attack timeline           (group anomalies into windows)
      -> annotate graph            (evidential edges for Bloodhound)

Nothing here reads the injection log. The only inputs are the manifest, the
world model and the provenance chain.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

# Importing the engines registers them in DETECTOR_REGISTRY.
import core.detection.cargo  # noqa: F401
import core.detection.duplicates  # noqa: F401
import core.detection.provenance  # noqa: F401
import core.detection.route  # noqa: F401
import core.detection.statistical  # noqa: F401
import core.geospatial.engine  # noqa: F401
import core.graph.engine  # noqa: F401
import core.temporal.engine  # noqa: F401
from core.confidence.arbitration import ArbitrationResult, arbitrate
from core.confidence.classifier import classify
from core.confidence.fusion import fuse
from core.config import MakarConfig, load_config
from core.detection.base import AnalysisContext, build_context, run_detectors
from core.io import read_json, read_rows
from core.models import (
    AnalysisResult,
    ConsistencyReport,
    Evidence,
    ManifestSummary,
    World,
)
from core.normalization import normalize_rows
from core.normalization.resolver import EntityResolver
from core.types import Classification, EvidenceType


@dataclass
class ProvenanceView:
    """What the pipeline knows about the provenance network."""

    chain: Any = None
    consistency: ConsistencyReport | None = None
    node_summary: dict[str, Any] = field(default_factory=dict)


def load_provenance(
    cfg: MakarConfig,
    world: World,
    directory: str | Path,
) -> ProvenanceView:
    """Load the chain and node set, returning the *majority* chain.

    Reading the majority chain rather than any single node's is what stops a
    compromised node from laundering its own edits.
    """
    directory = Path(directory)
    chain_path = directory / "chain.json"
    if not chain_path.exists():
        return ProvenanceView()

    from blockchain.chain import Chain
    from blockchain.network import VirtualNetwork

    canonical = Chain.from_dict(read_json(chain_path))
    network = VirtualNetwork.build(cfg, canonical, seed=world.seed)

    # Replace each node's chain with its persisted state, so the analysis sees
    # the network as it actually stands rather than an idealised copy.
    node_chains_path = directory / "node_chains.json"
    if node_chains_path.exists():
        persisted = read_json(node_chains_path)
        for node in network.nodes:
            if node.node_id in persisted:
                node.chain = Chain.from_dict(persisted[node.node_id])

    consistency = network.check_consistency()
    return ProvenanceView(
        chain=network.healthy_chain,
        consistency=consistency,
        node_summary=network.summary(),
    )


def analyze(
    rows: list[dict[str, Any]],
    world: World,
    cfg: MakarConfig | None = None,
    *,
    provenance: ProvenanceView | None = None,
    clock: datetime | None = None,
    enabled_detectors: list[str] | None = None,
    run_id: str | None = None,
) -> tuple[AnalysisResult, AnalysisContext, ArbitrationResult]:
    """Run the full forensic pipeline over raw manifest rows."""
    cfg = cfg or load_config()
    provenance = provenance or ProvenanceView()
    timings: dict[str, float] = {}

    def timed(label: str, start: float) -> None:
        timings[label] = round((time.perf_counter() - start) * 1000.0, 2)

    # --- 1. normalise ---
    start = time.perf_counter()
    resolver = EntityResolver(world)
    norm = normalize_rows(rows, world, cfg, resolver=resolver)
    timed("normalize", start)

    # --- 2. context ---
    start = time.perf_counter()
    ctx = build_context(
        cfg,
        world,
        norm.records,
        resolver=resolver,
        clock=clock or world.sim_end,
        prior_evidence=norm.evidence,
        chain=provenance.chain,
        consistency=provenance.consistency,
    )
    timed("index", start)

    # --- 3. detectors ---
    detector_evidence, detector_timings = run_detectors(ctx, enabled=enabled_detectors)
    timings.update({f"detect.{k}": round(v, 2) for k, v in detector_timings.items()})

    # Normalisation evidence joins the pool: FORMAT findings must participate
    # in fusion, where their negative weight discounts messy records.
    all_evidence: list[Evidence] = [
        *norm.evidence,
        *[e for e in detector_evidence if e.record_id != "__system__"],
    ]

    # --- 4. arbitration ---
    start = time.perf_counter()
    arbitration = arbitrate(ctx, all_evidence)
    timed("arbitrate", start)
    evidence = arbitration.evidence

    by_record: dict[str, list[Evidence]] = {}
    for item in evidence:
        by_record.setdefault(item.record_id, []).append(item)

    # --- 5. fuse + classify ---
    start = time.perf_counter()
    record_ids = [r.record_id for r in norm.records]
    verdicts = fuse(cfg, by_record, record_ids=record_ids)
    verdicts = classify(cfg, verdicts, by_record)
    timed("fuse_classify", start)

    # --- 6. reconstruct ---
    start = time.perf_counter()
    from core.reconstruction.engine import reconstruct_all

    reconstructions = reconstruct_all(ctx, verdicts, by_record)
    timed("reconstruct", start)

    # --- 7. attack timeline ---
    start = time.perf_counter()
    from core.timeline import build_attack_timeline

    windows = build_attack_timeline(ctx, verdicts)
    timed("timeline", start)

    # --- 8. assemble ---
    summary = _summarise(cfg, verdicts, reconstructions, by_record)
    result = AnalysisResult(
        run_id=run_id or uuid.uuid4().hex[:12],
        created_at=datetime.now(),
        seed=world.seed,
        config_sources=cfg.sources,
        summary=summary,
        records=norm.records,
        evidence=evidence,
        verdicts=verdicts,
        reconstructions=reconstructions,
        attack_windows=windows,
        consistency=provenance.consistency,
        inferred_deletions=_dedupe_deletions(ctx.inferred_deletions),
        timings_ms=timings,
    )
    return result, ctx, arbitration


def _dedupe_deletions(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse duplicate deletion inferences, keeping the most confident.

    The provenance layer and the graph layer often infer the same deletion by
    different routes. That corroboration raises confidence, so the merged
    entry records both sources rather than discarding one.
    """
    merged: dict[tuple, dict[str, Any]] = {}
    for entry in entries:
        key = (
            entry.get("record_id"),
            entry.get("container_id"),
            entry.get("port_id"),
            entry.get("missing_event"),
        )
        existing = merged.get(key)
        if existing is None:
            merged[key] = {**entry, "sources": [entry.get("source")]}
            continue
        existing["sources"] = sorted({*existing.get("sources", []), entry.get("source")})
        if entry.get("confidence", 0) > existing.get("confidence", 0):
            existing.update(
                {k: v for k, v in entry.items() if k != "sources"},
            )
        # Independent corroboration: two different routes to the same
        # conclusion is worth more than either alone.
        if len(existing["sources"]) > 1:
            existing["confidence"] = round(
                min(0.98, existing.get("confidence", 0) + 0.10), 3
            )
    return sorted(
        merged.values(), key=lambda e: e.get("confidence", 0), reverse=True
    )


def _summarise(
    cfg: MakarConfig,
    verdicts: dict[str, Any],
    reconstructions: dict[str, Any],
    by_record: dict[str, list[Evidence]],
) -> ManifestSummary:
    threshold = cfg.float_("fusion.thresholds.suspicious")
    summary = ManifestSummary(total_records=len(verdicts))

    for verdict in verdicts.values():
        if verdict.tampering_probability >= threshold:
            summary.suspicious += 1
        key = verdict.tamper_class
        summary.by_tamper_class[key] = summary.by_tamper_class.get(key, 0) + 1

    for items in by_record.values():
        for item in items:
            etype = EvidenceType(str(item.type))
            summary.by_evidence_type[etype] = summary.by_evidence_type.get(etype, 0) + 1

    confidences: list[float] = []
    for recon in reconstructions.values():
        if recon.classification is Classification.ORIGINAL:
            summary.original += 1
        elif recon.classification is Classification.REPAIRED:
            summary.repaired += 1
            confidences.append(recon.confidence)
        elif recon.classification is Classification.REMOVED:
            summary.removed += 1
            confidences.append(recon.confidence)
        else:
            summary.unrecoverable += 1

    summary.mean_repair_confidence = (
        round(sum(confidences) / len(confidences), 4) if confidences else 0.0
    )
    return summary


def analyze_directory(
    directory: str | Path,
    *,
    cfg: MakarConfig | None = None,
    manifest: str = "manifest_suspect.csv",
    enabled_detectors: list[str] | None = None,
) -> tuple[AnalysisResult, AnalysisContext, ArbitrationResult]:
    """Convenience wrapper: analyse a generated dataset directory."""
    directory = Path(directory)
    cfg = cfg or load_config()
    world = World.model_validate(read_json(directory / "world.json"))
    rows = read_rows(directory / manifest)
    provenance = load_provenance(cfg, world, directory)
    return analyze(
        rows,
        world,
        cfg,
        provenance=provenance,
        enabled_detectors=enabled_detectors,
    )


#: Re-exported so the API and scripts can discover detector names.
from core.detection.base import DETECTOR_REGISTRY  # noqa: E402

__all__ = [
    "DETECTOR_REGISTRY",
    "ProvenanceView",
    "analyze",
    "analyze_directory",
    "load_provenance",
]

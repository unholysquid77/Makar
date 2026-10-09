"""In-process analysis store.

Holds one loaded dataset, its analysis result, the derived graph and a live
stream processor. The whole analysis is held in memory because it is the
natural shape for an investigation surface: every endpoint is a different view
of the *same* run, and recomputing or re-querying a database per view would
make the UI's cross-linking (graph -> map -> timeline -> record) slow and
inconsistent.

A re-analysis swaps the whole object atomically, so a request in flight always
sees a coherent snapshot rather than a half-updated one.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.confidence.arbitration import ArbitrationResult
from core.config import MakarConfig, load_config
from core.detection.base import AnalysisContext
from core.graph.model import CargoGraph, annotate_with_evidence, build_graph
from core.io import read_json, read_rows
from core.models import AnalysisResult, Evidence, World
from core.pipeline import ProvenanceView, analyze, load_provenance
from core.streaming import StreamProcessor


@dataclass
class Snapshot:
    """One coherent analysis run plus everything derived from it."""

    cfg: MakarConfig
    world: World
    result: AnalysisResult
    ctx: AnalysisContext
    arbitration: ArbitrationResult
    graph: CargoGraph
    provenance: ProvenanceView
    directory: Path
    evidence_by_record: dict[str, list[Evidence]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for item in self.result.evidence:
            self.evidence_by_record.setdefault(item.record_id, []).append(item)


class AnalysisStore:
    """Thread-safe holder for the current snapshot and live stream."""

    def __init__(self, directory: str | Path = "out", manifest: str = "manifest_suspect.csv") -> None:
        self.directory = Path(directory)
        self.manifest = manifest
        self._lock = threading.Lock()
        self._snapshot: Snapshot | None = None
        self._stream: StreamProcessor | None = None
        self._stream_log: list[dict[str, Any]] = []

    # -- analysis ---------------------------------------------------------

    def load(
        self,
        directory: str | Path | None = None,
        manifest: str | None = None,
        *,
        enabled_detectors: list[str] | None = None,
    ) -> Snapshot:
        """Run the pipeline and install the result as the current snapshot."""
        directory = Path(directory or self.directory)
        manifest = manifest or self.manifest

        cfg = load_config()
        world = World.model_validate(read_json(directory / "world.json"))
        rows = read_rows(directory / manifest)
        provenance = load_provenance(cfg, world, directory)

        result, ctx, arbitration = analyze(
            rows, world, cfg, provenance=provenance, enabled_detectors=enabled_detectors
        )
        graph = annotate_with_evidence(build_graph(ctx), result.evidence)

        snapshot = Snapshot(
            cfg=cfg,
            world=world,
            result=result,
            ctx=ctx,
            arbitration=arbitration,
            graph=graph,
            provenance=provenance,
            directory=directory,
        )
        with self._lock:
            self.directory = directory
            self.manifest = manifest
            self._snapshot = snapshot
            # A new analysis invalidates any live session built on the old one.
            self._stream = None
            self._stream_log = []
        return snapshot

    @property
    def snapshot(self) -> Snapshot:
        if self._snapshot is None:
            return self.load()
        return self._snapshot

    @property
    def loaded(self) -> bool:
        return self._snapshot is not None

    # -- live stream ------------------------------------------------------

    def start_stream(self) -> StreamProcessor:
        """Start (or restart) a live session on top of the current snapshot."""
        snapshot = self.snapshot
        processor = StreamProcessor(
            snapshot.cfg,
            snapshot.world,
            snapshot.result.records,
            chain=snapshot.provenance.chain,
            consistency=snapshot.provenance.consistency,
        )
        with self._lock:
            self._stream = processor
            self._stream_log = []
        return processor

    @property
    def stream(self) -> StreamProcessor | None:
        return self._stream

    def record_stream_event(self, payload: dict[str, Any]) -> None:
        with self._lock:
            self._stream_log.append(payload)
            # Bounded: the UI shows a recent feed, not the whole session.
            if len(self._stream_log) > 500:
                del self._stream_log[:-500]

    def stream_log(self, limit: int = 100) -> list[dict[str, Any]]:
        return list(self._stream_log[-limit:])

    def register_world_additions(self, shipments: list[Any], containers: list[Any]) -> None:
        """Register live bookings in the world model (see generator.stream)."""
        snapshot = self.snapshot
        for shipment in shipments:
            snapshot.world.shipments[shipment.shipment_id] = shipment
        for container in containers:
            snapshot.world.containers[container.container_id] = container


#: Process-wide store. The FastAPI app installs its directory at startup.
store = AnalysisStore()

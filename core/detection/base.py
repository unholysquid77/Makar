"""Detector protocol, shared analysis context, and the detector registry.

The context is built once and holds every index the engines need. That is
both a performance decision -- the problem statement asks for thousands of
records handled efficiently, and re-scanning the manifest inside each engine
would make the pipeline quadratic -- and a correctness one: all engines then
reason over exactly the same view of the data.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from core.config import MakarConfig
from core.models import Evidence, ManifestRecord, World
from core.normalization.resolver import EntityResolver
from core.types import EVENT_ORDER


def _sort_key(rec: ManifestRecord) -> tuple[datetime, int, str]:
    """Order records by event time, then lifecycle order, then id.

    Records whose timestamps were destroyed sort to the end rather than
    crashing the sort, and are reported separately by the temporal engine.
    """
    when = rec.effective_time() or datetime.max
    return (when, EVENT_ORDER.get(rec.event_type or "", 99), rec.record_id)


@dataclass
class AnalysisContext:
    """Everything the detection engines read, indexed once up front."""

    cfg: MakarConfig
    world: World
    records: list[ManifestRecord]
    resolver: EntityResolver

    #: The analysis clock -- "now" for the purpose of future-event detection.
    #: This is an externally known fact (when the manifest was pulled), not
    #: something derived from the data, because deriving it from the data
    #: would let a future-dated forgery move the goalposts.
    clock: datetime = field(default_factory=datetime.utcnow)

    by_id: dict[str, ManifestRecord] = field(default_factory=dict)
    by_container: dict[str, list[ManifestRecord]] = field(default_factory=dict)
    by_shipment: dict[str, list[ManifestRecord]] = field(default_factory=dict)
    by_port: dict[str, list[ManifestRecord]] = field(default_factory=dict)
    by_owner: dict[str, list[ManifestRecord]] = field(default_factory=dict)
    by_route: dict[str, list[ManifestRecord]] = field(default_factory=dict)
    #: Records in event-time order, used by every sequential check.
    chronological: list[ManifestRecord] = field(default_factory=list)
    #: Evidence carried in from normalisation, so engines can see what the
    #: parser already knows (e.g. "this record has no usable timestamp").
    prior_evidence: list[Evidence] = field(default_factory=list)
    #: Side channel for records a detector believes were *removed*. A deleted
    #: record has no row to attach evidence to, so the inference is reported
    #: here and surfaces in the report as its own section (spec 18.2).
    inferred_deletions: list[dict] = field(default_factory=list)
    #: The provenance chain the *majority* of nodes agree on, or ``None`` when
    #: no chain is available. Typed loosely to keep ``core`` free of an
    #: import-time dependency on ``blockchain`` (a ``blockchain.chain.Chain``).
    chain: Any = None
    #: Cross-node consistency result (a ``core.models.ConsistencyReport``).
    consistency: Any = None

    def build_indexes(self) -> None:
        self.by_id = {r.record_id: r for r in self.records}
        for rec in self.records:
            if rec.container_id:
                self.by_container.setdefault(rec.container_id, []).append(rec)
            if rec.shipment_id:
                self.by_shipment.setdefault(rec.shipment_id, []).append(rec)
            if rec.port_id:
                self.by_port.setdefault(rec.port_id, []).append(rec)
            owner_id = self.resolver.owner_id_for(rec.owner)
            if owner_id:
                self.by_owner.setdefault(owner_id, []).append(rec)
            if rec.route_id:
                self.by_route.setdefault(rec.route_id, []).append(rec)

        for bucket in (self.by_container, self.by_shipment, self.by_port, self.by_route):
            for key in bucket:
                bucket[key].sort(key=_sort_key)
        self.chronological = sorted(self.records, key=_sort_key)

    # -- convenience lookups --------------------------------------------

    def container_timeline(self, container_id: str | None) -> list[ManifestRecord]:
        """All records for a container, in event order."""
        if not container_id:
            return []
        return self.by_container.get(container_id, [])

    def port_coords(self, port_id: str | None) -> tuple[float, float] | None:
        port = self.world.ports.get(port_id or "")
        return port.coords() if port else None

    def vessel_max_speed(self, vessel_id: str | None) -> float:
        """Speed ceiling for a vessel, falling back to the global default."""
        vessel = self.world.vessels.get(vessel_id or "")
        if vessel:
            return vessel.max_speed_knots
        return self.cfg.float_("vessel.max_speed_knots")

    def records_without_time(self) -> list[ManifestRecord]:
        return [r for r in self.records if r.effective_time() is None]


@runtime_checkable
class Detector(Protocol):
    """One independent reasoning layer.

    A detector observes and returns evidence. It must never decide that a
    record was tampered with -- that is the confidence layer's job, and
    keeping the boundary strict is what lets evidence be reweighted without
    touching detector code.
    """

    #: Registry key, matched against ``detection.enabled``.
    name: str

    def run(self, ctx: AnalysisContext) -> list[Evidence]:  # pragma: no cover - protocol
        ...


DETECTOR_REGISTRY: dict[str, Detector] = {}


def register_detector(detector: Detector) -> Detector:
    """Register a detector instance under its ``name``."""
    DETECTOR_REGISTRY[detector.name] = detector
    return detector


def build_context(
    cfg: MakarConfig,
    world: World,
    records: list[ManifestRecord],
    *,
    resolver: EntityResolver | None = None,
    clock: datetime | None = None,
    prior_evidence: list[Evidence] | None = None,
    chain: Any = None,
    consistency: Any = None,
) -> AnalysisContext:
    """Construct and index an :class:`AnalysisContext`."""
    ctx = AnalysisContext(
        cfg=cfg,
        world=world,
        records=records,
        resolver=resolver or EntityResolver(world),
        clock=clock or world.sim_end,
        prior_evidence=prior_evidence or [],
        chain=chain,
        consistency=consistency,
    )
    ctx.build_indexes()
    return ctx


def run_detectors(
    ctx: AnalysisContext,
    *,
    enabled: list[str] | None = None,
) -> tuple[list[Evidence], dict[str, float]]:
    """Run the enabled detectors, returning their evidence and timings.

    A detector that raises is reported and skipped rather than aborting the
    run: losing one reasoning layer degrades the analysis, while losing the
    whole analysis loses everything.
    """
    names = enabled if enabled is not None else ctx.cfg.list_("detection.enabled", [])
    if not names:
        names = list(DETECTOR_REGISTRY)

    evidence: list[Evidence] = []
    timings: dict[str, float] = {}

    for name in names:
        detector = DETECTOR_REGISTRY.get(name)
        if detector is None:
            timings[f"{name}:missing"] = 0.0
            continue
        start = time.perf_counter()
        try:
            produced = detector.run(ctx)
        except Exception as exc:  # noqa: BLE001 - deliberate isolation
            timings[f"{name}:error"] = (time.perf_counter() - start) * 1000.0
            evidence.append(
                Evidence(
                    record_id="__system__",
                    code="GRAPH_CONFLICT",  # type: ignore[arg-type]
                    type="GRAPH",  # type: ignore[arg-type]
                    severity=0.0,
                    description=f"Detector {name!r} failed: {exc}",
                    engine=name,
                    details={"error": str(exc), "detector": name},
                )
            )
            continue
        timings[name] = (time.perf_counter() - start) * 1000.0
        evidence.extend(produced)

    return evidence, timings

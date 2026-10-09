"""Incremental stream analysis (spec 30).

Re-running the full pipeline per event would cost ~10 s an event and scale
quadratically, so the live path is genuinely incremental:

* **Container-scoped engines.** Temporal, geospatial, route, cargo and graph
  reasoning all concern one container's history. The processor rebuilds a
  small context holding just that container's records — typically a dozen —
  and runs those engines over it. Cost is independent of manifest size.
* **Global indexes for duplicates.** Content hashes and structural keys are
  kept in dictionaries updated on ingest, so exact and structural duplicate
  detection against the whole manifest is a dictionary lookup.
* **Incremental peer statistics.** Per-cargo-type weight and value samples
  are carried over from the batch and extended as events arrive, so a robust
  z-score against the right peer group costs one pass over that group.
* **Provenance** is a hash comparison against the committed value, which is
  already O(1).

The important property, and the reason this works at all: the live path uses
**the same detectors and the same fusion weights** as the batch path. It is
not a second, weaker system with its own rules. Spec 30 requires the stream
to handle previously unseen attack patterns, and that is only possible if
detection rests on consistency constraints rather than on learned signatures
of the attacks already seen.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from core.confidence.arbitration import arbitrate
from core.confidence.classifier import classify
from core.confidence.fusion import fuse
from core.config import MakarConfig
from core.detection.base import DETECTOR_REGISTRY, build_context
from core.models import (
    Evidence,
    ManifestRecord,
    Reconstruction,
    RecordVerdict,
    World,
)
from core.normalization import normalize_rows
from core.normalization.resolver import EntityResolver
from core.reconstruction.engine import reconstruct_record
from core.stats import median, robust_z, severity_from_z
from core.types import EVIDENCE_CODE_TYPE, EvidenceCode, EvidenceType, TamperClass

#: Engines that reason over one container's history and can therefore run on
#: a scoped context.
_SCOPED_ENGINES: tuple[str, ...] = ("temporal", "geospatial", "route", "cargo", "graph")


@dataclass
class StreamVerdict:
    """Result of ingesting one live event."""

    sequence: int
    record: ManifestRecord
    verdict: RecordVerdict
    evidence: list[Evidence] = field(default_factory=list)
    reconstruction: Reconstruction | None = None
    latency_ms: float = 0.0

    @property
    def is_suspicious(self) -> bool:
        return self.verdict.tamper_class not in (
            TamperClass.CLEAN,
            TamperClass.BENIGN_ANOMALY,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "record_id": self.record.record_id,
            "container_id": self.record.container_id,
            "port_id": self.record.port_id,
            "event_type": self.record.event_type,
            "timestamp": self.record.timestamp.isoformat() if self.record.timestamp else None,
            "weight": self.record.weight,
            "tampering_probability": self.verdict.tampering_probability,
            "tamper_class": str(self.verdict.tamper_class),
            "class_confidence": self.verdict.class_confidence,
            "rationale": self.verdict.rationale,
            "contributions": [
                {"code": str(c.code), "type": str(c.type), "label": c.label, "points": c.points}
                for c in self.verdict.contributions
            ],
            "evidence": [
                {
                    "code": str(e.code),
                    "type": str(e.type),
                    "severity": e.severity,
                    "description": e.description,
                    "engine": e.engine,
                }
                for e in sorted(self.evidence, key=lambda e: -e.severity)
            ],
            "reconstruction": None
            if self.reconstruction is None
            else {
                "classification": str(self.reconstruction.classification),
                "confidence": self.reconstruction.confidence,
                "reason": self.reconstruction.reason,
            },
            "latency_ms": round(self.latency_ms, 2),
        }


def _ev(
    record_id: str,
    code: EvidenceCode,
    severity: float,
    description: str,
    *,
    supporting: list[str] | None = None,
    engine: str = "stream",
    **details: Any,
) -> Evidence:
    return Evidence(
        record_id=record_id,
        code=code,
        type=EvidenceType(EVIDENCE_CODE_TYPE[code]),
        severity=max(0.0, min(1.0, severity)),
        description=description,
        supporting_records=supporting or [],
        details=details,
        engine=engine,
    )


class StreamProcessor:
    """Stateful incremental analyser for the live feed."""

    def __init__(
        self,
        cfg: MakarConfig,
        world: World,
        batch_records: list[ManifestRecord],
        *,
        chain: Any = None,
        consistency: Any = None,
        clock: datetime | None = None,
    ) -> None:
        self.cfg = cfg
        self.world = world
        self.resolver = EntityResolver(world)
        self.chain = chain
        self.consistency = consistency

        self.records: list[ManifestRecord] = list(batch_records)
        self.by_container: dict[str, list[ManifestRecord]] = defaultdict(list)
        self.by_hash: dict[str, list[str]] = defaultdict(list)
        self.by_structural: dict[str, list[str]] = defaultdict(list)
        self.peer_weight: dict[str, list[float]] = defaultdict(list)
        self.peer_value: dict[str, list[float]] = defaultdict(list)

        for rec in batch_records:
            self._index(rec)

        # The live clock advances with the stream; events are "now", so they
        # are not future events merely by arriving.
        self.clock = clock or max(
            (r.effective_time() for r in batch_records if r.effective_time()),
            default=world.sim_end,
        )
        self.processed = 0
        self.suspicious = 0
        self.latencies: list[float] = []

    # -- indexing ---------------------------------------------------------

    def _index(self, rec: ManifestRecord) -> None:
        if rec.container_id:
            self.by_container[rec.container_id].append(rec)
        self.by_hash[rec.content_hash()].append(rec.record_id)
        self.by_structural[rec.structural_key()].append(rec.record_id)
        if rec.cargo_type:
            if rec.weight is not None:
                self.peer_weight[rec.cargo_type].append(rec.weight)
            if rec.declared_value is not None and rec.weight:
                self.peer_value[rec.cargo_type].append(rec.declared_value / rec.weight)

    # -- per-event detection ----------------------------------------------

    def _duplicate_evidence(self, rec: ManifestRecord) -> list[Evidence]:
        """Exact and structural duplicate checks against the whole manifest."""
        out: list[Evidence] = []
        digest = rec.content_hash()
        matches = [r for r in self.by_hash.get(digest, []) if r != rec.record_id]
        if matches:
            out.append(
                _ev(
                    rec.record_id,
                    EvidenceCode.EXACT_DUPLICATE,
                    self.cfg.float_("detection.duplicate.exact_severity"),
                    f"Content-identical to {', '.join(matches[:3])} already in the "
                    f"manifest; the canonical payloads hash to the same value.",
                    supporting=matches,
                    engine="stream.duplicate",
                    content_hash=digest[:16],
                    level=1,
                )
            )
            return out

        structural = [
            r for r in self.by_structural.get(rec.structural_key(), []) if r != rec.record_id
        ]
        if structural:
            out.append(
                _ev(
                    rec.record_id,
                    EvidenceCode.STRUCTURAL_DUPLICATE,
                    self.cfg.float_("detection.duplicate.structural_severity"),
                    f"Structurally identical to {', '.join(structural[:3])} on owner, "
                    f"cargo, route, weight, timestamp and location.",
                    supporting=structural,
                    engine="stream.duplicate",
                    level=2,
                )
            )
        return out

    def _statistical_evidence(self, rec: ManifestRecord) -> list[Evidence]:
        """Robust z against the running peer-group samples."""
        if not rec.cargo_type:
            return []
        threshold = self.cfg.float_("detection.statistical.robust_z_threshold")
        ceiling = self.cfg.float_("detection.statistical.max_severity")
        out: list[Evidence] = []

        samples = self.peer_weight.get(rec.cargo_type, [])
        if rec.weight is not None and len(samples) >= 25:
            z = robust_z(rec.weight, samples)
            severity = severity_from_z(z, threshold, saturate_at=8.0, ceiling=ceiling)
            if severity > 0:
                out.append(
                    _ev(
                        rec.record_id,
                        EvidenceCode.PEER_GROUP_OUTLIER,
                        severity,
                        f"Weight {rec.weight:,.0f} kg is {z:+.1f} robust standard "
                        f"deviations from the running {rec.cargo_type} median of "
                        f"{median(samples):,.0f} kg (n={len(samples)}).",
                        engine="stream.statistical",
                        field="weight",
                        robust_z=round(z, 2),
                        sample_size=len(samples),
                    )
                )

        density_samples = self.peer_value.get(rec.cargo_type, [])
        if rec.weight and rec.declared_value and len(density_samples) >= 25:
            density = rec.declared_value / rec.weight
            z = robust_z(density, density_samples)
            severity = severity_from_z(z, threshold, saturate_at=8.0, ceiling=ceiling)
            if severity > 0:
                out.append(
                    _ev(
                        rec.record_id,
                        EvidenceCode.PEER_GROUP_OUTLIER,
                        severity,
                        f"Value density {density:,.2f}/kg is {z:+.1f} robust standard "
                        f"deviations from the running {rec.cargo_type} median; weight "
                        f"and declared value disagree with each other.",
                        engine="stream.statistical",
                        field="value_per_kg",
                        robust_z=round(z, 2),
                        sample_size=len(density_samples),
                    )
                )
        return out

    def _provenance_evidence(self, rec: ManifestRecord) -> list[Evidence]:
        """Chain comparison for a live record.

        A live event post-dates the sealed window by construction, so the
        chain usually has nothing to say -- which is exactly the condition the
        forensic engines must cope with, and worth stating rather than hiding.
        """
        if self.chain is None or not getattr(self.chain, "height", 0):
            return []
        committed = self.chain.committed_hash(rec.record_id)
        if committed is None:
            return []
        if committed == rec.content_hash():
            return []
        return [
            _ev(
                rec.record_id,
                EvidenceCode.RECORD_HASH_MISMATCH,
                self.cfg.float_("detection.blockchain.hash_mismatch_severity"),
                f"A live event arrived under record id {rec.record_id}, which the "
                f"provenance chain already committed with a different hash in "
                f"{self.chain.block_of(rec.record_id)}.",
                engine="stream.provenance",
                committed_hash=committed,
                current_hash=rec.content_hash(),
                inconclusive=False,
            )
        ]

    # -- ingest -----------------------------------------------------------

    def ingest(self, row: dict[str, Any], *, sequence: int | None = None) -> StreamVerdict:
        """Normalise, analyse and score one incoming event."""
        start = time.perf_counter()
        self.processed += 1
        sequence = sequence if sequence is not None else self.processed

        norm = normalize_rows([row], self.world, self.cfg, resolver=self.resolver)
        rec = norm.records[0]

        # The clock advances to the newest event. Without this every live
        # event would read as a FUTURE_EVENT against the batch clock.
        when = rec.effective_time()
        if when is not None and when > self.clock:
            self.clock = when

        # --- scoped context: this container's history plus the new record ---
        container_records = list(self.by_container.get(rec.container_id or "", []))
        container_records.append(rec)
        scoped = build_context(
            self.cfg,
            self.world,
            container_records,
            resolver=self.resolver,
            clock=self.clock,
            prior_evidence=norm.evidence,
            chain=self.chain,
            consistency=self.consistency,
        )

        evidence: list[Evidence] = list(norm.evidence)
        for name in _SCOPED_ENGINES:
            detector = DETECTOR_REGISTRY.get(name)
            if detector is None:
                continue
            try:
                produced = detector.run(scoped)
            except Exception as exc:  # noqa: BLE001 - one layer must not kill the feed
                evidence.append(
                    _ev(
                        rec.record_id,
                        EvidenceCode.GRAPH_CONFLICT,
                        0.0,
                        f"Live detector {name!r} failed: {exc}",
                        engine=name,
                    )
                )
                continue
            # Only findings about the *new* record are reported for this event;
            # findings about its history were already reported when those
            # records arrived.
            evidence.extend(e for e in produced if e.record_id == rec.record_id)

        evidence.extend(self._duplicate_evidence(rec))
        evidence.extend(self._statistical_evidence(rec))
        evidence.extend(self._provenance_evidence(rec))

        # --- arbitrate, fuse, classify with the same weights as the batch ---
        arbitrated = arbitrate(scoped, evidence)
        by_record: dict[str, list[Evidence]] = {}
        for item in arbitrated.evidence:
            by_record.setdefault(item.record_id, []).append(item)
        mine = by_record.get(rec.record_id, [])

        verdicts = fuse(self.cfg, {rec.record_id: mine}, record_ids=[rec.record_id])
        verdicts = classify(self.cfg, verdicts, {rec.record_id: mine})
        verdict = verdicts[rec.record_id]

        reconstruction: Reconstruction | None = None
        if verdict.tamper_class not in (TamperClass.CLEAN, TamperClass.BENIGN_ANOMALY):
            reconstruction = reconstruct_record(scoped, rec, verdict, mine)
            self.suspicious += 1

        # --- commit the record to state ---
        self.records.append(rec)
        self._index(rec)

        latency = (time.perf_counter() - start) * 1000.0
        self.latencies.append(latency)

        return StreamVerdict(
            sequence=sequence,
            record=rec,
            verdict=verdict,
            evidence=mine,
            reconstruction=reconstruction,
            latency_ms=latency,
        )

    # -- stats ------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        latencies = sorted(self.latencies)
        return {
            "processed": self.processed,
            "suspicious": self.suspicious,
            "records_total": len(self.records),
            "latency_ms": {
                "mean": round(sum(latencies) / len(latencies), 2) if latencies else 0.0,
                "p50": round(latencies[len(latencies) // 2], 2) if latencies else 0.0,
                "p95": round(latencies[int(len(latencies) * 0.95)], 2)
                if len(latencies) > 1
                else 0.0,
                "max": round(latencies[-1], 2) if latencies else 0.0,
            },
            "clock": self.clock.isoformat(),
        }


__all__ = ["StreamProcessor", "StreamVerdict"]

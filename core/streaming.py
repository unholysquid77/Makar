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

from core.alerting import AlertManager, AlertOutcome
from core.confidence.arbitration import arbitrate
from core.confidence.classifier import classify
from core.confidence.fusion import fuse
from core.config import MakarConfig
from core.detection.base import DETECTOR_REGISTRY, AnalysisContext, build_context
from core.models import (
    HASHED_FIELDS,
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
#: Fields whose after-the-fact alteration materially changes what the manifest
#: asserts -- what was carried, by whom, to where, worth how much. Rewriting
#: one of these after the event is the shape the twist describes.
_MATERIAL_FIELDS: frozenset[str] = frozenset(
    {
        "weight",
        "declared_value",
        "container_count",
        "owner",
        "cargo_type",
        "origin",
        "destination",
        "current_location",
        "port_id",
        "timestamp",
        "arrival_timestamp",
        "event_type",
    }
)

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
    #: True when this event revised a record already on the feed.
    is_revision: bool = False
    #: The before/after diff and the consistency delta, when it was a revision.
    revision: dict[str, Any] | None = None
    #: What the alert manager did with this finding -- raised, escalated,
    #: suppressed into an existing alert, or ignored.
    alert: AlertOutcome | None = None

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
            "is_revision": self.is_revision,
            "revision": self.revision,
            "alert": None
            if self.alert is None
            else {
                "action": str(self.alert.action),
                "reason": self.alert.reason,
                "alert_id": self.alert.alert.alert_id if self.alert.alert else None,
                "should_notify": self.alert.should_notify,
            },
            "latency_ms": round(self.latency_ms, 2),
        }


def _render(value: Any) -> Any:
    """JSON-safe rendering of a field value for a revision diff."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (int, float, str, bool)):
        return value
    return str(value)


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
        self.by_id: dict[str, ManifestRecord] = {r.record_id: r for r in batch_records}
        self.by_container: dict[str, list[ManifestRecord]] = defaultdict(list)
        self.by_hash: dict[str, list[str]] = defaultdict(list)
        self.by_structural: dict[str, list[str]] = defaultdict(list)
        self.peer_weight: dict[str, list[float]] = defaultdict(list)
        self.peer_value: dict[str, list[float]] = defaultdict(list)

        # --- live reconstructed manifest ------------------------------------
        # The twist requires the reconstructed manifest and the report to stay
        # current as records arrive, so the disposition of every record is held
        # here and revised in place rather than recomputed from scratch.
        self.dispositions: dict[str, Reconstruction] = {}
        self.verdicts: dict[str, RecordVerdict] = {}
        self.evidence_by_record: dict[str, list[Evidence]] = {}
        #: record id -> how many times it has been revised on the feed.
        self.revision_counts: dict[str, int] = defaultdict(int)
        #: Revisions judged to be legitimate corrections, for the report.
        self.corrections: list[dict[str, Any]] = []

        self.alerts = AlertManager(cfg)

        for rec in batch_records:
            self._index(rec)

        # The live clock advances with the stream; events are "now", so they
        # are not future events merely by arriving.
        self.clock = clock or max(
            (r.effective_time() for r in batch_records if r.effective_time()),
            default=world.sim_end,
        )
        self._alert_threshold = cfg.float_(
            "stream.alert_threshold", cfg.float_("fusion.thresholds.suspicious")
        )
        self.processed = 0
        self.suspicious = 0
        self.revisions = 0
        self.latencies: list[float] = []

    # -- indexing ---------------------------------------------------------

    def _index(self, rec: ManifestRecord) -> None:
        self.by_id[rec.record_id] = rec
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

    def _duplicate_evidence(
        self, rec: ManifestRecord, *, exclude_self: bool = False
    ) -> list[Evidence]:
        """Exact and structural duplicate checks against the whole manifest.

        ``exclude_self`` is set when the arriving record *revises* one already
        indexed: its superseded version is still in the hash index, and
        matching against it would report every revision as a duplicate of
        itself.
        """
        out: list[Evidence] = []
        _ = exclude_self  # matches are filtered by record id below
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
        """Normalise, analyse and score one incoming event or revision."""
        start = time.perf_counter()
        self.processed += 1
        sequence = sequence if sequence is not None else self.processed

        norm = normalize_rows([row], self.world, self.cfg, resolver=self.resolver)
        rec = norm.records[0]

        # Is this a *revision* of a record already on the feed? The twist is
        # that the attacker is inside the system editing in real time, so an
        # arriving record_id we have seen before is an update, not an insert.
        previous = self.by_id.get(rec.record_id)
        is_revision = previous is not None
        if is_revision:
            self.revisions += 1
            self.revision_counts[rec.record_id] += 1

        # The clock advances to the newest event. Without this every live
        # event would read as a FUTURE_EVENT against the batch clock.
        when = rec.effective_time()
        if when is not None and when > self.clock:
            self.clock = when

        # --- scoped context: this container's history plus the new record ---
        # On a revision the superseded version is dropped, or the container
        # would appear to hold two conflicting records and every revision
        # would manufacture a duplicate.
        container_records = [
            r
            for r in self.by_container.get(rec.container_id or "", [])
            if r.record_id != rec.record_id
        ]
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

        evidence.extend(self._duplicate_evidence(rec, exclude_self=is_revision))
        evidence.extend(self._statistical_evidence(rec))
        evidence.extend(self._provenance_evidence(rec))

        revision_detail: dict[str, Any] | None = None
        if previous is not None:
            revision_evidence, revision_detail = self._revision_evidence(
                previous, rec, scoped
            )
            evidence.extend(revision_evidence)

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

        # --- commit to state, and keep the live manifest current ------------
        if previous is not None:
            # Replace in place: the reconstructed manifest holds one row per
            # record id, whatever the feed does to it.
            self.records = [r for r in self.records if r.record_id != rec.record_id]
            self.by_container[rec.container_id or ""] = [
                r
                for r in self.by_container.get(rec.container_id or "", [])
                if r.record_id != rec.record_id
            ]
        self.records.append(rec)
        self._index(rec)

        self.verdicts[rec.record_id] = verdict
        self.evidence_by_record[rec.record_id] = mine
        if reconstruction is not None:
            self.dispositions[rec.record_id] = reconstruction
        else:
            self.dispositions.pop(rec.record_id, None)

        # --- fold into the alert set rather than notifying per event --------
        outcome = self.alerts.observe(
            rec,
            verdict,
            layers={str(t) for t in verdict.type_scores},
            codes={str(item.code) for item in mine},
            now=self.clock,
        )

        latency = (time.perf_counter() - start) * 1000.0
        self.latencies.append(latency)

        return StreamVerdict(
            sequence=sequence,
            record=rec,
            verdict=verdict,
            evidence=mine,
            reconstruction=reconstruction,
            latency_ms=latency,
            is_revision=is_revision,
            revision=revision_detail,
            alert=outcome,
        )


    # -- live revisions (the Shifting Waters twist) -----------------------

    def _revision_evidence(
        self, previous: ManifestRecord, revised: ManifestRecord, scoped: AnalysisContext
    ) -> tuple[list[Evidence], dict[str, Any]]:
        """Judge an in-place edit to a record already on the feed.

        The attacker is inside the system editing records in real time, but
        operators also issue legitimate corrections -- a mistyped weight, a
        departure stamp that arrives late. So the question is never "did this
        record change?" (alerting on that would bury the operator in noise the
        first time anyone fixed a typo) but **"did the change move the record
        toward consistency or away from it?"**.

        That is measured rather than enumerated. The scoped detectors are run
        over the record as it *was* and as it now *is*, and the change in total
        anomaly weight is the evidence. Nothing here encodes what a malicious
        edit looks like, which is why it also covers revision attacks nobody
        wrote a rule for.
        """
        cfg = self.cfg
        epsilon = cfg.float_("stream.revision.improvement_epsilon", 0.05)
        saturate = cfg.float_("stream.revision.degradation_saturates_at", 0.60)
        ceiling = cfg.float_("stream.revision.max_severity", 0.90)

        changed = {
            field: (getattr(previous, field, None), getattr(revised, field, None))
            for field in HASHED_FIELDS
            if getattr(previous, field, None) != getattr(revised, field, None)
        }

        # How did each field change? The distinction is the whole mechanism.
        #
        #   filled    null -> value. A late-arriving field. Routine.
        #   cleared   value -> null. Data loss, not an edit.
        #   altered   value -> a DIFFERENT value. An already-reported fact has
        #             been rewritten.
        #
        # A manifest record describes an event that has already happened. A
        # LOADED event at 09:00 does not justify revising that event's weight
        # at 14:00 -- the loading is over. So altering a populated field after
        # the fact is intrinsically an edit of history, whoever did it, and
        # that is the signal. Re-running the consistency engines alone cannot
        # see most of these, because conservation is deliberately skipped
        # across a port call containing a cargo event: it legitimately changes
        # cargo, so the check stands down exactly where the attacker is working.
        filled = [f for f, (before, after) in changed.items() if before is None and after is not None]
        cleared = [f for f, (before, after) in changed.items() if before is not None and after is None]
        altered = [
            f
            for f, (before, after) in changed.items()
            if before is not None and after is not None
        ]
        material = [f for f in altered if f in _MATERIAL_FIELDS]

        before_weight = self._anomaly_weight(previous, scoped)
        after_weight = self._anomaly_weight(revised, scoped)
        delta = after_weight - before_weight

        detail: dict[str, Any] = {
            "fields_changed": sorted(changed),
            "filled": sorted(filled),
            "cleared": sorted(cleared),
            "altered": sorted(altered),
            "material_fields_altered": sorted(material),
            "before": {k: _render(v[0]) for k, v in changed.items()},
            "after": {k: _render(v[1]) for k, v in changed.items()},
            "anomaly_before": round(before_weight, 4),
            "anomaly_after": round(after_weight, 4),
            "anomaly_delta": round(delta, 4),
            "revision_number": self.revision_counts[revised.record_id],
        }

        out: list[Evidence] = [
            _ev(
                revised.record_id,
                EvidenceCode.RECORD_REVISED,
                0.10,
                f"Record revised on the live feed. "
                f"{len(filled)} field(s) filled, {len(altered)} already-reported "
                f"value(s) altered, {len(cleared)} cleared. "
                f"Revision {detail['revision_number']}.",
                engine="stream.revision",
                **detail,
            )
        ]

        # --- the chain is decisive where it has coverage ---
        chain = self.chain
        if chain is not None and getattr(chain, "height", 0):
            committed = chain.committed_hash(revised.record_id)
            if committed is not None:
                was_matching = previous.content_hash() == committed
                now_matching = revised.content_hash() == committed
                if was_matching and not now_matching:
                    out.append(
                        _ev(
                            revised.record_id,
                            EvidenceCode.REVISION_CONTRADICTS_CHAIN,
                            cfg.float_("stream.revision.chain_contradiction_severity", 0.95),
                            f"The record matched its commitment in "
                            f"{chain.block_of(revised.record_id)} and no longer does. "
                            f"The edit happened after the block was sealed.",
                            engine="stream.revision",
                            committed_hash=committed,
                            **detail,
                        )
                    )
                    detail["verdict"] = "contradicts_chain"
                    return out, detail
                if now_matching and not was_matching:
                    detail["verdict"] = "restores_chain"
                    self.corrections.append(
                        {
                            "record_id": revised.record_id,
                            "reason": "revision restored the committed hash",
                            **detail,
                        }
                    )
                    return out, detail

        # --- did the edit move the record toward consistency or away? ---
        if delta > epsilon:
            drift = "degrades"
        elif delta < -epsilon:
            drift = "improves"
        else:
            drift = "neutral"

        # --- altering an already-reported fact ---
        if altered:
            if drift == "degrades":
                severity = ceiling
                judgement = (
                    "and the record became measurably less consistent as a result"
                )
            elif drift == "improves":
                severity = 0.15
                judgement = (
                    "but the record became more consistent, which is what a genuine "
                    "correction looks like"
                )
            else:
                # No measurable consistency change. Still an edit of history,
                # and on a material field that is worth an operator's eyes --
                # but not a conviction.
                severity = 0.62 if material else 0.30
                judgement = (
                    "with no measurable change in consistency either way, so the "
                    "edit is unexplained rather than proven malicious"
                )

            out.append(
                _ev(
                    revised.record_id,
                    EvidenceCode.REVISION_ALTERS_REPORTED_VALUE,
                    severity,
                    f"Already-reported value(s) rewritten after the event: "
                    f"{', '.join(f'{f} {_render(changed[f][0])!r} -> {_render(changed[f][1])!r}' for f in sorted(altered)[:3])}"
                    f"{' and others' if len(altered) > 3 else ''}. "
                    f"Total anomaly weight moved {before_weight:.2f} -> "
                    f"{after_weight:.2f} ({delta:+.2f}), {judgement}.",
                    engine="stream.revision",
                    **detail,
                )
            )

        # --- the measured consistency delta, as its own corroborating line ---
        if drift == "degrades":
            severity = min(ceiling, (delta - epsilon) / max(1e-6, saturate) * ceiling)
            out.append(
                _ev(
                    revised.record_id,
                    EvidenceCode.REVISION_DEGRADES_CONSISTENCY,
                    severity,
                    f"The revision moved the container away from consistency: total "
                    f"anomaly weight rose {before_weight:.2f} -> {after_weight:.2f} "
                    f"({delta:+.2f}). A legitimate correction lowers this figure.",
                    engine="stream.revision",
                    **detail,
                )
            )

        detail["verdict"] = (
            "degrades"
            if drift == "degrades"
            else ("improves" if drift == "improves" else ("altered" if material else "neutral"))
        )
        if detail["verdict"] in ("improves", "neutral"):
            self.corrections.append(
                {
                    "record_id": revised.record_id,
                    "reason": (
                        f"revision {'improved consistency' if drift == 'improves' else 'left consistency unchanged'}"
                        f"; accepted without alerting"
                    ),
                    **detail,
                }
            )

        return out, detail

    def _anomaly_weight(self, rec: ManifestRecord, scoped: AnalysisContext) -> float:
        """Total severity the scoped engines raise across the whole container.

        Two deliberate choices:

        *The sum of severities, not a fused probability.* This is a relative
        comparison between two versions of one record, so the prior and the
        saturation curve would only compress the signal being read.

        *Container-wide, not record-scoped.* An edit's consequences frequently
        land on a **neighbour** -- the cargo engine attributes a broken
        conservation step to the record carrying the changed value in the
        *next* port call, not to the one that was edited. Summing only the
        edited record's own evidence measured a delta of exactly 0.0 for 15 of
        30 known malicious edits. The question that matters is "did this edit
        make the container less consistent?", and that is what this measures.
        """
        probe = AnalysisContext(
            cfg=scoped.cfg,
            world=scoped.world,
            records=[r for r in scoped.records if r.record_id != rec.record_id] + [rec],
            resolver=scoped.resolver,
            clock=scoped.clock,
            chain=scoped.chain,
            consistency=scoped.consistency,
        )
        probe.build_indexes()

        total = 0.0
        for name in _SCOPED_ENGINES:
            detector = DETECTOR_REGISTRY.get(name)
            if detector is None:
                continue
            try:
                for item in detector.run(probe):
                    total += item.severity
            except Exception:  # noqa: BLE001 - a probe must never break ingest
                continue
        return total

    # -- live reconstructed manifest and report ---------------------------

    def live_manifest(self, limit: int | None = None) -> list[dict[str, Any]]:
        """The reconstructed manifest as of this instant.

        Every record carries exactly one disposition, exactly as the batch
        output does -- the twist requires this to stay current as records
        arrive, not to be rebuilt on demand.
        """
        rows: list[dict[str, Any]] = []
        for rec in self.records:
            recon = self.dispositions.get(rec.record_id)
            verdict = self.verdicts.get(rec.record_id)
            rows.append(
                {
                    "record_id": rec.record_id,
                    "container_id": rec.container_id,
                    "shipment_id": rec.shipment_id,
                    "owner": rec.owner,
                    "cargo_type": rec.cargo_type,
                    "port_id": rec.port_id,
                    "event_type": rec.event_type,
                    "timestamp": rec.timestamp.isoformat() if rec.timestamp else None,
                    "weight": rec.weight,
                    "declared_value": rec.declared_value,
                    "classification": str(recon.classification) if recon else "ORIGINAL",
                    "confidence": recon.confidence if recon else None,
                    "tampering_probability": verdict.tampering_probability if verdict else 0.0,
                    "tamper_class": str(verdict.tamper_class) if verdict else "CLEAN",
                    "revisions": self.revision_counts.get(rec.record_id, 0),
                    "reconstructed": recon.reconstructed if recon else None,
                }
            )
        rows.sort(key=lambda r: -r["tampering_probability"])
        return rows[:limit] if limit else rows

    def live_summary(self) -> dict[str, Any]:
        counts = {"ORIGINAL": 0, "REPAIRED": 0, "REMOVED": 0, "UNRECOVERABLE": 0}
        by_class: dict[str, int] = {}
        for rec in self.records:
            recon = self.dispositions.get(rec.record_id)
            counts[str(recon.classification) if recon else "ORIGINAL"] += 1
        for verdict in self.verdicts.values():
            key = str(verdict.tamper_class)
            if key not in ("CLEAN", "BENIGN_ANOMALY"):
                by_class[key] = by_class.get(key, 0) + 1
        confidences = [
            r.confidence
            for r in self.dispositions.values()
            if str(r.classification) in ("REPAIRED", "REMOVED")
        ]
        return {
            "total_records": len(self.records),
            "disposition": counts,
            "by_tamper_class": by_class,
            "suspicious": sum(by_class.values()),
            "revisions_seen": sum(self.revision_counts.values()),
            "records_revised": len(self.revision_counts),
            "corrections_accepted": len(self.corrections),
            "mean_repair_confidence": (
                round(sum(confidences) / len(confidences), 4) if confidences else 0.0
            ),
        }

    def live_report(self, top: int = 20) -> dict[str, Any]:
        """The suspicious activity report, current as of the last event."""
        ranked = sorted(
            (
                (rid, verdict)
                for rid, verdict in self.verdicts.items()
                if str(verdict.tamper_class) not in ("CLEAN", "BENIGN_ANOMALY")
                and verdict.tampering_probability >= self._alert_threshold
            ),
            key=lambda kv: kv[1].tampering_probability,
            reverse=True,
        )

        affected_owners: dict[str, int] = {}
        affected_ports: dict[str, int] = {}
        for rid, _verdict in ranked:
            rec = self.by_id.get(rid)
            if not rec:
                continue
            if rec.owner:
                affected_owners[rec.owner] = affected_owners.get(rec.owner, 0) + 1
            if rec.port_id:
                affected_ports[rec.port_id] = affected_ports.get(rec.port_id, 0) + 1

        entries = []
        for rid, verdict in ranked[:top]:
            rec = self.by_id.get(rid)
            recon = self.dispositions.get(rid)
            entries.append(
                {
                    "record_id": rid,
                    "tampering_probability": verdict.tampering_probability,
                    "tamper_class": str(verdict.tamper_class),
                    "rationale": verdict.rationale,
                    "revisions": self.revision_counts.get(rid, 0),
                    "container_id": rec.container_id if rec else None,
                    "port_id": rec.port_id if rec else None,
                    "owner": rec.owner if rec else None,
                    "classification": str(recon.classification) if recon else None,
                    "contributions": [
                        {"code": str(c.code), "label": c.label, "points": c.points}
                        for c in verdict.contributions
                    ],
                    "evidence": [
                        {
                            "code": str(e.code),
                            "severity": e.severity,
                            "description": e.description,
                        }
                        for e in sorted(
                            self.evidence_by_record.get(rid, []),
                            key=lambda e: -e.severity,
                        )[:6]
                    ],
                }
            )

        return {
            "generated_at": self.clock.isoformat(),
            "live": True,
            "summary": self.live_summary(),
            "alerts": {
                "open": [a.as_dict() for a in self.alerts.open_alerts()[:50]],
                **self.alerts.stats(),
            },
            "ranked_records": entries,
            "affected": {
                "owners": sorted(affected_owners.items(), key=lambda kv: -kv[1])[:10],
                "ports": sorted(affected_ports.items(), key=lambda kv: -kv[1])[:10],
            },
            "corrections": self.corrections[-20:],
            "throughput": self.stats()["latency_ms"],
        }

    # -- stats ------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        latencies = sorted(self.latencies)
        return {
            "processed": self.processed,
            "suspicious": self.suspicious,
            "revisions": self.revisions,
            "records_revised": len(self.revision_counts),
            "corrections_accepted": len(self.corrections),
            "alerts": self.alerts.stats(),
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

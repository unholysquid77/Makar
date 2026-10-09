"""Reconstruction engine (spec 19, 20).

For every suspicious record the engine *generates* candidate original states,
scores each against the same consistency criteria the detectors use, and keeps
the best one only if it clears the configured repair threshold. Otherwise the
record is marked ``UNRECOVERABLE``. Nothing is ever changed silently: each
output carries its original state, its reconstructed state, the classification,
the confidence, the supporting evidence and the reason (spec 20).

**Which fields to repair** is driven by the evidence, not by guesswork. A
record with ``WEIGHT_NOT_CONSERVED`` gets weight candidates; one with
``OFF_ROUTE_PORT`` gets location candidates. Evidence that says nothing about
a field produces no candidate for it.

**Candidate generation** (``reconstruction.strategies``):

``neighbor_interpolation``
    The strongest strategy by far. Records of one port call share the call's
    cargo state, so an adjacent record of the same container *holds the value
    that was overwritten*. An inflated weight is repaired by reading the
    weight its neighbours still report.
``conservation_solve``
    Invert the conservation identity: with no cargo-mutating event, the
    outgoing weight must equal the incoming one.
``route_schedule``
    For locations and destinations, the world model's route says which port
    the container should be at, and when.
``historical_median``
    Peer-group median for the cargo type. Weak, and used only when a record
    has no usable neighbours.
``remove``
    Always offered. For duplicates and fabrications it is usually the correct
    answer -- the original manifest did not contain this row at all.

**The provenance chain confirms, it does not reveal.** Blocks commit hashes,
never values (design decision D9), so the chain cannot be read for the
original weight. But once a candidate has been *constructed*, hashing it and
comparing against the commitment either confirms the repair outright or
refutes it. That asymmetry is the whole point: the forensic engines do the
work of finding the value, and the chain certifies the answer where it has
coverage. For the uncommitted tail there is no certificate and confidence
rests on consistency alone -- which the output states explicitly.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from core.detection.base import AnalysisContext
from core.detection.segments import event_calls
from core.models import CandidateRepair, Evidence, ManifestRecord, Reconstruction, RecordVerdict
from core.stats import median, robust_z
from core.types import CARGO_MUTATING_EVENTS, Classification, TamperClass

#: evidence code -> fields its presence implicates
_CODE_FIELDS: dict[str, tuple[str, ...]] = {
    "WEIGHT_NOT_CONSERVED": ("weight",),
    "CARGO_DRIFT_UNEXPLAINED": ("weight", "declared_value"),
    "WEIGHT_EXCEEDS_CAPACITY": ("weight",),
    "VALUE_NOT_CONSERVED": ("declared_value",),
    "CONTAINER_COUNT_NOT_CONSERVED": ("container_count",),
    "OWNER_CHANGED_WITHOUT_TRANSFER": ("owner",),
    "CARGO_TYPE_MUTATED": ("cargo_type",),
    "PEER_GROUP_OUTLIER": ("weight", "declared_value"),
    "ROBUST_Z_OUTLIER": ("weight", "declared_value"),
    "IQR_OUTLIER": ("weight", "declared_value"),
    "ISOLATION_FOREST_OUTLIER": ("weight", "declared_value"),
    "LOF_OUTLIER": ("weight", "declared_value"),
    "OFF_ROUTE_PORT": ("port_id", "current_location", "latitude", "longitude"),
    "SPEED_INFEASIBLE": ("port_id", "current_location", "latitude", "longitude", "timestamp"),
    "IMPOSSIBLE_TRANSIT": ("timestamp", "port_id", "current_location"),
    "SIMULTANEOUS_PRESENCE": ("port_id", "current_location", "latitude", "longitude"),
    "COORDINATE_PORT_MISMATCH": ("latitude", "longitude"),
    "FUTURE_EVENT": ("timestamp", "arrival_timestamp", "departure_timestamp"),
    "REVERSE_CHRONOLOGY": ("arrival_timestamp", "departure_timestamp"),
    "EVENT_ORDER_VIOLATION": ("timestamp",),
    "DESTINATION_CONTRADICTION": ("destination",),
    "ROUTE_SEQUENCE_BREAK": ("port_id", "current_location"),
    "RECORD_HASH_MISMATCH": (),  # says something changed, not what
}


def _implicated_fields(items: list[Evidence]) -> list[str]:
    """Fields the evidence actually points at, in deterministic order."""
    fields: list[str] = []
    for item in items:
        for field in _CODE_FIELDS.get(str(item.code), ()):
            if field not in fields:
                fields.append(field)
    return fields


def _apply(rec: ManifestRecord, changes: dict[str, Any]) -> ManifestRecord:
    patched = rec.model_copy(deep=True)
    for field, value in changes.items():
        setattr(patched, field, value)
    return patched


def _neighbours(ctx: AnalysisContext, rec: ManifestRecord) -> list[ManifestRecord]:
    """Other records of the same container, nearest in time first."""
    timeline = ctx.container_timeline(rec.container_id)
    when = rec.effective_time()
    others = [r for r in timeline if r.record_id != rec.record_id]
    if when is None:
        return others
    return sorted(
        others,
        key=lambda r: abs(((r.effective_time() or when) - when).total_seconds()),
    )


# ======================================================================
# Candidate generation
# ======================================================================


def _neighbor_candidates(
    ctx: AnalysisContext, rec: ManifestRecord, fields: list[str]
) -> list[dict[str, Any]]:
    """Values taken from the record's nearest neighbours in the same container."""
    neighbours = _neighbours(ctx, rec)
    if not neighbours:
        return []

    out: list[dict[str, Any]] = []
    same_call = [n for n in neighbours if n.arrival_timestamp == rec.arrival_timestamp]
    sources = [("same port call", same_call), ("adjacent records", neighbours[:4])]

    for _label, group in sources:
        if not group:
            continue
        changes: dict[str, Any] = {}
        for field in fields:
            values = [getattr(n, field, None) for n in group]
            values = [v for v in values if v is not None]
            if not values:
                continue
            if isinstance(values[0], (int, float)) and not isinstance(values[0], bool):
                # Median of the neighbours, so one more tampered sibling
                # cannot drag the repair with it.
                proposed = median([float(v) for v in values])
                if isinstance(getattr(rec, field, None), int) or field == "container_count":
                    proposed = int(round(proposed))
                else:
                    proposed = round(proposed, 2)
            else:
                # Modal value among neighbours.
                counts: dict[Any, int] = {}
                for value in values:
                    counts[value] = counts.get(value, 0) + 1
                proposed = max(sorted(counts, key=str), key=lambda k: counts[k])
            if proposed != getattr(rec, field, None):
                changes[field] = proposed
        if changes and changes not in out:
            out.append(changes)
    return out


def _conservation_candidates(
    ctx: AnalysisContext, rec: ManifestRecord, fields: list[str]
) -> list[dict[str, Any]]:
    """Solve the conservation identity for the implicated cargo field."""
    if not ({"weight", "declared_value", "container_count"} & set(fields)):
        return []
    calls = event_calls(ctx.container_timeline(rec.container_id))
    if len(calls) < 2:
        return []

    index = next(
        (i for i, c in enumerate(calls) if rec.record_id in c.record_ids), None
    )
    if index is None:
        return []

    # Look to the nearest call on either side that is not separated from this
    # one by a cargo-mutating event, since those legitimately change state.
    def state_from(call_index: int) -> dict[str, Any]:
        call = calls[call_index]
        if any((r.event_type or "") in CARGO_MUTATING_EVENTS for r in call.records):
            return {}
        changes: dict[str, Any] = {}
        for field in fields:
            if field not in {"weight", "declared_value", "container_count"}:
                continue
            values = [
                getattr(r, field, None)
                for r in call.records
                if getattr(r, field, None) is not None
            ]
            if not values:
                continue
            proposed = median([float(v) for v in values])
            proposed = int(round(proposed)) if field == "container_count" else round(proposed, 2)
            if proposed != getattr(rec, field, None):
                changes[field] = proposed
        return changes

    out: list[dict[str, Any]] = []
    for offset in (-1, 1):
        neighbour_index = index + offset
        if 0 <= neighbour_index < len(calls):
            changes = state_from(neighbour_index)
            if changes and changes not in out:
                out.append(changes)
    return out


def _route_candidates(
    ctx: AnalysisContext, rec: ManifestRecord, fields: list[str]
) -> list[dict[str, Any]]:
    """Location and destination implied by the declared route and the clock."""
    route = ctx.world.routes.get(rec.route_id or "")
    if route is None:
        return []
    out: list[dict[str, Any]] = []

    if "destination" in fields:
        terminus = ctx.world.ports.get(route.port_sequence[-1])
        if terminus and rec.destination != terminus.name:
            out.append({"destination": terminus.name})

    location_fields = {"port_id", "current_location", "latitude", "longitude"} & set(fields)
    if location_fields:
        # Which port should the container have been at? Take the port its
        # neighbouring records agree on, constrained to the route.
        neighbours = _neighbours(ctx, rec)
        on_route = [
            n for n in neighbours if n.port_id and n.port_id in route.port_sequence
        ]
        when = rec.effective_time()
        candidate_ports: list[str] = []
        if on_route and when is not None:
            before = [n for n in on_route if (n.effective_time() or when) <= when]
            after = [n for n in on_route if (n.effective_time() or when) > when]
            if before:
                candidate_ports.append(before[0].port_id)
            if after:
                candidate_ports.append(after[0].port_id)
        for port_id in dict.fromkeys(candidate_ports):
            port = ctx.world.ports.get(port_id)
            if port is None or port_id == rec.port_id:
                continue
            changes: dict[str, Any] = {}
            if "port_id" in fields:
                changes["port_id"] = port.port_id
            if "current_location" in fields:
                changes["current_location"] = port.name
            if "latitude" in fields:
                changes["latitude"] = round(port.latitude, 6)
            if "longitude" in fields:
                changes["longitude"] = round(port.longitude, 6)
            if changes and changes not in out:
                out.append(changes)
    return out


def _temporal_candidates(
    ctx: AnalysisContext, rec: ManifestRecord, fields: list[str]
) -> list[dict[str, Any]]:
    """Timestamps consistent with the record's own port call and neighbours."""
    out: list[dict[str, Any]] = []
    time_fields = {"timestamp", "arrival_timestamp", "departure_timestamp"} & set(fields)
    if not time_fields:
        return out

    # Un-swap an inverted port call.
    if (
        "arrival_timestamp" in fields
        and rec.arrival_timestamp
        and rec.departure_timestamp
        and rec.arrival_timestamp > rec.departure_timestamp
    ):
        out.append(
            {
                "arrival_timestamp": rec.departure_timestamp,
                "departure_timestamp": rec.arrival_timestamp,
            }
        )

    # Place the event inside its port call's window.
    if "timestamp" in fields and rec.arrival_timestamp:
        window_end = rec.departure_timestamp or (
            rec.arrival_timestamp + timedelta(hours=6)
        )
        midpoint = rec.arrival_timestamp + (window_end - rec.arrival_timestamp) / 2
        if rec.timestamp != midpoint:
            out.append({"timestamp": midpoint.replace(microsecond=0)})

    # Interpolate between the nearest clean neighbours in time.
    if "timestamp" in fields:
        neighbours = _neighbours(ctx, rec)
        times = sorted(
            n.effective_time() for n in neighbours if n.effective_time() is not None
        )
        when = rec.effective_time()
        if times and when is not None:
            before = [t for t in times if t <= ctx.clock]
            if before:
                nearest = min(before, key=lambda t: abs((t - when).total_seconds()))
                if nearest != rec.timestamp:
                    out.append({"timestamp": nearest})
    return out


def _historical_candidates(
    ctx: AnalysisContext, rec: ManifestRecord, fields: list[str]
) -> list[dict[str, Any]]:
    """Peer-group median for the cargo type. The weakest strategy."""
    numeric = {"weight", "declared_value"} & set(fields)
    if not numeric or not rec.cargo_type:
        return []
    changes: dict[str, Any] = {}
    for field in numeric:
        peers = [
            getattr(r, field)
            for r in ctx.records
            if r.cargo_type == rec.cargo_type
            and r.record_id != rec.record_id
            and getattr(r, field, None) is not None
        ]
        if len(peers) < 10:
            continue
        proposed = round(median([float(p) for p in peers]), 2)
        if proposed != getattr(rec, field, None):
            changes[field] = proposed
    return [changes] if changes else []


# ======================================================================
# Candidate scoring
# ======================================================================


def _score_candidate(
    ctx: AnalysisContext,
    rec: ManifestRecord,
    changes: dict[str, Any],
) -> tuple[dict[str, float], str | None]:
    """Score a patched record against each consistency criterion.

    Returns ``(criterion -> score in [0,1], certificate)``. ``certificate`` is
    the block id when the candidate's hash matches the provenance commitment,
    which is a proof of correctness rather than a score.
    """
    patched = _apply(rec, changes)
    scores: dict[str, float] = {}

    # --- blockchain: a hash match is certainty, a mismatch is uninformative ---
    certificate: str | None = None
    chain = ctx.chain
    if chain is not None and getattr(chain, "height", 0):
        committed = chain.committed_hash(rec.record_id)
        if committed is None:
            scores["blockchain_state"] = 0.5  # no coverage: no opinion
        elif patched.content_hash() == committed:
            scores["blockchain_state"] = 1.0
            certificate = chain.block_of(rec.record_id)
        else:
            scores["blockchain_state"] = 0.0
    else:
        scores["blockchain_state"] = 0.5

    # --- route consistency ---
    route = ctx.world.routes.get(patched.route_id or "")
    if route is None:
        scores["route_consistency"] = 0.5
    else:
        checks: list[float] = []
        if patched.port_id:
            checks.append(1.0 if patched.port_id in route.port_sequence else 0.0)
        if patched.destination:
            terminus = ctx.world.ports.get(route.port_sequence[-1])
            checks.append(
                1.0 if terminus and patched.destination == terminus.name else 0.0
            )
        scores["route_consistency"] = sum(checks) / len(checks) if checks else 0.5

    # --- temporal consistency ---
    temporal: list[float] = []
    when = patched.effective_time()
    if when is not None:
        temporal.append(0.0 if when > ctx.clock else 1.0)
    if patched.arrival_timestamp and patched.departure_timestamp:
        temporal.append(
            1.0 if patched.arrival_timestamp <= patched.departure_timestamp else 0.0
        )
    neighbours = _neighbours(ctx, patched)
    neighbour_times = [
        n.effective_time() for n in neighbours if n.effective_time() is not None
    ]
    if when is not None and neighbour_times:
        lo, hi = min(neighbour_times), max(neighbour_times)
        span = max(1.0, (hi - lo).total_seconds())
        if lo <= when <= hi:
            temporal.append(1.0)
        else:
            overshoot = (
                (lo - when).total_seconds() if when < lo else (when - hi).total_seconds()
            )
            temporal.append(max(0.0, 1.0 - overshoot / span))
    scores["temporal_consistency"] = (
        sum(temporal) / len(temporal) if temporal else 0.5
    )

    # --- cargo conservation ---
    calls = event_calls(ctx.container_timeline(rec.container_id))
    conservation: list[float] = []
    if patched.weight is not None and len(calls) >= 2:
        index = next((i for i, c in enumerate(calls) if rec.record_id in c.record_ids), None)
        if index is not None:
            for offset in (-1, 1):
                j = index + offset
                if not (0 <= j < len(calls)):
                    continue
                call = calls[j]
                if any((r.event_type or "") in CARGO_MUTATING_EVENTS for r in call.records):
                    continue
                weights = [r.weight for r in call.records if r.weight is not None]
                if not weights:
                    continue
                reference = median(weights)
                if reference > 0:
                    relative = abs(patched.weight - reference) / reference
                    conservation.append(max(0.0, 1.0 - relative / 0.10))
    scores["cargo_conservation"] = (
        sum(conservation) / len(conservation) if conservation else 0.5
    )

    # --- graph consistency: does it still belong anywhere? ---
    graph: list[float] = []
    if patched.port_id and patched.container_id:
        siblings = [
            r
            for r in ctx.container_timeline(patched.container_id)
            if r.record_id != patched.record_id and r.port_id == patched.port_id
        ]
        graph.append(1.0 if siblings else 0.2)
    scores["graph_consistency"] = sum(graph) / len(graph) if graph else 0.5

    # --- historical pattern: plausible for this cargo class? ---
    historical: list[float] = []
    for field in ("weight", "declared_value"):
        value = getattr(patched, field, None)
        if value is None or not patched.cargo_type:
            continue
        peers = [
            getattr(r, field)
            for r in ctx.records
            if r.cargo_type == patched.cargo_type
            and r.record_id != patched.record_id
            and getattr(r, field, None) is not None
        ]
        if len(peers) < 10:
            continue
        z = abs(robust_z(float(value), [float(p) for p in peers]))
        historical.append(max(0.0, 1.0 - z / 6.0))
    scores["historical_pattern"] = (
        sum(historical) / len(historical) if historical else 0.5
    )

    # --- neighbour agreement on the changed fields ---
    agreement: list[float] = []
    for field in changes:
        values = [
            getattr(n, field, None) for n in neighbours[:6] if getattr(n, field, None) is not None
        ]
        if not values:
            continue
        proposed = changes[field]
        if isinstance(proposed, (int, float)) and not isinstance(proposed, bool):
            reference = median([float(v) for v in values])
            if reference:
                agreement.append(
                    max(0.0, 1.0 - abs(float(proposed) - reference) / abs(reference))
                )
        else:
            agreement.append(sum(1 for v in values if v == proposed) / len(values))
    scores["neighbor_agreement"] = (
        sum(agreement) / len(agreement) if agreement else 0.5
    )

    return scores, certificate


def _weighted(cfg_weights: dict[str, float], scores: dict[str, float]) -> float:
    total = sum(abs(w) for w in cfg_weights.values()) or 1.0
    return sum(cfg_weights.get(k, 0.0) * v for k, v in scores.items()) / total


# ======================================================================
# Orchestration
# ======================================================================


def reconstruct_record(
    ctx: AnalysisContext,
    rec: ManifestRecord,
    verdict: RecordVerdict,
    items: list[Evidence],
) -> Reconstruction:
    """Generate, score and select a reconstruction for one record."""
    cfg = ctx.cfg
    repair_threshold = cfg.float_("reconstruction.repair_threshold")
    removal_threshold = cfg.float_("reconstruction.removal_threshold")
    max_candidates = cfg.int_("reconstruction.max_candidates")
    strategies = [str(s) for s in cfg.list_("reconstruction.strategies")]
    weights = {
        str(k): float(v)
        for k, v in (cfg.get("reconstruction.candidate_weights", {}) or {}).items()
    }

    original = rec.model_dump(mode="json", exclude={"raw", "normalization_notes"})
    base = Reconstruction(
        record_id=rec.record_id,
        classification=Classification.ORIGINAL,
        original=original,
        evidence=items,
        confidence=round(1.0 - verdict.tampering_probability, 4),
        reason="No repair required: the record is consistent with its evidence.",
    )

    if verdict.tamper_class in (TamperClass.CLEAN, TamperClass.BENIGN_ANOMALY):
        if verdict.tamper_class is TamperClass.BENIGN_ANOMALY:
            base.reason = (
                "Left as ORIGINAL: the irregularities found are data-quality "
                "artefacts, not evidence of tampering, so altering the record "
                "would destroy information rather than restore it."
            )
        return base

    fields = _implicated_fields(items)
    candidates: list[CandidateRepair] = []
    counter = 0

    def add(strategy: str, changes: dict[str, Any], *, remove: bool = False) -> None:
        nonlocal counter
        if not remove and not changes:
            return
        counter += 1
        candidates.append(
            CandidateRepair(
                candidate_id=f"{rec.record_id}-C{counter}",
                strategy=strategy,
                changes=changes,
                remove=remove,
            )
        )

    if "neighbor_interpolation" in strategies:
        for changes in _neighbor_candidates(ctx, rec, fields):
            add("neighbor_interpolation", changes)
    if "conservation_solve" in strategies:
        for changes in _conservation_candidates(ctx, rec, fields):
            add("conservation_solve", changes)
    if "route_schedule" in strategies:
        for changes in _route_candidates(ctx, rec, fields):
            add("route_schedule", changes)
        for changes in _temporal_candidates(ctx, rec, fields):
            add("route_schedule", changes)
    if "historical_median" in strategies:
        for changes in _historical_candidates(ctx, rec, fields):
            add("historical_median", changes)
    if "remove" in strategies:
        add("remove", {}, remove=True)

    candidates = candidates[:max_candidates]

    # --- score ---
    removal_prior = {
        TamperClass.DUPLICATED: 0.90,
        TamperClass.FABRICATED: 0.92,
        TamperClass.MODIFIED: 0.20,
        TamperClass.DELETED: 0.10,
    }.get(verdict.tamper_class, 0.2)

    certificates: dict[str, str] = {}
    for candidate in candidates:
        if candidate.remove:
            # Removal is scored by how strongly the classification supports
            # "this row should not exist", tempered by the fused probability.
            candidate.criterion_scores = {"removal_prior": removal_prior}
            candidate.score = round(
                removal_prior * verdict.tampering_probability, 4
            )
            candidate.explanation = (
                f"Remove the record entirely. Classified {verdict.tamper_class} "
                f"at {verdict.tampering_probability:.1%}, which indicates the "
                f"original manifest did not contain this row."
            )
            continue

        scores, certificate = _score_candidate(ctx, rec, candidate.changes)
        candidate.criterion_scores = {k: round(v, 4) for k, v in scores.items()}
        candidate.score = round(_weighted(weights, scores), 4)
        if certificate:
            certificates[candidate.candidate_id] = certificate
            # A hash match against the committed value is proof, not a score.
            candidate.score = 1.0
            candidate.explanation = (
                f"Hash of the repaired record matches the commitment in "
                f"{certificate}. This reconstruction is confirmed by the "
                f"provenance chain, not merely consistent with it."
            )
        else:
            described = ", ".join(
                f"{k.replace('_', ' ')} {v:.2f}" for k, v in sorted(scores.items())
            )
            candidate.explanation = (
                f"Proposed by {candidate.strategy}: "
                + "; ".join(f"{k} -> {v!r}" for k, v in candidate.changes.items())
                + f". Scored on {described}."
            )

    if not candidates:
        base.classification = Classification.UNRECOVERABLE
        base.confidence = 0.0
        base.reason = (
            f"Classified {verdict.tamper_class} at "
            f"{verdict.tampering_probability:.1%}, but the evidence does not "
            f"implicate any specific field, so no candidate original state "
            f"could be constructed."
        )
        return base

    candidates.sort(key=lambda c: c.score, reverse=True)
    best = candidates[0]
    base.candidates = candidates

    if best.remove and best.score >= removal_threshold:
        base.classification = Classification.REMOVED
        base.confidence = round(best.score, 4)
        base.reconstructed = None
        base.selected_candidate_id = best.candidate_id
        base.reason = best.explanation
        return base

    if not best.remove and best.score >= repair_threshold:
        patched = _apply(rec, best.changes)
        base.classification = Classification.REPAIRED
        base.confidence = round(best.score, 4)
        base.reconstructed = patched.model_dump(
            mode="json", exclude={"raw", "normalization_notes"}
        )
        base.selected_candidate_id = best.candidate_id
        certificate = certificates.get(best.candidate_id)
        base.reason = (
            best.explanation
            if certificate
            else (
                f"{best.explanation} Selected over {len(candidates) - 1} other "
                f"candidate(s); confidence {best.score:.1%} exceeds the repair "
                f"threshold of {repair_threshold:.0%}."
            )
        )
        return base

    base.classification = Classification.UNRECOVERABLE
    base.confidence = round(best.score, 4)
    base.selected_candidate_id = None
    base.reason = (
        f"Classified {verdict.tamper_class} at "
        f"{verdict.tampering_probability:.1%}, but the best of "
        f"{len(candidates)} candidate reconstruction(s) scored only "
        f"{best.score:.1%}, below the repair threshold of "
        f"{repair_threshold:.0%} and the removal threshold of "
        f"{removal_threshold:.0%}. The record is flagged as unrecoverable "
        f"rather than altered on weak evidence."
    )
    return base


def reconstruct_all(
    ctx: AnalysisContext,
    verdicts: dict[str, RecordVerdict],
    evidence_by_record: dict[str, list[Evidence]],
) -> dict[str, Reconstruction]:
    """Reconstruct every record, returning one disposition each."""
    out: dict[str, Reconstruction] = {}
    for rec in ctx.records:
        verdict = verdicts.get(rec.record_id)
        if verdict is None:
            continue
        out[rec.record_id] = reconstruct_record(
            ctx, rec, verdict, evidence_by_record.get(rec.record_id, [])
        )
    return out

"""Temporal intelligence engine (spec 9).

Checks, in order of how hard they are to argue with:

1. **Future events** -- an event dated after the analysis clock cannot have
   happened yet. Near-deterministic.
2. **Reverse chronology** -- arrival after departure for the same port call.
   Deterministic.
3. **Simultaneous presence** -- one container inside two ports at overlapping
   times. Deterministic, and the single most convincing piece of evidence the
   system produces, because it needs two records to agree to be impossible.
4. **Event-order violation** -- a container DELIVERED before it was LOADED.
5. **Dwell-time anomaly** -- a port call far outside what that port normally
   sees. Explicitly *anomalous, not malicious* (spec 9.5): it gets a capped
   severity and will never on its own push a record over the suspicion
   threshold.

Dwell baselines are learned from the manifest with median/MAD rather than
read from the world model. The problem statement requires the system to work
out what normal looks like for itself, and a learned baseline also survives
the Shifting Waters twist changing operational patterns.

**Division of labour with the geospatial engine.** Both specs describe a
``distance / elapsed_time`` check. It is computed once, in
:mod:`core.geospatial.engine`, and emitted as ``SPEED_INFEASIBLE``. This
engine only raises ``IMPOSSIBLE_TRANSIT`` for the degenerate case where
elapsed time is zero or negative between two *different* ports -- a pure
temporal contradiction for which no speed is even defined. Counting one
physical violation twice would inflate the fused probability for free.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from core.detection.base import AnalysisContext, register_detector
from core.models import Evidence, ManifestRecord
from core.stats import median, robust_z, severity_from_z
from core.types import (
    EVENT_ORDER,
    IN_PORT_EVENTS,
    EvidenceCode,
    EvidenceType,
)

ENGINE = "temporal"

#: Dwell samples needed before a port gets its own baseline rather than the
#: pooled one. Below this the estimate is noise.
_MIN_PORT_SAMPLES = 12


def _ev(
    record_id: str,
    code: EvidenceCode,
    severity: float,
    description: str,
    *,
    supporting: list[str] | None = None,
    **details: object,
) -> Evidence:
    from core.types import EVIDENCE_CODE_TYPE

    return Evidence(
        record_id=record_id,
        code=code,
        type=EvidenceType(EVIDENCE_CODE_TYPE[code]),
        severity=max(0.0, min(1.0, severity)),
        description=description,
        supporting_records=supporting or [],
        details=details,
        engine=ENGINE,
    )


class _PortVisit:
    """A container's presence interval at one port, from one record."""

    __slots__ = ("record", "port_id", "start", "end")

    def __init__(self, record: ManifestRecord, port_id: str, start: datetime, end: datetime) -> None:
        self.record = record
        self.port_id = port_id
        self.start = start
        self.end = end

    def overlaps(self, other: _PortVisit, tolerance: timedelta) -> timedelta:
        """Length of the overlap with ``other``, net of ``tolerance``."""
        latest_start = max(self.start, other.start)
        earliest_end = min(self.end, other.end)
        gap = earliest_end - latest_start
        return gap - tolerance if gap > tolerance else timedelta(0)


class TemporalEngine:
    name = "temporal"

    def run(self, ctx: AnalysisContext) -> list[Evidence]:
        out: list[Evidence] = []
        out.extend(self._future_events(ctx))
        out.extend(self._reverse_chronology(ctx))
        out.extend(self._degenerate_transit(ctx))
        out.extend(self._simultaneous_presence(ctx))
        out.extend(self._event_order(ctx))
        out.extend(self._dwell_times(ctx))
        return [e for e in out if e.severity > 0.0]

    # -- 9.1 future events ----------------------------------------------

    def _future_events(self, ctx: AnalysisContext) -> list[Evidence]:
        grace = timedelta(hours=ctx.cfg.float_("detection.temporal.future_event_grace_hours"))
        floor = ctx.cfg.float_("detection.temporal.future_event_min_severity")
        ceiling = ctx.cfg.float_("detection.temporal.future_event_max_severity")
        cutoff = ctx.clock + grace
        out: list[Evidence] = []

        # ``departure_timestamp`` is deliberately excluded. On the most recent
        # record of a port call it is a *scheduled* departure -- a forecast,
        # not a claim that something already happened -- so a future value is
        # normal and flagging it made every live event look tampered with.
        # ``timestamp`` and ``arrival_timestamp`` are assertions about the
        # past, and a future value there is genuinely impossible; the
        # generator's future-dating attack moves ``timestamp``, so coverage of
        # that attack is unaffected.
        for rec in ctx.records:
            for field_name in ("timestamp", "arrival_timestamp"):
                when = getattr(rec, field_name)
                if when is None or when <= cutoff:
                    continue
                ahead_hours = (when - ctx.clock).total_seconds() / 3600.0
                # Severity rises with how far past the clock it sits: a few
                # hours could be a clock-skew artefact, a month cannot.
                severity = min(
                    ceiling,
                    floor + min(ceiling - floor, ahead_hours / (24.0 * 30.0) * (ceiling - floor)),
                )
                out.append(
                    _ev(
                        rec.record_id,
                        EvidenceCode.FUTURE_EVENT,
                        severity,
                        f"Field '{field_name}' is dated {when.isoformat()}, "
                        f"{ahead_hours:.1f}h after the analysis clock "
                        f"({ctx.clock.isoformat()}); the event cannot have occurred yet.",
                        field=field_name,
                        event_time=when.isoformat(),
                        clock=ctx.clock.isoformat(),
                        hours_ahead=round(ahead_hours, 2),
                    )
                )
                break  # one finding per record is enough
        return out

    # -- 9.2 reverse chronology -----------------------------------------

    def _reverse_chronology(self, ctx: AnalysisContext) -> list[Evidence]:
        severity = ctx.cfg.float_("detection.temporal.reverse_chronology_severity")
        out: list[Evidence] = []
        for rec in ctx.records:
            if rec.arrival_timestamp is None or rec.departure_timestamp is None:
                continue
            if rec.arrival_timestamp <= rec.departure_timestamp:
                continue
            delta_hours = (
                rec.arrival_timestamp - rec.departure_timestamp
            ).total_seconds() / 3600.0
            out.append(
                _ev(
                    rec.record_id,
                    EvidenceCode.REVERSE_CHRONOLOGY,
                    severity,
                    f"Arrival ({rec.arrival_timestamp.isoformat()}) is "
                    f"{delta_hours:.1f}h after departure "
                    f"({rec.departure_timestamp.isoformat()}) for the same port call.",
                    arrival=rec.arrival_timestamp.isoformat(),
                    departure=rec.departure_timestamp.isoformat(),
                    hours_inverted=round(delta_hours, 2),
                )
            )
        return out

    # -- 9.3 degenerate transit (zero/negative elapsed time) -------------

    def _degenerate_transit(self, ctx: AnalysisContext) -> list[Evidence]:
        """Two different ports with no time between them.

        The speed-based feasibility check lives in the geospatial engine; this
        covers only the case where elapsed time is <= 0 and a speed cannot be
        computed at all.
        """
        severity = ctx.cfg.float_("detection.temporal.degenerate_transit_severity")
        out: list[Evidence] = []
        for container_id, timeline in ctx.by_container.items():
            previous: ManifestRecord | None = None
            for rec in timeline:
                if rec.port_id is None or rec.effective_time() is None:
                    continue
                if previous is not None and previous.port_id != rec.port_id:
                    elapsed = (
                        rec.effective_time() - previous.effective_time()
                    ).total_seconds()
                    if elapsed <= 0:
                        out.append(
                            _ev(
                                rec.record_id,
                                EvidenceCode.IMPOSSIBLE_TRANSIT,
                                severity,
                                f"Container {container_id} moves from "
                                f"{previous.port_id} to {rec.port_id} with "
                                f"{elapsed:.0f}s of elapsed time; no transit is possible.",
                                supporting=[previous.record_id],
                                from_port=previous.port_id,
                                to_port=rec.port_id,
                                elapsed_seconds=elapsed,
                                container_id=container_id,
                            )
                        )
                previous = rec
        return out

    # -- 9.4 simultaneous presence ---------------------------------------

    def _simultaneous_presence(self, ctx: AnalysisContext) -> list[Evidence]:
        """One container inside two different ports at overlapping times."""
        severity = ctx.cfg.float_("detection.temporal.simultaneous_presence_severity")
        # Small tolerance so two records describing the same real port call
        # with slightly different stamps do not trip the check.
        tolerance = timedelta(minutes=30)
        out: list[Evidence] = []

        for container_id, timeline in ctx.by_container.items():
            visits: list[_PortVisit] = []
            for rec in timeline:
                if rec.port_id is None or (rec.event_type or "") not in IN_PORT_EVENTS:
                    continue
                start = rec.arrival_timestamp or rec.effective_time()
                if start is None:
                    continue
                end = rec.departure_timestamp or start
                if end < start:
                    # Reverse chronology is reported separately; use the span
                    # either way so the overlap test still means something.
                    start, end = end, start
                visits.append(_PortVisit(rec, rec.port_id, start, end))

            visits.sort(key=lambda v: v.start)
            for i, visit in enumerate(visits):
                for other in visits[i + 1 :]:
                    if other.start > visit.end:
                        break  # sorted: no later visit can overlap
                    if other.port_id == visit.port_id:
                        continue
                    overlap = visit.overlaps(other, tolerance)
                    if overlap <= timedelta(0):
                        continue
                    hours = overlap.total_seconds() / 3600.0
                    description = (
                        f"Container {container_id} is reported at "
                        f"{visit.port_id} ({visit.start.isoformat()} to "
                        f"{visit.end.isoformat()}) and at {other.port_id} "
                        f"({other.start.isoformat()} to {other.end.isoformat()}); "
                        f"the presences overlap by {hours:.1f}h."
                    )
                    for subject, counterpart in ((visit, other), (other, visit)):
                        out.append(
                            _ev(
                                subject.record.record_id,
                                EvidenceCode.SIMULTANEOUS_PRESENCE,
                                severity,
                                description,
                                supporting=[counterpart.record.record_id],
                                container_id=container_id,
                                this_port=subject.port_id,
                                other_port=counterpart.port_id,
                                overlap_hours=round(hours, 2),
                            )
                        )
        return out

    # -- event lifecycle ordering ----------------------------------------

    def _event_order(self, ctx: AnalysisContext) -> list[Evidence]:
        """A container's events must not run backwards through the lifecycle.

        Scoped to ``(container, shipment)`` rather than to the container
        alone. Containers are reused: one delivered on a shipment and then
        created again on the next booking is completely normal, and keying on
        the container's whole lifetime reported every reuse as an event after
        delivery.

        Only *terminal* regressions are reported -- an event after that
        shipment's DELIVERED, or before its CREATED. Intermediate ordering
        legitimately repeats (arrive/depart at every port), so comparing raw
        ranks would flag every multi-leg voyage.
        """
        after_delivery = ctx.cfg.float_(
            "detection.temporal.event_order_after_delivery_severity"
        )
        before_creation = ctx.cfg.float_(
            "detection.temporal.event_order_before_creation_severity"
        )
        out: list[Evidence] = []
        for container_id, timeline in ctx.by_container.items():
            # Group the container's history by shipment, so each booking is
            # assessed as its own lifecycle.
            by_shipment: dict[str | None, list[ManifestRecord]] = defaultdict(list)
            for rec in timeline:
                by_shipment[rec.shipment_id].append(rec)

            for shipment_id, records in by_shipment.items():
                delivered_at: datetime | None = None
                created_at: datetime | None = None
                for rec in records:
                    when = rec.effective_time()
                    if when is None:
                        continue
                    if rec.event_type == "DELIVERED":
                        delivered_at = when if delivered_at is None else min(delivered_at, when)
                    if rec.event_type == "CREATED":
                        created_at = when if created_at is None else min(created_at, when)

                for rec in records:
                    when = rec.effective_time()
                    if when is None or rec.event_type is None:
                        continue
                    rank = EVENT_ORDER.get(rec.event_type, 99)
                    scope = f"shipment {shipment_id}" if shipment_id else "its shipment"

                    if (
                        delivered_at is not None
                        and when > delivered_at
                        and rank < EVENT_ORDER["DELIVERED"]
                    ):
                        hours = (when - delivered_at).total_seconds() / 3600.0
                        out.append(
                            _ev(
                                rec.record_id,
                                EvidenceCode.EVENT_ORDER_VIOLATION,
                                after_delivery,
                                f"Container {container_id} records a "
                                f"'{rec.event_type}' event {hours:.1f}h after it was "
                                f"already DELIVERED on {scope}.",
                                container_id=container_id,
                                shipment_id=shipment_id,
                                event_type=rec.event_type,
                                delivered_at=delivered_at.isoformat(),
                                hours_after_delivery=round(hours, 2),
                            )
                        )
                    elif created_at is not None and when < created_at - timedelta(minutes=1):
                        hours = (created_at - when).total_seconds() / 3600.0
                        out.append(
                            _ev(
                                rec.record_id,
                                EvidenceCode.EVENT_ORDER_VIOLATION,
                                before_creation,
                                f"Container {container_id} records a "
                                f"'{rec.event_type}' event {hours:.1f}h before it was "
                                f"CREATED on {scope}.",
                                container_id=container_id,
                                shipment_id=shipment_id,
                                event_type=rec.event_type,
                                created_at=created_at.isoformat(),
                                hours_before_creation=round(hours, 2),
                            )
                        )
        return out

    # -- 9.5 dwell-time analysis -----------------------------------------

    def _dwell_times(self, ctx: AnalysisContext) -> list[Evidence]:
        """Compare each port call against that port's learned dwell distribution."""
        cfg = ctx.cfg
        threshold = cfg.float_("detection.temporal.dwell_z_threshold")
        ceiling = cfg.float_("detection.temporal.dwell_max_severity")
        floor_h = cfg.float_("port.dwell_hours_min")
        ceil_h = cfg.float_("port.dwell_hours_max")

        samples: dict[str, list[float]] = defaultdict(list)
        observed: list[tuple[ManifestRecord, str, float]] = []

        for rec in ctx.records:
            if rec.port_id is None:
                continue
            if rec.arrival_timestamp is None or rec.departure_timestamp is None:
                continue
            hours = (rec.departure_timestamp - rec.arrival_timestamp).total_seconds() / 3600.0
            if hours <= 0:
                continue  # inverted: reported by _reverse_chronology
            observed.append((rec, rec.port_id, hours))
            samples[rec.port_id].append(hours)

        pooled = [h for values in samples.values() for h in values]
        if not pooled:
            return []

        out: list[Evidence] = []
        for rec, port_id, hours in observed:
            port_samples = samples[port_id]
            if len(port_samples) >= _MIN_PORT_SAMPLES:
                basis, baseline = "port", port_samples
            else:
                basis, baseline = "pooled", pooled

            z = robust_z(hours, baseline)
            severity = severity_from_z(z, threshold, saturate_at=6.0, ceiling=ceiling)
            if severity <= 0.0:
                continue

            port_name = ctx.world.ports[port_id].name if port_id in ctx.world.ports else port_id
            out.append(
                _ev(
                    rec.record_id,
                    EvidenceCode.DWELL_TIME_ANOMALY,
                    severity,
                    f"Dwell of {hours:.1f}h at {port_name} is {z:+.1f} robust "
                    f"standard deviations from the {basis} median of "
                    f"{median(baseline):.1f}h (expected operating range "
                    f"{floor_h:.0f}-{ceil_h:.0f}h). Anomalous, not necessarily malicious.",
                    port_id=port_id,
                    observed_hours=round(hours, 2),
                    robust_z=round(z, 2),
                    baseline_median_hours=round(median(baseline), 2),
                    baseline=basis,
                    sample_size=len(baseline),
                )
            )
        return out


register_detector(TemporalEngine())

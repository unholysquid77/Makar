"""Cargo conservation engine (spec 11).

The governing identity is::

    incoming_weight + added_cargo - removed_cargo == outgoing_weight

In manifest terms: a container's cargo state may only change across a port
call that contains a cargo-mutating event (``LOADED``, ``UNLOADED``,
``TRANSFERRED``). A weight that moves with no such event is unexplained, and
unexplained is the whole point — it is the single most direct signal that a
value was edited rather than observed.

Equivalent checks run over `container_count`, `declared_value`, `owner` and
`cargo_type` (spec 11), each with its own tolerance:

* **weight** — relative tolerance, because rounding and unit conversion
  legitimately move the last digit.
* **declared_value** — looser tolerance, since value is re-stated per leg and
  partial discharge scales it.
* **container_count** — exact, since it is an integer count of a shipment.
* **owner** — may only change across a `TRANSFERRED` event. This is what
  catches ownership laundering.
* **cargo_type** — may never change for a given container. A container of
  coffee does not become a container of steel.

A note on honesty: the engine compares *consecutive port calls*, not a record
against the world model's `initial_weight_kg`. Comparing against the world
would make every post-discharge record look wrong, and would also be using
reference data to answer a question the manifest should answer itself.
"""

from __future__ import annotations

from core.detection.base import AnalysisContext, register_detector
from core.detection.segments import PortCall, container_port_calls
from core.models import Evidence, ManifestRecord
from core.stats import median, severity_from_ratio
from core.types import (
    CARGO_MUTATING_EVENTS,
    EVIDENCE_CODE_TYPE,
    OWNERSHIP_TRANSFER_EVENTS,
    EvidenceCode,
    EvidenceType,
)

ENGINE = "cargo"


def _ev(
    record_id: str,
    code: EvidenceCode,
    severity: float,
    description: str,
    *,
    supporting: list[str] | None = None,
    **details: object,
) -> Evidence:
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


def _call_has_mutating_event(call: PortCall) -> bool:
    return any((r.event_type or "") in CARGO_MUTATING_EVENTS for r in call.records)


def _call_has_transfer(call: PortCall) -> bool:
    return any((r.event_type or "") in OWNERSHIP_TRANSFER_EVENTS for r in call.records)


def _first_not_none(records: list[ManifestRecord], field: str):
    for rec in records:
        value = getattr(rec, field, None)
        if value is not None:
            return value
    return None


def _last_not_none(records: list[ManifestRecord], field: str):
    for rec in reversed(records):
        value = getattr(rec, field, None)
        if value is not None:
            return value
    return None


def _carrier(records: list[ManifestRecord], field: str, value, fallback: ManifestRecord):
    """The record that actually carries ``value`` in ``field``.

    Evidence about a changed value belongs on the row that changed, not on
    whichever record happens to represent the port call. Besides being what
    an investigator wants to see, it is what makes the finding visible in the
    live path: the streaming processor reports findings about the event it
    just ingested, so a mutation attributed to an earlier sibling record was
    silently dropped.
    """
    for rec in records:
        if getattr(rec, field, None) == value:
            return rec
    return fallback


class CargoEngine:
    name = "cargo"

    def run(self, ctx: AnalysisContext) -> list[Evidence]:
        out: list[Evidence] = []
        out.extend(self._conservation(ctx))
        out.extend(self._cumulative_drift(ctx))
        out.extend(self._intra_call_consistency(ctx))
        out.extend(self._capacity(ctx))
        return [e for e in out if e.severity > 0.0]

    # -- cumulative drift across a run of transitions ---------------------

    def _cumulative_drift(self, ctx: AnalysisContext) -> list[Evidence]:
        """Cargo must not drift across a run of transitions, not merely across one.

        The per-transition check above tolerates a small relative change,
        because rounding and unit conversion legitimately move the last digit.
        Summed over a long voyage those tolerances add up to a large number,
        and a series of individually-legal steps can move a lot of cargo while
        no single step looks wrong.

        This closes that gap generally: within any run of transitions with no
        cargo-mutating event to explain them, the *total* change is held to a
        much tighter bound than the sum of the per-step bounds. The constraint
        is about conservation, not about any particular attack technique --
        which is what lets it catch a pattern the batch data never contained.
        """
        cfg = ctx.cfg
        tolerance = cfg.float_("detection.cargo.cumulative_rel_tolerance", 0.045)
        step_tolerance = cfg.float_("detection.cargo.weight_rel_tolerance")
        min_steps = cfg.int_("detection.cargo.cumulative_min_steps", 3)
        ceiling = cfg.float_("detection.cargo.max_severity")

        out: list[Evidence] = []
        for container_id, calls in container_port_calls(ctx).items():
            if len(calls) < min_steps + 1:
                continue

            # Walk the voyage, restarting the accumulation whenever a cargo
            # event legitimately changes the baseline.
            baseline: float | None = None
            baseline_call = None
            steps: list[PortCall] = []
            # Weight observed at each point in the run, so the size of the
            # individual steps can be checked -- see below.
            trail: list[float] = []

            def flush(current_weight: float | None, tail: PortCall | None) -> None:
                nonlocal baseline, baseline_call, steps, trail
                if (
                    baseline is not None
                    and baseline > 0
                    and current_weight is not None
                    and len(steps) >= min_steps
                ):
                    drift = current_weight - baseline
                    relative = abs(drift) / baseline

                    # This check exists only to catch drift that *hides below*
                    # the per-transition tolerance. If any single step breaches
                    # that tolerance, the per-transition check already reported
                    # it, on the record that actually carries the changed
                    # value. Reporting it again here would attribute a single
                    # large edit to the last record of the run, which is
                    # usually innocent -- measured, that cost 14 extra false
                    # positives across three seeds.
                    # Gradualness is tested on the *record-level* weight
                    # sequence, not on per-call medians. A call holds several
                    # records, so a median-to-median delta can exceed the
                    # per-transition tolerance even when every individual
                    # report moved by less -- which is precisely the shape a
                    # gradual siphon has, and testing medians suppressed every
                    # detection of it.
                    run_calls = [c for c in ([baseline_call] + steps + ([tail] if tail else [])) if c]
                    sequence = [
                        r.weight
                        for c in run_calls
                        for r in c.records
                        if r.weight is not None
                    ]
                    gradual = True
                    for first, second in zip(sequence, sequence[1:], strict=False):
                        if first > 0 and abs(second - first) / first > step_tolerance:
                            gradual = False
                            break

                    if relative > tolerance and gradual:
                        # Saturates at 15%, not 50%. A seventh of a
                        # container's cargo vanishing with no unloading event
                        # anywhere in the run is about as bad as conservation
                        # gets; ramping to 50% scored a 15% unexplained loss
                        # at severity 0.20, which is absurd.
                        severity = severity_from_ratio(
                            relative, tolerance, 0.15, ceiling=ceiling
                        )
                        tail_call = tail or steps[-1]
                        # The drift is observed *as of* the most recent record
                        # in the run, so that is where the finding belongs.
                        # Matching on the median weight instead fell back to
                        # the call representative whenever a call held two
                        # different weights -- which is exactly the case a
                        # gradual siphon produces, so the finding never landed
                        # on the record that had just arrived and the live path
                        # dropped it.
                        subject = tail_call.records[-1]
                        support = [
                            r.record_id for c in steps for r in c.records
                        ][:8]
                        per_step = relative / max(1, len(steps))
                        out.append(
                            _ev(
                                subject.record_id,
                                EvidenceCode.CARGO_DRIFT_UNEXPLAINED,
                                severity,
                                f"Container {container_id} loses "
                                f"{abs(drift):,.0f} kg ({relative:.1%}) across "
                                f"{len(steps)} consecutive transitions with no "
                                f"loading, unloading or transfer event anywhere in "
                                f"the run. Each individual step averages "
                                f"{per_step:.1%}, inside the per-transition "
                                f"tolerance of "
                                f"{cfg.float_('detection.cargo.weight_rel_tolerance'):.1%}, "
                                f"so the drift is only visible cumulatively.",
                                supporting=support,
                                container_id=container_id,
                                weight_start=round(baseline, 1),
                                weight_end=round(current_weight, 1),
                                drift_kg=round(drift, 1),
                                relative_drift=round(relative, 4),
                                steps=len(steps),
                                mean_step_fraction=round(per_step, 5),
                                cumulative_tolerance=tolerance,
                                scope="cumulative",
                            )
                        )
                baseline, baseline_call, steps = None, None, []

            for call in calls:
                weights = [r.weight for r in call.records if r.weight is not None]
                weight = median(weights) if weights else None
                explained = _call_has_mutating_event(call)

                if explained:
                    flush(weight, call)
                    baseline, baseline_call, steps, trail = weight, call, [], []
                    continue

                if baseline is None:
                    baseline, baseline_call, steps, trail = weight, call, [], []
                else:
                    steps.append(call)
                    if weight is not None:
                        trail.append(weight)

            last_weights = [
                r.weight for r in calls[-1].records if r.weight is not None
            ]
            flush(median(last_weights) if last_weights else None, calls[-1])
        return out

    # -- across consecutive port calls ------------------------------------

    def _conservation(self, ctx: AnalysisContext) -> list[Evidence]:
        cfg = ctx.cfg
        weight_tol = cfg.float_("detection.cargo.weight_rel_tolerance")
        value_tol = cfg.float_("detection.cargo.value_rel_tolerance")
        count_tol = cfg.int_("detection.cargo.container_count_tolerance")
        ceiling = cfg.float_("detection.cargo.max_severity")
        count_severity = cfg.float_("detection.cargo.count_not_conserved_severity")
        owner_severity = cfg.float_("detection.cargo.owner_changed_severity")
        cargo_type_severity = cfg.float_("detection.cargo.cargo_type_mutated_severity")

        out: list[Evidence] = []
        for container_id, calls in container_port_calls(ctx).items():
            for previous, current in zip(calls, calls[1:], strict=False):
                explained = _call_has_mutating_event(previous) or _call_has_mutating_event(
                    current
                )
                subject = current.representative
                support = previous.record_ids

                # --- weight ---
                before = _last_not_none(previous.records, "weight")
                after = _first_not_none(current.records, "weight")
                if before is not None and after is not None and before > 0:
                    delta = after - before
                    relative = abs(delta) / before
                    if relative > weight_tol and not explained:
                        severity = severity_from_ratio(
                            relative, weight_tol, 1.0, ceiling=ceiling
                        )
                        carrier = _carrier(current.records, "weight", after, subject)
                        out.append(
                            _ev(
                                carrier.record_id,
                                EvidenceCode.WEIGHT_NOT_CONSERVED,
                                severity,
                                f"Container {container_id} weight changes from "
                                f"{before:,.0f} kg at {previous.port_id} to "
                                f"{after:,.0f} kg at {current.port_id} "
                                f"({delta:+,.0f} kg, {relative:.1%}) with no "
                                f"loading, unloading or transfer event to explain it.",
                                supporting=support,
                                container_id=container_id,
                                from_port=previous.port_id,
                                to_port=current.port_id,
                                weight_before=before,
                                weight_after=after,
                                delta_kg=round(delta, 1),
                                relative_change=round(relative, 4),
                                tolerance=weight_tol,
                                explained_by_event=False,
                            )
                        )

                # --- declared value ---
                before_v = _last_not_none(previous.records, "declared_value")
                after_v = _first_not_none(current.records, "declared_value")
                if before_v is not None and after_v is not None and before_v > 0:
                    delta = after_v - before_v
                    relative = abs(delta) / before_v
                    if relative > value_tol and not explained:
                        severity = severity_from_ratio(
                            relative, value_tol, 1.5, ceiling=ceiling * 0.85
                        )
                        carrier = _carrier(current.records, "declared_value", after_v, subject)
                        out.append(
                            _ev(
                                carrier.record_id,
                                EvidenceCode.VALUE_NOT_CONSERVED,
                                severity,
                                f"Container {container_id} declared value changes from "
                                f"{before_v:,.0f} to {after_v:,.0f} ({relative:.1%}) "
                                f"between {previous.port_id} and {current.port_id} "
                                f"with no cargo event to explain it.",
                                supporting=support,
                                container_id=container_id,
                                value_before=before_v,
                                value_after=after_v,
                                relative_change=round(relative, 4),
                                tolerance=value_tol,
                            )
                        )

                # --- container count ---
                before_c = _last_not_none(previous.records, "container_count")
                after_c = _first_not_none(current.records, "container_count")
                if (
                    before_c is not None
                    and after_c is not None
                    and abs(after_c - before_c) > count_tol
                ):
                    carrier = _carrier(
                        current.records, "container_count", after_c, subject
                    )
                    out.append(
                        _ev(
                            carrier.record_id,
                            EvidenceCode.CONTAINER_COUNT_NOT_CONSERVED,
                            count_severity,
                            f"Shipment container count changes from {before_c} to "
                            f"{after_c} between {previous.port_id} and "
                            f"{current.port_id} for container {container_id}.",
                            supporting=support,
                            container_id=container_id,
                            count_before=before_c,
                            count_after=after_c,
                        )
                    )

                # --- owner ---
                before_o = _last_not_none(previous.records, "owner")
                after_o = _first_not_none(current.records, "owner")
                if before_o and after_o and before_o != after_o:
                    transferred = _call_has_transfer(previous) or _call_has_transfer(current)
                    if not transferred:
                        carrier = _carrier(current.records, "owner", after_o, subject)
                        out.append(
                            _ev(
                                carrier.record_id,
                                EvidenceCode.OWNER_CHANGED_WITHOUT_TRANSFER,
                                owner_severity,
                                f"Container {container_id} changes owner from "
                                f"{before_o!r} to {after_o!r} between "
                                f"{previous.port_id} and {current.port_id} with no "
                                f"TRANSFERRED event.",
                                supporting=support,
                                container_id=container_id,
                                owner_before=before_o,
                                owner_after=after_o,
                            )
                        )

                # --- cargo type ---
                before_t = _last_not_none(previous.records, "cargo_type")
                after_t = _first_not_none(current.records, "cargo_type")
                if before_t and after_t and before_t != after_t:
                    carrier = _carrier(current.records, "cargo_type", after_t, subject)
                    out.append(
                        _ev(
                            carrier.record_id,
                            EvidenceCode.CARGO_TYPE_MUTATED,
                            cargo_type_severity,
                            f"Container {container_id} cargo type changes from "
                            f"{before_t} to {after_t} between {previous.port_id} and "
                            f"{current.port_id}; a container's cargo class does not "
                            f"change in transit.",
                            supporting=support,
                            container_id=container_id,
                            cargo_before=before_t,
                            cargo_after=after_t,
                        )
                    )
        return out

    # -- within a single port call ----------------------------------------

    def _intra_call_consistency(self, ctx: AnalysisContext) -> list[Evidence]:
        """Records describing one port call must agree with each other.

        Within one call, only a cargo-mutating event may change the weight. Two
        records of the same call disagreeing with no such event between them is
        a direct contradiction with a very small number of moving parts, which
        makes it one of the easier findings to defend.
        """
        weight_tol = ctx.cfg.float_("detection.cargo.weight_rel_tolerance")
        ceiling = ctx.cfg.float_("detection.cargo.max_severity")
        out: list[Evidence] = []

        for container_id, calls in container_port_calls(ctx).items():
            for call in calls:
                if len(call.records) < 2 or _call_has_mutating_event(call):
                    continue
                weights = [(r, r.weight) for r in call.records if r.weight is not None]
                if len(weights) < 2:
                    continue
                baseline_record, baseline = weights[0]
                for rec, weight in weights[1:]:
                    if baseline <= 0:
                        continue
                    relative = abs(weight - baseline) / baseline
                    if relative <= weight_tol:
                        continue
                    severity = severity_from_ratio(relative, weight_tol, 1.0, ceiling=ceiling)
                    out.append(
                        _ev(
                            rec.record_id,
                            EvidenceCode.WEIGHT_NOT_CONSERVED,
                            severity,
                            f"Two records of the same port call at {call.port_id} "
                            f"for container {container_id} disagree on weight "
                            f"({baseline:,.0f} kg vs {weight:,.0f} kg, "
                            f"{relative:.1%}) with no cargo event between them.",
                            supporting=[baseline_record.record_id],
                            container_id=container_id,
                            port_id=call.port_id,
                            weight_a=baseline,
                            weight_b=weight,
                            relative_change=round(relative, 4),
                            scope="intra_port_call",
                        )
                    )
        return out

    # -- physical capacity -------------------------------------------------

    def _capacity(self, ctx: AnalysisContext) -> list[Evidence]:
        """A container cannot hold more than its rated payload."""
        ceiling = ctx.cfg.float_("detection.cargo.capacity_max_severity")
        out: list[Evidence] = []
        for rec in ctx.records:
            if rec.weight is None or rec.container_id is None:
                continue
            container = ctx.world.containers.get(rec.container_id)
            if container is None:
                continue
            limit = container.max_weight_kg
            if limit <= 0 or rec.weight <= limit:
                continue
            ratio = rec.weight / limit
            severity = severity_from_ratio(ratio, 1.0, 3.0, ceiling=ceiling)
            out.append(
                _ev(
                    rec.record_id,
                    EvidenceCode.WEIGHT_EXCEEDS_CAPACITY,
                    severity,
                    f"Declared weight {rec.weight:,.0f} kg exceeds the rated "
                    f"payload of container {rec.container_id} "
                    f"({limit:,.0f} kg) by {ratio:.1f}x.",
                    container_id=rec.container_id,
                    weight=rec.weight,
                    capacity_kg=limit,
                    ratio=round(ratio, 3),
                )
            )
        return out


register_detector(CargoEngine())

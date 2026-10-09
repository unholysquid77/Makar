"""Graph / lineage detector (spec 14, 18.2, 18.4).

This engine answers the questions a single record cannot: does this record
*belong* to anything, and is anything *missing*?

``ORPHAN_RECORD`` / ``LINEAGE_BREAK``
    A fabricated record is plausible field by field — real owner, real cargo
    class, real port — and only its *relationships* betray it. A record whose
    container has no other record at that port, whose port is not on its
    route, and which no neighbouring event leads into, has no lineage. This is
    the signal that catches fabrication (spec 18.4).

``MISSING_EXPECTED_EVENT`` and inferred deletions
    A deletion leaves no row, so it cannot carry evidence. It is inferred from
    the *shape* of what remains and reported through
    ``ctx.inferred_deletions``, while the records that bracket the hole carry
    ``MISSING_EXPECTED_EVENT``.

Four independent deletion signatures are used, because the provenance chain
can only see some deletions (an attacker who recycles the freed id leaves no
missing commitment, and the unsealed tail has no commitments at all):

1. **Unclosed port call** — ARRIVED with no DEPARTED, *and a later port call
   exists*. The qualifier matters: a voyage still in progress legitimately
   ends on an open call, and flagging those would punish every in-flight
   shipment.
2. **Unopened port call** — DEPARTED with no ARRIVED and an earlier call.
3. **Missing creation** — a container's history starts mid-voyage.
4. **Skipped route port** — the declared route calls at B, the container has
   calls at A and C, and nothing at B. This catches deletion of a whole port
   call rather than a single record.

Record-id gaps corroborate but never stand alone: inserted rows recycle freed
ids, so a filled gap proves nothing and an empty one is only suggestive.
"""

from __future__ import annotations

import re

from core.detection.base import AnalysisContext, register_detector
from core.detection.segments import container_event_calls
from core.models import Evidence
from core.types import EVIDENCE_CODE_TYPE, EventType, EvidenceCode, EvidenceType

ENGINE = "graph"

_ID_PATTERN = re.compile(r"^R(\d{6})$")


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


class GraphEngine:
    name = "graph"

    def run(self, ctx: AnalysisContext) -> list[Evidence]:
        out: list[Evidence] = []
        out.extend(self._lineage(ctx))
        out.extend(self._deletions(ctx))
        self._id_gaps(ctx, out)
        return [e for e in out if e.severity > 0.0]

    # -- lineage / orphan detection ---------------------------------------

    def _lineage(self, ctx: AnalysisContext) -> list[Evidence]:
        orphan_severity = ctx.cfg.float_("detection.graph.orphan_severity")
        break_severity = ctx.cfg.float_("detection.graph.lineage_break_severity")
        out: list[Evidence] = []

        for rec in ctx.records:
            if rec.container_id is None:
                continue
            timeline = ctx.container_timeline(rec.container_id)
            siblings = [r for r in timeline if r.record_id != rec.record_id]

            # Signals of absent lineage, each independently checkable.
            reasons: list[str] = []
            score = 0.0

            when = rec.effective_time()
            # Is this the container's latest known event? If so, "nothing else
            # places it here" may simply mean the rest of the port call has not
            # been reported yet. On a live feed every genuine new arrival looks
            # orphaned under the naive test, so absence only counts as evidence
            # when later events exist that should have accompanied this one.
            has_later = bool(
                when is not None
                and any(
                    s.effective_time() is not None and s.effective_time() > when
                    for s in siblings
                )
            )

            at_same_port = [r for r in siblings if r.port_id == rec.port_id]
            if rec.port_id and not at_same_port and has_later:
                reasons.append(
                    f"no other record places container {rec.container_id} at "
                    f"{rec.port_id}, although later events exist"
                )
                score += 0.40

            # Cargo cannot be handled where it never arrived. A loading,
            # unloading or transfer event at a port with no arrival for that
            # container is a hard lineage violation, not a soft one -- as
            # fundamental as a container being in two places at once.
            if (
                rec.port_id
                and (rec.event_type or "") in {"TRANSFERRED", "LOADED", "UNLOADED"}
                and not any(
                    s.port_id == rec.port_id
                    and (s.event_type or "") in {"ARRIVED", "CREATED"}
                    for s in siblings
                )
            ):
                reasons.append(
                    f"a {rec.event_type} event at {rec.port_id} with no arrival "
                    f"there for container {rec.container_id}"
                )
                score += 0.45

            route = ctx.world.routes.get(rec.route_id or "")
            if route is not None and rec.port_id and rec.port_id not in route.port_sequence:
                reasons.append(f"{rec.port_id} is not a call on route {route.route_id}")
                score += 0.35

            # An ARRIVED/TRANSFERRED event should be preceded by a departure
            # from somewhere. Nothing leading in means nothing brought it here.
            if when is not None and (rec.event_type or "") in {
                EventType.ARRIVED,
                EventType.TRANSFERRED,
            }:
                earlier = [
                    r
                    for r in siblings
                    if r.effective_time() is not None and r.effective_time() < when
                ]
                if not earlier:
                    reasons.append("no preceding event in the container's history")
                    score += 0.25

            if rec.shipment_id and not ctx.resolver.known_shipment(rec.shipment_id):
                reasons.append(f"shipment {rec.shipment_id} is unknown")
                score += 0.30

            # Does this record occupy a port call the container actually had?
            # Records of one real port call share that call's arrival stamp.
            # This separates the two ways a record can look orphaned:
            #
            #   shares a slot -> it was one of the container's real events and
            #                    something about it was *rewritten*
            #   shares none   -> the event itself was *invented*
            #
            # The distinction matters downstream: without it, a record whose
            # location was teleported is indistinguishable from a fabrication,
            # since both lose their port and route relationships.
            shares_time_slot = False
            if rec.arrival_timestamp is not None:
                shares_time_slot = any(
                    s.arrival_timestamp == rec.arrival_timestamp for s in siblings
                )
            if not shares_time_slot and siblings:
                reasons.append(
                    "occupies a port call no other record of the container shares"
                )
                score += 0.30

            if score <= 0.0:
                continue

            # Two or more independent reasons means no lineage at all; one
            # means the chain is broken but the record still belongs somewhere.
            if len(reasons) >= 2:
                out.append(
                    _ev(
                        rec.record_id,
                        EvidenceCode.ORPHAN_RECORD,
                        min(orphan_severity, 0.35 + score * 0.55),
                        f"Record has no supporting lineage: "
                        f"{'; '.join(reasons)}. Nothing in the manifest or the "
                        f"world model accounts for this claim.",
                        supporting=[r.record_id for r in at_same_port][:3],
                        container_id=rec.container_id,
                        reasons=reasons,
                        lineage_score=round(score, 3),
                        shares_time_slot=shares_time_slot,
                    )
                )
            else:
                out.append(
                    _ev(
                        rec.record_id,
                        EvidenceCode.LINEAGE_BREAK,
                        min(break_severity, 0.25 + score * 0.6),
                        f"Lineage is broken for this record: {reasons[0]}.",
                        supporting=[r.record_id for r in at_same_port][:3],
                        container_id=rec.container_id,
                        reasons=reasons,
                        lineage_score=round(score, 3),
                        shares_time_slot=shares_time_slot,
                    )
                )
        return out

    # -- deletion inference ------------------------------------------------

    def _deletions(self, ctx: AnalysisContext) -> list[Evidence]:
        """Infer removed records from the shape of what remains.

        Works over :func:`event_calls` -- records grouped by *time*, not by
        port -- so a record whose location was rewritten still occupies its
        original slot instead of reading as two deletions. See the long note
        in ``core/detection/segments.py``.

        For each call the expected event set follows from its position in the
        voyage, and anything expected but absent is reported. The final call
        of an unfinished voyage expects only an arrival, which is what keeps
        in-progress shipments from being accused of losing records.
        """
        floor = ctx.cfg.float_("detection.graph.missing_event_min_severity")
        ceiling = ctx.cfg.float_("detection.graph.missing_event_max_severity")
        skipped_severity = ctx.cfg.float_("detection.graph.skipped_port_severity")
        out: list[Evidence] = []

        for container_id, all_calls in container_event_calls(ctx).items():
            if not all_calls:
                continue

            route_for_filter = ctx.world.routes.get(
                next(
                    (r.route_id for call in all_calls for r in call.records if r.route_id),
                    "",
                )
                or ""
            )

            # Only reason about calls at ports the container's route actually
            # calls at. A cluster at an off-route port is a relocated or
            # fabricated record, not a port call with records missing from it,
            # and the route and geospatial engines already report it as such.
            # Without this filter every teleport manufactured a phantom call
            # whose "missing" events were reported as deletions.
            if route_for_filter is not None:
                on_route = set(route_for_filter.port_sequence)
                calls = [c for c in all_calls if c.port_id in on_route]
            else:
                calls = list(all_calls)
            if not calls:
                continue

            for index, call in enumerate(calls):
                observed = call.event_types
                is_first = index == 0
                is_last = index == len(calls) - 1
                delivered = EventType.DELIVERED in observed

                # What this call should contain, given where it sits.
                if is_first and not is_last:
                    expected = {EventType.CREATED, EventType.LOADED, EventType.DEPARTED}
                elif is_first and is_last:
                    expected = {EventType.CREATED, EventType.LOADED}
                    if delivered:
                        expected = expected | {EventType.UNLOADED, EventType.DELIVERED}
                elif is_last:
                    # Voyage finished -> full discharge set. Voyage still in
                    # progress -> an arrival is all that is owed.
                    expected = (
                        {EventType.ARRIVED, EventType.UNLOADED, EventType.DELIVERED}
                        if delivered
                        else {EventType.ARRIVED}
                    )
                else:
                    expected = {EventType.ARRIVED, EventType.DEPARTED}

                missing = sorted(str(e) for e in expected - observed)
                if not missing:
                    continue

                subject = call.representative
                neighbours: list[str] = []
                if index > 0:
                    neighbours += calls[index - 1].record_ids[-2:]
                if not is_last:
                    neighbours += calls[index + 1].record_ids[:2]

                port_label = call.port_id or "an unidentified port"
                position = "first" if is_first else ("final" if is_last else "intermediate")
                # Confidence scales with how much of the call survived. A call
                # missing one of three events is a strong deletion signal; a
                # call missing nearly everything is more likely a voyage that
                # has not reached that stage yet.
                intact = len(observed & expected) / max(1, len(expected))
                severity = min(ceiling, floor + intact * (ceiling - floor))

                out.append(
                    _ev(
                        subject.record_id,
                        EvidenceCode.MISSING_EXPECTED_EVENT,
                        severity,
                        f"The {position} port call for container {container_id} at "
                        f"{port_label} records "
                        f"{sorted(str(e) for e in observed)} but is missing "
                        f"{missing}. {len(observed & expected)} of {len(expected)} "
                        f"expected events are present, so the call did happen and "
                        f"the absent record(s) appear to have been removed.",
                        supporting=neighbours,
                        container_id=container_id,
                        port_id=call.port_id,
                        missing_events=missing,
                        observed_events=sorted(str(e) for e in observed),
                        call_position=position,
                        intact_fraction=round(intact, 3),
                        signature="incomplete_port_call",
                    )
                )
                for event_name in missing:
                    ctx.inferred_deletions.append(
                        {
                            "record_id": None,
                            "source": "graph",
                            "container_id": container_id,
                            "port_id": call.port_id,
                            "missing_event": event_name,
                            "between": neighbours[:2] or [subject.record_id],
                            "confidence": round(severity, 3),
                            "reason": (
                                f"The {position} port call for container "
                                f"{container_id} at {port_label} is missing its "
                                f"{event_name} event while the rest of the call "
                                f"is present."
                            ),
                        }
                    )

            # A port the declared route calls at, with no record at all.
            route = route_for_filter
            if route is None or len(calls) < 2:
                continue
            visited = sorted(
                {i for i in (route.index_of(c.port_id) for c in calls) if i is not None}
            )
            if len(visited) < 2:
                continue
            for leg in range(visited[0], visited[-1] + 1):
                if leg in visited:
                    continue
                port_id = route.port_sequence[leg]
                subject = calls[0].representative
                out.append(
                    _ev(
                        subject.record_id,
                        EvidenceCode.MISSING_EXPECTED_EVENT,
                        skipped_severity,
                        f"Route {route.route_id} calls at {port_id} between legs "
                        f"{visited[0]} and {visited[-1]}, but container "
                        f"{container_id} has no record there at all. An entire "
                        f"port call appears to have been removed.",
                        container_id=container_id,
                        port_id=port_id,
                        route_id=route.route_id,
                        missing_events=["PORT_CALL"],
                        signature="skipped_route_port",
                    )
                )
                ctx.inferred_deletions.append(
                    {
                        "record_id": None,
                        "source": "graph",
                        "container_id": container_id,
                        "port_id": port_id,
                        "missing_event": "PORT_CALL",
                        "route_id": route.route_id,
                        "confidence": 0.68,
                        "reason": (
                            f"Route {route.route_id} calls at {port_id} but "
                            f"container {container_id} has no record there."
                        ),
                    }
                )
        return out

    # -- record-id gaps (corroboration only) -------------------------------

    def _id_gaps(self, ctx: AnalysisContext, out: list[Evidence]) -> None:
        """Missing integers in the dense record-id sequence.

        Deliberately weak. Inserted rows may recycle a freed id, so a filled
        gap is not evidence of innocence and an empty one is not proof of
        deletion. It is recorded as a low-confidence inferred deletion and
        attached to the bracketing records at low severity.
        """
        severity = ctx.cfg.float_("detection.graph.sequence_gap_severity")
        numbered: dict[int, str] = {}
        for rec in ctx.records:
            match = _ID_PATTERN.match(rec.record_id)
            if match:
                numbered[int(match.group(1))] = rec.record_id
        if len(numbered) < 10:
            return

        present = sorted(numbered)
        low, high = present[0], present[-1]
        missing = [n for n in range(low, high + 1) if n not in numbered]
        # A huge number of gaps means the ids were never dense and the signal
        # is meaningless; say nothing rather than emit noise.
        if not missing or len(missing) > 0.25 * (high - low + 1):
            return

        for number in missing:
            before = next((numbered[n] for n in range(number - 1, low - 1, -1) if n in numbered), None)
            after = next((numbered[n] for n in range(number + 1, high + 1) if n in numbered), None)
            gap_id = f"R{number:06d}"
            ctx.inferred_deletions.append(
                {
                    "record_id": gap_id,
                    "source": "id_sequence",
                    "between": [before, after],
                    "confidence": 0.45,
                    "reason": (
                        f"Record id {gap_id} is absent from an otherwise dense id "
                        f"sequence. Corroborating only: an inserted row may reuse a "
                        f"freed id, so gaps under-count deletions."
                    ),
                }
            )
            for neighbour in (before, after):
                if neighbour:
                    out.append(
                        _ev(
                            neighbour,
                            EvidenceCode.SEQUENCE_GAP,
                            severity,
                            f"Adjacent to missing record id {gap_id} in an otherwise "
                            f"dense sequence.",
                            supporting=[x for x in (before, after) if x and x != neighbour],
                            missing_record_id=gap_id,
                        )
                    )


register_detector(GraphEngine())

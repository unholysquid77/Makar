"""Port-call segmentation.

Several engines need to reason about a container's *journey* rather than its
individual rows: a voyage leg runs from one port call's departure to the next
port call's arrival, and a single port call is usually described by three or
four records (ARRIVED, INSPECTED, UNLOADED, DEPARTED).

Collapsing records into port calls first means the geospatial engine computes
one speed per leg instead of one per record pair, and the cargo engine
compares cargo state across calls rather than within them. It also means a
record that was teleported to a distant port shows up as its own one-record
call wedged between two legitimate ones -- producing two impossible legs, in
and out, which is exactly the signature we want.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from core.detection.base import AnalysisContext
from core.models import ManifestRecord


@dataclass
class PortCall:
    """One contiguous presence of a container at one port."""

    port_id: str
    records: list[ManifestRecord] = field(default_factory=list)
    arrival: datetime | None = None
    departure: datetime | None = None

    @property
    def record_ids(self) -> list[str]:
        return [r.record_id for r in self.records]

    @property
    def representative(self) -> ManifestRecord:
        """Record that best identifies the call, for evidence attribution.

        Prefers an arrival-type event; otherwise the earliest record.
        """
        for rec in self.records:
            if rec.event_type in {"ARRIVED", "CREATED"}:
                return rec
        return self.records[0]

    @property
    def departure_record(self) -> ManifestRecord:
        for rec in reversed(self.records):
            if rec.event_type in {"DEPARTED", "DELIVERED"}:
                return rec
        return self.records[-1]

    def span(self) -> tuple[datetime | None, datetime | None]:
        return (self.arrival, self.departure)

    def is_singleton_intrusion(self) -> bool:
        """True when this call rests on a single record.

        A legitimate port call almost always leaves several records behind. A
        lone record claiming a port is weak support for the claim, which the
        graph engine uses when weighing fabrication.
        """
        return len(self.records) == 1


def port_calls(timeline: list[ManifestRecord]) -> list[PortCall]:
    """Collapse a container's chronological records into port calls."""
    calls: list[PortCall] = []
    current: PortCall | None = None

    for rec in timeline:
        port_id = rec.port_id
        if port_id is None:
            continue
        if current is None or current.port_id != port_id:
            current = PortCall(port_id=port_id)
            calls.append(current)
        current.records.append(rec)

    for call in calls:
        arrivals = [
            t
            for t in (
                [r.arrival_timestamp for r in call.records]
                + [r.effective_time() for r in call.records]
            )
            if t is not None
        ]
        departures = [
            t
            for t in (
                [r.departure_timestamp for r in call.records]
                + [r.effective_time() for r in call.records]
            )
            if t is not None
        ]
        call.arrival = min(arrivals) if arrivals else None
        call.departure = max(departures) if departures else None

    return calls


def container_port_calls(ctx: AnalysisContext) -> dict[str, list[PortCall]]:
    """Port calls for every container in the manifest."""
    return {cid: port_calls(timeline) for cid, timeline in ctx.by_container.items()}


# ======================================================================
# Event calls: the same records, grouped by TIME instead of by port
# ======================================================================
#
# Two groupings exist because two questions need different answers, and
# conflating them produced a real false-positive cascade:
#
# * :func:`port_calls` groups by ``port_id``. Correct for voyage *legs*: a
#   record relocated to a distant port becomes its own one-record call, which
#   is precisely what makes the two impossible legs show up.
#
# * :func:`event_calls` groups by *time*. Correct for asking "is an event
#   missing?": records of one real port call share that call's arrival and
#   departure stamps, so a record whose *port* was rewritten still belongs to
#   the time slot it always occupied.
#
# Using the port-based grouping to infer deletions made every location edit
# look like two deletions -- the original call lost its closing DEPARTED and
# the next call lost its opening ARRIVED. Grouping by time removes that
# entirely: the relocated record still fills its slot, and its wrong port is
# reported by the route and geospatial engines, where it belongs.

#: Records more than this far apart in time belong to different calls when no
#: arrival stamp is available to group them.
_CALL_GAP_HOURS = 6.0


@dataclass
class EventCall:
    """A container's records for one port call, grouped by time."""

    records: list[ManifestRecord] = field(default_factory=list)
    arrival: datetime | None = None
    departure: datetime | None = None
    #: Port the majority of the call's records agree on. One relocated record
    #: cannot rename the call.
    port_id: str | None = None
    #: Records claiming a port other than the majority -- i.e. relocated.
    dissenting: list[ManifestRecord] = field(default_factory=list)

    @property
    def event_types(self) -> set[str]:
        return {r.event_type for r in self.records if r.event_type}

    @property
    def record_ids(self) -> list[str]:
        return [r.record_id for r in self.records]

    @property
    def representative(self) -> ManifestRecord:
        for rec in self.records:
            if rec.event_type in {"ARRIVED", "CREATED"}:
                return rec
        return self.records[0]


def event_calls(timeline: list[ManifestRecord]) -> list[EventCall]:
    """Group a container's records into port calls by time.

    Primary key is ``arrival_timestamp`` truncated to the minute, since every
    record of one real port call carries that call's arrival stamp. Records
    without one fall back to gap-based clustering.
    """
    keyed: dict[str, EventCall] = {}
    ungrouped: list[ManifestRecord] = []

    for rec in timeline:
        if rec.arrival_timestamp is not None:
            key = rec.arrival_timestamp.replace(second=0, microsecond=0).isoformat()
            call = keyed.setdefault(key, EventCall())
            call.records.append(rec)
        else:
            ungrouped.append(rec)

    calls = list(keyed.values())

    # Fold records with no arrival stamp into the nearest call in time, or
    # start a new one when nothing is close enough.
    for rec in ungrouped:
        when = rec.effective_time()
        if when is None:
            continue
        best: EventCall | None = None
        best_gap = None
        for call in calls:
            anchor = call.arrival or (
                call.records[0].effective_time() if call.records else None
            )
            if anchor is None:
                continue
            gap = abs((when - anchor).total_seconds()) / 3600.0
            if gap <= _CALL_GAP_HOURS and (best_gap is None or gap < best_gap):
                best, best_gap = call, gap
        if best is None:
            best = EventCall()
            calls.append(best)
        best.records.append(rec)

    for call in calls:
        call.records.sort(key=lambda r: (r.effective_time() or datetime.max, r.record_id))
        arrivals = [r.arrival_timestamp for r in call.records if r.arrival_timestamp]
        departures = [r.departure_timestamp for r in call.records if r.departure_timestamp]
        times = [r.effective_time() for r in call.records if r.effective_time()]
        call.arrival = min(arrivals) if arrivals else (min(times) if times else None)
        call.departure = max(departures) if departures else (max(times) if times else None)

        ports = [r.port_id for r in call.records if r.port_id]
        if ports:
            counts: dict[str, int] = {}
            for port in ports:
                counts[port] = counts.get(port, 0) + 1
            call.port_id = max(sorted(counts), key=lambda p: counts[p])
            call.dissenting = [
                r for r in call.records if r.port_id and r.port_id != call.port_id
            ]

    calls.sort(key=lambda c: (c.arrival or datetime.max))
    return _merge_same_port_calls(calls)


#: Two clusters at the same port within this many hours are one port call.
#: Matches the upper end of the dwell distribution: a single call can span up
#: to about three days, so splitting on sub-window gaps would invent calls.
_SAME_PORT_MERGE_HOURS = 72.0


def _merge_same_port_calls(calls: list[EventCall]) -> list[EventCall]:
    """Merge consecutive clusters that describe the same port call.

    A near-duplicate inserted a few hours after the record it copied, or a
    record whose arrival stamp was edited, otherwise forms its own cluster at
    a port the container is already sitting in. Left alone, that phantom
    cluster looks like a port call missing almost all of its events, and the
    deletion inference reports a deletion that never happened.

    Merging on (same port, overlapping-or-adjacent window) folds them back
    together. The justification is the domain, not convenience: one port call
    *is* one contiguous presence at one port.
    """
    if len(calls) < 2:
        return calls

    merged: list[EventCall] = [calls[0]]
    for call in calls[1:]:
        previous = merged[-1]
        same_port = (
            previous.port_id is not None
            and call.port_id is not None
            and previous.port_id == call.port_id
        )
        close_in_time = True
        if previous.departure is not None and call.arrival is not None:
            gap_hours = (call.arrival - previous.departure).total_seconds() / 3600.0
            close_in_time = gap_hours <= _SAME_PORT_MERGE_HOURS

        if same_port and close_in_time:
            previous.records.extend(call.records)
            previous.records.sort(
                key=lambda r: (r.effective_time() or datetime.max, r.record_id)
            )
            arrivals = [r.arrival_timestamp for r in previous.records if r.arrival_timestamp]
            departures = [
                r.departure_timestamp for r in previous.records if r.departure_timestamp
            ]
            times = [r.effective_time() for r in previous.records if r.effective_time()]
            previous.arrival = min(arrivals) if arrivals else (min(times) if times else None)
            previous.departure = (
                max(departures) if departures else (max(times) if times else None)
            )
            previous.dissenting.extend(call.dissenting)
        else:
            merged.append(call)
    return merged


def container_event_calls(ctx: AnalysisContext) -> dict[str, list[EventCall]]:
    """Time-grouped event calls for every container."""
    return {cid: event_calls(timeline) for cid, timeline in ctx.by_container.items()}

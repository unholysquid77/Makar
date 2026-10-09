"""Clean baseline manifest generation (spec 5, 7).

Each shipment is *simulated* as a voyage along its route: arrive, dwell,
depart, sail, repeat. Timings come from the port's own dwell distribution and
the vessel's own speed envelope, so the clean manifest is internally
consistent by construction. Every later detector earns its keep by finding
where corruption broke that consistency.

Two details matter for honest evaluation:

* **Dense, time-ordered record ids.** Records are sorted by event time and
  then numbered ``R000001``, ``R000002``, ... so a deleted record leaves a
  visible gap in both the id sequence and the container's event chain -- which
  is exactly how a real analyst would notice a deletion.
* **Voyages are truncated at the simulation clock.** Shipments still at sea
  when ``world.sim_end`` arrives simply have no further events, and their
  current port visit has ``departure = null``. That produces legitimately
  open-ended histories, so the detector cannot assume "no further events"
  means "records were deleted".
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Any

from core.config import MakarConfig
from core.geo import interpolate, sea_distance_nm
from core.models import (
    Container,
    ManifestRecord,
    Port,
    RouteEvent,
    RouteManifest,
    Shipment,
    World,
)
from core.types import EVENT_ORDER, EventType
from generator.catalog import CARGO_PROFILE_BY_NAME, STATUS_BY_EVENT


class _Visit:
    """One port call on a voyage."""

    __slots__ = ("port_id", "arrival", "departure", "index", "is_last")

    def __init__(
        self,
        port_id: str,
        arrival: datetime,
        departure: datetime | None,
        index: int,
        is_last: bool,
    ) -> None:
        self.port_id = port_id
        self.arrival = arrival
        self.departure = departure
        self.index = index
        self.is_last = is_last


def _plan_voyage(
    rng: random.Random,
    cfg: MakarConfig,
    world: World,
    shipment: Shipment,
) -> list[_Visit]:
    """Compute the port-call schedule for one shipment.

    Returns visits whose arrival falls at or before ``world.sim_end``; the
    last visit may have ``departure=None`` either because it is the final
    destination or because the simulation clock ran out mid-call.
    """
    route = world.routes[shipment.route_id]
    vessel = world.vessels.get(shipment.vessel_id)
    cruise = (
        vessel.cruise_speed_knots if vessel else cfg.float_("vessel.cruise_speed_knots")
    )
    route_factor = cfg.float_("vessel.sea_route_factor")
    dwell_floor = cfg.float_("port.dwell_hours_min")
    dwell_ceiling = cfg.float_("port.dwell_hours_max")

    visits: list[_Visit] = []
    clock = shipment.created_at or world.sim_start
    sequence = route.port_sequence

    for idx, port_id in enumerate(sequence):
        if clock > world.sim_end:
            break
        port: Port = world.ports[port_id]
        is_last = idx == len(sequence) - 1

        dwell_hours = rng.gauss(port.dwell_mean_hours, port.dwell_sigma_hours)
        dwell_hours = min(max(dwell_hours, dwell_floor), dwell_ceiling)
        departure = None if is_last else clock + timedelta(hours=dwell_hours)

        # The clock may expire during this call: the visit stays, but its
        # departure has not happened yet.
        if departure is not None and departure > world.sim_end:
            departure = None

        visits.append(_Visit(port_id, clock, departure, idx, is_last))

        if departure is None:
            break

        next_port: Port = world.ports[sequence[idx + 1]]
        distance_nm = sea_distance_nm(port.coords(), next_port.coords(), route_factor)
        # Weather and traffic jitter: a voyage is never exactly nominal.
        effective_speed = max(1.0, cruise * rng.uniform(0.88, 1.08))
        transit_hours = distance_nm / effective_speed
        clock = departure + timedelta(hours=transit_hours)

    return visits


def _container_events(
    rng: random.Random,
    visit: _Visit,
    is_first_visit: bool,
) -> list[tuple[EventType, datetime]]:
    """Events a container generates during one port call, with their times.

    ``INSPECTED`` and transhipment discharge are sampled, so not every call
    looks the same -- the dwell-time and conservation engines need natural
    variance to calibrate against.
    """
    events: list[tuple[EventType, datetime]] = []
    arrival = visit.arrival
    departure = visit.departure
    # Place intra-call events inside the dwell window when one exists.
    span = (departure - arrival) if departure else timedelta(hours=4)

    def at(fraction: float) -> datetime:
        return arrival + span * max(0.0, min(0.99, fraction))

    if is_first_visit:
        events.append((EventType.CREATED, arrival))
        events.append((EventType.LOADED, at(0.45)))
    else:
        events.append((EventType.ARRIVED, arrival))
        if rng.random() < 0.08:
            events.append((EventType.INSPECTED, at(0.30)))

    if visit.is_last:
        events.append((EventType.UNLOADED, at(0.55)))
        events.append((EventType.DELIVERED, at(0.80)))
    elif departure is not None:
        events.append((EventType.DEPARTED, departure))

    return events


def _record_from_event(
    *,
    record_index: int,
    event_type: EventType,
    when: datetime,
    visit: _Visit,
    shipment: Shipment,
    container: Container,
    world: World,
    current_weight: float,
    current_value: float,
    current_owner: str,
    node_ids: list[str],
    rng: random.Random,
) -> ManifestRecord:
    """Build one manifest row for one container event."""
    route = world.routes[shipment.route_id]
    sequence = route.port_sequence
    port = world.ports[visit.port_id]

    previous_location = (
        world.ports[sequence[visit.index - 1]].name if visit.index > 0 else None
    )
    next_location = (
        world.ports[sequence[visit.index + 1]].name
        if visit.index + 1 < len(sequence)
        else None
    )

    # A DEPARTED record is logged as the vessel clears the port, so its
    # position is the port itself; mid-ocean positions only appear in the
    # observed-trajectory layer the map renders.
    latitude, longitude = port.latitude, port.longitude

    return ManifestRecord(
        record_id=f"TMP_{record_index:07d}",
        cargo_type=container.cargo_type,
        owner=world.owners[current_owner].name,
        origin=world.ports[shipment.origin].name,
        destination=world.ports[shipment.destination].name,
        current_location=port.name,
        weight=round(current_weight, 1),
        container_count=len(shipment.container_ids),
        declared_value=round(current_value, 2),
        status=STATUS_BY_EVENT[str(event_type)],
        timestamp=when,
        shipment_id=shipment.shipment_id,
        container_id=container.container_id,
        route_id=shipment.route_id,
        vessel_id=shipment.vessel_id,
        port_id=port.port_id,
        event_type=str(event_type),
        arrival_timestamp=visit.arrival,
        departure_timestamp=visit.departure,
        latitude=round(latitude, 6),
        longitude=round(longitude, 6),
        previous_location=previous_location,
        next_location=next_location,
        source_node=node_ids[record_index % len(node_ids)],
        schema_version="1.0",
    )


def build_clean_manifest(
    cfg: MakarConfig,
    world: World,
) -> tuple[list[ManifestRecord], dict[str, RouteManifest], World]:
    """Generate the clean manifest and the per-container route histories.

    Returns ``(records, route_manifests, pruned_world)``. The world is pruned
    to the shipments and containers that actually produced records, so the
    world model and the manifest agree -- otherwise every unrealised shipment
    would look like a mass deletion to the graph engine.
    """
    rng = random.Random(world.seed * 7919 + 13)
    budget = cfg.int_("world.records")
    node_ids = [str(n) for n in cfg.list_("nodes.ids")]

    rows: list[tuple[datetime, int, str, ManifestRecord]] = []
    route_events: dict[str, list[RouteEvent]] = {}
    realised_shipments: set[str] = set()
    realised_containers: set[str] = set()
    counter = 0

    # Deterministic shipment order: by creation time, then id.
    ordered = sorted(
        world.shipments.values(),
        key=lambda s: ((s.created_at or world.sim_start), s.shipment_id),
    )

    for shipment in ordered:
        visits = _plan_voyage(rng, cfg, world, shipment)
        if not visits:
            continue

        pending: list[tuple[datetime, int, str, ManifestRecord]] = []
        pending_route_events: dict[str, list[RouteEvent]] = {}

        for container_id in shipment.container_ids:
            container = world.containers[container_id]
            profile = CARGO_PROFILE_BY_NAME.get(container.cargo_type)
            weight = container.initial_weight_kg
            value = container.declared_value
            owner = shipment.owner_id

            for visit in visits:
                pending_route_events.setdefault(container_id, []).append(
                    RouteEvent(
                        port=visit.port_id, arrival=visit.arrival, departure=visit.departure
                    )
                )

                is_first = visit.index == 0
                events = _container_events(rng, visit, is_first)

                # Partial transhipment discharge: splittable cargo may have
                # part of its load removed at an intermediate hub. The
                # UNLOADED event is what makes the weight delta legitimate.
                discharge = False
                if (
                    profile is not None
                    and profile.splittable
                    and not is_first
                    and not visit.is_last
                    and visit.departure is not None
                    and rng.random() < 0.06
                ):
                    discharge = True

                for event_type, when in events:
                    rec = _record_from_event(
                        record_index=counter,
                        event_type=event_type,
                        when=when,
                        visit=visit,
                        shipment=shipment,
                        container=container,
                        world=world,
                        current_weight=weight,
                        current_value=value,
                        current_owner=owner,
                        node_ids=node_ids,
                        rng=rng,
                    )
                    pending.append((when, EVENT_ORDER.get(str(event_type), 99), container_id, rec))
                    counter += 1

                if discharge:
                    removed_fraction = rng.uniform(0.12, 0.35)
                    removed_weight = weight * removed_fraction
                    unload_time = visit.arrival + (visit.departure - visit.arrival) * 0.6
                    weight -= removed_weight
                    value *= 1.0 - removed_fraction
                    rec = _record_from_event(
                        record_index=counter,
                        event_type=EventType.UNLOADED,
                        when=unload_time,
                        visit=visit,
                        shipment=shipment,
                        container=container,
                        world=world,
                        current_weight=weight,
                        current_value=value,
                        current_owner=owner,
                        node_ids=node_ids,
                        rng=rng,
                    )
                    pending.append(
                        (
                            unload_time,
                            EVENT_ORDER[str(EventType.UNLOADED)],
                            container_id,
                            rec,
                        )
                    )
                    counter += 1

        if budget and len(rows) + len(pending) > budget and rows:
            # Stop at a shipment boundary so no voyage is cut in half.
            break

        rows.extend(pending)
        for cid, evts in pending_route_events.items():
            route_events[cid] = evts
            realised_containers.add(cid)
        realised_shipments.add(shipment.shipment_id)

    # Sort by event time and renumber densely so deletions leave visible gaps.
    rows.sort(key=lambda t: (t[0], t[2], t[1]))
    records: list[ManifestRecord] = []
    for i, (_when, _order, _cid, rec) in enumerate(rows, start=1):
        rec.record_id = f"R{i:06d}"
        rec.sequence_index = i
        rec.record_hash = rec.content_hash()
        records.append(rec)

    pruned = World(
        seed=world.seed,
        sim_start=world.sim_start,
        sim_end=world.sim_end,
        ports=world.ports,
        vessels=world.vessels,
        routes=world.routes,
        owners=world.owners,
        shipments={k: v for k, v in world.shipments.items() if k in realised_shipments},
        containers={k: v for k, v in world.containers.items() if k in realised_containers},
        cargo_types=world.cargo_types,
    )

    manifests = {
        cid: RouteManifest(container_id=cid, events=evts) for cid, evts in route_events.items()
    }
    return records, manifests, pruned


def observed_trajectory(
    world: World, manifest: RouteManifest, samples_per_leg: int = 6
) -> list[dict[str, Any]]:
    """Interpolated positions along a container's actual history.

    Feeds the map's observed-trajectory layer (spec 8.3) and the timeline
    slider, which needs a position for any instant, not only at port calls.
    """
    points: list[dict[str, Any]] = []
    legs = list(zip(manifest.events, manifest.events[1:], strict=False))
    for first, second in legs:
        a, b = world.ports.get(first.port), world.ports.get(second.port)
        if not a or not b or first.departure is None or second.arrival is None:
            continue
        total = (second.arrival - first.departure).total_seconds()
        if total <= 0:
            continue
        for step in range(samples_per_leg + 1):
            fraction = step / samples_per_leg
            lat, lon = interpolate(a.coords(), b.coords(), fraction)
            points.append(
                {
                    "timestamp": (first.departure + timedelta(seconds=total * fraction)).isoformat(),
                    "latitude": round(lat, 6),
                    "longitude": round(lon, 6),
                    "from_port": first.port,
                    "to_port": second.port,
                }
            )
    return points

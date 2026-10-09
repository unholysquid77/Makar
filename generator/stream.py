"""Live event stream with attack patterns absent from the batch data (spec 30).

The problem statement requires the live feed to contain at least one attack
type the batch data never held. Three are implemented, chosen because each
defeats a *different* assumption the batch detectors rely on. They are not
variations on the batch attacks with new names.

``weight_siphon``
    Cargo is removed a little at a time across consecutive events, each step
    inside the per-step conservation tolerance, so no single transition looks
    wrong while the cumulative loss is large. This attacks the *tolerance
    itself* — a per-step check cannot see it by construction. The correct
    answer is a general cumulative-drift constraint, not a rule that knows
    about siphoning, and that is what was added to the cargo engine.

``ghost_transfer``
    A ``TRANSFERRED`` event moves cargo between shipments at a port where the
    container never arrived. Every field is individually plausible; only the
    absence of an arrival makes it impossible. Attacks *lineage* rather than
    values.

``identity_swap``
    Two containers exchange ids mid-voyage. Each record still references a
    real container at a real port at a plausible time — but the cargo type
    and weight travelling under each id change. Attacks *identity continuity*,
    which no single-record check can see.

The stream also emits legitimate traffic, at a configurable ratio, so the
system has to keep its false-alarm rate down live and not merely flag
everything that arrives.
"""

from __future__ import annotations

import random
from collections.abc import Iterator
from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field

from core.config import MakarConfig
from core.geo import sea_distance_nm
from core.models import Container, ManifestRecord, Shipment, World
from core.types import AttackClass, EventType
from generator.catalog import CARGO_PROFILES, STATUS_BY_EVENT
from generator.corruption import record_to_row

#: Attack names this module can produce. Referenced by
#: ``stream.novel_attack_patterns`` in config.
NOVEL_PATTERNS: tuple[str, ...] = ("weight_siphon", "ghost_transfer", "identity_swap")


class StreamEvent(BaseModel):
    """One event delivered by the live feed."""

    sequence: int
    emitted_at: datetime
    row: dict[str, Any]
    #: Ground truth for this event, used only by the evaluator. The streaming
    #: processor never reads it.
    truth: dict[str, Any] = Field(default_factory=dict)


class StreamPlan(BaseModel):
    """A reproducible stream: the events plus their private answer key."""

    seed: int
    events: list[StreamEvent] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)

    def rows(self) -> list[dict[str, Any]]:
        return [e.row for e in self.events]

    #: Bookings created by the live feed. The consumer registers these in its
    #: world model, exactly as an operator's master data receives a booking
    #: before its events start flowing.
    new_shipments: list[Shipment] = Field(default_factory=list)
    #: Containers booked by the live feed, registered alongside the shipments.
    new_containers: list[Container] = Field(default_factory=list)

    def tampered_sequences(self) -> set[int]:
        return {e.sequence for e in self.events if e.truth.get("attack")}


def _base_record(
    world: World,
    container_id: str,
    port_id: str,
    event_type: EventType,
    when: datetime,
    *,
    weight: float,
    value: float,
    record_id: str,
    node_id: str,
    shipment: Shipment | None = None,
    route: Any = None,
    container: Any = None,
) -> ManifestRecord:
    container = container or world.containers[container_id]
    shipment = shipment or world.shipments[container.shipment_id]
    route = route or world.routes[shipment.route_id]
    port = world.ports[port_id]
    index = route.index_of(port_id)

    return ManifestRecord(
        record_id=record_id,
        cargo_type=container.cargo_type,
        owner=world.owners[shipment.owner_id].name,
        origin=world.ports[shipment.origin].name,
        destination=world.ports[shipment.destination].name,
        current_location=port.name,
        weight=round(weight, 1),
        container_count=len(shipment.container_ids),
        declared_value=round(value, 2),
        status=STATUS_BY_EVENT[str(event_type)],
        timestamp=when,
        shipment_id=shipment.shipment_id,
        container_id=container_id,
        route_id=route.route_id,
        vessel_id=shipment.vessel_id,
        port_id=port_id,
        event_type=str(event_type),
        arrival_timestamp=when,
        departure_timestamp=None,
        latitude=round(port.latitude, 6),
        longitude=round(port.longitude, 6),
        previous_location=(
            world.ports[route.port_sequence[index - 1]].name
            if index is not None and index > 0
            else None
        ),
        next_location=(
            world.ports[route.port_sequence[index + 1]].name
            if index is not None and index + 1 < len(route.port_sequence)
            else None
        ),
        source_node=node_id,
    )


class _Leg:
    """A planned port call on a live voyage."""

    __slots__ = ("port_id", "arrival", "departure", "index", "is_last")

    def __init__(self, port_id, arrival, departure, index, is_last):
        self.port_id = port_id
        self.arrival = arrival
        self.departure = departure
        self.index = index
        self.is_last = is_last


def _plan_live_voyage(
    rng: random.Random,
    cfg: MakarConfig,
    world: World,
    route,
    start: datetime,
) -> list[_Leg]:
    """Schedule a live voyage with real dwell and transit times.

    Uses the same physics as the batch voyage planner. That matters: if the
    live feed advanced a container between ports faster than a ship can sail,
    every legitimate event would trip SPEED_INFEASIBLE and the stream's own
    ground truth would be wrong.
    """
    cruise = cfg.float_("vessel.cruise_speed_knots")
    vessel = world.vessels.get(route.vessel_id or "")
    if vessel:
        cruise = vessel.cruise_speed_knots
    route_factor = cfg.float_("vessel.sea_route_factor")
    dwell_floor = cfg.float_("port.dwell_hours_min")
    dwell_ceiling = cfg.float_("port.dwell_hours_max")

    legs: list[_Leg] = []
    clock = start
    sequence = route.port_sequence

    for index, port_id in enumerate(sequence):
        port = world.ports[port_id]
        is_last = index == len(sequence) - 1
        dwell = min(
            max(rng.gauss(port.dwell_mean_hours, port.dwell_sigma_hours), dwell_floor),
            dwell_ceiling,
        )
        departure = None if is_last else clock + timedelta(hours=dwell)
        legs.append(_Leg(port_id, clock, departure, index, is_last))
        if departure is None:
            break
        next_port = world.ports[sequence[index + 1]]
        distance = sea_distance_nm(port.coords(), next_port.coords(), route_factor)
        clock = departure + timedelta(hours=distance / max(1.0, cruise * rng.uniform(0.9, 1.08)))

    return legs


def _legit_events(rng: random.Random, leg: _Leg) -> list[tuple[EventType, datetime]]:
    """Events one container produces during one live port call."""
    span = (leg.departure - leg.arrival) if leg.departure else timedelta(hours=6)

    def at(fraction: float) -> datetime:
        return leg.arrival + span * max(0.0, min(0.99, fraction))

    events: list[tuple[EventType, datetime]] = []
    if leg.index == 0:
        events.append((EventType.CREATED, leg.arrival))
        events.append((EventType.LOADED, at(0.45)))
    else:
        events.append((EventType.ARRIVED, leg.arrival))
        if rng.random() < 0.08:
            events.append((EventType.INSPECTED, at(0.30)))
    if leg.is_last:
        events.append((EventType.UNLOADED, at(0.55)))
        events.append((EventType.DELIVERED, at(0.80)))
    elif leg.departure is not None:
        events.append((EventType.DEPARTED, leg.departure))
    return events


def build_stream(
    cfg: MakarConfig,
    world: World,
    batch_records: list[ManifestRecord],
    *,
    count: int = 200,
    seed: int | None = None,
    patterns: list[str] | None = None,
) -> StreamPlan:
    """Build a reproducible live feed of ``count`` events.

    Legitimate traffic is **new bookings**: fresh shipments carrying fresh
    containers on real routes, with voyages planned using the same dwell and
    transit physics as the batch generator. Both the shipments and the
    containers are returned on the plan so the consumer can register them in
    its world model, exactly as an operator's master data receives a booking
    before its events start flowing.

    Two earlier versions of this function were wrong in instructive ways, and
    both failures were in the *generator*, not the detector:

    * Advancing already-delivered containers port to port every few minutes
      made 87 legitimate events trip SPEED_INFEASIBLE and EVENT_ORDER_VIOLATION.
      Fixed by planning voyages with real transit times.
    * Reusing batch containers under new bookings made legitimate events trip
      OWNER_CHANGED_WITHOUT_TRANSFER and ROUTE_SEQUENCE_BREAK, because a
      container's history then spans two bookings with different owners and
      routes. Containers *are* reused in reality, but modelling that properly
      means scoping every continuity check to a shipment leg rather than to a
      container's whole life. That is noted as a limitation; the feed books
      new containers instead.

    Attacks are planned up front per container rather than sampled per event,
    so a siphon runs across a genuine sequence of that container's transitions
    and an identity swap lands mid-voyage where there is history to contradict.
    """
    effective_seed = int(seed if seed is not None else world.seed + 8191)
    rng = random.Random(effective_seed)
    patterns = patterns or [
        p for p in cfg.list_("stream.novel_attack_patterns", list(NOVEL_PATTERNS))
    ]
    patterns = [p for p in patterns if p in NOVEL_PATTERNS] or list(NOVEL_PATTERNS)
    node_ids = [str(n) for n in cfg.list_("nodes.ids")]

    numbers = [
        int(r.record_id[1:])
        for r in batch_records
        if r.record_id.startswith("R") and r.record_id[1:].isdigit()
    ]
    next_record_number = (max(numbers) if numbers else 0) + 1

    live_start = max(
        (r.effective_time() for r in batch_records if r.effective_time()),
        default=world.sim_end,
    ) + timedelta(hours=2)

    route_ids = sorted(world.routes)
    owner_ids = sorted(world.owners)
    lo, hi = cfg.list_("world.containers_per_shipment")

    new_shipments: list[Shipment] = []
    new_containers: list[Container] = []
    voyages: list[dict[str, Any]] = []
    booking = 0
    container_counter = 0
    event_estimate = 0

    # --- plan bookings until there are enough events to fill the feed ---
    while event_estimate < count + 40 and booking < 300:
        booking += 1
        route = world.routes[rng.choice(route_ids)]
        owner_id = rng.choice(owner_ids)
        shipment_id = f"SHIP_L{booking:05d}"
        start = live_start + timedelta(hours=rng.uniform(0.0, 24.0 * 12))
        legs = _plan_live_voyage(rng, cfg, world, route, start)

        container_ids: list[str] = []
        for _ in range(rng.randint(int(lo), int(hi))):
            container_counter += 1
            profile = rng.choice(CARGO_PROFILES)
            weight = min(
                30_000.0,
                max(1_500.0, rng.gauss(profile.weight_mean_kg, profile.weight_sigma_kg)),
            )
            density = max(
                0.05,
                rng.gauss(profile.value_per_kg, profile.value_per_kg * profile.value_sigma_frac),
            )
            container_id = f"CONT_L{container_counter:05d}"
            new_containers.append(
                Container(
                    container_id=container_id,
                    shipment_id=shipment_id,
                    cargo_type=profile.name,
                    initial_weight_kg=round(weight, 1),
                    declared_value=round(weight * density, 2),
                )
            )
            container_ids.append(container_id)

        new_shipments.append(
            Shipment(
                shipment_id=shipment_id,
                owner_id=owner_id,
                route_id=route.route_id,
                vessel_id=route.vessel_id or "",
                origin=route.port_sequence[0],
                destination=route.port_sequence[-1],
                container_ids=container_ids,
                created_at=start,
            )
        )
        voyages.append(
            {
                "shipment_id": shipment_id,
                "owner_id": owner_id,
                "route": route,
                "legs": legs,
                "container_ids": container_ids,
            }
        )
        event_estimate += len(container_ids) * sum(
            len(_legit_events(random.Random(0), leg)) for leg in legs
        )

    container_by_id = {c.container_id: c for c in new_containers}

    # --- plan the attacks per container, before any record is built ---
    all_containers = [c.container_id for c in new_containers]
    rng.shuffle(all_containers)
    plan_attacks: dict[str, dict[str, Any]] = {}
    budget = max(1, int(len(all_containers) * 0.22))

    for container_id in all_containers[:budget]:
        choice = rng.choice(patterns)
        if choice == "weight_siphon":
            plan_attacks[container_id] = {
                "attack": "weight_siphon",
                "step": rng.uniform(0.014, 0.019),
            }
        elif choice == "identity_swap":
            partners = [
                c
                for c in all_containers
                if container_by_id[c].cargo_type != container_by_id[container_id].cargo_type
            ]
            if partners:
                plan_attacks[container_id] = {
                    "attack": "identity_swap",
                    "partner": rng.choice(partners),
                    # Mid-voyage: there must be history for the swap to contradict.
                    "from_leg": rng.randint(1, 2),
                }
        else:
            plan_attacks[container_id] = {"attack": "ghost_transfer"}

    # --- build the event list ---
    planned: list[dict[str, Any]] = []
    for voyage in voyages:
        route = voyage["route"]
        legs: list[_Leg] = voyage["legs"]
        shipment = Shipment(
            shipment_id=voyage["shipment_id"],
            owner_id=voyage["owner_id"],
            route_id=route.route_id,
            vessel_id=route.vessel_id or "",
            origin=route.port_sequence[0],
            destination=route.port_sequence[-1],
            container_ids=voyage["container_ids"],
        )
        for container_id in voyage["container_ids"]:
            container = container_by_id[container_id]
            attack = plan_attacks.get(container_id, {})
            weight = container.initial_weight_kg
            value = container.declared_value
            siphon_cumulative = 0.0
            ghost_emitted = False

            for leg in legs:
                for event_type, when in _legit_events(rng, leg):
                    truth: dict[str, Any] = {}
                    event_weight, event_value = weight, value
                    cargo_override: str | None = None

                    kind = attack.get("attack")

                    if (
                        kind == "weight_siphon"
                        and leg.index >= 1
                        and event_type in (EventType.ARRIVED, EventType.DEPARTED)
                    ):
                        step = float(attack["step"])
                        siphon_cumulative = 1.0 - (1.0 - siphon_cumulative) * (1.0 - step)
                        weight = container.initial_weight_kg * (1.0 - siphon_cumulative)
                        value = container.declared_value * (1.0 - siphon_cumulative)
                        event_weight, event_value = weight, value
                        truth = {
                            "attack": kind,
                            "attack_class": str(AttackClass.MODIFIED),
                            "container_id": container_id,
                            "note": (
                                f"siphon step {step:.3f}; cumulative "
                                f"{siphon_cumulative:.3f} removed. Each step is inside "
                                f"the per-transition conservation tolerance."
                            ),
                        }

                    elif (
                        kind == "identity_swap"
                        and leg.index >= int(attack.get("from_leg", 1))
                        and event_type in (EventType.ARRIVED, EventType.DEPARTED)
                    ):
                        partner = container_by_id[attack["partner"]]
                        cargo_override = partner.cargo_type
                        event_weight = partner.initial_weight_kg
                        event_value = partner.declared_value
                        truth = {
                            "attack": kind,
                            "attack_class": str(AttackClass.MODIFIED),
                            "container_id": container_id,
                            "partner_container_id": partner.container_id,
                            "note": (
                                f"identity swap from leg {leg.index}: this id now "
                                f"carries {partner.cargo_type} at "
                                f"{partner.initial_weight_kg:,.0f} kg"
                            ),
                        }

                    planned.append(
                        {
                            "when": when,
                            "shipment": shipment,
                            "route": route,
                            "container_id": container_id,
                            "leg": leg,
                            "event_type": event_type,
                            "weight": event_weight,
                            "value": event_value,
                            "cargo_override": cargo_override,
                            "truth": truth,
                        }
                    )

                # A ghost transfer is an *extra* event at an off-route port,
                # emitted once per targeted container, mid-voyage.
                if (
                    attack.get("attack") == "ghost_transfer"
                    and not ghost_emitted
                    and leg.index >= 1
                    and leg.departure is not None
                ):
                    ghost_emitted = True
                    off_route = [p for p in sorted(world.ports) if p not in route.port_sequence]
                    ghost_port = off_route[rng.randrange(len(off_route))] if off_route else leg.port_id
                    other_owner = rng.choice([o for o in owner_ids if o != voyage["owner_id"]])
                    planned.append(
                        {
                            "when": leg.arrival + (leg.departure - leg.arrival) * 0.5,
                            "shipment": shipment,
                            "route": route,
                            "container_id": container_id,
                            "leg": leg,
                            "event_type": EventType.TRANSFERRED,
                            "weight": weight,
                            "value": value,
                            "cargo_override": None,
                            "ghost_port": ghost_port,
                            "ghost_owner": other_owner,
                            "truth": {
                                "attack": "ghost_transfer",
                                "attack_class": str(AttackClass.FABRICATED),
                                "container_id": container_id,
                                "note": (
                                    f"TRANSFERRED at {ghost_port}, not a call on route "
                                    f"{route.route_id}, with no arrival there and "
                                    f"ownership reassigned"
                                ),
                            },
                        }
                    )

    planned.sort(key=lambda p: (p["when"], p["container_id"], str(p["event_type"])))
    planned = planned[:count]

    events: list[StreamEvent] = []
    summary: dict[str, int] = {}

    for sequence, item in enumerate(planned, start=1):
        leg: _Leg = item["leg"]
        route = item["route"]
        shipment: Shipment = item["shipment"]
        node_id = node_ids[sequence % len(node_ids)]
        record_id = f"R{next_record_number:06d}"
        next_record_number += 1

        port_id = item.get("ghost_port") or leg.port_id
        rec = _base_record(
            world,
            item["container_id"],
            port_id,
            item["event_type"],
            item["when"],
            weight=float(item["weight"]),
            value=float(item["value"]),
            record_id=record_id,
            node_id=node_id,
            shipment=shipment,
            route=route,
            container=container_by_id[item["container_id"]],
        )
        if item.get("ghost_port"):
            rec.owner = world.owners[item["ghost_owner"]].name
            rec.arrival_timestamp = item["when"]
            rec.departure_timestamp = None
        else:
            rec.arrival_timestamp = leg.arrival
            rec.departure_timestamp = leg.departure
        if item.get("cargo_override"):
            rec.cargo_type = item["cargo_override"]
        rec.record_hash = rec.content_hash()

        truth = item["truth"]
        if truth.get("attack"):
            summary[truth["attack"]] = summary.get(truth["attack"], 0) + 1

        events.append(
            StreamEvent(
                sequence=sequence,
                emitted_at=item["when"],
                row=record_to_row(rec),
                truth=truth,
            )
        )

    summary["total"] = len(events)
    summary["legitimate"] = len(events) - sum(
        v for k, v in summary.items() if k in NOVEL_PATTERNS
    )
    return StreamPlan(
        seed=effective_seed,
        events=events,
        summary=summary,
        new_shipments=new_shipments,
        new_containers=new_containers,
    )


def iter_stream(plan: StreamPlan) -> Iterator[StreamEvent]:
    yield from plan.events

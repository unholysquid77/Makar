"""Synthetic maritime world construction (spec 5).

The world is built *before* any record exists, and the manifest is then
derived from its relationships rather than sampled as independent rows. That
ordering is the whole point: consistency reasoning can only detect tampering
if the clean data was genuinely consistent to begin with.

Determinism: every random draw comes from a single seeded
:class:`random.Random` instance, so ``--seed 481516`` reproduces the world
exactly (spec 5.2).
"""

from __future__ import annotations

import random
from datetime import datetime

from core.config import MakarConfig
from core.models import Container, Owner, Port, Route, Shipment, Vessel, World
from generator.catalog import (
    CARGO_PROFILES,
    CORRIDORS,
    OWNER_SEEDS,
    PORT_CATALOG,
    VESSEL_CLASSES,
    VESSEL_NAME_PREFIX,
    VESSEL_NAME_SUFFIX,
)


def _parse_dt(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)


def _build_ports(rng: random.Random, n_ports: int) -> dict[str, Port]:
    """Select ``n_ports`` ports from the catalog, largest hubs first.

    Hubs are kept deterministically rather than sampled, because dropping
    Singapore or Colombo would break the corridors that depend on them.
    """
    chosen = sorted(PORT_CATALOG, key=lambda p: -p.capacity_teu)[: max(4, n_ports)]
    ports: dict[str, Port] = {}
    for spec in chosen:
        ports[spec.port_id] = Port(
            port_id=spec.port_id,
            name=spec.name,
            country=spec.country,
            latitude=spec.lat,
            longitude=spec.lon,
            dwell_mean_hours=spec.dwell_mean_hours,
            dwell_sigma_hours=spec.dwell_sigma_hours,
            capacity_teu=spec.capacity_teu,
        )
    return ports


def _build_vessels(rng: random.Random, n_vessels: int) -> dict[str, Vessel]:
    vessels: dict[str, Vessel] = {}
    used_names: set[str] = set()
    for i in range(n_vessels):
        klass = VESSEL_CLASSES[i % len(VESSEL_CLASSES)]
        for _ in range(40):
            name = f"{rng.choice(VESSEL_NAME_PREFIX)} {rng.choice(VESSEL_NAME_SUFFIX)}"
            if name not in used_names:
                break
        used_names.add(name)
        vessel_id = f"VESSEL_{i + 1:02d}"
        # Jitter the envelope slightly per hull so the feasibility engine is
        # not comparing against a handful of identical constants.
        cruise = klass.cruise_knots * rng.uniform(0.94, 1.06)
        vessels[vessel_id] = Vessel(
            vessel_id=vessel_id,
            name=f"{name} ({klass.label})",
            cruise_speed_knots=round(cruise, 2),
            max_speed_knots=round(max(cruise + 2.0, klass.max_knots * rng.uniform(0.97, 1.03)), 2),
            capacity_containers=klass.capacity_containers,
            capacity_weight_kg=klass.capacity_weight_kg,
        )
    return vessels


def _build_routes(
    rng: random.Random,
    n_routes: int,
    ports: dict[str, Port],
    vessels: dict[str, Vessel],
) -> dict[str, Route]:
    """Draw routes as contiguous subsequences of the trade corridors.

    Using subsequences rather than random port sets guarantees every route
    is geographically monotonic, which is what makes OFF_ROUTE_PORT and
    ROUTE_SEQUENCE_BREAK meaningful signals later.
    """
    vessel_ids = list(vessels)
    routes: dict[str, Route] = {}
    attempts = 0
    seen: set[tuple[str, ...]] = set()

    while len(routes) < n_routes and attempts < n_routes * 60:
        attempts += 1
        corridor = [p for p in rng.choice(CORRIDORS) if p in ports]
        if len(corridor) < 3:
            continue
        length = rng.randint(3, min(6, len(corridor)))
        start = rng.randint(0, len(corridor) - length)
        sequence = tuple(corridor[start : start + length])
        # Half of all routes run the corridor in reverse (return legs).
        if rng.random() < 0.5:
            sequence = tuple(reversed(sequence))
        if sequence in seen:
            continue
        seen.add(sequence)
        route_id = f"ROUTE_{len(routes) + 1:02d}"
        routes[route_id] = Route(
            route_id=route_id,
            port_sequence=list(sequence),
            vessel_id=rng.choice(vessel_ids),
        )
    return routes


def _build_owners(rng: random.Random, n_owners: int) -> dict[str, Owner]:
    owners: dict[str, Owner] = {}
    seeds = list(OWNER_SEEDS)
    rng.shuffle(seeds)
    for i, (name, country, aliases) in enumerate(seeds[:n_owners]):
        owner_id = f"OWNER_{i + 1:02d}"
        owners[owner_id] = Owner(
            owner_id=owner_id, name=name, country=country, aliases=list(aliases)
        )
    return owners


def _build_shipments_and_containers(
    rng: random.Random,
    cfg: MakarConfig,
    ports: dict[str, Port],
    routes: dict[str, Route],
    owners: dict[str, Owner],
    sim_start: datetime,
    sim_end: datetime,
) -> tuple[dict[str, Shipment], dict[str, Container]]:
    n_shipments = cfg.int_("world.n_shipments")
    lo, hi = cfg.list_("world.containers_per_shipment")
    owner_ids = list(owners)
    route_ids = list(routes)

    # Owner activity is Zipf-like: a few owners move most of the cargo. This
    # gives the statistical layer a realistic volume distribution instead of
    # a flat one, and makes "affected owners" in the report meaningful.
    owner_weights = [1.0 / (i + 1) ** 0.8 for i in range(len(owner_ids))]

    span_seconds = max(1.0, (sim_end - sim_start).total_seconds())
    # Shipments are created across almost the whole window. Late ones are
    # therefore still mid-voyage when the clock stops, which gives the
    # detector legitimate open-ended histories to learn from.
    creation_span = span_seconds * 0.92

    shipments: dict[str, Shipment] = {}
    containers: dict[str, Container] = {}
    container_counter = 1

    for i in range(n_shipments):
        shipment_id = f"SHIP_{i + 1:05d}"
        route_id = rng.choice(route_ids)
        route = routes[route_id]
        owner_id = rng.choices(owner_ids, weights=owner_weights, k=1)[0]
        created_at = sim_start + _seconds(rng.random() * creation_span)

        n_containers = rng.randint(int(lo), int(hi))
        container_ids: list[str] = []
        for _ in range(n_containers):
            profile = rng.choice(CARGO_PROFILES)
            weight = max(
                1_500.0,
                rng.gauss(profile.weight_mean_kg, profile.weight_sigma_kg),
            )
            # Cap at a realistic per-container maximum payload.
            weight = min(weight, 30_000.0)
            value_per_kg = max(
                0.05, rng.gauss(profile.value_per_kg, profile.value_per_kg * profile.value_sigma_frac)
            )
            container_id = f"CONT_{container_counter:06d}"
            container_counter += 1
            containers[container_id] = Container(
                container_id=container_id,
                shipment_id=shipment_id,
                cargo_type=profile.name,
                initial_weight_kg=round(weight, 1),
                declared_value=round(weight * value_per_kg, 2),
                max_weight_kg=30_000.0,
            )
            container_ids.append(container_id)

        shipments[shipment_id] = Shipment(
            shipment_id=shipment_id,
            owner_id=owner_id,
            route_id=route_id,
            vessel_id=route.vessel_id or "",
            origin=route.port_sequence[0],
            destination=route.port_sequence[-1],
            container_ids=container_ids,
            created_at=created_at,
        )

    return shipments, containers


def _seconds(value: float):
    from datetime import timedelta

    return timedelta(seconds=value)


def build_world(cfg: MakarConfig, seed: int | None = None) -> World:
    """Construct the full synthetic world from configuration.

    ``seed`` overrides ``world.seed`` so a scenario can fork a variant world
    without editing config.
    """
    effective_seed = int(seed if seed is not None else cfg.int_("world.seed"))
    rng = random.Random(effective_seed)

    sim_start = _parse_dt(cfg.get("world.sim_start"))
    sim_end = _parse_dt(cfg.get("world.sim_end"))
    if sim_end <= sim_start:
        raise ValueError("world.sim_end must be after world.sim_start")

    ports = _build_ports(rng, cfg.int_("world.n_ports"))
    vessels = _build_vessels(rng, cfg.int_("world.n_vessels"))
    routes = _build_routes(rng, cfg.int_("world.n_routes"), ports, vessels)
    if not routes:
        raise RuntimeError("no routes could be built; check world.n_ports against the corridors")
    owners = _build_owners(rng, cfg.int_("world.n_owners"))
    shipments, containers = _build_shipments_and_containers(
        rng, cfg, ports, routes, owners, sim_start, sim_end
    )

    return World(
        seed=effective_seed,
        sim_start=sim_start,
        sim_end=sim_end,
        ports=ports,
        vessels=vessels,
        routes=routes,
        owners=owners,
        shipments=shipments,
        containers=containers,
        cargo_types=[p.name for p in CARGO_PROFILES],
    )

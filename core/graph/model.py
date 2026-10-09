"""The Cargo Intelligence Graph (spec 14).

Node and edge types follow spec 14.1/14.2 exactly. Every edge may carry
``timestamp``, ``confidence``, ``source_record`` and ``evidence_type``, which
is what turns the graph from a picture into an investigation surface: an
analyst can follow a chain of relationships and read the justification off
each hop (spec 15.4).

**Two-phase construction, and why.** The graph is built in two passes:

1. *Structural* -- entities and lifecycle relationships, derived purely from
   the manifest and the world model. The graph detector reasons over this.
2. *Evidential* -- ``DUPLICATES``, ``CONFLICTS_WITH`` and ``SUPPORTS`` edges,
   added from the evidence once every detector has run.

The split exists because the graph detector *produces* evidence, so it cannot
also consume the evidence-derived edges without a circular dependency. Keeping
the phases explicit means the detector can never accidentally read a
conclusion it helped create.
"""

from __future__ import annotations

from collections import deque
from enum import StrEnum
from typing import Any

import networkx as nx

from core.detection.base import AnalysisContext
from core.models import Evidence
from core.types import EventType


class NodeType(StrEnum):
    OWNER = "Owner"
    SHIPMENT = "Shipment"
    CONTAINER = "Container"
    CARGO = "Cargo"
    EVENT = "Event"
    PORT = "Port"
    VESSEL = "Vessel"
    ROUTE = "Route"
    RECORD = "Record"
    BLOCK = "Block"


class EdgeType(StrEnum):
    OWNS = "OWNS"
    CONTAINS = "CONTAINS"
    TRAVELS_TO = "TRAVELS_TO"
    ARRIVED_AT = "ARRIVED_AT"
    DEPARTED_FROM = "DEPARTED_FROM"
    TRANSFERRED_TO = "TRANSFERRED_TO"
    CARRIED_BY = "CARRIED_BY"
    PRECEDES = "PRECEDES"
    DUPLICATES = "DUPLICATES"
    CONFLICTS_WITH = "CONFLICTS_WITH"
    SUPPORTS = "SUPPORTS"
    DERIVED_FROM = "DERIVED_FROM"


#: Edges that represent a contradiction rather than a relationship. The
#: CONFLICT investigation mode (spec 15.3) shows only these.
CONTRADICTORY_EDGES: frozenset[str] = frozenset(
    {EdgeType.CONFLICTS_WITH, EdgeType.DUPLICATES}
)


def node_key(node_type: NodeType | str, identifier: str) -> str:
    """Typed node key, e.g. ``record:R000847``."""
    return f"{str(node_type).lower()}:{identifier}"


def split_key(key: str) -> tuple[str, str]:
    """Inverse of :func:`node_key`."""
    kind, _, identifier = key.partition(":")
    return kind, identifier


class CargoGraph:
    """A queryable wrapper around the underlying NetworkX graph."""

    def __init__(self, graph: nx.MultiDiGraph) -> None:
        self.g = graph

    # -- basic stats -------------------------------------------------------

    @property
    def node_count(self) -> int:
        return self.g.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self.g.number_of_edges()

    def exists(self, key: str) -> bool:
        return self.g.has_node(key)

    def attrs(self, key: str) -> dict[str, Any]:
        return dict(self.g.nodes.get(key, {}))

    # -- EXPAND (spec 15.3) ------------------------------------------------

    def neighbourhood(
        self,
        key: str,
        depth: int = 1,
        *,
        max_nodes: int = 160,
        hub_degree: int = 40,
    ) -> set[str]:
        """Keys within ``depth`` hops, ignoring edge direction.

        Direction-agnostic on purpose: an investigator asking "show everything
        connected to R847" means everything, not only what R847 points at.

        **Hubs are included but not traversed through.** A port node touches
        every record at that port, so a naive two-hop expansion from one
        record returned 1,995 nodes and 5,708 edges -- unreadable, and not
        what the question meant. The port itself is relevant context; the
        other 400 records that happen to share it are not. Nodes whose degree
        exceeds ``hub_degree`` are therefore shown as endpoints and never
        expanded past.

        ``max_nodes`` is a hard ceiling so the graph endpoint cannot be made
        to return the whole manifest.
        """
        if not self.g.has_node(key):
            return set()

        undirected = self.g.to_undirected(as_view=True)
        seen = {key}
        frontier = deque([(key, 0)])

        while frontier and len(seen) < max_nodes:
            current, level = frontier.popleft()
            if level >= depth:
                continue
            # Do not expand *through* a hub, though it stays in the result.
            if current != key and undirected.degree(current) > hub_degree:
                continue
            for neighbour in undirected.neighbors(current):
                if neighbour in seen:
                    continue
                seen.add(neighbour)
                if len(seen) >= max_nodes:
                    break
                frontier.append((neighbour, level + 1))
        return seen

    def subgraph(self, keys: set[str]) -> dict[str, Any]:
        """Serialisable node/edge payload for the given keys."""
        view = self.g.subgraph(keys)
        return {
            "nodes": [
                {"id": key, "type": split_key(key)[0], **dict(data)}
                for key, data in view.nodes(data=True)
            ],
            "edges": [
                {
                    "source": u,
                    "target": v,
                    "type": data.get("type"),
                    **{k: val for k, val in data.items() if k != "type"},
                }
                for u, v, data in view.edges(data=True)
            ],
        }

    # -- CONFLICT (spec 15.3) ---------------------------------------------

    def conflicts(self, key: str) -> list[dict[str, Any]]:
        """Contradictory edges touching ``key``."""
        if not self.g.has_node(key):
            return []
        out: list[dict[str, Any]] = []
        for u, v, data in self.g.edges(key, data=True):
            if data.get("type") in CONTRADICTORY_EDGES:
                out.append({"source": u, "target": v, **dict(data)})
        for u, v, data in self.g.in_edges(key, data=True):
            if data.get("type") in CONTRADICTORY_EDGES:
                out.append({"source": u, "target": v, **dict(data)})
        return out

    # -- TRACE (spec 15.1, 15.4) ------------------------------------------

    def evidence_path(self, source: str, target: str) -> list[dict[str, Any]]:
        """Shortest relationship path between two nodes, hop by hop.

        This is what renders as the human-readable evidence chain of spec
        15.4: ``R847 -> Temporal Conflict -> Container C17 -> Port Colombo ->
        R812 -> Vessel V17 -> Block 184``.
        """
        if not (self.g.has_node(source) and self.g.has_node(target)):
            return []
        undirected = self.g.to_undirected(as_view=True)
        try:
            keys = nx.shortest_path(undirected, source, target)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

        hops: list[dict[str, Any]] = []
        for left, right in zip(keys, keys[1:], strict=False):
            data: dict[str, Any] = {}
            if self.g.has_edge(left, right):
                data = dict(next(iter(self.g[left][right].values())))
            elif self.g.has_edge(right, left):
                data = dict(next(iter(self.g[right][left].values())))
            hops.append(
                {
                    "from": left,
                    "to": right,
                    "relationship": data.get("type", "RELATED"),
                    "evidence_type": data.get("evidence_type"),
                    "confidence": data.get("confidence"),
                    "source_record": data.get("source_record"),
                    "timestamp": data.get("timestamp"),
                }
            )
        return hops

    def provenance_chain(self, record_id: str) -> list[dict[str, Any]]:
        """Walk a record back through its lineage to its block."""
        key = node_key(NodeType.RECORD, record_id)
        if not self.g.has_node(key):
            return []
        chain: list[dict[str, Any]] = [{"node": key, **self.attrs(key)}]
        for kind in (
            NodeType.CONTAINER,
            NodeType.SHIPMENT,
            NodeType.OWNER,
            NodeType.ROUTE,
            NodeType.VESSEL,
            NodeType.BLOCK,
        ):
            prefix = f"{str(kind).lower()}:"
            found = [
                n for n in self.neighbourhood(key, depth=2) if n.startswith(prefix)
            ]
            for node in sorted(found)[:2]:
                chain.append({"node": node, **self.attrs(node)})
        return chain

    # -- ISOLATE (spec 15.3) ----------------------------------------------

    def isolate(
        self, keys: set[str], depth: int = 1, *, max_nodes: int = 160
    ) -> dict[str, Any]:
        """Subgraph around a seed set with everything else hidden."""
        expanded: set[str] = set()
        budget = max(20, max_nodes // max(1, len(keys)))
        for key in keys:
            expanded |= self.neighbourhood(key, depth=depth, max_nodes=budget)
        return self.subgraph(expanded)


# ======================================================================
# Phase 1: structural construction
# ======================================================================


def build_graph(ctx: AnalysisContext) -> CargoGraph:
    """Build the structural graph from the manifest and the world model."""
    g = nx.MultiDiGraph()

    # --- world entities ---
    for port in ctx.world.ports.values():
        g.add_node(
            node_key(NodeType.PORT, port.port_id),
            label=port.name,
            country=port.country,
            latitude=port.latitude,
            longitude=port.longitude,
            kind=str(NodeType.PORT),
        )
    for vessel in ctx.world.vessels.values():
        g.add_node(
            node_key(NodeType.VESSEL, vessel.vessel_id),
            label=vessel.name,
            max_speed_knots=vessel.max_speed_knots,
            kind=str(NodeType.VESSEL),
        )
    for owner in ctx.world.owners.values():
        g.add_node(
            node_key(NodeType.OWNER, owner.owner_id),
            label=owner.name,
            country=owner.country,
            kind=str(NodeType.OWNER),
        )
    for route in ctx.world.routes.values():
        route_key = node_key(NodeType.ROUTE, route.route_id)
        g.add_node(
            route_key,
            label=route.route_id,
            port_sequence=route.port_sequence,
            kind=str(NodeType.ROUTE),
        )
        for index, (left, right) in enumerate(route.legs()):
            g.add_edge(
                node_key(NodeType.PORT, left),
                node_key(NodeType.PORT, right),
                type=str(EdgeType.TRAVELS_TO),
                route_id=route.route_id,
                leg=index,
                confidence=1.0,
            )
        if route.vessel_id:
            g.add_edge(
                route_key,
                node_key(NodeType.VESSEL, route.vessel_id),
                type=str(EdgeType.CARRIED_BY),
                confidence=1.0,
            )

    for cargo_type in ctx.world.cargo_types:
        g.add_node(
            node_key(NodeType.CARGO, cargo_type), label=cargo_type, kind=str(NodeType.CARGO)
        )

    for shipment in ctx.world.shipments.values():
        shipment_key = node_key(NodeType.SHIPMENT, shipment.shipment_id)
        g.add_node(
            shipment_key,
            label=shipment.shipment_id,
            origin=shipment.origin,
            destination=shipment.destination,
            kind=str(NodeType.SHIPMENT),
        )
        g.add_edge(
            node_key(NodeType.OWNER, shipment.owner_id),
            shipment_key,
            type=str(EdgeType.OWNS),
            confidence=1.0,
        )
        if shipment.route_id:
            g.add_edge(
                shipment_key,
                node_key(NodeType.ROUTE, shipment.route_id),
                type=str(EdgeType.TRAVELS_TO),
                confidence=1.0,
            )
        for container_id in shipment.container_ids:
            g.add_edge(
                shipment_key,
                node_key(NodeType.CONTAINER, container_id),
                type=str(EdgeType.CONTAINS),
                confidence=1.0,
            )

    for container in ctx.world.containers.values():
        container_key = node_key(NodeType.CONTAINER, container.container_id)
        g.add_node(
            container_key,
            label=container.container_id,
            cargo_type=container.cargo_type,
            initial_weight_kg=container.initial_weight_kg,
            kind=str(NodeType.CONTAINER),
        )
        if container.cargo_type:
            g.add_edge(
                container_key,
                node_key(NodeType.CARGO, container.cargo_type),
                type=str(EdgeType.CONTAINS),
                confidence=1.0,
            )

    # --- records and their lifecycle edges ---
    for rec in ctx.records:
        record_key = node_key(NodeType.RECORD, rec.record_id)
        when = rec.effective_time()
        g.add_node(
            record_key,
            label=rec.record_id,
            event_type=rec.event_type,
            timestamp=when.isoformat() if when else None,
            weight=rec.weight,
            declared_value=rec.declared_value,
            owner=rec.owner,
            cargo_type=rec.cargo_type,
            port_id=rec.port_id,
            container_id=rec.container_id,
            shipment_id=rec.shipment_id,
            kind=str(NodeType.RECORD),
        )

        if rec.container_id:
            g.add_edge(
                node_key(NodeType.CONTAINER, rec.container_id),
                record_key,
                type=str(EdgeType.DERIVED_FROM),
                confidence=1.0,
                timestamp=when.isoformat() if when else None,
            )
        if rec.shipment_id:
            g.add_edge(
                node_key(NodeType.SHIPMENT, rec.shipment_id),
                record_key,
                type=str(EdgeType.DERIVED_FROM),
                confidence=1.0,
            )
        if rec.vessel_id:
            g.add_edge(
                record_key,
                node_key(NodeType.VESSEL, rec.vessel_id),
                type=str(EdgeType.CARRIED_BY),
                confidence=1.0,
            )
        if rec.port_id:
            port_key = node_key(NodeType.PORT, rec.port_id)
            event = rec.event_type or ""
            if event in {EventType.ARRIVED, EventType.CREATED, EventType.LOADED}:
                edge_type = EdgeType.ARRIVED_AT
            elif event in {EventType.DEPARTED}:
                edge_type = EdgeType.DEPARTED_FROM
            elif event in {EventType.TRANSFERRED}:
                edge_type = EdgeType.TRANSFERRED_TO
            else:
                edge_type = EdgeType.ARRIVED_AT
            g.add_edge(
                record_key,
                port_key,
                type=str(edge_type),
                confidence=1.0,
                timestamp=when.isoformat() if when else None,
                source_record=rec.record_id,
            )
        owner_id = ctx.resolver.owner_id_for(rec.owner)
        if owner_id:
            g.add_edge(
                node_key(NodeType.OWNER, owner_id),
                record_key,
                type=str(EdgeType.OWNS),
                confidence=1.0,
            )

    # --- PRECEDES: a container's event chain in time order ---
    for _container_id, timeline in ctx.by_container.items():
        for left, right in zip(timeline, timeline[1:], strict=False):
            left_time, right_time = left.effective_time(), right.effective_time()
            g.add_edge(
                node_key(NodeType.RECORD, left.record_id),
                node_key(NodeType.RECORD, right.record_id),
                type=str(EdgeType.PRECEDES),
                confidence=1.0,
                gap_hours=(
                    round((right_time - left_time).total_seconds() / 3600.0, 2)
                    if left_time and right_time
                    else None
                ),
            )

    # --- blocks ---
    chain = ctx.chain
    if chain is not None:
        for block in getattr(chain, "blocks", []):
            block_key = node_key(NodeType.BLOCK, block.header.block_id)
            g.add_node(
                block_key,
                label=block.header.block_id,
                index=block.header.index,
                state_root=block.header.state_root,
                record_count=block.header.record_count,
                timestamp=block.header.timestamp.isoformat(),
                kind=str(NodeType.BLOCK),
            )
            for record_id in block.record_ids:
                record_key = node_key(NodeType.RECORD, record_id)
                if g.has_node(record_key):
                    g.add_edge(
                        record_key,
                        block_key,
                        type=str(EdgeType.DERIVED_FROM),
                        confidence=1.0,
                        evidence_type="BLOCKCHAIN",
                    )

    return CargoGraph(g)


# ======================================================================
# Phase 2: evidential annotation
# ======================================================================


def annotate_with_evidence(graph: CargoGraph, evidence: list[Evidence]) -> CargoGraph:
    """Add DUPLICATES / CONFLICTS_WITH / SUPPORTS edges from the evidence.

    Called once every detector has run. ``SUPPORTS`` is emitted when evidence
    cites a corroborating record without contradicting it, which is what the
    Bloodhound SUPPORTS view and the arbitration layer both read.
    """
    g = graph.g
    duplicate_codes = {"EXACT_DUPLICATE", "STRUCTURAL_DUPLICATE", "FUZZY_DUPLICATE"}
    conflict_codes = {
        "SIMULTANEOUS_PRESENCE",
        "IMPOSSIBLE_TRANSIT",
        "SPEED_INFEASIBLE",
        "WEIGHT_NOT_CONSERVED",
        "CARGO_DRIFT_UNEXPLAINED",
        "VALUE_NOT_CONSERVED",
        "OWNER_CHANGED_WITHOUT_TRANSFER",
        "CARGO_TYPE_MUTATED",
        "ROUTE_SEQUENCE_BREAK",
        "CONTAINER_COUNT_NOT_CONSERVED",
    }

    for item in evidence:
        subject = node_key(NodeType.RECORD, item.record_id)
        if not g.has_node(subject):
            continue
        code = str(item.code)
        for other_id in item.supporting_records:
            other = node_key(NodeType.RECORD, other_id)
            if not g.has_node(other):
                continue
            if code in duplicate_codes:
                edge_type = EdgeType.DUPLICATES
            elif code in conflict_codes:
                edge_type = EdgeType.CONFLICTS_WITH
            else:
                edge_type = EdgeType.SUPPORTS
            g.add_edge(
                subject,
                other,
                type=str(edge_type),
                evidence_type=str(item.type),
                evidence_code=code,
                confidence=round(item.severity, 3),
                source_record=item.record_id,
            )
    return graph

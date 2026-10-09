"""Enumerations and primitive aliases shared across the whole system.

These are plain ``str`` enums so they serialise to readable JSON for the API,
the ground-truth log and the provenance hashes without a custom encoder.
"""

from __future__ import annotations

from enum import StrEnum

RecordId = str
ShipmentId = str
ContainerId = str
PortId = str
VesselId = str
RouteId = str
OwnerId = str
NodeId = str
BlockId = str


class EventType(StrEnum):
    """Lifecycle events a manifest record may describe (spec 4.3)."""

    CREATED = "CREATED"
    LOADED = "LOADED"
    DEPARTED = "DEPARTED"
    ARRIVED = "ARRIVED"
    TRANSFERRED = "TRANSFERRED"
    INSPECTED = "INSPECTED"
    UNLOADED = "UNLOADED"
    DELIVERED = "DELIVERED"
    CANCELLED = "CANCELLED"


#: Order in which events may legitimately occur for one container.
#: ``INSPECTED`` is absent deliberately: an inspection may happen at any point
#: while a container sits in a port, so it imposes no ordering constraint.
EVENT_ORDER: dict[str, int] = {
    EventType.CREATED: 0,
    EventType.LOADED: 1,
    EventType.DEPARTED: 2,
    EventType.ARRIVED: 3,
    EventType.TRANSFERRED: 4,
    EventType.UNLOADED: 5,
    EventType.DELIVERED: 6,
    EventType.CANCELLED: 7,
}

#: Events that change how much cargo a container holds. The conservation
#: engine (spec 11) only tolerates a weight delta when one of these is present.
CARGO_MUTATING_EVENTS: frozenset[str] = frozenset(
    {EventType.LOADED, EventType.UNLOADED, EventType.TRANSFERRED}
)

#: Events that place a container *inside* a port for a measurable interval.
#: Used by simultaneous-presence and dwell-time analysis (spec 9.4, 9.5).
IN_PORT_EVENTS: frozenset[str] = frozenset(
    {
        EventType.CREATED,
        EventType.LOADED,
        EventType.ARRIVED,
        EventType.INSPECTED,
        EventType.UNLOADED,
        EventType.TRANSFERRED,
        EventType.DELIVERED,
    }
)

#: Events that legitimately transfer custody to a different owner.
OWNERSHIP_TRANSFER_EVENTS: frozenset[str] = frozenset({EventType.TRANSFERRED})


class ShipmentStatus(StrEnum):
    IN_TRANSIT = "IN_TRANSIT"
    AT_PORT = "AT_PORT"
    DELIVERED = "DELIVERED"
    HELD = "HELD"
    CANCELLED = "CANCELLED"


class EvidenceType(StrEnum):
    """Independent reasoning layers that may emit evidence (spec 16).

    No single type is authoritative. The fusion layer (spec 17) assigns each
    type a configurable weight; ``FORMAT`` carries a *negative* weight because
    benign formatting noise argues against deliberate tampering.
    """

    TEMPORAL = "TEMPORAL"
    SPATIAL = "SPATIAL"
    ROUTE = "ROUTE"
    CARGO = "CARGO"
    DUPLICATE = "DUPLICATE"
    STATISTICAL = "STATISTICAL"
    GRAPH = "GRAPH"
    BLOCKCHAIN = "BLOCKCHAIN"
    IDENTITY = "IDENTITY"
    FORMAT = "FORMAT"


class EvidenceCode(StrEnum):
    """The specific finding, one level finer than :class:`EvidenceType`.

    The code is what the UI renders in the evidence breakdown and what the
    classifier pattern-matches on, so these names are part of the contract.
    """

    # --- TEMPORAL (spec 9) ---
    FUTURE_EVENT = "FUTURE_EVENT"
    REVERSE_CHRONOLOGY = "REVERSE_CHRONOLOGY"
    IMPOSSIBLE_TRANSIT = "IMPOSSIBLE_TRANSIT"
    SIMULTANEOUS_PRESENCE = "SIMULTANEOUS_PRESENCE"
    DWELL_TIME_ANOMALY = "DWELL_TIME_ANOMALY"
    EVENT_ORDER_VIOLATION = "EVENT_ORDER_VIOLATION"
    TIMESTAMP_MISSING = "TIMESTAMP_MISSING"
    SEQUENCE_GAP = "SEQUENCE_GAP"

    # --- SPATIAL (spec 10) ---
    SPEED_INFEASIBLE = "SPEED_INFEASIBLE"
    COORDINATE_PORT_MISMATCH = "COORDINATE_PORT_MISMATCH"
    COORDINATE_OUT_OF_RANGE = "COORDINATE_OUT_OF_RANGE"

    # --- ROUTE ---
    OFF_ROUTE_PORT = "OFF_ROUTE_PORT"
    ROUTE_SEQUENCE_BREAK = "ROUTE_SEQUENCE_BREAK"
    DESTINATION_CONTRADICTION = "DESTINATION_CONTRADICTION"
    UNKNOWN_ROUTE = "UNKNOWN_ROUTE"

    # --- CARGO (spec 11) ---
    WEIGHT_NOT_CONSERVED = "WEIGHT_NOT_CONSERVED"
    CARGO_DRIFT_UNEXPLAINED = "CARGO_DRIFT_UNEXPLAINED"
    CONTAINER_COUNT_NOT_CONSERVED = "CONTAINER_COUNT_NOT_CONSERVED"
    VALUE_NOT_CONSERVED = "VALUE_NOT_CONSERVED"
    OWNER_CHANGED_WITHOUT_TRANSFER = "OWNER_CHANGED_WITHOUT_TRANSFER"
    CARGO_TYPE_MUTATED = "CARGO_TYPE_MUTATED"
    WEIGHT_EXCEEDS_CAPACITY = "WEIGHT_EXCEEDS_CAPACITY"

    # --- DUPLICATE (spec 12) ---
    EXACT_DUPLICATE = "EXACT_DUPLICATE"
    STRUCTURAL_DUPLICATE = "STRUCTURAL_DUPLICATE"
    FUZZY_DUPLICATE = "FUZZY_DUPLICATE"

    # --- STATISTICAL (spec 13) ---
    ROBUST_Z_OUTLIER = "ROBUST_Z_OUTLIER"
    IQR_OUTLIER = "IQR_OUTLIER"
    ISOLATION_FOREST_OUTLIER = "ISOLATION_FOREST_OUTLIER"
    LOF_OUTLIER = "LOF_OUTLIER"
    DBSCAN_NOISE = "DBSCAN_NOISE"
    DISTRIBUTION_SHIFT = "DISTRIBUTION_SHIFT"
    PEER_GROUP_OUTLIER = "PEER_GROUP_OUTLIER"

    # --- GRAPH (spec 14) ---
    ORPHAN_RECORD = "ORPHAN_RECORD"
    LINEAGE_BREAK = "LINEAGE_BREAK"
    GRAPH_CONFLICT = "GRAPH_CONFLICT"
    MISSING_EXPECTED_EVENT = "MISSING_EXPECTED_EVENT"
    UNKNOWN_ENTITY_REFERENCE = "UNKNOWN_ENTITY_REFERENCE"

    # --- BLOCKCHAIN (spec 21-23) ---
    RECORD_HASH_MISMATCH = "RECORD_HASH_MISMATCH"
    RECORD_NOT_IN_CHAIN = "RECORD_NOT_IN_CHAIN"
    NODE_STATE_DIVERGENCE = "NODE_STATE_DIVERGENCE"
    BLOCK_CHAIN_BROKEN = "BLOCK_CHAIN_BROKEN"

    # --- IDENTITY ---
    UNKNOWN_OWNER = "UNKNOWN_OWNER"
    OWNER_ALIAS_COLLISION = "OWNER_ALIAS_COLLISION"
    ID_FORMAT_INVALID = "ID_FORMAT_INVALID"

    # --- FORMAT (benign; spec 6.3) ---
    FIELD_BLANK = "FIELD_BLANK"
    TIMESTAMP_FORMAT_VARIANT = "TIMESTAMP_FORMAT_VARIANT"
    NAME_UNNORMALISED = "NAME_UNNORMALISED"
    NUMERIC_FORMAT_VARIANT = "NUMERIC_FORMAT_VARIANT"
    CASE_INCONSISTENCY = "CASE_INCONSISTENCY"


#: Which reasoning layer each code belongs to. Single source of truth: the
#: fusion layer looks the type up here rather than trusting the emitter.
EVIDENCE_CODE_TYPE: dict[str, str] = {
    EvidenceCode.FUTURE_EVENT: EvidenceType.TEMPORAL,
    EvidenceCode.REVERSE_CHRONOLOGY: EvidenceType.TEMPORAL,
    EvidenceCode.IMPOSSIBLE_TRANSIT: EvidenceType.TEMPORAL,
    EvidenceCode.SIMULTANEOUS_PRESENCE: EvidenceType.TEMPORAL,
    EvidenceCode.DWELL_TIME_ANOMALY: EvidenceType.TEMPORAL,
    EvidenceCode.EVENT_ORDER_VIOLATION: EvidenceType.TEMPORAL,
    EvidenceCode.TIMESTAMP_MISSING: EvidenceType.TEMPORAL,
    EvidenceCode.SEQUENCE_GAP: EvidenceType.TEMPORAL,
    EvidenceCode.SPEED_INFEASIBLE: EvidenceType.SPATIAL,
    EvidenceCode.COORDINATE_PORT_MISMATCH: EvidenceType.SPATIAL,
    EvidenceCode.COORDINATE_OUT_OF_RANGE: EvidenceType.SPATIAL,
    EvidenceCode.OFF_ROUTE_PORT: EvidenceType.ROUTE,
    EvidenceCode.ROUTE_SEQUENCE_BREAK: EvidenceType.ROUTE,
    EvidenceCode.DESTINATION_CONTRADICTION: EvidenceType.ROUTE,
    EvidenceCode.UNKNOWN_ROUTE: EvidenceType.ROUTE,
    EvidenceCode.WEIGHT_NOT_CONSERVED: EvidenceType.CARGO,
    EvidenceCode.CARGO_DRIFT_UNEXPLAINED: EvidenceType.CARGO,
    EvidenceCode.CONTAINER_COUNT_NOT_CONSERVED: EvidenceType.CARGO,
    EvidenceCode.VALUE_NOT_CONSERVED: EvidenceType.CARGO,
    EvidenceCode.OWNER_CHANGED_WITHOUT_TRANSFER: EvidenceType.CARGO,
    EvidenceCode.CARGO_TYPE_MUTATED: EvidenceType.CARGO,
    EvidenceCode.WEIGHT_EXCEEDS_CAPACITY: EvidenceType.CARGO,
    EvidenceCode.EXACT_DUPLICATE: EvidenceType.DUPLICATE,
    EvidenceCode.STRUCTURAL_DUPLICATE: EvidenceType.DUPLICATE,
    EvidenceCode.FUZZY_DUPLICATE: EvidenceType.DUPLICATE,
    EvidenceCode.ROBUST_Z_OUTLIER: EvidenceType.STATISTICAL,
    EvidenceCode.IQR_OUTLIER: EvidenceType.STATISTICAL,
    EvidenceCode.ISOLATION_FOREST_OUTLIER: EvidenceType.STATISTICAL,
    EvidenceCode.LOF_OUTLIER: EvidenceType.STATISTICAL,
    EvidenceCode.DBSCAN_NOISE: EvidenceType.STATISTICAL,
    EvidenceCode.DISTRIBUTION_SHIFT: EvidenceType.STATISTICAL,
    EvidenceCode.PEER_GROUP_OUTLIER: EvidenceType.STATISTICAL,
    EvidenceCode.ORPHAN_RECORD: EvidenceType.GRAPH,
    EvidenceCode.LINEAGE_BREAK: EvidenceType.GRAPH,
    EvidenceCode.GRAPH_CONFLICT: EvidenceType.GRAPH,
    EvidenceCode.MISSING_EXPECTED_EVENT: EvidenceType.GRAPH,
    EvidenceCode.UNKNOWN_ENTITY_REFERENCE: EvidenceType.GRAPH,
    EvidenceCode.RECORD_HASH_MISMATCH: EvidenceType.BLOCKCHAIN,
    EvidenceCode.RECORD_NOT_IN_CHAIN: EvidenceType.BLOCKCHAIN,
    EvidenceCode.NODE_STATE_DIVERGENCE: EvidenceType.BLOCKCHAIN,
    EvidenceCode.BLOCK_CHAIN_BROKEN: EvidenceType.BLOCKCHAIN,
    EvidenceCode.UNKNOWN_OWNER: EvidenceType.IDENTITY,
    EvidenceCode.OWNER_ALIAS_COLLISION: EvidenceType.IDENTITY,
    EvidenceCode.ID_FORMAT_INVALID: EvidenceType.IDENTITY,
    EvidenceCode.FIELD_BLANK: EvidenceType.FORMAT,
    EvidenceCode.TIMESTAMP_FORMAT_VARIANT: EvidenceType.FORMAT,
    EvidenceCode.NAME_UNNORMALISED: EvidenceType.FORMAT,
    EvidenceCode.NUMERIC_FORMAT_VARIANT: EvidenceType.FORMAT,
    EvidenceCode.CASE_INCONSISTENCY: EvidenceType.FORMAT,
}

#: Human-readable labels for the evidence breakdown panel (spec 17).
EVIDENCE_LABEL: dict[str, str] = {
    EvidenceCode.FUTURE_EVENT: "Event dated after the simulation clock",
    EvidenceCode.REVERSE_CHRONOLOGY: "Arrival precedes departure",
    EvidenceCode.IMPOSSIBLE_TRANSIT: "Transit time physically implausible",
    EvidenceCode.SIMULTANEOUS_PRESENCE: "Container reported in two ports at once",
    EvidenceCode.DWELL_TIME_ANOMALY: "Dwell time outside port distribution",
    EvidenceCode.EVENT_ORDER_VIOLATION: "Event out of lifecycle order",
    EvidenceCode.TIMESTAMP_MISSING: "Timestamp absent or unparseable",
    EvidenceCode.SEQUENCE_GAP: "Gap in an otherwise coherent event sequence",
    EvidenceCode.SPEED_INFEASIBLE: "Impossible route transition",
    EvidenceCode.COORDINATE_PORT_MISMATCH: "Coordinates do not match declared port",
    EvidenceCode.COORDINATE_OUT_OF_RANGE: "Coordinates outside valid range",
    EvidenceCode.OFF_ROUTE_PORT: "Port not on the declared route",
    EvidenceCode.ROUTE_SEQUENCE_BREAK: "Route legs visited out of sequence",
    EvidenceCode.DESTINATION_CONTRADICTION: "Destination contradicts route",
    EvidenceCode.UNKNOWN_ROUTE: "Route not present in the world model",
    EvidenceCode.WEIGHT_NOT_CONSERVED: "Cargo weight changed without a loading event",
    EvidenceCode.CARGO_DRIFT_UNEXPLAINED: "Cargo drifted across a run of transitions",
    EvidenceCode.CONTAINER_COUNT_NOT_CONSERVED: "Container count changed unexplained",
    EvidenceCode.VALUE_NOT_CONSERVED: "Declared value changed unexplained",
    EvidenceCode.OWNER_CHANGED_WITHOUT_TRANSFER: "Owner changed without a transfer event",
    EvidenceCode.CARGO_TYPE_MUTATED: "Cargo type changed mid-shipment",
    EvidenceCode.WEIGHT_EXCEEDS_CAPACITY: "Weight exceeds container capacity",
    EvidenceCode.EXACT_DUPLICATE: "Byte-identical duplicate record",
    EvidenceCode.STRUCTURAL_DUPLICATE: "Structurally identical duplicate",
    EvidenceCode.FUZZY_DUPLICATE: "Near-duplicate of another record",
    EvidenceCode.ROBUST_Z_OUTLIER: "Robust z-score outlier",
    EvidenceCode.IQR_OUTLIER: "Interquartile-range outlier",
    EvidenceCode.ISOLATION_FOREST_OUTLIER: "Isolation Forest outlier",
    EvidenceCode.LOF_OUTLIER: "Local Outlier Factor outlier",
    EvidenceCode.DBSCAN_NOISE: "Unclustered by DBSCAN",
    EvidenceCode.DISTRIBUTION_SHIFT: "Distribution shift against baseline",
    EvidenceCode.PEER_GROUP_OUTLIER: "Outlier within its own peer group",
    EvidenceCode.ORPHAN_RECORD: "Record has no supporting lineage",
    EvidenceCode.LINEAGE_BREAK: "Provenance chain broken",
    EvidenceCode.GRAPH_CONFLICT: "Graph dependency conflict",
    EvidenceCode.MISSING_EXPECTED_EVENT: "Expected event absent from sequence",
    EvidenceCode.UNKNOWN_ENTITY_REFERENCE: "References an entity not in the world",
    EvidenceCode.RECORD_HASH_MISMATCH: "Blockchain record-hash mismatch",
    EvidenceCode.RECORD_NOT_IN_CHAIN: "Record absent from the provenance chain",
    EvidenceCode.NODE_STATE_DIVERGENCE: "Node state root diverges",
    EvidenceCode.BLOCK_CHAIN_BROKEN: "Block hash linkage broken",
    EvidenceCode.UNKNOWN_OWNER: "Owner not in the registry",
    EvidenceCode.OWNER_ALIAS_COLLISION: "Owner alias collides with another entity",
    EvidenceCode.ID_FORMAT_INVALID: "Identifier format invalid",
    EvidenceCode.FIELD_BLANK: "Benign blank field",
    EvidenceCode.TIMESTAMP_FORMAT_VARIANT: "Benign timestamp formatting variant",
    EvidenceCode.NAME_UNNORMALISED: "Benign unnormalised name",
    EvidenceCode.NUMERIC_FORMAT_VARIANT: "Benign numeric formatting variant",
    EvidenceCode.CASE_INCONSISTENCY: "Benign case inconsistency",
}


class TamperClass(StrEnum):
    """What the classifier believes was done to a record (spec 18)."""

    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    DUPLICATED = "DUPLICATED"
    FABRICATED = "FABRICATED"
    BENIGN_ANOMALY = "BENIGN_ANOMALY"
    CLEAN = "CLEAN"


class Classification(StrEnum):
    """Disposition of a record in the reconstructed manifest (spec 1.1).

    Every output record carries exactly one of these, so nothing is ever
    silently altered.
    """

    ORIGINAL = "ORIGINAL"
    REPAIRED = "REPAIRED"
    REMOVED = "REMOVED"
    UNRECOVERABLE = "UNRECOVERABLE"


class NodeStatus(StrEnum):
    HEALTHY = "HEALTHY"
    DIVERGENT = "DIVERGENT"
    OFFLINE = "OFFLINE"
    SYNCING = "SYNCING"


class AttackClass(StrEnum):
    """Ground-truth attack labels used by the corruption generator (spec 6).

    These live in the private injection log only. Nothing under ``core/`` may
    import this for detection purposes -- it exists so the evaluator can
    compare predictions against the answer key.
    """

    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    DUPLICATED = "DUPLICATED"
    FABRICATED = "FABRICATED"
    NOISE = "NOISE"

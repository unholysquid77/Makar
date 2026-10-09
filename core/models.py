"""Canonical data model.

Two families of model live here:

* **World entities** -- ports, vessels, routes, owners, shipments, containers.
  The synthetic generator builds these first and derives the manifest from
  their relationships (spec 5.1), which is what makes the data coherent
  enough for consistency reasoning to have any teeth.
* **Forensic objects** -- records, evidence, verdicts, candidate repairs,
  reconstructions. These follow the Observation -> Evidence -> Inference ->
  Decision layering of spec 38, and each is a separate type precisely so the
  layers cannot be collapsed by accident.

Manifest records are parsed *tolerantly*: a suspect manifest legitimately
contains blanks, mixed timestamp formats and junk numerics. Every field the
normaliser could not interpret stays ``None`` and is reported as FORMAT
evidence rather than crashing the pipeline.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.types import (
    Classification,
    EvidenceCode,
    EvidenceType,
    NodeStatus,
    TamperClass,
)

SCHEMA_VERSION = "1.0"


class MakarModel(BaseModel):
    """Base model with settings shared by everything in the system."""

    model_config = ConfigDict(
        populate_by_name=True,
        str_strip_whitespace=False,
        extra="ignore",
        ser_json_timedelta="float",
    )


# ======================================================================
# World entities (spec 5.1)
# ======================================================================


class Port(MakarModel):
    port_id: str
    name: str
    country: str
    latitude: float
    longitude: float
    #: Mean/sigma of this port's dwell-time distribution, in hours. The
    #: temporal engine compares observed dwell against the port's own
    #: distribution rather than a single global constant (spec 9.5).
    dwell_mean_hours: float = 20.0
    dwell_sigma_hours: float = 10.0
    #: Larger hubs legitimately see more traffic; used for peer grouping.
    capacity_teu: int = 100_000

    def coords(self) -> tuple[float, float]:
        """Return ``(lat, lon)``."""
        return (self.latitude, self.longitude)

    def to_geojson_feature(self) -> dict[str, Any]:
        """GeoJSON Point feature in the shape spec 8.1 prescribes."""
        return {
            "type": "Feature",
            "geometry": {"type": "Point", "coordinates": [self.longitude, self.latitude]},
            "properties": {
                "port_id": self.port_id,
                "name": self.name,
                "country": self.country,
                "capacity_teu": self.capacity_teu,
            },
        }


class Vessel(MakarModel):
    vessel_id: str
    name: str
    #: Per-vessel speed envelope. The feasibility engine prefers these over
    #: the global defaults when the record names a known vessel (spec 9.3).
    cruise_speed_knots: float = 18.0
    max_speed_knots: float = 28.0
    capacity_containers: int = 200
    capacity_weight_kg: float = 4_000_000.0


class Route(MakarModel):
    route_id: str
    #: Ordered port sequence, e.g. ``[PORT_MUM, PORT_COL, PORT_SIN]``.
    port_sequence: list[str]
    vessel_id: str | None = None

    def legs(self) -> list[tuple[str, str]]:
        """Consecutive port pairs along the route."""
        return list(zip(self.port_sequence, self.port_sequence[1:], strict=False))

    def index_of(self, port_id: str) -> int | None:
        """Position of ``port_id`` in the sequence, or ``None`` if off-route."""
        try:
            return self.port_sequence.index(port_id)
        except ValueError:
            return None

    def to_geojson_feature(self, ports: dict[str, Port]) -> dict[str, Any]:
        """GeoJSON LineString feature in the shape spec 8.2 prescribes."""
        coords = [
            [ports[p].longitude, ports[p].latitude] for p in self.port_sequence if p in ports
        ]
        return {
            "type": "Feature",
            "geometry": {"type": "LineString", "coordinates": coords},
            "properties": {
                "route_id": self.route_id,
                "port_sequence": self.port_sequence,
                "vessel_id": self.vessel_id,
            },
        }


class Owner(MakarModel):
    owner_id: str
    name: str
    country: str
    #: Alternate spellings the generator may emit as harmless noise, and that
    #: the entity resolver must fold back together (spec 6.3).
    aliases: list[str] = Field(default_factory=list)


class Container(MakarModel):
    container_id: str
    shipment_id: str
    cargo_type: str
    #: Weight at creation. Conservation checks measure drift from this.
    initial_weight_kg: float
    declared_value: float
    max_weight_kg: float = 30_000.0


class Shipment(MakarModel):
    shipment_id: str
    owner_id: str
    route_id: str
    vessel_id: str
    origin: str
    destination: str
    container_ids: list[str] = Field(default_factory=list)
    created_at: datetime | None = None


class RouteEvent(MakarModel):
    """One port visit in a container's route history (spec 7)."""

    port: str
    arrival: datetime | None = None
    departure: datetime | None = None


class RouteManifest(MakarModel):
    """A container's full route history -- the temporal graph's backbone."""

    container_id: str
    events: list[RouteEvent] = Field(default_factory=list)


class World(MakarModel):
    """The complete synthetic world the manifest was generated from.

    The detection side receives this as the *world model*: the set of entities
    that legitimately exist. A record referencing anything outside it is
    evidence of fabrication (spec 18.4).
    """

    seed: int
    sim_start: datetime
    sim_end: datetime
    ports: dict[str, Port] = Field(default_factory=dict)
    vessels: dict[str, Vessel] = Field(default_factory=dict)
    routes: dict[str, Route] = Field(default_factory=dict)
    owners: dict[str, Owner] = Field(default_factory=dict)
    shipments: dict[str, Shipment] = Field(default_factory=dict)
    containers: dict[str, Container] = Field(default_factory=dict)
    cargo_types: list[str] = Field(default_factory=list)

    def port_of(self, name_or_id: str | None) -> Port | None:
        """Resolve a port by id or by display name (manifests carry both)."""
        if not name_or_id:
            return None
        if name_or_id in self.ports:
            return self.ports[name_or_id]
        needle = name_or_id.strip().casefold()
        for port in self.ports.values():
            if port.name.casefold() == needle or port.port_id.casefold() == needle:
                return port
        return None

    def ports_geojson(self) -> dict[str, Any]:
        return {
            "type": "FeatureCollection",
            "features": [p.to_geojson_feature() for p in self.ports.values()],
        }

    def routes_geojson(self) -> dict[str, Any]:
        return {
            "type": "FeatureCollection",
            "features": [r.to_geojson_feature(self.ports) for r in self.routes.values()],
        }


# ======================================================================
# Manifest records
# ======================================================================

#: Fields that participate in the content hash. Provenance fields
#: (``record_hash``, ``block_id``, ``source_node``) are excluded by design:
#: the hash must describe the *cargo claim*, not where it was stored.
HASHED_FIELDS: tuple[str, ...] = (
    "record_id",
    "shipment_id",
    "container_id",
    "route_id",
    "vessel_id",
    "owner",
    "cargo_type",
    "origin",
    "destination",
    "current_location",
    "port_id",
    "event_type",
    "weight",
    "container_count",
    "declared_value",
    "status",
    "timestamp",
    "arrival_timestamp",
    "departure_timestamp",
)

#: Fields compared by the structural duplicate check (spec 12.2).
STRUCTURAL_FIELDS: tuple[str, ...] = (
    "owner",
    "cargo_type",
    "route_id",
    "weight",
    "timestamp",
    "current_location",
)


def _canon(value: Any) -> Any:
    """Canonicalise a value for hashing: stable across formatting noise."""
    if value is None:
        return None
    if isinstance(value, datetime):
        # Normalise to UTC-naive microsecond-free ISO: formatting variants
        # must not change the hash, only real content changes should.
        return value.replace(microsecond=0, tzinfo=None).isoformat()
    if isinstance(value, float):
        # Round to 3dp so float noise does not fork the hash.
        return round(value, 3)
    if isinstance(value, str):
        return value.strip()
    return value


class ManifestRecord(MakarModel):
    """One normalised manifest row -- a single claimed cargo event.

    Required fields follow spec 4.1; the rest are the extended set of
    spec 4.2. Everything except ``record_id`` is optional because the suspect
    manifest is allowed to be damaged, and a detector that cannot run on a
    record must say so rather than guess.
    """

    # -- spec 4.1: required --
    record_id: str
    cargo_type: str | None = None
    owner: str | None = None
    origin: str | None = None
    destination: str | None = None
    current_location: str | None = None
    weight: float | None = None
    container_count: int | None = None
    declared_value: float | None = None
    status: str | None = None
    timestamp: datetime | None = None

    # -- spec 4.2: extended --
    shipment_id: str | None = None
    container_id: str | None = None
    route_id: str | None = None
    vessel_id: str | None = None
    port_id: str | None = None

    event_type: str | None = None
    arrival_timestamp: datetime | None = None
    departure_timestamp: datetime | None = None

    latitude: float | None = None
    longitude: float | None = None

    previous_location: str | None = None
    next_location: str | None = None

    source_node: str | None = None
    block_id: str | None = None
    record_hash: str | None = None
    schema_version: str = SCHEMA_VERSION

    # -- normalisation bookkeeping (never hashed) --
    #: The row exactly as it arrived, before normalisation. Kept so the
    #: report can show the investigator what was literally in the file.
    raw: dict[str, Any] = Field(default_factory=dict, repr=False)
    #: FORMAT-class observations made while normalising this row.
    normalization_notes: list[str] = Field(default_factory=list)
    #: Sequence position in the manifest as delivered, for gap detection.
    sequence_index: int | None = None

    # -- derived ---------------------------------------------------------

    def canonical_payload(self) -> dict[str, Any]:
        """The content-bearing subset of the record, canonicalised."""
        return {f: _canon(getattr(self, f, None)) for f in HASHED_FIELDS}

    def content_hash(self) -> str:
        """SHA-256 over the canonical payload (spec 12.1, spec 21)."""
        blob = json.dumps(self.canonical_payload(), sort_keys=True, default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def structural_key(self) -> str:
        """Hash over the structural-duplicate field subset (spec 12.2)."""
        payload = {f: _canon(getattr(self, f, None)) for f in STRUCTURAL_FIELDS}
        blob = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def effective_time(self) -> datetime | None:
        """Best available timestamp for ordering this record.

        Prefers ``timestamp``, then arrival, then departure. Records whose
        times were all destroyed sort last and pick up TIMESTAMP_MISSING.
        """
        return self.timestamp or self.arrival_timestamp or self.departure_timestamp

    def location_key(self) -> str | None:
        """Best available location identifier for this record."""
        return self.port_id or self.current_location


# ======================================================================
# Forensic objects
# ======================================================================


class Evidence(MakarModel):
    """One finding about one record (spec 16).

    Evidence is an *observation with a severity*, never a verdict. ``severity``
    is the detector's own confidence that what it saw is abnormal, in [0, 1];
    turning that into a tampering probability is the fusion layer's job.
    """

    record_id: str
    code: EvidenceCode
    type: EvidenceType
    severity: float = Field(ge=0.0, le=1.0)
    description: str
    #: Other records that corroborate or contradict this one.
    supporting_records: list[str] = Field(default_factory=list)
    #: Machine-readable specifics: measured values, thresholds, deltas.
    #: The UI renders these verbatim so a judge can check our arithmetic.
    details: dict[str, Any] = Field(default_factory=dict)
    #: Which engine produced this, for auditing and for disabling a layer.
    engine: str = ""

    def short(self) -> str:
        return f"{self.code}({self.severity:.2f})"


class EvidenceContribution(MakarModel):
    """One line of the tampering-probability breakdown (spec 17)."""

    code: EvidenceCode
    type: EvidenceType
    label: str
    severity: float
    #: Signed log-odds this contributed to the fused score.
    log_odds: float
    #: Same thing rendered as the integer points the UI shows (+23, -05).
    points: int


class RecordVerdict(MakarModel):
    """Fused inference about one record (spec 17, 18).

    This is the only place a record acquires a probability, and the only
    place a :class:`TamperClass` is assigned.
    """

    record_id: str
    #: Max severity seen per evidence type -- the per-layer summary the
    #: investigation panel shows as "Temporal 0.91 / Spatial 0.87 / ...".
    type_scores: dict[EvidenceType, float] = Field(default_factory=dict)
    #: Raw unfused anomaly strength, useful for ranking without calibration.
    anomaly_score: float = 0.0
    #: Calibrated probability the record was deliberately tampered with.
    tampering_probability: float = 0.0
    tamper_class: TamperClass = TamperClass.CLEAN
    class_confidence: float = 0.0
    #: Why we believe it, in descending order of contribution.
    contributions: list[EvidenceContribution] = Field(default_factory=list)
    #: One-paragraph deterministic explanation, no LLM involved.
    rationale: str = ""

    @property
    def is_suspicious(self) -> bool:
        return self.tamper_class not in (TamperClass.CLEAN,)


class CandidateRepair(MakarModel):
    """A proposed original state for a damaged record (spec 19)."""

    candidate_id: str
    #: Which strategy produced it, e.g. ``neighbor_interpolation``.
    strategy: str
    #: Field -> proposed value. Empty when ``remove`` is True.
    changes: dict[str, Any] = Field(default_factory=dict)
    #: True when the candidate is "this record should not exist".
    remove: bool = False
    #: Per-criterion scores, keyed by the weights in
    #: ``reconstruction.candidate_weights``.
    criterion_scores: dict[str, float] = Field(default_factory=dict)
    score: float = 0.0
    explanation: str = ""


class Reconstruction(MakarModel):
    """Final disposition of one record (spec 20).

    Retains the original state, the reconstructed state, the classification,
    the confidence, the supporting evidence and the reason -- all six, always,
    so no change is ever unexplained.
    """

    record_id: str
    classification: Classification
    original: dict[str, Any] = Field(default_factory=dict)
    reconstructed: dict[str, Any] | None = None
    confidence: float = 0.0
    evidence: list[Evidence] = Field(default_factory=list)
    candidates: list[CandidateRepair] = Field(default_factory=list)
    selected_candidate_id: str | None = None
    reason: str = ""


# ======================================================================
# Timeline, provenance, nodes
# ======================================================================


class TimelineBucket(MakarModel):
    """Anomaly counts in one time bucket (spec 25)."""

    start: datetime
    end: datetime
    total: int = 0
    by_class: dict[TamperClass, int] = Field(default_factory=dict)
    record_ids: list[str] = Field(default_factory=list)


class AttackWindow(MakarModel):
    """An inferred attack window -- a hypothesis, not a fact (spec 25)."""

    window_id: str
    start: datetime
    end: datetime
    buckets: list[TimelineBucket] = Field(default_factory=list)
    record_count: int = 0
    #: Entities disproportionately represented inside the window.
    affected_ports: list[str] = Field(default_factory=list)
    affected_owners: list[str] = Field(default_factory=list)
    affected_vessels: list[str] = Field(default_factory=list)
    #: Inferred ordering of attack phases, e.g. MODIFIED -> DUPLICATED.
    likely_sequence: list[TamperClass] = Field(default_factory=list)
    confidence: float = 0.0
    narrative: str = ""


class BlockHeader(MakarModel):
    """Header of a provenance block (spec 21.1)."""

    block_id: str
    index: int
    timestamp: datetime
    previous_hash: str
    manifest_root: str
    route_root: str
    state_root: str
    record_count: int
    block_hash: str = ""


class Block(MakarModel):
    header: BlockHeader
    record_hashes: list[str] = Field(default_factory=list)
    record_ids: list[str] = Field(default_factory=list)
    node_signatures: dict[str, str] = Field(default_factory=dict)


class NodeView(MakarModel):
    """One virtual node's reported state (spec 22, 23)."""

    node_id: str
    status: NodeStatus = NodeStatus.HEALTHY
    endpoint: str = ""
    peers: list[str] = Field(default_factory=list)
    height: int = 0
    latest_block_id: str | None = None
    state_root: str = ""
    #: Set when this node's state root disagrees with the network majority.
    divergent_blocks: list[str] = Field(default_factory=list)
    divergent_records: list[str] = Field(default_factory=list)


class ConsistencyReport(MakarModel):
    """Result of comparing state roots across nodes (spec 23)."""

    majority_state_root: str = ""
    agreeing_nodes: list[str] = Field(default_factory=list)
    divergent_nodes: list[str] = Field(default_factory=list)
    affected_blocks: list[str] = Field(default_factory=list)
    affected_records: list[str] = Field(default_factory=list)
    nodes: list[NodeView] = Field(default_factory=list)


# ======================================================================
# Top-level analysis result
# ======================================================================


class ManifestSummary(MakarModel):
    total_records: int = 0
    suspicious: int = 0
    original: int = 0
    repaired: int = 0
    removed: int = 0
    unrecoverable: int = 0
    by_tamper_class: dict[TamperClass, int] = Field(default_factory=dict)
    by_evidence_type: dict[EvidenceType, int] = Field(default_factory=dict)
    mean_repair_confidence: float = 0.0


class AnalysisResult(MakarModel):
    """Everything one analysis run produced.

    This is the object the API serves, the report renders and the evaluator
    scores, so it holds the full chain from observation to decision.
    """

    run_id: str
    created_at: datetime
    seed: int | None = None
    config_sources: list[str] = Field(default_factory=list)
    summary: ManifestSummary = Field(default_factory=ManifestSummary)
    records: list[ManifestRecord] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    verdicts: dict[str, RecordVerdict] = Field(default_factory=dict)
    reconstructions: dict[str, Reconstruction] = Field(default_factory=dict)
    attack_windows: list[AttackWindow] = Field(default_factory=list)
    consistency: ConsistencyReport | None = None
    #: Records inferred to be missing entirely (spec 18.2). These have no
    #: row in the manifest, so they are reported separately.
    inferred_deletions: list[dict[str, Any]] = Field(default_factory=list)
    timings_ms: dict[str, float] = Field(default_factory=dict)

    def evidence_for(self, record_id: str) -> list[Evidence]:
        return [e for e in self.evidence if e.record_id == record_id]

    def ranked_suspicious(self, limit: int | None = None) -> list[RecordVerdict]:
        """Verdicts sorted by tampering probability, highest first."""
        ranked = sorted(
            (v for v in self.verdicts.values() if v.is_suspicious),
            key=lambda v: v.tampering_probability,
            reverse=True,
        )
        return ranked[:limit] if limit else ranked

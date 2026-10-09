"""Row -> :class:`ManifestRecord` normalisation.

Produces typed records plus the evidence raised while parsing them. Severity
is kept deliberately low for formatting findings: they exist so the fusion
layer can *discount* a messy record, and so the report can tell an analyst
"this looked odd because the export is untidy, not because anyone edited it".

Where normalisation cannot recover a value it leaves ``None`` and says so.
Downstream engines then skip that check for that record and report the gap,
which is honest -- far better than imputing a value and then detecting an
anomaly we invented ourselves.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.config import MakarConfig
from core.geo import coords_valid
from core.models import Evidence, ManifestRecord, World
from core.normalization.parsers import (
    is_blank,
    normalize_enum,
    parse_float,
    parse_int,
    parse_timestamp,
)
from core.normalization.resolver import EntityResolver
from core.types import EventType, EvidenceCode, EvidenceType, ShipmentStatus

ENGINE = "normalizer"

#: Formatting findings are benign by default, so their severity stays small.
#: ``FORMAT`` also carries a negative fusion weight, which means a tidy-looking
#: forgery is *not* given the benefit of the doubt that a messy row gets.
_FORMAT_SEVERITY = 0.15
_UNPARSEABLE_SEVERITY = 0.30

#: Fields whose emptiness carries *no* information because the data model
#: guarantees it: the final port call has no departure, a CREATED record has
#: no previous port, a destination record has no next port. These are counted
#: in the data-quality stats but never raised as evidence -- doing so would
#: attach a FORMAT finding to roughly a third of a clean manifest and make the
#: breakdown useless.
_STRUCTURALLY_NULLABLE = frozenset(
    {
        "departure_timestamp",
        "previous_location",
        "next_location",
        "block_id",
        "record_hash",
    }
)

#: Fields that are populated in a clean export but may be blanked by untidy
#: tooling. A blank here is a genuine (benign) data-quality finding.
_NULLABLE = frozenset(
    {
        "declared_value",
        "vessel_id",
        "container_count",
        "status",
        "latitude",
        "longitude",
    }
)

_EVENT_TYPES = {str(e) for e in EventType}
_STATUSES = {str(s) for s in ShipmentStatus}


@dataclass
class NormalizationResult:
    records: list[ManifestRecord] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    #: Counts by note tag, for the report's data-quality section.
    stats: dict[str, int] = field(default_factory=dict)
    #: Row indices that could not be turned into a record at all.
    rejected: list[dict[str, Any]] = field(default_factory=list)


class _Builder:
    """Accumulates one record's parsed fields and its FORMAT evidence."""

    def __init__(self, record_id: str, result: NormalizationResult) -> None:
        self.record_id = record_id
        self.result = result
        self.notes: list[str] = []

    def bump(self, tag: str) -> None:
        self.result.stats[tag] = self.result.stats.get(tag, 0) + 1

    def evidence(
        self,
        code: EvidenceCode,
        severity: float,
        description: str,
        **details: Any,
    ) -> None:
        self.result.evidence.append(
            Evidence(
                record_id=self.record_id,
                code=code,
                type=EvidenceType.FORMAT
                if code
                in {
                    EvidenceCode.FIELD_BLANK,
                    EvidenceCode.TIMESTAMP_FORMAT_VARIANT,
                    EvidenceCode.NAME_UNNORMALISED,
                    EvidenceCode.NUMERIC_FORMAT_VARIANT,
                    EvidenceCode.CASE_INCONSISTENCY,
                }
                else _type_for(code),
                severity=severity,
                description=description,
                details=details,
                engine=ENGINE,
            )
        )

    def note(self, text: str) -> None:
        self.notes.append(text)


def _type_for(code: EvidenceCode) -> EvidenceType:
    from core.types import EVIDENCE_CODE_TYPE

    return EvidenceType(EVIDENCE_CODE_TYPE[code])


def _note_to_code(field_name: str, note: str) -> EvidenceCode | None:
    """Map a parser note to the evidence code that describes it."""
    if note == "blank":
        return EvidenceCode.FIELD_BLANK
    if note in {
        "epoch",
        "no_timezone",
        "space_separator",
        "subsecond",
        "explicit_offset",
        "dash_dayfirst",
        "slash_monthfirst",
    }:
        return EvidenceCode.TIMESTAMP_FORMAT_VARIANT
    if note in {"thousands_separator", "unit_suffix", "currency_prefix", "padded", "scientific", "rounded"}:
        return EvidenceCode.NUMERIC_FORMAT_VARIANT
    if note in {"case_drift", "whitespace"}:
        return EvidenceCode.CASE_INCONSISTENCY
    if note == "unparseable":
        return (
            EvidenceCode.TIMESTAMP_FORMAT_VARIANT
            if "timestamp" in field_name
            else EvidenceCode.NUMERIC_FORMAT_VARIANT
        )
    return None


def _handle_note(builder: _Builder, field_name: str, note: str | None, raw: Any) -> None:
    """Record one parser note as stats, a record note and FORMAT evidence."""
    if note is None:
        return
    builder.bump(f"{field_name}:{note}")

    if note == "blank":
        if field_name in _STRUCTURALLY_NULLABLE:
            # Expected to be empty for structural reasons; not a finding.
            return
        if field_name in _NULLABLE:
            builder.note(f"{field_name} blank in export")
            builder.evidence(
                EvidenceCode.FIELD_BLANK,
                _FORMAT_SEVERITY,
                f"Field '{field_name}' is blank in the export; treated as absent, not altered.",
                field=field_name,
                raw=raw,
                nullable=True,
            )
        return

    code = _note_to_code(field_name, note)
    if code is None:
        return

    if note == "unparseable":
        builder.note(f"{field_name} unparseable ({raw!r})")
        builder.evidence(
            code,
            _UNPARSEABLE_SEVERITY,
            f"Field '{field_name}' could not be parsed from {raw!r}; "
            f"checks depending on it are skipped for this record.",
            field=field_name,
            raw=raw,
            recovered=False,
        )
        return

    builder.note(f"{field_name} reformatted ({note})")
    builder.evidence(
        code,
        _FORMAT_SEVERITY,
        f"Field '{field_name}' used a non-canonical format ({note}); value recovered.",
        field=field_name,
        raw=raw,
        variant=note,
        recovered=True,
    )


def normalize_rows(
    rows: list[dict[str, Any]],
    world: World,
    cfg: MakarConfig,
    *,
    resolver: EntityResolver | None = None,
) -> NormalizationResult:
    """Normalise raw manifest rows into typed records plus FORMAT evidence."""
    result = NormalizationResult()
    resolver = resolver or EntityResolver(world)
    seen_ids: dict[str, int] = {}

    for index, row in enumerate(rows):
        raw_id = str(row.get("record_id", "") or "").strip()
        if is_blank(raw_id):
            raw_id = f"UNIDENTIFIED_{index:06d}"
            builder_id = raw_id
        else:
            builder_id = raw_id

        # Duplicate primary keys are themselves a finding, and renaming the
        # second occurrence keeps the rest of the pipeline addressable.
        if builder_id in seen_ids:
            seen_ids[builder_id] += 1
            builder_id = f"{builder_id}#{seen_ids[builder_id]}"
        else:
            seen_ids[builder_id] = 0

        b = _Builder(builder_id, result)

        if raw_id.startswith("UNIDENTIFIED_"):
            b.evidence(
                EvidenceCode.ID_FORMAT_INVALID,
                0.55,
                "Record has no usable record_id; a synthetic id was assigned for tracking.",
                raw=row.get("record_id"),
            )

        # --- numerics ---
        weight, note = parse_float(row.get("weight"))
        _handle_note(b, "weight", note, row.get("weight"))
        declared_value, note = parse_float(row.get("declared_value"))
        _handle_note(b, "declared_value", note, row.get("declared_value"))
        container_count, note = parse_int(row.get("container_count"))
        _handle_note(b, "container_count", note, row.get("container_count"))
        latitude, note = parse_float(row.get("latitude"))
        _handle_note(b, "latitude", note, row.get("latitude"))
        longitude, note = parse_float(row.get("longitude"))
        _handle_note(b, "longitude", note, row.get("longitude"))

        # --- timestamps ---
        timestamp, note = parse_timestamp(row.get("timestamp"))
        _handle_note(b, "timestamp", note, row.get("timestamp"))
        arrival, note = parse_timestamp(row.get("arrival_timestamp"))
        _handle_note(b, "arrival_timestamp", note, row.get("arrival_timestamp"))
        departure, note = parse_timestamp(row.get("departure_timestamp"))
        _handle_note(b, "departure_timestamp", note, row.get("departure_timestamp"))

        if timestamp is None:
            b.evidence(
                EvidenceCode.TIMESTAMP_MISSING,
                0.45,
                "Primary timestamp is missing or unparseable; temporal ordering "
                "for this record falls back to arrival/departure.",
                raw=row.get("timestamp"),
            )

        # --- coordinates ---
        # Only a *present but impossible* pair is a spatial finding. One half
        # of the pair being blank is a data-quality note already handled above.
        if (
            latitude is not None
            and longitude is not None
            and not coords_valid(latitude, longitude)
        ):
            b.evidence(
                EvidenceCode.COORDINATE_OUT_OF_RANGE,
                0.65,
                f"Coordinates ({latitude}, {longitude}) are outside the valid range.",
                latitude=latitude,
                longitude=longitude,
            )
            latitude = longitude = None
        elif latitude is None or longitude is None:
            # An incomplete pair is unusable; drop both so no engine reads a
            # half-position as a real location.
            latitude = longitude = None

        # --- entity resolution ---
        owner_res = resolver.resolve_owner(row.get("owner"))
        if owner_res.method == "alias":
            b.note("owner written as an alias")
            b.evidence(
                EvidenceCode.NAME_UNNORMALISED,
                _FORMAT_SEVERITY,
                f"Owner written as {row.get('owner')!r}; resolved to "
                f"{owner_res.value!r} via the owner registry.",
                raw=row.get("owner"),
                canonical=owner_res.value,
                owner_id=owner_res.entity_id,
                method="alias",
            )
            b.bump("owner:alias")
        elif owner_res.method == "fuzzy":
            b.note("owner resolved fuzzily")
            b.evidence(
                EvidenceCode.NAME_UNNORMALISED,
                _FORMAT_SEVERITY,
                f"Owner {row.get('owner')!r} matched {owner_res.value!r} at "
                f"similarity {owner_res.score:.2f} (likely a typo in the export).",
                raw=row.get("owner"),
                canonical=owner_res.value,
                owner_id=owner_res.entity_id,
                similarity=round(owner_res.score, 3),
                method="fuzzy",
            )
            b.bump("owner:fuzzy")
        elif owner_res.method == "unknown":
            b.evidence(
                EvidenceCode.UNKNOWN_OWNER,
                0.70,
                f"Owner {row.get('owner')!r} is not in the owner registry "
                f"(closest match scored {owner_res.score:.2f}).",
                raw=row.get("owner"),
                best_similarity=round(owner_res.score, 3),
            )
            b.bump("owner:unknown")

        def _port(field_name: str) -> tuple[str | None, str | None]:
            res = resolver.resolve_port(row.get(field_name))
            if res.method == "blank":
                b.bump(f"{field_name}:blank")
            elif res.method == "alias" and res.resolved:
                b.bump(f"{field_name}:alias")
                b.evidence(
                    EvidenceCode.NAME_UNNORMALISED,
                    _FORMAT_SEVERITY,
                    f"Port written as {row.get(field_name)!r} in '{field_name}'; "
                    f"normalised to {res.value!r}.",
                    field=field_name,
                    raw=row.get(field_name),
                    canonical=res.value,
                    method="alias",
                )
            elif res.method == "fuzzy" and res.resolved:
                b.bump(f"{field_name}:fuzzy")
                b.evidence(
                    EvidenceCode.NAME_UNNORMALISED,
                    _FORMAT_SEVERITY,
                    f"Port {row.get(field_name)!r} in '{field_name}' matched "
                    f"{res.value!r} at similarity {res.score:.2f}.",
                    field=field_name,
                    raw=row.get(field_name),
                    canonical=res.value,
                    similarity=round(res.score, 3),
                )
            elif res.method == "unknown":
                b.bump(f"{field_name}:unknown_port")
                b.evidence(
                    EvidenceCode.UNKNOWN_ENTITY_REFERENCE,
                    0.68,
                    f"Port {row.get(field_name)!r} in '{field_name}' is not in the "
                    f"world model (closest match {res.score:.2f}).",
                    field=field_name,
                    raw=row.get(field_name),
                    best_similarity=round(res.score, 3),
                )
            return res.value, res.entity_id

        origin_name, _ = _port("origin")
        destination_name, _ = _port("destination")
        current_name, current_port_id = _port("current_location")
        previous_name, _ = _port("previous_location")
        next_name, _ = _port("next_location")
        _declared_name, declared_port_id = _port("port_id")

        port_id = declared_port_id or current_port_id

        cargo_res = resolver.resolve_cargo_type(row.get("cargo_type"))
        if cargo_res.method in {"alias", "fuzzy"}:
            b.bump(f"cargo_type:{cargo_res.method}")
            b.evidence(
                EvidenceCode.NAME_UNNORMALISED,
                _FORMAT_SEVERITY,
                f"Cargo type written as {row.get('cargo_type')!r}; normalised to "
                f"{cargo_res.value!r}.",
                field="cargo_type",
                raw=row.get("cargo_type"),
                canonical=cargo_res.value,
                method=cargo_res.method,
            )
        elif cargo_res.method == "unknown":
            b.bump("cargo_type:unknown")
            b.evidence(
                EvidenceCode.UNKNOWN_ENTITY_REFERENCE,
                0.55,
                f"Cargo type {row.get('cargo_type')!r} is not a known cargo class.",
                raw=row.get("cargo_type"),
            )

        # --- enums and labels ---
        event_type, note = normalize_enum(row.get("event_type"), _EVENT_TYPES)
        if note == "case_drift":
            _handle_note(b, "event_type", note, row.get("event_type"))
        elif note == "unknown_value":
            b.bump("event_type:unknown")
            b.evidence(
                EvidenceCode.UNKNOWN_ENTITY_REFERENCE,
                0.60,
                f"Event type {row.get('event_type')!r} is not a known lifecycle event.",
                raw=row.get("event_type"),
            )
            event_type = None

        status, note = normalize_enum(row.get("status"), _STATUSES)
        if note in {"case_drift", "blank"}:
            _handle_note(b, "status", note, row.get("status"))
        elif note == "unknown_value":
            b.bump("status:unknown")

        # --- id references ---
        # A blank token resolves to None, so an empty cell is never reported
        # as a reference to a nonexistent entity.
        def _ref(field_name: str) -> str | None:
            value = row.get(field_name)
            if is_blank(value):
                b.bump(f"{field_name}:blank")
                return None
            return str(value).strip()

        route_id = _ref("route_id")
        vessel_id = _ref("vessel_id")
        container_id = _ref("container_id")
        shipment_id = _ref("shipment_id")

        if route_id and not resolver.known_route(route_id):
            b.evidence(
                EvidenceCode.UNKNOWN_ROUTE,
                0.72,
                f"Route {route_id!r} does not exist in the world model.",
                route_id=route_id,
            )
        if vessel_id and not resolver.known_vessel(vessel_id):
            b.evidence(
                EvidenceCode.UNKNOWN_ENTITY_REFERENCE,
                0.68,
                f"Vessel {vessel_id!r} does not exist in the world model.",
                vessel_id=vessel_id,
            )
        if container_id and not resolver.known_container(container_id):
            b.evidence(
                EvidenceCode.UNKNOWN_ENTITY_REFERENCE,
                0.74,
                f"Container {container_id!r} does not exist in the world model.",
                container_id=container_id,
            )
        if shipment_id and not resolver.known_shipment(shipment_id):
            b.evidence(
                EvidenceCode.UNKNOWN_ENTITY_REFERENCE,
                0.70,
                f"Shipment {shipment_id!r} does not exist in the world model.",
                shipment_id=shipment_id,
            )

        if is_blank(row.get("vessel_id")):
            _handle_note(b, "vessel_id", "blank", row.get("vessel_id"))

        record = ManifestRecord(
            record_id=builder_id,
            cargo_type=cargo_res.value,
            owner=owner_res.value,
            origin=origin_name,
            destination=destination_name,
            current_location=current_name,
            weight=weight,
            container_count=container_count,
            declared_value=declared_value,
            status=status,
            timestamp=timestamp,
            shipment_id=shipment_id,
            container_id=container_id,
            route_id=route_id,
            vessel_id=vessel_id,
            port_id=port_id,
            event_type=event_type,
            arrival_timestamp=arrival,
            departure_timestamp=departure,
            latitude=latitude,
            longitude=longitude,
            previous_location=previous_name,
            next_location=next_name,
            source_node=(row.get("source_node") or "").strip() or None,
            block_id=(row.get("block_id") or "").strip() or None,
            record_hash=(row.get("record_hash") or "").strip() or None,
            schema_version=(row.get("schema_version") or "1.0").strip() or "1.0",
            raw=dict(row),
            normalization_notes=b.notes,
            sequence_index=index,
        )
        result.records.append(record)

    return result

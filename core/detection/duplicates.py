"""Duplicate detection engine (spec 12).

Three levels, cheapest first:

**Level 1 — exact.** SHA-256 over the canonical payload. Canonicalisation
rounds floats to 3dp and strips timestamp formatting, so two rows that differ
only in how they were *written* hash identically. That is deliberate: a replay
attack that re-exported a row with a different date format is still a replay.

**Level 2 — structural.** Hash over (owner, cargo_type, route, weight,
timestamp, location) exactly as spec 12.2 lists. Catches a copy whose
bookkeeping fields (``record_id``, ``source_node``, ``block_id``) were
rewritten to disguise it.

**Level 3 — fuzzy.** Field-level similarity inside a time window. This is the
one that needs care, because a naive all-pairs comparison over 5,000 records
is 12.5M comparisons and the problem statement asks for thousands of records
handled efficiently.

*Blocking strategy.* Candidates are only compared within a block, and blocks
are keyed on things a duplicate cannot change without ceasing to be a
duplicate: the container, or the (owner, cargo_type) pair. Within a block,
records are sorted by time and only compared against others inside
``near_duplicate_window_hours``. That turns the quadratic term into a small
constant per record.

*What is not a duplicate.* A container legitimately produces several records
per port call, and a route legitimately repeats ARRIVED/DEPARTED at every
port. The similarity function therefore requires the *event type and port* to
match before it will call two records near-duplicates, and the structural
check deliberately includes the timestamp.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from core.detection.base import AnalysisContext, register_detector
from core.models import Evidence, ManifestRecord
from core.types import EVIDENCE_CODE_TYPE, EvidenceCode, EvidenceType

ENGINE = "duplicate"

#: Fields compared by the fuzzy matcher, with their weights. They sum to 1.0
#: so the resulting similarity reads as a fraction.
_FUZZY_FIELDS: tuple[tuple[str, float], ...] = (
    ("owner", 0.16),
    ("cargo_type", 0.12),
    ("route_id", 0.10),
    ("port_id", 0.14),
    ("event_type", 0.12),
    ("weight", 0.16),
    ("declared_value", 0.10),
    ("destination", 0.10),
)

#: Relative difference at which a numeric field scores zero similarity.
_NUMERIC_SPAN = 0.10


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


def _numeric_similarity(a: float | None, b: float | None) -> float | None:
    if a is None or b is None:
        return None
    if a == b:
        return 1.0
    base = max(abs(a), abs(b))
    if base <= 0:
        return 1.0
    relative = abs(a - b) / base
    return max(0.0, 1.0 - relative / _NUMERIC_SPAN)


def field_similarity(a: ManifestRecord, b: ManifestRecord) -> tuple[float, dict[str, float]]:
    """Weighted field-level similarity in [0, 1], plus the per-field detail.

    Fields absent from both records are dropped and the weights renormalised,
    so a sparsely populated pair is not penalised for the columns it lacks.
    """
    total_weight = 0.0
    score = 0.0
    detail: dict[str, float] = {}

    for field, weight in _FUZZY_FIELDS:
        left, right = getattr(a, field, None), getattr(b, field, None)
        if left is None and right is None:
            continue
        if isinstance(left, (int, float)) or isinstance(right, (int, float)):
            similarity = _numeric_similarity(
                float(left) if left is not None else None,
                float(right) if right is not None else None,
            )
        else:
            similarity = 1.0 if left == right else 0.0
        if similarity is None:
            continue
        detail[field] = round(similarity, 3)
        score += similarity * weight
        total_weight += weight

    if total_weight <= 0:
        return 0.0, detail
    return score / total_weight, detail


class DuplicateEngine:
    name = "duplicate"

    def run(self, ctx: AnalysisContext) -> list[Evidence]:
        out: list[Evidence] = []
        exact_pairs = self._exact(ctx, out)
        structural_pairs = self._structural(ctx, out, exclude=exact_pairs)
        self._fuzzy(ctx, out, exclude=exact_pairs | structural_pairs)
        return [e for e in out if e.severity > 0.0]

    # -- level 1 -----------------------------------------------------------

    def _exact(self, ctx: AnalysisContext, out: list[Evidence]) -> set[frozenset[str]]:
        severity = ctx.cfg.float_("detection.duplicate.exact_severity")
        groups: dict[str, list[ManifestRecord]] = defaultdict(list)
        for rec in ctx.records:
            groups[rec.content_hash()].append(rec)

        seen: set[frozenset[str]] = set()
        for digest, members in groups.items():
            if len(members) < 2:
                continue
            ids = [m.record_id for m in members]
            for rec in members:
                others = [i for i in ids if i != rec.record_id]
                out.append(
                    _ev(
                        rec.record_id,
                        EvidenceCode.EXACT_DUPLICATE,
                        severity,
                        f"Content-identical to {len(others)} other record(s) "
                        f"({', '.join(others[:4])}{'...' if len(others) > 4 else ''}); "
                        f"the canonical payloads hash to the same value.",
                        supporting=others,
                        content_hash=digest[:16],
                        group_size=len(members),
                        level=1,
                    )
                )
            for i, left in enumerate(ids):
                for right in ids[i + 1 :]:
                    seen.add(frozenset((left, right)))
        return seen

    # -- level 2 -----------------------------------------------------------

    def _structural(
        self, ctx: AnalysisContext, out: list[Evidence], *, exclude: set[frozenset[str]]
    ) -> set[frozenset[str]]:
        severity = ctx.cfg.float_("detection.duplicate.structural_severity")
        groups: dict[str, list[ManifestRecord]] = defaultdict(list)
        for rec in ctx.records:
            groups[rec.structural_key()].append(rec)

        seen: set[frozenset[str]] = set()
        for digest, members in groups.items():
            if len(members) < 2:
                continue
            ids = [m.record_id for m in members]
            reported = False
            for rec in members:
                others = [
                    i
                    for i in ids
                    if i != rec.record_id and frozenset((rec.record_id, i)) not in exclude
                ]
                if not others:
                    continue
                reported = True
                out.append(
                    _ev(
                        rec.record_id,
                        EvidenceCode.STRUCTURAL_DUPLICATE,
                        severity,
                        f"Structurally identical to {', '.join(others[:4])} on "
                        f"owner, cargo, route, weight, timestamp and location, "
                        f"while differing in bookkeeping fields.",
                        supporting=others,
                        structural_key=digest[:16],
                        group_size=len(members),
                        level=2,
                    )
                )
            if reported:
                for i, left in enumerate(ids):
                    for right in ids[i + 1 :]:
                        seen.add(frozenset((left, right)))
        return seen

    # -- level 3 -----------------------------------------------------------

    def _fuzzy(
        self, ctx: AnalysisContext, out: list[Evidence], *, exclude: set[frozenset[str]]
    ) -> None:
        cfg = ctx.cfg
        threshold = cfg.float_("detection.duplicate.fuzzy_threshold")
        window = timedelta(hours=cfg.float_("detection.duplicate.near_duplicate_window_hours"))
        scale = cfg.float_("detection.duplicate.fuzzy_severity_scale")

        # Blocking: a near-duplicate keeps either the container or the
        # (owner, cargo) pair, so comparing only inside those blocks is safe
        # and keeps the comparison count near-linear.
        blocks: dict[tuple[str, str], list[ManifestRecord]] = defaultdict(list)
        for rec in ctx.records:
            when = rec.effective_time()
            if when is None:
                continue
            if rec.container_id:
                blocks[("container", rec.container_id)].append(rec)
            if rec.owner and rec.cargo_type:
                blocks[("owner_cargo", f"{rec.owner}|{rec.cargo_type}")].append(rec)

        emitted: set[frozenset[str]] = set()

        for (_kind, _key), members in blocks.items():
            if len(members) < 2:
                continue
            members.sort(key=lambda r: r.effective_time())
            for i, left in enumerate(members):
                left_time = left.effective_time()
                for right in members[i + 1 :]:
                    right_time = right.effective_time()
                    if right_time - left_time > window:
                        break  # sorted: everything later is further away
                    pair = frozenset((left.record_id, right.record_id))
                    if pair in exclude or pair in emitted:
                        continue
                    # A real duplicate claims the same event at the same place.
                    # Without this guard, consecutive ARRIVED/DEPARTED records
                    # of one port call would look like near-duplicates.
                    if left.event_type != right.event_type or left.port_id != right.port_id:
                        continue

                    similarity, detail = field_similarity(left, right)
                    if similarity < threshold:
                        continue

                    emitted.add(pair)
                    gap_hours = (right_time - left_time).total_seconds() / 3600.0
                    severity = min(0.95, similarity * scale + 0.10)
                    description = (
                        f"Near-duplicate of {right.record_id}: field similarity "
                        f"{similarity:.2f} on the same event ({left.event_type}) at "
                        f"the same port, {gap_hours:.1f}h apart."
                    )
                    shared = {
                        "similarity": round(similarity, 3),
                        "timestamp_gap_hours": round(gap_hours, 2),
                        "field_similarity": detail,
                        "same_owner": left.owner == right.owner,
                        "same_cargo": left.cargo_type == right.cargo_type,
                        "same_route": left.route_id == right.route_id,
                        "level": 3,
                    }
                    out.append(
                        _ev(
                            left.record_id,
                            EvidenceCode.FUZZY_DUPLICATE,
                            severity,
                            description,
                            supporting=[right.record_id],
                            **shared,
                        )
                    )
                    out.append(
                        _ev(
                            right.record_id,
                            EvidenceCode.FUZZY_DUPLICATE,
                            severity,
                            f"Near-duplicate of {left.record_id}: field similarity "
                            f"{similarity:.2f} on the same event ({left.event_type}) "
                            f"at the same port, {gap_hours:.1f}h apart.",
                            supporting=[left.record_id],
                            **shared,
                        )
                    )


register_detector(DuplicateEngine())

"""Conflict arbitration: symmetric evidence, asymmetric blame.

See design decision D7. The detectors are deliberately symmetric about
contradictions -- when a container is reported in two ports at once, *both*
records carry ``SIMULTANEOUS_PRESENCE``, because the observation genuinely
concerns both. But only one of them is usually the lie, and scoring both
equally guarantees a false positive on the honest one.

Measured on the real dataset with temporal + geospatial detectors alone:
every single clean-record false positive was the innocent half of a genuine
conflict pair -- 72 ``SIMULTANEOUS_PRESENCE`` items had exactly one tampered
end and **zero** had neither. The detectors were never wrong that a
contradiction existed; they could not tell which side was lying.

So this pass asks a different question: of these two records, which one does
the rest of the manifest support? Corroboration is assembled from signals
that are independent of the conflict itself:

================================  ==========================================
signal                            reasoning
================================  ==========================================
hash matches the chain            cryptographic: this record is as observed
committed in the chain at all     it existed when the block was sealed
port lies on the declared route   the world model expects it to be there
other records share its port call a real call leaves several records
neighbours are themselves clean   a lie tends to sit among its consequences
not an orphan / no lineage break  it belongs to something
================================  ==========================================

The better-corroborated record has its share of the conflict's severity
damped; the worse-corroborated one keeps it. Every adjustment is recorded in
``evidence.details["arbitration"]`` so the report can state *why* blame fell
where it did -- which is exactly what a judge asking "why did you flag this
one and not that one?" needs to hear.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.detection.base import AnalysisContext
from core.models import Evidence

#: Codes describing a mutual contradiction between two records. Only these
#: are arbitrated; one-sided findings have no second party to blame.
CONFLICT_CODES: frozenset[str] = frozenset(
    {
        "SIMULTANEOUS_PRESENCE",
        "SPEED_INFEASIBLE",
        "IMPOSSIBLE_TRANSIT",
        "EXACT_DUPLICATE",
        "STRUCTURAL_DUPLICATE",
        "FUZZY_DUPLICATE",
        "WEIGHT_NOT_CONSERVED",
        "VALUE_NOT_CONSERVED",
        "CONTAINER_COUNT_NOT_CONSERVED",
        "OWNER_CHANGED_WITHOUT_TRANSFER",
        "CARGO_TYPE_MUTATED",
        "ROUTE_SEQUENCE_BREAK",
    }
)

#: Codes that are themselves signs of a record standing alone, used when
#: judging whether a record's neighbourhood supports it.
_WEAKNESS_CODES: frozenset[str] = frozenset(
    {
        "ORPHAN_RECORD",
        "LINEAGE_BREAK",
        "RECORD_NOT_IN_CHAIN",
        "OFF_ROUTE_PORT",
        "UNKNOWN_ENTITY_REFERENCE",
        "UNKNOWN_ROUTE",
        "UNKNOWN_OWNER",
        "FUTURE_EVENT",
        "DESTINATION_CONTRADICTION",
    }
)

#: Minimum multiplier an arbitrated-away severity keeps. Never zero: the
#: corroborated record is still *part of* a real contradiction, and silencing
#: it entirely would hide the conflict from the investigator.
_MIN_MULTIPLIER = 0.15


@dataclass
class ArbitrationResult:
    evidence: list[Evidence] = field(default_factory=list)
    #: record id -> corroboration score in [0, 1]
    corroboration: dict[str, float] = field(default_factory=dict)
    #: Human-readable account of each blame decision, for the report.
    decisions: list[dict] = field(default_factory=list)


def _corroboration_scores(
    ctx: AnalysisContext, evidence: list[Evidence]
) -> tuple[dict[str, float], dict[str, list[str]]]:
    """Score how well the rest of the manifest supports each record."""
    weakness: dict[str, set[str]] = {}
    for item in evidence:
        code = str(item.code)
        if code in _WEAKNESS_CODES:
            weakness.setdefault(item.record_id, set()).add(code)
        # A clean hash match is recorded by the absence of a mismatch, so we
        # track mismatches explicitly instead.
        if code == "RECORD_HASH_MISMATCH" and not item.details.get("inconclusive"):
            weakness.setdefault(item.record_id, set()).add(code)

    chain = ctx.chain
    scores: dict[str, float] = {}
    reasons: dict[str, list[str]] = {}

    for rec in ctx.records:
        points = 0.0
        total = 0.0
        why: list[str] = []

        # --- provenance ---
        if chain is not None and getattr(chain, "height", 0):
            total += 3.0
            committed = chain.committed_hash(rec.record_id)
            if committed is None:
                why.append("not committed in the provenance chain")
            elif committed == rec.content_hash():
                points += 3.0
                why.append("content hash matches its chain commitment")
            else:
                why.append("content hash contradicts its chain commitment")

        # --- route membership ---
        route = ctx.world.routes.get(rec.route_id or "")
        if route is not None and rec.port_id:
            total += 1.5
            if rec.port_id in route.port_sequence:
                points += 1.5
                why.append(f"{rec.port_id} is a scheduled call on {route.route_id}")
            else:
                why.append(f"{rec.port_id} is not on route {route.route_id}")

        # --- company at the port call ---
        if rec.container_id and rec.port_id:
            total += 1.5
            siblings = [
                r
                for r in ctx.container_timeline(rec.container_id)
                if r.record_id != rec.record_id and r.port_id == rec.port_id
            ]
            if siblings:
                points += 1.5
                why.append(
                    f"{len(siblings)} other record(s) place the container at this port"
                )
            else:
                why.append("no other record places the container at this port")

        # --- its own weaknesses ---
        total += 2.0
        own = weakness.get(rec.record_id, set())
        if not own:
            points += 2.0
            why.append("no independent lineage or provenance problem")
        else:
            why.append("weakened by " + ", ".join(sorted(own)))

        # --- neighbourhood ---
        if rec.container_id:
            total += 1.0
            neighbours = [
                r.record_id
                for r in ctx.container_timeline(rec.container_id)
                if r.record_id != rec.record_id
            ]
            dirty = sum(1 for n in neighbours if weakness.get(n))
            if neighbours and dirty == 0:
                points += 1.0
                why.append("its neighbouring records are themselves unproblematic")
            elif neighbours:
                why.append(f"{dirty} of {len(neighbours)} neighbouring records are suspect")

        scores[rec.record_id] = (points / total) if total > 0 else 0.5
        reasons[rec.record_id] = why

    return scores, reasons


def arbitrate(ctx: AnalysisContext, evidence: list[Evidence]) -> ArbitrationResult:
    """Redistribute conflict severity toward the less-corroborated record."""
    scores, reasons = _corroboration_scores(ctx, evidence)
    result = ArbitrationResult(corroboration=scores)
    seen_pairs: set[tuple[str, str, str]] = set()

    for item in evidence:
        code = str(item.code)
        if code not in CONFLICT_CODES or not item.supporting_records:
            result.evidence.append(item)
            continue

        mine = scores.get(item.record_id, 0.5)
        # Compare against the best-corroborated counterpart: if any party to
        # the conflict is better supported than this record, this record is
        # the more likely author of the contradiction.
        others = [s for s in item.supporting_records if s in scores]
        if not others:
            result.evidence.append(item)
            continue
        best_other_id = max(others, key=lambda r: scores[r])
        theirs = scores[best_other_id]

        delta = mine - theirs
        if delta <= 0.0:
            # We are the weaker (or equal) party: keep full severity.
            updated = item.model_copy(deep=True)
            updated.details = {
                **item.details,
                "arbitration": {
                    "outcome": "blamed",
                    "corroboration": round(mine, 3),
                    "counterpart": best_other_id,
                    "counterpart_corroboration": round(theirs, 3),
                    "multiplier": 1.0,
                    "why": reasons.get(item.record_id, [])[:4],
                },
            }
            result.evidence.append(updated)
            continue

        multiplier = max(_MIN_MULTIPLIER, 1.0 - delta)
        updated = item.model_copy(deep=True)
        updated.severity = round(item.severity * multiplier, 4)
        updated.details = {
            **item.details,
            "arbitration": {
                "outcome": "exonerated",
                "corroboration": round(mine, 3),
                "counterpart": best_other_id,
                "counterpart_corroboration": round(theirs, 3),
                "multiplier": round(multiplier, 3),
                "original_severity": item.severity,
                "why": reasons.get(item.record_id, [])[:4],
            },
        }
        updated.description = (
            f"{item.description} Blame for this contradiction is attributed to "
            f"{best_other_id} rather than this record: corroboration "
            f"{theirs:.2f} vs {mine:.2f}."
        )
        result.evidence.append(updated)

        key = (code, *sorted((item.record_id, best_other_id)))
        if key not in seen_pairs:
            seen_pairs.add(key)
            result.decisions.append(
                {
                    "code": code,
                    "blamed": best_other_id if mine > theirs else item.record_id,
                    "exonerated": item.record_id if mine > theirs else best_other_id,
                    "corroboration": {
                        item.record_id: round(mine, 3),
                        best_other_id: round(theirs, 3),
                    },
                    "multiplier": round(multiplier, 3),
                    "reason": (
                        f"{item.record_id} is corroborated at {mine:.2f} against "
                        f"{best_other_id} at {theirs:.2f}; the contradiction is "
                        f"more likely authored by the less-corroborated record."
                    ),
                }
            )

    return result

"""Tampering classifier (spec 18).

Fusion says *how likely* a record was tampered with. This says *what kind*.
The two are separate because they use the evidence differently: fusion cares
about total weight, classification cares about the **pattern** — which layers
fired, not how hard.

The five classes and the signatures that identify them:

``DUPLICATED`` (18.3)
    A duplicate finding is close to self-identifying: another record says the
    same thing. Checked first because a duplicate also inevitably trips cargo
    and temporal checks, and those would otherwise out-shout it.

``FABRICATED`` (18.4)
    No legitimate lineage *and* conflicts with the world model. The
    distinguishing feature against MODIFIED is absence of history: an orphan
    record, or one absent from the provenance chain inside the sealed window,
    was never part of the manifest to begin with.

``MODIFIED`` (18.1)
    The record exists in the lineage but its *values* contradict the evidence
    around it — a hash mismatch, an unexplained weight change, an impossible
    transit. The record belongs; its contents do not.

``DELETED`` (18.2)
    Surfaced through `MISSING_EXPECTED_EVENT` on the records bracketing a
    hole. Note this labels *the surviving neighbour* as evidence of a deletion
    nearby; the deletion itself has no row and is reported separately in
    ``AnalysisResult.inferred_deletions``.

``BENIGN_ANOMALY`` (18.5)
    Something is irregular but the evidence does not support tampering — most
    often a record whose only findings are FORMAT or STATISTICAL. This class
    is what stops the system from treating every oddity as an attack, and the
    problem statement scores us on exactly that.

A record below ``classifier.min_probability`` is left ``CLEAN`` regardless of
pattern: a weak signal is not a quiet accusation.
"""

from __future__ import annotations

from core.config import MakarConfig
from core.models import Evidence, RecordVerdict
from core.types import EvidenceType, TamperClass

#: Codes that indicate the record is a copy of another.
_DUPLICATE_CODES = frozenset(
    {"EXACT_DUPLICATE", "STRUCTURAL_DUPLICATE", "FUZZY_DUPLICATE"}
)

#: Codes that indicate the record has no legitimate history.
_FABRICATION_CODES = frozenset(
    {
        "ORPHAN_RECORD",
        "RECORD_NOT_IN_CHAIN",
        "UNKNOWN_ENTITY_REFERENCE",
        "UNKNOWN_ROUTE",
        "UNKNOWN_OWNER",
    }
)

#: Codes that indicate values were edited while the record itself belongs.
_MODIFICATION_CODES = frozenset(
    {
        "RECORD_HASH_MISMATCH",
        "NODE_STATE_DIVERGENCE",
        "WEIGHT_NOT_CONSERVED",
        "CARGO_DRIFT_UNEXPLAINED",
        "VALUE_NOT_CONSERVED",
        "CONTAINER_COUNT_NOT_CONSERVED",
        "OWNER_CHANGED_WITHOUT_TRANSFER",
        "CARGO_TYPE_MUTATED",
        "WEIGHT_EXCEEDS_CAPACITY",
        "SPEED_INFEASIBLE",
        "IMPOSSIBLE_TRANSIT",
        "SIMULTANEOUS_PRESENCE",
        "REVERSE_CHRONOLOGY",
        "FUTURE_EVENT",
        "OFF_ROUTE_PORT",
        "DESTINATION_CONTRADICTION",
        "ROUTE_SEQUENCE_BREAK",
        "COORDINATE_PORT_MISMATCH",
        "EVENT_ORDER_VIOLATION",
    }
)

#: Codes that point at a *neighbouring* deletion.
_DELETION_CODES = frozenset({"MISSING_EXPECTED_EVENT", "SEQUENCE_GAP"})

#: Layers whose evidence alone never justifies a tampering label.
_WEAK_TYPES = frozenset({EvidenceType.FORMAT, EvidenceType.STATISTICAL})


def _strength(items: list[Evidence], codes: frozenset[str]) -> float:
    """Strongest severity among ``items`` whose code is in ``codes``."""
    severities = [i.severity for i in items if str(i.code) in codes]
    return max(severities) if severities else 0.0


def classify(
    cfg: MakarConfig,
    verdicts: dict[str, RecordVerdict],
    evidence_by_record: dict[str, list[Evidence]],
) -> dict[str, RecordVerdict]:
    """Assign a :class:`TamperClass` and class confidence to each verdict."""
    min_probability = cfg.float_("classifier.min_probability")
    deleted_min = cfg.float_("classifier.deleted_gap_min_severity")
    fabricated_min = cfg.float_("classifier.fabricated_lineage_min")
    suspicious_threshold = cfg.float_("fusion.thresholds.suspicious")

    for record_id, verdict in verdicts.items():
        items = evidence_by_record.get(record_id, [])
        if not items:
            verdict.tamper_class = TamperClass.CLEAN
            verdict.class_confidence = 1.0 - verdict.tampering_probability
            continue

        present_types = {EvidenceType(str(i.type)) for i in items}
        only_weak = present_types.issubset(_WEAK_TYPES)

        duplicate = _strength(items, _DUPLICATE_CODES)
        fabrication = _strength(items, _FABRICATION_CODES)
        modification = _strength(items, _MODIFICATION_CODES)
        deletion = _strength(items, _DELETION_CODES)

        # --- below the bar: not an accusation ---
        if verdict.tampering_probability < min_probability:
            if only_weak or verdict.tampering_probability < suspicious_threshold * 0.6:
                verdict.tamper_class = (
                    TamperClass.BENIGN_ANOMALY if only_weak else TamperClass.CLEAN
                )
            else:
                verdict.tamper_class = TamperClass.BENIGN_ANOMALY
            verdict.class_confidence = round(
                1.0 - verdict.tampering_probability, 4
            )
            verdict.rationale += (
                " Classified as a benign anomaly: the evidence is irregular but "
                "does not support deliberate tampering."
                if verdict.tamper_class is TamperClass.BENIGN_ANOMALY
                else ""
            )
            continue

        # --- strong enough to be called tampering: decide which kind ---
        if only_weak:
            # Even a high fused score built purely from formatting and
            # statistical evidence is a data-quality story, not an attack.
            verdict.tamper_class = TamperClass.BENIGN_ANOMALY
            verdict.class_confidence = 0.60
            verdict.rationale += (
                " Only formatting and statistical evidence was raised, so this is "
                "reported as a benign anomaly rather than tampering."
            )
            continue

        # --- provenance is decisive where it has coverage ---
        # The chain answers the question the evidence patterns can only guess
        # at. "Was this record ever committed?" separates editing from
        # insertion outright:
        #
        #   committed, content now differs  -> the record existed and CHANGED
        #   never committed, inside the sealed window -> it was INSERTED
        #
        # Without this, every fabrication was labelled MODIFIED: a fabricated
        # record trips SPEED_INFEASIBLE and OFF_ROUTE_PORT at ~0.9, which
        # out-shouts the ~0.7 orphan signal that actually identifies it.
        hash_mismatch = any(
            str(i.code) == "RECORD_HASH_MISMATCH"
            and not i.details.get("inconclusive")
            for i in items
        )
        not_in_chain = any(str(i.code) == "RECORD_NOT_IN_CHAIN" for i in items)

        # Which side of a duplicate pair is this? Arbitration already decided
        # which record the rest of the manifest supports, so reuse that answer
        # instead of guessing again: the *blamed* record is the copy, the
        # *exonerated* one is the original that was copied.
        duplicate_items = [i for i in items if str(i.code) in _DUPLICATE_CODES]
        duplicate_exonerated = bool(duplicate_items) and all(
            i.details.get("arbitration", {}).get("outcome") == "exonerated"
            for i in duplicate_items
        )
        orphan_items = [i for i in items if str(i.code) == "ORPHAN_RECORD"]
        orphaned = max([i.severity for i in orphan_items], default=0.0)
        # An orphan that occupies a port call *no other record of its container
        # shares* describes an event that never happened. An orphan that does
        # share a slot was one of the container's real events with something
        # rewritten. Both lose their port and route relationships, so this is
        # what tells a fabrication apart from a relocated record -- including
        # when the fabrication squats on a recycled, already-committed id and
        # the chain can only report a hash mismatch.
        invented_slot = bool(orphan_items) and all(
            i.details.get("shares_time_slot") is False for i in orphan_items
        )

        scores: dict[TamperClass, float] = {}
        decisive: str | None = None

        if duplicate_items and not duplicate_exonerated:
            # Another record says the same thing and this is the copy. A more
            # specific claim than "content differs from its commitment", and it
            # holds even when the copy landed on a recycled, committed id.
            scores[TamperClass.DUPLICATED] = max(duplicate, 0.85)
            decisive = "the copy in a duplicate pair, by corroboration"
        elif invented_slot and orphaned >= fabricated_min:
            # Checked before the hash comparison on purpose: an inserted row
            # may have been given an id freed by a deletion, in which case the
            # chain holds a commitment for that id and reports a mismatch. The
            # mismatch is real but describes the id, not this record.
            scores[TamperClass.FABRICATED] = max(orphaned * 1.25, 0.86)
            decisive = (
                "an orphan occupying a port call its container never had, so the "
                "event was invented rather than edited"
            )
        elif hash_mismatch:
            # Committed, so it existed; content now differs, so it changed.
            scores[TamperClass.MODIFIED] = max(modification, 0.90)
            decisive = "committed to the chain, but its content has since changed"
        elif not_in_chain:
            scores[TamperClass.FABRICATED] = max(fabrication, 0.85)
            decisive = (
                "never committed to the chain despite falling inside the sealed window"
            )
        elif orphaned >= fabricated_min:
            # No chain coverage, so fall back to lineage. ORPHAN_RECORD means
            # two or more independent relationships failed -- nothing in the
            # manifest or the world model accounts for the claim. That outranks
            # any value contradiction: a record that was never real cannot
            # meaningfully be said to have had its values edited. Without this,
            # fabrications in the uncommitted tail were labelled MODIFIED,
            # because a fabricated record trips SPEED_INFEASIBLE at ~0.9 while
            # the orphan signal that actually identifies it sits near 0.7.
            scores[TamperClass.FABRICATED] = max(orphaned * 1.25, 0.80)
            decisive = "an orphan with no lineage anywhere in the manifest"

        # A decisive rule *wins*; it does not merely add a score. Letting the
        # pattern scores below compete with it was a real defect: a fabricated
        # record carries FUTURE_EVENT at 0.92, which outvoted the FABRICATED
        # score of 0.85 and relabelled it MODIFIED. The provenance and lineage
        # answers are categorically better evidence about *which kind* of
        # tampering occurred than the loudest severity happens to be.
        if decisive:
            best = next(iter(scores))
            verdict.tamper_class = best
            verdict.class_confidence = round(min(0.97, scores[best]), 4)
            verdict.rationale += (
                f" Classified {best}: the record is {decisive}, which settles the "
                f"question of what kind of tampering this is independently of how "
                f"loud the other findings are."
            )
            continue

        # --- evidence patterns, for records no decisive rule covered ---
        if duplicate > 0:
            scores[TamperClass.DUPLICATED] = duplicate * 1.15
        if fabrication >= fabricated_min:
            # Lineage absence outranks value contradiction: a record that was
            # never real cannot meaningfully be said to have been edited.
            scores[TamperClass.FABRICATED] = fabrication * 1.10
        if modification > 0:
            scores[TamperClass.MODIFIED] = modification
        if deletion >= deleted_min:
            scores[TamperClass.DELETED] = deletion

        if not scores:
            verdict.tamper_class = TamperClass.BENIGN_ANOMALY
            verdict.class_confidence = 0.5
            continue

        best = max(scores, key=lambda k: scores[k])
        runner_up = sorted(scores.values(), reverse=True)
        margin = (
            runner_up[0] - runner_up[1] if len(runner_up) > 1 else runner_up[0]
        )

        verdict.tamper_class = best
        # Confidence in the *label* blends how strongly its signature fired
        # with how clearly it beat the alternatives.
        verdict.class_confidence = round(
            min(0.99, 0.55 * min(1.0, scores[best]) + 0.45 * min(1.0, margin + 0.35)), 4
        )
        verdict.rationale += (
            f" Classified {best} on the strength of its evidence signature "
            f"({scores[best]:.2f})"
            + (
                f", ahead of {sorted(scores, key=lambda k: scores[k], reverse=True)[1]} "
                f"by {margin:.2f}."
                if len(scores) > 1
                else "."
            )
        )

    return verdicts

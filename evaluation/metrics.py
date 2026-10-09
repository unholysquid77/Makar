"""Scoring the system against the private injection log (spec 31).

Reported metrics:

* **Detection** — precision, recall, F1, false-positive rate, false-negative
  rate at the record level, plus the false-alarm rate broken out separately
  over *noise-only* records and *clean* records. That split matters: a flag on
  a scruffy-but-honest row is a different failure from a flag on a pristine
  one, and the problem statement cares about both.
* **Classification accuracy** — a confusion matrix over MODIFIED / DELETED /
  DUPLICATED / FABRICATED, computed only over records correctly detected,
  because labelling something we never flagged is not a classification
  question.
* **Repair accuracy** — for each REPAIRED record, whether the reconstructed
  value equals the pre-attack value in the answer key, field by field. This is
  the strictest metric in the suite and the one that actually tests
  reconstruction rather than detection.
* **Deletion / duplicate / fabrication accuracy** — scored per attack type,
  with deletions scored on the *inferred deletion slots* rather than on record
  labels, since a deleted record has no row to label.
* **Calibration** — reliability bins. A system that says 94% should be right
  about 94% of the time; without this, a confident-sounding probability is
  decoration.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from core.models import AnalysisResult
from core.types import Classification, TamperClass
from evaluation.ground_truth import GroundTruth

#: Fields whose repair we score. Bookkeeping fields are excluded: the system
#: is not expected to restore a hash it never had.
_SCORED_FIELDS: tuple[str, ...] = (
    "weight",
    "declared_value",
    "container_count",
    "owner",
    "cargo_type",
    "destination",
    "current_location",
    "port_id",
    "timestamp",
    "arrival_timestamp",
    "departure_timestamp",
    "latitude",
    "longitude",
)


@dataclass
class BinaryMetrics:
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        denominator = self.false_positives + self.true_negatives
        return self.false_positives / denominator if denominator else 0.0

    @property
    def false_negative_rate(self) -> float:
        denominator = self.false_negatives + self.true_positives
        return self.false_negatives / denominator if denominator else 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
        }


@dataclass
class EvaluationReport:
    seed: int | None = None
    run_id: str = ""
    total_records: int = 0
    detection: BinaryMetrics = field(default_factory=BinaryMetrics)
    #: False alarms split by what the record actually was.
    false_alarms: dict[str, int] = field(default_factory=dict)
    recall_by_attack: dict[str, dict[str, Any]] = field(default_factory=dict)
    classification: dict[str, Any] = field(default_factory=dict)
    repair: dict[str, Any] = field(default_factory=dict)
    deletions: dict[str, Any] = field(default_factory=dict)
    calibration: list[dict[str, Any]] = field(default_factory=list)
    disposition: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "run_id": self.run_id,
            "total_records": self.total_records,
            "detection": self.detection.as_dict(),
            "false_alarms": self.false_alarms,
            "recall_by_attack": self.recall_by_attack,
            "classification": self.classification,
            "repair": self.repair,
            "deletions": self.deletions,
            "calibration": self.calibration,
            "disposition": self.disposition,
            "notes": self.notes,
        }


def _values_equal(expected: Any, actual: Any) -> bool:
    """Compare a repaired value against the answer key tolerantly.

    Numbers are compared with a small relative tolerance (a repair derived
    from a neighbour's median may differ in the last digit); timestamps to the
    second; everything else exactly.
    """
    if expected is None or actual is None:
        return expected == actual
    if isinstance(expected, bool) or isinstance(actual, bool):
        return expected == actual
    if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
        if expected == 0:
            return abs(actual) < 1e-6
        return abs(float(expected) - float(actual)) / abs(float(expected)) <= 0.01
    expected_text, actual_text = str(expected), str(actual)
    if "T" in expected_text and "T" in actual_text:
        return expected_text[:19] == actual_text[:19]
    try:
        return abs(float(expected_text) - float(actual_text)) <= 1e-6
    except ValueError:
        return expected_text == actual_text


def evaluate(
    result: AnalysisResult,
    truth: GroundTruth,
    *,
    threshold: float = 0.5,
    label: str = "",
) -> EvaluationReport:
    """Score an analysis run against the answer key."""
    report = EvaluationReport(
        seed=result.seed, run_id=result.run_id, total_records=len(result.records)
    )
    if label:
        report.notes.append(label)

    present = {r.record_id for r in result.records}
    tampered = truth.tampered & present
    noise_only = truth.noise_only & present
    clean = present - tampered - noise_only

    flagged = {
        record_id
        for record_id, verdict in result.verdicts.items()
        if verdict.tampering_probability >= threshold
        and verdict.tamper_class
        not in (TamperClass.CLEAN, TamperClass.BENIGN_ANOMALY)
    }

    # --- detection ---
    report.detection.true_positives = len(flagged & tampered)
    report.detection.false_positives = len(flagged - tampered)
    report.detection.false_negatives = len(tampered - flagged)
    report.detection.true_negatives = len(present - flagged - tampered)
    report.false_alarms = {
        "on_noise_only_records": len(flagged & noise_only),
        "on_clean_records": len(flagged & clean),
        "noise_only_population": len(noise_only),
        "clean_population": len(clean),
        "noise_only_rate": round(len(flagged & noise_only) / max(1, len(noise_only)), 4),
        "clean_rate": round(len(flagged & clean) / max(1, len(clean)), 4),
    }

    # --- recall by attack class ---
    by_attack: dict[str, set[str]] = defaultdict(set)
    for record_id, attack in truth.attack_by_record.items():
        if record_id in present:
            by_attack[attack].add(record_id)
    for attack, ids in sorted(by_attack.items()):
        hit = len(ids & flagged)
        report.recall_by_attack[attack] = {
            "population": len(ids),
            "detected": hit,
            "recall": round(hit / max(1, len(ids)), 4),
        }

    # --- classification confusion matrix (over detected records only) ---
    matrix: dict[str, Counter] = defaultdict(Counter)
    correct = 0
    scored = 0
    for record_id in sorted(flagged & tampered):
        expected = truth.expected_class(record_id)
        predicted = result.verdicts[record_id].tamper_class
        if expected is None:
            continue
        scored += 1
        matrix[str(expected)][str(predicted)] += 1
        if expected == predicted:
            correct += 1
    report.classification = {
        "scored": scored,
        "correct": correct,
        "accuracy": round(correct / max(1, scored), 4),
        "confusion": {k: dict(v) for k, v in matrix.items()},
        "note": (
            "Computed over correctly detected records only: labelling a record "
            "we never flagged is not a classification question."
        ),
    }

    # --- repair accuracy ---
    repaired_ids = [
        rid
        for rid, recon in result.reconstructions.items()
        if recon.classification is Classification.REPAIRED
    ]
    field_total = field_correct = 0
    record_exact = 0
    record_scored = 0
    unverifiable = 0
    per_field: dict[str, dict[str, int]] = defaultdict(lambda: {"scored": 0, "correct": 0})

    for record_id in repaired_ids:
        recon = result.reconstructions[record_id]
        expected_before = truth.before_by_record.get(record_id)
        if not expected_before or not recon.reconstructed:
            unverifiable += 1
            continue
        changed = [
            f
            for f in _SCORED_FIELDS
            if f in expected_before and expected_before[f] is not None
        ]
        if not changed:
            unverifiable += 1
            continue
        record_scored += 1
        all_right = True
        for field_name in changed:
            expected = expected_before[field_name]
            actual = recon.reconstructed.get(field_name)
            field_total += 1
            per_field[field_name]["scored"] += 1
            if _values_equal(expected, actual):
                field_correct += 1
                per_field[field_name]["correct"] += 1
            else:
                all_right = False
        if all_right:
            record_exact += 1

    confidences = [
        result.reconstructions[r].confidence
        for r in repaired_ids
        if r in result.reconstructions
    ]
    report.repair = {
        "repaired_records": len(repaired_ids),
        "verifiable_records": record_scored,
        "unverifiable_records": unverifiable,
        "exact_record_matches": record_exact,
        "record_accuracy": round(record_exact / max(1, record_scored), 4),
        "fields_scored": field_total,
        "fields_correct": field_correct,
        "field_accuracy": round(field_correct / max(1, field_total), 4),
        "mean_repair_confidence": round(
            sum(confidences) / len(confidences), 4
        )
        if confidences
        else 0.0,
        "by_field": {
            k: {**v, "accuracy": round(v["correct"] / max(1, v["scored"]), 4)}
            for k, v in sorted(per_field.items())
        },
    }

    # --- deletion detection ---
    # Scored on slots (container, port, event) because a removed record has no
    # row to label. An inferred deletion matches if it names the same
    # container and port, and either the same missing event or none at all.
    expected_slots = {
        (c, p, e) for (c, p, e) in truth.deleted_slots if c is not None
    }
    expected_containers = {c for (c, _p, _e) in expected_slots}
    inferred = result.inferred_deletions

    matched_slots: set[tuple] = set()
    inferred_containers: set[str] = set()
    for entry in inferred:
        container = entry.get("container_id")
        port = entry.get("port_id")
        event = entry.get("missing_event")
        if container:
            inferred_containers.add(container)
        for slot in expected_slots:
            if slot[0] != container:
                continue
            if port and slot[1] and port != slot[1]:
                continue
            if event and event not in ("PORT_CALL", None) and slot[2] and event != slot[2]:
                continue
            matched_slots.add(slot)

    # Chain-sourced entries name an exact record id, which is a stronger claim.
    exact_ids = {
        entry["record_id"]
        for entry in inferred
        if entry.get("record_id") and entry.get("source") == "provenance"
    }
    report.deletions = {
        "injected": len(truth.deleted),
        "injected_slots": len(expected_slots),
        "injected_containers": len(expected_containers),
        "inferred_entries": len(inferred),
        "slots_matched": len(matched_slots),
        "slot_recall": round(len(matched_slots) / max(1, len(expected_slots)), 4),
        "containers_flagged": len(inferred_containers),
        "containers_correct": len(inferred_containers & expected_containers),
        "container_precision": round(
            len(inferred_containers & expected_containers) / max(1, len(inferred_containers)), 4
        ),
        "container_recall": round(
            len(inferred_containers & expected_containers) / max(1, len(expected_containers)), 4
        ),
        "exact_record_ids_identified": len(exact_ids & truth.deleted),
        "exact_record_ids_claimed": len(exact_ids),
    }

    # --- calibration ---
    bins = [(i / 10, (i + 1) / 10) for i in range(10)]
    for low, high in bins:
        members = [
            rid
            for rid, verdict in result.verdicts.items()
            if low <= verdict.tampering_probability < high or (high == 1.0 and verdict.tampering_probability == 1.0)
        ]
        if not members:
            continue
        actual = sum(1 for rid in members if rid in tampered)
        mean_predicted = sum(
            result.verdicts[rid].tampering_probability for rid in members
        ) / len(members)
        report.calibration.append(
            {
                "bin": f"{low:.1f}-{high:.1f}",
                "count": len(members),
                "mean_predicted": round(mean_predicted, 4),
                "observed_rate": round(actual / len(members), 4),
                "gap": round(actual / len(members) - mean_predicted, 4),
            }
        )

    report.disposition = {
        "ORIGINAL": result.summary.original,
        "REPAIRED": result.summary.repaired,
        "REMOVED": result.summary.removed,
        "UNRECOVERABLE": result.summary.unrecoverable,
    }
    return report

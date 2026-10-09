"""Reading and indexing the private answer key.

The injection log records every act of tampering *and* every act of benign
noise. Both matter for scoring: the first gives recall, the second gives the
false-alarm rate that the problem statement weighs just as heavily, since a
wrongly flagged record is a legitimate shipment held up at a port.

One subtlety handled explicitly: a record can be both tampered with *and*
noisy, because noise is injected blind at the row layer. Those records count
as tampered. Only records with noise and no tampering are "noise-only", and
flagging one of those is a false alarm.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.io import read_json
from core.types import AttackClass, TamperClass
from generator.corruption import InjectionEntry, InjectionLog

#: Ground-truth attack class -> the label the classifier should produce.
ATTACK_TO_TAMPER: dict[str, TamperClass] = {
    str(AttackClass.MODIFIED): TamperClass.MODIFIED,
    str(AttackClass.DELETED): TamperClass.DELETED,
    str(AttackClass.DUPLICATED): TamperClass.DUPLICATED,
    str(AttackClass.FABRICATED): TamperClass.FABRICATED,
}


@dataclass
class GroundTruth:
    log: InjectionLog
    #: record id -> the attack class applied to it (tampering only)
    attack_by_record: dict[str, str] = field(default_factory=dict)
    #: record ids that were maliciously touched and still exist
    tampered: set[str] = field(default_factory=set)
    #: record ids touched only by benign noise
    noise_only: set[str] = field(default_factory=set)
    #: ids of records that were removed entirely
    deleted: set[str] = field(default_factory=set)
    #: container ids that lost at least one record
    deleted_containers: set[str] = field(default_factory=set)
    #: (container_id, port_id, event_type) of each removed record
    deleted_slots: set[tuple[str | None, str | None, str | None]] = field(
        default_factory=set
    )
    #: record id -> field -> value before the attack
    before_by_record: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: cluster id -> record ids, for coordinated-attack scoring
    clusters: dict[str, list[str]] = field(default_factory=dict)

    def entries_for(self, record_id: str) -> list[InjectionEntry]:
        return [e for e in self.log.entries if e.record_id == record_id]

    def expected_class(self, record_id: str) -> TamperClass | None:
        attack = self.attack_by_record.get(record_id)
        return ATTACK_TO_TAMPER.get(attack) if attack else None


def load_ground_truth(path: str | Path) -> GroundTruth:
    """Load and index the injection log."""
    log = InjectionLog.model_validate(read_json(path))
    truth = GroundTruth(log=log)

    noisy: set[str] = set()
    for entry in log.entries:
        klass = str(entry.attack_class)

        if klass == str(AttackClass.NOISE):
            if entry.record_id:
                noisy.add(entry.record_id)
            continue

        if entry.deleted_record_id:
            truth.deleted.add(entry.deleted_record_id)
            before = entry.before or {}
            truth.deleted_containers.add(before.get("container_id"))
            truth.deleted_slots.add(
                (
                    before.get("container_id"),
                    before.get("port_id"),
                    before.get("event_type"),
                )
            )

        if entry.record_id:
            truth.tampered.add(entry.record_id)
            # A record hit twice (compound attacks) keeps the first label; the
            # compound names in the log preserve the full story.
            truth.attack_by_record.setdefault(entry.record_id, klass)
            if entry.before:
                merged = truth.before_by_record.setdefault(entry.record_id, {})
                for key, value in entry.before.items():
                    merged.setdefault(key, value)

        if entry.cluster_id and entry.record_id:
            truth.clusters.setdefault(entry.cluster_id, []).append(entry.record_id)

    truth.deleted_containers.discard(None)
    # Noise on a tampered record does not make it innocent.
    truth.noise_only = noisy - truth.tampered
    return truth

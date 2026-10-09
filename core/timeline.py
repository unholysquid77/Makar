"""Attack timeline engine (spec 25).

Suspicious records are bucketed by event time, contiguous busy buckets are
merged into windows, and each window is described by the entities it
disproportionately touches and the order its tampering classes appear in.

**What "time" means here.** The manifest does not record *when the attacker
acted* -- a real tampered database rarely preserves that, and assuming an
audit column survived would be convenient rather than realistic. What it does
record is *which cargo events* were targeted. So a window is a region of
cargo-event time where tampering concentrates, which is also the actionable
form: it tells an investigator which voyages, ports and owners to re-verify.

**Affected entities are reported by lift, not by count.** The busiest port in
the window is usually just the busiest port overall. A window is characterised
by entities whose share of *suspicious* records exceeds their share of *all*
records in that window, which is what makes "primary affected: PORT_SIN" a
claim rather than a restatement of traffic volume.

Spec 25 is explicit that the result is a hypothesis with confidence, never a
fact, and the narrative is phrased accordingly.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta

from core.detection.base import AnalysisContext
from core.models import AttackWindow, ManifestRecord, RecordVerdict, TimelineBucket
from core.types import TamperClass

#: Entity must exceed this share of a window's suspicious records, and beat
#: its own baseline share, before it is named.
_MIN_SHARE = 0.12
_MIN_LIFT = 1.4


def _bucket_start(when: datetime, minutes: int, origin: datetime) -> datetime:
    offset = int((when - origin).total_seconds() // (minutes * 60))
    return origin + timedelta(minutes=minutes * offset)


def _entity_lift(
    suspicious: list[ManifestRecord],
    population: list[ManifestRecord],
    key,
) -> list[tuple[str, float, float]]:
    """Entities over-represented among ``suspicious`` relative to ``population``."""
    sus_counts = Counter(k for k in (key(r) for r in suspicious) if k)
    pop_counts = Counter(k for k in (key(r) for r in population) if k)
    total_sus = sum(sus_counts.values())
    total_pop = sum(pop_counts.values())
    if not total_sus or not total_pop:
        return []

    out: list[tuple[str, float, float]] = []
    for entity, count in sus_counts.items():
        share = count / total_sus
        baseline = pop_counts.get(entity, 0) / total_pop
        lift = (share / baseline) if baseline > 0 else float("inf")
        if share >= _MIN_SHARE and lift >= _MIN_LIFT:
            out.append((entity, round(share, 3), round(min(lift, 99.0), 2)))
    return sorted(out, key=lambda t: -t[1])


def build_attack_timeline(
    ctx: AnalysisContext, verdicts: dict[str, RecordVerdict]
) -> list[AttackWindow]:
    """Group suspicious records into inferred attack windows."""
    cfg = ctx.cfg
    bucket_minutes = cfg.int_("timeline.bucket_minutes")
    min_cluster = cfg.int_("timeline.min_cluster_size")
    gap_tolerance = timedelta(minutes=cfg.float_("timeline.gap_tolerance_minutes"))
    threshold = cfg.float_("fusion.thresholds.suspicious")

    suspicious: list[tuple[datetime, ManifestRecord, RecordVerdict]] = []
    for rec in ctx.records:
        verdict = verdicts.get(rec.record_id)
        if verdict is None or verdict.tampering_probability < threshold:
            continue
        if verdict.tamper_class in (TamperClass.CLEAN, TamperClass.BENIGN_ANOMALY):
            continue
        when = rec.effective_time()
        if when is None:
            continue
        suspicious.append((when, rec, verdict))

    if not suspicious:
        return []

    suspicious.sort(key=lambda t: t[0])
    origin = suspicious[0][0].replace(second=0, microsecond=0)

    buckets: dict[datetime, TimelineBucket] = {}
    bucket_records: dict[datetime, list[ManifestRecord]] = defaultdict(list)
    for when, rec, verdict in suspicious:
        start = _bucket_start(when, bucket_minutes, origin)
        bucket = buckets.get(start)
        if bucket is None:
            bucket = TimelineBucket(
                start=start, end=start + timedelta(minutes=bucket_minutes)
            )
            buckets[start] = bucket
        bucket.total += 1
        bucket.by_class[verdict.tamper_class] = (
            bucket.by_class.get(verdict.tamper_class, 0) + 1
        )
        bucket.record_ids.append(rec.record_id)
        bucket_records[start].append(rec)

    # --- merge contiguous buckets into windows ---
    ordered = sorted(buckets.values(), key=lambda b: b.start)
    groups: list[list[TimelineBucket]] = []
    current: list[TimelineBucket] = []
    for bucket in ordered:
        if not current:
            current = [bucket]
            continue
        if bucket.start - current[-1].end <= gap_tolerance:
            current.append(bucket)
        else:
            groups.append(current)
            current = [bucket]
    if current:
        groups.append(current)

    population = ctx.records
    windows: list[AttackWindow] = []

    for index, group in enumerate(groups, start=1):
        record_count = sum(b.total for b in group)
        if record_count < min_cluster:
            continue

        start, end = group[0].start, group[-1].end
        window_records = [r for b in group for r in bucket_records[b.start]]
        # Baseline is the records that exist in the same time span, so lift
        # compares against the traffic actually flowing then.
        in_span = [
            r
            for r in population
            if r.effective_time() is not None and start <= r.effective_time() <= end
        ] or population

        ports = _entity_lift(window_records, in_span, lambda r: r.port_id)
        owners = _entity_lift(window_records, in_span, lambda r: r.owner)
        vessels = _entity_lift(window_records, in_span, lambda r: r.vessel_id)

        # Phase ordering: when each class first appears, by median event time.
        first_seen: dict[TamperClass, list[datetime]] = defaultdict(list)
        for bucket in group:
            for klass, count in bucket.by_class.items():
                if count:
                    first_seen[klass].append(bucket.start)
        sequence = [
            klass for klass, times in sorted(first_seen.items(), key=lambda kv: min(kv[1]))
        ]

        class_totals = Counter()
        for bucket in group:
            class_totals.update(bucket.by_class)

        span_hours = max(0.01, (end - start).total_seconds() / 3600.0)
        density = record_count / span_hours
        # Confidence in the window being a coordinated episode rather than a
        # coincidence: driven by how concentrated it is and how many records
        # it covers, both capped so nothing reads as certainty.
        confidence = min(
            0.92,
            0.30
            + min(0.35, record_count / 60.0)
            + min(0.27, density / 12.0),
        )

        phases = " -> ".join(str(k) for k in sequence) if sequence else "none"
        affected_bits: list[str] = []
        if ports:
            affected_bits.append(
                "ports "
                + ", ".join(
                    f"{port} ({share:.0%} of window, {lift}x lift)"
                    for port, share, lift in ports[:3]
                )
            )
        if owners:
            affected_bits.append("owners " + ", ".join(owner for owner, _share, _lift in owners[:3]))
        if vessels:
            affected_bits.append("vessels " + ", ".join(vessel for vessel, _share, _lift in vessels[:3]))

        narrative = (
            f"Hypothesis: a coordinated episode between {start.isoformat()} and "
            f"{end.isoformat()} ({span_hours:.1f}h) affecting {record_count} "
            f"records at {density:.1f} records/hour. Composition: "
            + ", ".join(f"{count} {klass}" for klass, count in class_totals.most_common())
            + f". Apparent phase order: {phases}."
            + (f" Concentrated on {'; '.join(affected_bits)}." if affected_bits else "")
            + f" Confidence {confidence:.0%} -- this is an inference from the "
            f"distribution of suspicious records in cargo-event time, not an "
            f"observed intrusion log."
        )

        windows.append(
            AttackWindow(
                window_id=f"WINDOW_{index:02d}",
                start=start,
                end=end,
                buckets=group,
                record_count=record_count,
                affected_ports=[p for p, _s, _l in ports],
                affected_owners=[o for o, _s, _l in owners],
                affected_vessels=[v for v, _s, _l in vessels],
                likely_sequence=sequence,
                confidence=round(confidence, 3),
                narrative=narrative,
            )
        )

    windows.sort(key=lambda w: w.record_count, reverse=True)
    return windows


__all__ = ["build_attack_timeline"]

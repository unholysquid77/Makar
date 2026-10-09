"""Evidence fusion and confidence scoring (spec 17).

The model is additive in **log-odds**, which is the only formulation that
makes the spec's required breakdown honest::

    94.2% TAMPERING PROBABILITY
    +23  Impossible route transition
    +19  Temporal contradiction
    ...
    -05  Benign formatting anomaly

Each evidence type contributes a signed number of log-odds; the integer
"points" the UI shows are those log-odds rescaled, so the lines genuinely sum
to the result rather than being a decorative ranking.

Three mechanisms keep it from becoming naive-Bayes overconfidence, which is
the standard failure of this approach:

**Within-type discounting.** Several findings of the same type are combined
as a geometrically discounted sum (``fusion.saturation``), not added. Six
mediocre statistical outliers cannot impersonate one hard violation, and a
detector that happens to emit the same finding twice gains almost nothing.

**Across-type discounting.** The same discount applies again across types,
ranked strongest first. Independent layers do corroborate each other, but
they are not *fully* independent -- an impossible transit and an off-route
port often describe one edit -- so the second and third opinions are worth
progressively less than the first.

**Per-code multipliers.** ``fusion.code_multipliers`` down-weights individual
findings independently of their type. ``DWELL_TIME_ANOMALY`` is genuinely
``TEMPORAL``, but spec 9.5 is explicit that a long dwell is *anomalous, not
automatically malicious*. Relabelling its type to dodge the temporal weight
would be dishonest; a multiplier says "real temporal observation, weak
evidence of intent" without lying about which layer saw it.

Weights live entirely in ``configs/*.yaml`` and are calibrated against a
tuning seed, then reported on a different seed (see the evaluation console).
"""

from __future__ import annotations

import math

from core.config import MakarConfig
from core.models import Evidence, EvidenceContribution, RecordVerdict
from core.types import EVIDENCE_LABEL, EvidenceType, TamperClass

#: Log-odds are rendered as integer "points" for display. 10 points per unit
#: of log-odds keeps typical contributions in the +05..+25 range the spec
#: illustrates.
POINTS_PER_LOG_ODDS = 10.0

#: Ceiling on one layer's aggregated severity. Above 1.0 so that several
#: *distinct* violations within one layer can outweigh a single one, while
#: still bounding how far any single layer can push the result on its own.
_TYPE_CAP = 1.30


def _logit(p: float) -> float:
    p = min(max(p, 1e-6), 1 - 1e-6)
    return math.log(p / (1 - p))


def _sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-min(x, 60.0)))
    exp_x = math.exp(max(x, -60.0))
    return exp_x / (1.0 + exp_x)


def _discounted_sum(values: list[float], saturation: float, cap: float | None = None) -> float:
    """Geometrically discounted sum of ``values``, largest first.

    With ``saturation = 0.75`` the strongest value counts fully, the next at
    75%, the next at 56%, and so on. This is the "diminishing returns" the
    config names: it rewards corroboration without letting volume win.
    """
    total = 0.0
    for rank, value in enumerate(sorted(values, reverse=True)):
        total += value * (saturation**rank)
    if cap is not None:
        total = min(total, cap)
    return total


def fuse(
    cfg: MakarConfig,
    evidence_by_record: dict[str, list[Evidence]],
    *,
    record_ids: list[str] | None = None,
) -> dict[str, RecordVerdict]:
    """Fuse evidence into a calibrated verdict per record.

    ``record_ids`` lets callers include records with *no* evidence, which
    should receive an explicit clean verdict rather than being absent.
    """
    weights: dict[str, float] = {
        str(k): float(v) for k, v in (cfg.get("fusion.weights", {}) or {}).items()
    }
    multipliers: dict[str, float] = {
        str(k): float(v) for k, v in (cfg.get("fusion.code_multipliers", {}) or {}).items()
    }
    decisive: dict[str, dict] = {
        str(k): dict(v) for k, v in (cfg.get("fusion.decisive_floors", {}) or {}).items()
    }
    prior = cfg.float_("fusion.prior_tampering_rate")
    saturation = cfg.float_("fusion.saturation")
    base_logit = _logit(prior)

    ids = record_ids if record_ids is not None else list(evidence_by_record)
    verdicts: dict[str, RecordVerdict] = {}

    for record_id in ids:
        items = evidence_by_record.get(record_id, [])
        verdict = RecordVerdict(record_id=record_id)

        if not items:
            verdict.tampering_probability = round(_sigmoid(base_logit), 4)
            verdict.anomaly_score = 0.0
            verdict.tamper_class = TamperClass.CLEAN
            verdict.rationale = (
                "No detector raised evidence against this record; it is consistent "
                "with the manifest, the world model and the provenance chain."
            )
            verdicts[record_id] = verdict
            continue

        # --- group by type, applying per-code multipliers ---
        by_type: dict[str, list[tuple[Evidence, float]]] = {}
        for item in items:
            code = str(item.code)
            effective = item.severity * multipliers.get(code, 1.0)
            if effective <= 0.0:
                continue
            by_type.setdefault(str(item.type), []).append((item, effective))

        type_scores: dict[EvidenceType, float] = {}
        type_logodds: dict[str, float] = {}

        for type_name, entries in by_type.items():
            severities = [sev for _item, sev in entries]
            # The per-layer score shown in the investigation panel is the
            # strongest finding of that layer, which is what an analyst means
            # by "Temporal 0.91".
            type_scores[EvidenceType(type_name)] = round(max(severities), 4)

            # Aggregate by *code*, not by raw count. Repeated instances of one
            # code are redundant -- two SPEED_INFEASIBLE findings on the same
            # leg describe one violation -- so only the strongest is kept. But
            # distinct codes within a layer are independent constraints and
            # genuinely corroborate: an unexplained weight change and a cargo
            # type change are both CARGO, and treating them as one finding
            # caused a 98% unexplained weight jump plus a cargo substitution to
            # score the same as either alone.
            per_code: dict[str, float] = {}
            for item, severity in entries:
                code = str(item.code)
                per_code[code] = max(per_code.get(code, 0.0), severity)

            aggregated = _discounted_sum(
                list(per_code.values()), saturation, cap=_TYPE_CAP
            )
            type_logodds[type_name] = weights.get(type_name, 0.0) * aggregated

        # --- across-type discounting, strongest magnitude first ---
        positives = [v for v in type_logodds.values() if v > 0]
        negatives = [v for v in type_logodds.values() if v < 0]
        positive_total = _discounted_sum(positives, saturation)
        # Negative (exculpatory) evidence is not discounted: a tidy record
        # should not accumulate unbounded innocence either, but FORMAT is the
        # only negative layer and it is already small.
        negative_total = sum(negatives)

        total_logit = base_logit + positive_total + negative_total
        probability = _sigmoid(total_logit)

        # --- decisive evidence overrides the score ---
        # A physical or logical impossibility is not a matter of degree. Where
        # one is present above its configured severity, the probability is
        # floored: the deterministic finding settles the question and the
        # log-odds arithmetic only refines it upward from there.
        decisive_note: str | None = None
        for item in items:
            rule = decisive.get(str(item.code))
            if not rule:
                continue
            if str(item.code) == "RECORD_HASH_MISMATCH" and item.details.get(
                "inconclusive"
            ):
                # The mismatch is explained by a field lost in the export, so
                # it proves nothing. Never decisive.
                continue
            if item.severity < float(rule.get("min_severity", 1.0)):
                continue
            floor = float(rule.get("floor", 0.0))
            if floor > probability:
                probability = floor
                decisive_note = (
                    f"Probability floored at {floor:.0%} by deterministic evidence "
                    f"({EVIDENCE_LABEL.get(str(item.code), str(item.code)).lower()}, "
                    f"severity {item.severity:.2f}), which does not require "
                    f"corroboration to be conclusive."
                )

        # --- auditable breakdown ---
        contributions: list[EvidenceContribution] = []
        # Rank positives by magnitude so each line can be shown with exactly
        # the discount the total applied to it -- the breakdown then sums to
        # the result instead of merely ranking alongside it.
        positive_order = sorted(positives, reverse=True)

        for type_name, raw in sorted(
            type_logodds.items(), key=lambda kv: abs(kv[1]), reverse=True
        ):
            shown = raw * (saturation ** positive_order.index(raw)) if raw > 0 else raw
            item, effective = max(by_type[type_name], key=lambda pair: pair[1])
            contributions.append(
                EvidenceContribution(
                    code=item.code,
                    type=EvidenceType(type_name),
                    label=EVIDENCE_LABEL.get(str(item.code), str(item.code)),
                    severity=round(effective, 4),
                    log_odds=round(shown, 4),
                    points=int(round(shown * POINTS_PER_LOG_ODDS)),
                )
            )
        contributions.sort(key=lambda c: c.points, reverse=True)

        verdict.type_scores = type_scores
        verdict.anomaly_score = round(max(type_scores.values()), 4)
        verdict.tampering_probability = round(probability, 4)
        verdict.contributions = contributions
        verdict.rationale = _rationale(probability, contributions, prior)
        if decisive_note:
            verdict.rationale += " " + decisive_note
        verdicts[record_id] = verdict

    return verdicts


def _rationale(
    probability: float, contributions: list[EvidenceContribution], prior: float
) -> str:
    """One-paragraph deterministic explanation. No LLM involved."""
    if not contributions:
        return "No evidence was raised against this record."

    drivers = [c for c in contributions if c.points > 0][:3]
    mitigators = [c for c in contributions if c.points < 0]

    parts = [
        f"Fused tampering probability {probability:.1%}, from a base rate of "
        f"{prior:.1%}."
    ]
    if drivers:
        listed = "; ".join(
            f"{c.label.lower()} ({c.type}, severity {c.severity:.2f}, "
            f"{c.points:+d} points)"
            for c in drivers
        )
        parts.append(f"Driven by {listed}.")
    if mitigators:
        listed = "; ".join(f"{c.label.lower()} ({c.points:+d})" for c in mitigators)
        parts.append(
            f"Partially offset by evidence of benign data-quality problems: {listed}."
        )
    if len(contributions) > len(drivers):
        parts.append(
            f"{len(contributions)} independent evidence layers contributed in total."
        )
    return " ".join(parts)

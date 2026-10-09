"""Robust statistics helpers.

The problem statement is explicit that there is no labelled ground truth, so
the system has to work out what "normal" looks like from the manifest itself.
The manifest is also the thing that has been tampered with -- which means any
baseline computed with a mean and a standard deviation is being computed from
contaminated data, and a handful of inflated weights will drag the mean far
enough to hide the rest.

Everything here is therefore median/MAD based. A breakdown point of 50% means
the baseline survives contamination up to half the sample, which is far
beyond any plausible attack rate.
"""

from __future__ import annotations

import math
from collections.abc import Sequence

#: Scale factor making MAD a consistent estimator of sigma for normal data.
MAD_TO_SIGMA = 1.4826


def median(values: Sequence[float]) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def mad(values: Sequence[float], center: float | None = None) -> float:
    """Median absolute deviation."""
    if not values:
        return float("nan")
    mid = median(values) if center is None else center
    return median([abs(v - mid) for v in values])


def robust_sigma(values: Sequence[float], center: float | None = None) -> float:
    """MAD rescaled to a sigma estimate; falls back to IQR then stdev.

    A MAD of zero happens whenever more than half the sample shares one value
    (common for ``container_count``). Falling through to the IQR, and then to
    the standard deviation, avoids reporting every non-modal value as an
    infinitely extreme outlier.
    """
    if not values:
        return float("nan")
    mid = median(values) if center is None else center
    scale = mad(values, mid) * MAD_TO_SIGMA
    if scale > 1e-9:
        return scale

    lo, hi = quantiles(values, 0.25, 0.75)
    iqr_scale = (hi - lo) / 1.349
    if iqr_scale > 1e-9:
        return iqr_scale

    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    variance = sum((v - mean) ** 2 for v in values) / (n - 1)
    return math.sqrt(variance)


def quantiles(values: Sequence[float], *fractions: float) -> list[float]:
    """Linear-interpolation quantiles."""
    if not values:
        return [float("nan")] * len(fractions)
    ordered = sorted(values)
    out: list[float] = []
    for frac in fractions:
        if len(ordered) == 1:
            out.append(float(ordered[0]))
            continue
        pos = max(0.0, min(1.0, frac)) * (len(ordered) - 1)
        lo = int(math.floor(pos))
        hi = int(math.ceil(pos))
        if lo == hi:
            out.append(float(ordered[lo]))
        else:
            weight = pos - lo
            out.append(ordered[lo] * (1 - weight) + ordered[hi] * weight)
    return out


def robust_z(value: float, values: Sequence[float]) -> float:
    """Robust z-score of ``value`` against ``values``.

    Returns 0.0 when no usable scale can be estimated, which is the honest
    answer: with no spread there is no basis for calling anything an outlier.
    """
    if not values:
        return 0.0
    center = median(values)
    scale = robust_sigma(values, center)
    if not scale or scale <= 1e-9 or math.isnan(scale):
        return 0.0
    return (value - center) / scale


def iqr_bounds(values: Sequence[float], multiplier: float = 1.5) -> tuple[float, float]:
    """Tukey fences."""
    if not values:
        return (float("nan"), float("nan"))
    q1, q3 = quantiles(values, 0.25, 0.75)
    span = q3 - q1
    return (q1 - multiplier * span, q3 + multiplier * span)


def severity_from_ratio(ratio: float, soft: float, hard: float, ceiling: float = 1.0) -> float:
    """Map a violation ratio onto a severity in ``[0, ceiling]``.

    ``soft`` is where severity starts rising from zero and ``hard`` is where
    it saturates. A linear ramp between two configured points keeps severity
    auditable: a judge can check the arithmetic by hand, which a logistic
    curve with fitted parameters would not allow.
    """
    if ratio <= soft:
        return 0.0
    if hard <= soft:
        return ceiling
    fraction = (ratio - soft) / (hard - soft)
    return float(max(0.0, min(ceiling, fraction * ceiling)))


def severity_from_z(z: float, threshold: float, saturate_at: float = 3.0, ceiling: float = 1.0) -> float:
    """Severity from a robust z-score, zero below ``threshold``."""
    magnitude = abs(z)
    if magnitude <= threshold:
        return 0.0
    span = max(1e-9, saturate_at)
    fraction = (magnitude - threshold) / span
    return float(max(0.0, min(ceiling, fraction * ceiling)))

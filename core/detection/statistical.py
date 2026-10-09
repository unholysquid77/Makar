"""Statistical intelligence engine (spec 13).

Spec 13 is explicit that this layer *generates evidence* and must not
independently classify a record as tampered. Two mechanisms enforce that:
severities are capped by ``detection.statistical.max_severity`` (default
0.55, below the suspicion threshold), and the ``STATISTICAL`` fusion weight
is the lowest of any evidence-bearing layer. A record with nothing but
statistical evidence cannot cross the line on its own.

Methods, in the order they earn their keep:

**Peer-group robust z-score.** The single most useful one, and the reason the
generator bothers with cargo profiles. Weight and value are meaningless in
isolation — 27 tonnes is normal for cement and impossible for
pharmaceuticals — so every numeric field is compared against *other records of
the same cargo type*, with a pooled fallback for thin groups.

**Value-per-kilogram.** A derived invariant: within a cargo type, value
density is tight. An attacker who inflates a weight without touching the
declared value (or vice versa) leaves the ratio badly wrong even when both
fields individually look plausible. This catches edits that survive the
marginal checks.

**IQR fences.** A second, distribution-free opinion on the same fields.

**Isolation Forest / LOF / DBSCAN.** Multivariate opinions over the scaled
feature vector, which pick up combinations that no single field reveals.
These are the only fitted models in the system, they are unsupervised, and
nothing downstream depends on them being present — if scikit-learn were
unavailable the pipeline would simply lose one weak evidence source.
"""

from __future__ import annotations

from collections import defaultdict

import numpy as np

from core.detection.base import AnalysisContext, register_detector
from core.models import Evidence, ManifestRecord
from core.stats import iqr_bounds, median, robust_z, severity_from_z
from core.types import EVIDENCE_CODE_TYPE, EvidenceCode, EvidenceType

ENGINE = "statistical"

#: Minimum peer-group size before the group gets its own baseline.
_MIN_GROUP = 25


def _ev(
    record_id: str,
    code: EvidenceCode,
    severity: float,
    description: str,
    **details: object,
) -> Evidence:
    return Evidence(
        record_id=record_id,
        code=code,
        type=EvidenceType(EVIDENCE_CODE_TYPE[code]),
        severity=max(0.0, min(1.0, severity)),
        description=description,
        details=details,
        engine=ENGINE,
    )


class StatisticalEngine:
    name = "statistical"

    def run(self, ctx: AnalysisContext) -> list[Evidence]:
        out: list[Evidence] = []
        out.extend(self._peer_group_z(ctx))
        out.extend(self._value_density(ctx))
        out.extend(self._iqr(ctx))
        out.extend(self._multivariate(ctx))
        return [e for e in out if e.severity > 0.0]

    # -- peer-group robust z ----------------------------------------------

    def _peer_group_z(self, ctx: AnalysisContext) -> list[Evidence]:
        cfg = ctx.cfg
        fields = [str(f) for f in cfg.list_("detection.statistical.numeric_fields")]
        threshold = cfg.float_("detection.statistical.robust_z_threshold")
        ceiling = cfg.float_("detection.statistical.max_severity")

        out: list[Evidence] = []
        for field in fields:
            groups: dict[str, list[tuple[ManifestRecord, float]]] = defaultdict(list)
            for rec in ctx.records:
                value = getattr(rec, field, None)
                if value is None:
                    continue
                groups[rec.cargo_type or "__unknown__"].append((rec, float(value)))

            pooled = [v for members in groups.values() for _, v in members]
            if len(pooled) < 2:
                continue

            for cargo_type, members in groups.items():
                values = [v for _, v in members]
                if len(values) >= _MIN_GROUP:
                    basis, baseline = cargo_type, values
                else:
                    basis, baseline = "all cargo types (thin peer group)", pooled

                for rec, value in members:
                    z = robust_z(value, baseline)
                    severity = severity_from_z(z, threshold, saturate_at=8.0, ceiling=ceiling)
                    if severity <= 0.0:
                        continue
                    out.append(
                        _ev(
                            rec.record_id,
                            EvidenceCode.PEER_GROUP_OUTLIER
                            if basis == cargo_type
                            else EvidenceCode.ROBUST_Z_OUTLIER,
                            severity,
                            f"{field.replace('_', ' ').title()} of {value:,.1f} is "
                            f"{z:+.1f} robust standard deviations from the median "
                            f"of {median(baseline):,.1f} for {basis} "
                            f"(n={len(baseline)}).",
                            field=field,
                            value=value,
                            robust_z=round(z, 2),
                            peer_group=basis,
                            peer_median=round(median(baseline), 2),
                            sample_size=len(baseline),
                        )
                    )
        return out

    # -- value density ----------------------------------------------------

    def _value_density(self, ctx: AnalysisContext) -> list[Evidence]:
        """Declared value per kilogram, compared within cargo type.

        Catches the common case where one of weight/value was edited and the
        other was not, leaving each field individually plausible.
        """
        cfg = ctx.cfg
        threshold = cfg.float_("detection.statistical.robust_z_threshold")
        ceiling = cfg.float_("detection.statistical.max_severity")

        groups: dict[str, list[tuple[ManifestRecord, float]]] = defaultdict(list)
        for rec in ctx.records:
            if not rec.weight or not rec.declared_value or rec.weight <= 0:
                continue
            groups[rec.cargo_type or "__unknown__"].append(
                (rec, rec.declared_value / rec.weight)
            )

        pooled = [v for members in groups.values() for _, v in members]
        if len(pooled) < 2:
            return []

        out: list[Evidence] = []
        for cargo_type, members in groups.items():
            values = [v for _, v in members]
            baseline = values if len(values) >= _MIN_GROUP else pooled
            basis = cargo_type if len(values) >= _MIN_GROUP else "all cargo types"
            for rec, density in members:
                z = robust_z(density, baseline)
                severity = severity_from_z(z, threshold, saturate_at=8.0, ceiling=ceiling)
                if severity <= 0.0:
                    continue
                out.append(
                    _ev(
                        rec.record_id,
                        EvidenceCode.PEER_GROUP_OUTLIER,
                        severity,
                        f"Declared value density of {density:,.2f} per kg is "
                        f"{z:+.1f} robust standard deviations from the {basis} "
                        f"median of {median(baseline):,.2f} per kg; weight and "
                        f"declared value are inconsistent with each other.",
                        field="value_per_kg",
                        value=round(density, 4),
                        robust_z=round(z, 2),
                        peer_group=basis,
                        peer_median=round(median(baseline), 4),
                        weight=rec.weight,
                        declared_value=rec.declared_value,
                    )
                )
        return out

    # -- IQR fences -------------------------------------------------------

    def _iqr(self, ctx: AnalysisContext) -> list[Evidence]:
        cfg = ctx.cfg
        fields = [str(f) for f in cfg.list_("detection.statistical.numeric_fields")]
        multiplier = cfg.float_("detection.statistical.iqr_multiplier")
        ceiling = cfg.float_("detection.statistical.max_severity") * 0.7

        out: list[Evidence] = []
        for field in fields:
            groups: dict[str, list[tuple[ManifestRecord, float]]] = defaultdict(list)
            for rec in ctx.records:
                value = getattr(rec, field, None)
                if value is None:
                    continue
                groups[rec.cargo_type or "__unknown__"].append((rec, float(value)))

            for cargo_type, members in groups.items():
                values = [v for _, v in members]
                if len(values) < _MIN_GROUP:
                    continue
                low, high = iqr_bounds(values, multiplier)
                span = max(1e-9, high - low)
                for rec, value in members:
                    if low <= value <= high:
                        continue
                    excess = (low - value if value < low else value - high) / span
                    severity = min(ceiling, 0.18 + min(0.8, excess) * (ceiling - 0.18))
                    out.append(
                        _ev(
                            rec.record_id,
                            EvidenceCode.IQR_OUTLIER,
                            severity,
                            f"{field.replace('_', ' ').title()} of {value:,.1f} lies "
                            f"outside the {multiplier}x IQR fence "
                            f"[{low:,.1f}, {high:,.1f}] for {cargo_type}.",
                            field=field,
                            value=value,
                            fence_low=round(low, 2),
                            fence_high=round(high, 2),
                            cargo_type=cargo_type,
                        )
                    )
        return out

    # -- multivariate models ----------------------------------------------

    def _features(
        self, ctx: AnalysisContext
    ) -> tuple[list[ManifestRecord], np.ndarray, list[str]]:
        """Build the scaled feature matrix for the unsupervised models."""
        names = ["weight", "declared_value", "container_count", "value_per_kg", "dwell_hours"]
        records: list[ManifestRecord] = []
        rows: list[list[float]] = []

        for rec in ctx.records:
            if rec.weight is None or rec.declared_value is None:
                continue
            dwell = 0.0
            if rec.arrival_timestamp and rec.departure_timestamp:
                dwell = max(
                    0.0,
                    (rec.departure_timestamp - rec.arrival_timestamp).total_seconds() / 3600.0,
                )
            density = rec.declared_value / rec.weight if rec.weight > 0 else 0.0
            rows.append(
                [
                    float(rec.weight),
                    float(rec.declared_value),
                    float(rec.container_count or 0),
                    float(density),
                    dwell,
                ]
            )
            records.append(rec)

        if not rows:
            return [], np.empty((0, len(names))), names

        matrix = np.asarray(rows, dtype=float)
        # Robust scaling: median/MAD per column, for the same contamination
        # reason the univariate checks use robust statistics.
        centre = np.median(matrix, axis=0)
        spread = np.median(np.abs(matrix - centre), axis=0) * 1.4826
        spread[spread < 1e-9] = 1.0
        return records, (matrix - centre) / spread, names

    def _multivariate(self, ctx: AnalysisContext) -> list[Evidence]:
        try:
            from sklearn.cluster import DBSCAN
            from sklearn.ensemble import IsolationForest
            from sklearn.neighbors import LocalOutlierFactor
        except ImportError:  # pragma: no cover - optional dependency
            return []

        cfg = ctx.cfg
        ceiling = cfg.float_("detection.statistical.max_severity")
        records, features, names = self._features(ctx)
        if len(records) < 50:
            return []

        out: list[Evidence] = []

        # --- Isolation Forest ---
        contamination = cfg.float_("detection.statistical.isolation_forest_contamination")
        forest = IsolationForest(
            contamination=contamination,
            random_state=ctx.world.seed,
            n_estimators=200,
        )
        forest_labels = forest.fit_predict(features)
        forest_scores = forest.score_samples(features)
        # score_samples is negative, lower = more anomalous.
        worst = float(np.min(forest_scores))
        cut = float(np.percentile(forest_scores, contamination * 100))
        for rec, label, score in zip(records, forest_labels, forest_scores, strict=False):
            if label != -1:
                continue
            depth = (cut - score) / max(1e-9, cut - worst)
            out.append(
                _ev(
                    rec.record_id,
                    EvidenceCode.ISOLATION_FOREST_OUTLIER,
                    min(ceiling, 0.15 + depth * (ceiling - 0.15)),
                    f"Isolation Forest isolates this record from the bulk of the "
                    f"manifest on {', '.join(names)} (anomaly score {score:.3f}, "
                    f"cut-off {cut:.3f}).",
                    model="IsolationForest",
                    score=round(float(score), 4),
                    cutoff=round(cut, 4),
                    features=names,
                )
            )

        # --- Local Outlier Factor ---
        neighbors = min(cfg.int_("detection.statistical.lof_neighbors"), len(records) - 1)
        if neighbors >= 5:
            lof = LocalOutlierFactor(n_neighbors=neighbors, contamination=contamination)
            lof_labels = lof.fit_predict(features)
            lof_scores = lof.negative_outlier_factor_
            lof_cut = float(np.percentile(lof_scores, contamination * 100))
            lof_worst = float(np.min(lof_scores))
            for rec, label, score in zip(records, lof_labels, lof_scores, strict=False):
                if label != -1:
                    continue
                depth = (lof_cut - score) / max(1e-9, lof_cut - lof_worst)
                out.append(
                    _ev(
                        rec.record_id,
                        EvidenceCode.LOF_OUTLIER,
                        min(ceiling * 0.85, 0.12 + depth * (ceiling * 0.85 - 0.12)),
                        f"Local Outlier Factor finds this record in a far sparser "
                        f"neighbourhood than its {neighbors} nearest peers "
                        f"(factor {score:.3f}).",
                        model="LocalOutlierFactor",
                        score=round(float(score), 4),
                        n_neighbors=neighbors,
                        features=names,
                    )
                )

        # --- DBSCAN noise points ---
        dbscan = DBSCAN(
            eps=cfg.float_("detection.statistical.dbscan_eps"),
            min_samples=cfg.int_("detection.statistical.dbscan_min_samples"),
        )
        labels = dbscan.fit_predict(features)
        noise_count = int(np.sum(labels == -1))
        # If DBSCAN calls a large fraction noise, eps is simply mistuned for
        # this data and the result carries no information -- say nothing
        # rather than emit hundreds of weak findings that only serve to
        # saturate the fusion layer.
        if 0 < noise_count <= max(20, int(0.03 * len(records))):
            for rec, label in zip(records, labels, strict=False):
                if label != -1:
                    continue
                out.append(
                    _ev(
                        rec.record_id,
                        EvidenceCode.DBSCAN_NOISE,
                        ceiling * 0.5,
                        f"DBSCAN assigns this record to no cluster "
                        f"(eps={dbscan.eps}, min_samples={dbscan.min_samples}); "
                        f"{noise_count} of {len(records)} records are unclustered.",
                        model="DBSCAN",
                        noise_points=noise_count,
                        total=len(records),
                        features=names,
                    )
                )
        return out


register_detector(StatisticalEngine())

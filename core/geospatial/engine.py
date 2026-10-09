"""Geospatial feasibility engine (spec 10).

For each voyage leg the engine computes::

    distance      = sea_distance(port_a, port_b)      # nautical miles
    required      = distance / (arrival_b - departure_a)
    ratio         = required / vessel_max_speed

and emits ``SPEED_INFEASIBLE`` once the ratio passes the configured soft
threshold, with severity ramping to saturation at the hard threshold.

Two guards keep the false-alarm rate down, which matters because a wrongly
flagged record is a legitimate shipment held up:

* The straight-line distance is inflated by ``vessel.sea_route_factor``
  before dividing, since no ship sails a great circle through land. Under-
  estimating the distance would manufacture violations.
* The soft threshold sits slightly *above* 1.0 (default 1.05), so a vessel
  that merely made unusually good time is not accused of teleporting.

The engine also checks declared coordinates against the declared port. An
attacker who rewrites a location but forgets the coordinates -- or rewrites
the coordinates but forgets the port -- leaves exactly this inconsistency.
"""

from __future__ import annotations

from core.detection.base import AnalysisContext, register_detector
from core.detection.segments import container_port_calls
from core.geo import coords_valid, haversine_km, required_speed_knots, sea_distance_nm
from core.models import Evidence
from core.stats import severity_from_ratio
from core.types import EVIDENCE_CODE_TYPE, EvidenceCode, EvidenceType

ENGINE = "geospatial"

#: A record's own coordinates must sit within this many km of the port it
#: claims. Generous: ports sprawl, and anchorages sit offshore.
_PORT_COORD_TOLERANCE_KM = 75.0


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


class GeospatialEngine:
    name = "geospatial"

    def run(self, ctx: AnalysisContext) -> list[Evidence]:
        out: list[Evidence] = []
        out.extend(self._leg_feasibility(ctx))
        out.extend(self._coordinate_consistency(ctx))
        return [e for e in out if e.severity > 0.0]

    # -- speed feasibility ------------------------------------------------

    def _leg_feasibility(self, ctx: AnalysisContext) -> list[Evidence]:
        cfg = ctx.cfg
        soft = cfg.float_("detection.geospatial.speed_ratio_soft")
        hard = cfg.float_("detection.geospatial.speed_ratio_hard")
        min_elapsed = cfg.float_("detection.geospatial.min_elapsed_seconds")
        route_factor = cfg.float_("vessel.sea_route_factor")

        out: list[Evidence] = []
        for container_id, calls in container_port_calls(ctx).items():
            for previous, current in zip(calls, calls[1:], strict=False):
                if previous.port_id == current.port_id:
                    continue

                a = ctx.port_coords(previous.port_id)
                b = ctx.port_coords(current.port_id)
                if a is None or b is None:
                    continue

                start = previous.departure or previous.arrival
                end = current.arrival or current.departure
                if start is None or end is None:
                    continue

                elapsed = (end - start).total_seconds()
                if elapsed <= min_elapsed:
                    # Zero/negative elapsed time is a temporal contradiction
                    # and is reported by the temporal engine, not here.
                    continue

                distance_nm = sea_distance_nm(a, b, route_factor)
                required = required_speed_knots(distance_nm, elapsed)
                if required is None:
                    continue

                departure_record = previous.departure_record
                arrival_record = current.representative
                max_speed = max(
                    ctx.vessel_max_speed(arrival_record.vessel_id),
                    ctx.vessel_max_speed(departure_record.vessel_id),
                )
                ratio = required / max_speed if max_speed > 0 else 0.0
                severity = severity_from_ratio(ratio, soft, hard, ceiling=0.97)
                if severity <= 0.0:
                    continue

                from_name = ctx.world.ports[previous.port_id].name
                to_name = ctx.world.ports[current.port_id].name
                description = (
                    f"Container {container_id} covers {from_name} -> {to_name} "
                    f"({distance_nm:.0f} nm by sea) in {elapsed / 3600.0:.1f}h, "
                    f"requiring {required:.1f} knots against a vessel maximum of "
                    f"{max_speed:.1f} knots ({ratio:.2f}x)."
                )
                details = {
                    "container_id": container_id,
                    "from_port": previous.port_id,
                    "to_port": current.port_id,
                    "distance_nm": round(distance_nm, 1),
                    "elapsed_hours": round(elapsed / 3600.0, 2),
                    "required_speed_knots": round(required, 2),
                    "expected_max_knots": round(max_speed, 2),
                    "ratio": round(ratio, 3),
                    "feasible": False,
                }

                # Attribute to both ends of the leg: either record could be
                # the altered one, and the fusion layer should see both.
                out.append(
                    _ev(
                        arrival_record.record_id,
                        EvidenceCode.SPEED_INFEASIBLE,
                        severity,
                        description,
                        supporting=[departure_record.record_id],
                        **details,
                    )
                )
                out.append(
                    _ev(
                        departure_record.record_id,
                        EvidenceCode.SPEED_INFEASIBLE,
                        severity * 0.85,
                        description,
                        supporting=[arrival_record.record_id],
                        **details,
                    )
                )
        return out

    # -- coordinates vs declared port -------------------------------------

    def _coordinate_consistency(self, ctx: AnalysisContext) -> list[Evidence]:
        out: list[Evidence] = []
        for rec in ctx.records:
            if not coords_valid(rec.latitude, rec.longitude):
                continue
            port = ctx.world.ports.get(rec.port_id or "")
            if port is None:
                continue
            distance_km = haversine_km((rec.latitude, rec.longitude), port.coords())
            if distance_km <= _PORT_COORD_TOLERANCE_KM:
                continue
            # Severity ramps from the tolerance edge to "other side of the
            # world"; a 200 km error is sloppy, a 5000 km error is a rewrite.
            severity = severity_from_ratio(
                distance_km / _PORT_COORD_TOLERANCE_KM, 1.0, 20.0, ceiling=0.80
            )
            out.append(
                _ev(
                    rec.record_id,
                    EvidenceCode.COORDINATE_PORT_MISMATCH,
                    severity,
                    f"Declared coordinates ({rec.latitude:.4f}, {rec.longitude:.4f}) "
                    f"are {distance_km:.0f} km from {port.name}, the port this "
                    f"record claims.",
                    port_id=port.port_id,
                    port_name=port.name,
                    distance_km=round(distance_km, 1),
                    tolerance_km=_PORT_COORD_TOLERANCE_KM,
                    latitude=rec.latitude,
                    longitude=rec.longitude,
                )
            )
        return out


register_detector(GeospatialEngine())

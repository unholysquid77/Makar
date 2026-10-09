"""Route consistency engine.

A shipment declares a route, and a route is an ordered sequence of ports. Three
things can then go wrong, in increasing order of how much context they need:

* ``OFF_ROUTE_PORT`` -- the record claims a port that is not on its route at
  all. One record, one route lookup.
* ``DESTINATION_CONTRADICTION`` -- the record's declared destination is not
  where its route ends.
* ``ROUTE_SEQUENCE_BREAK`` -- the ports are all on the route, but the container
  visited them out of order.

The sequence check tolerates one legitimate pattern that would otherwise
dominate the output: a container may sit at the same port across several calls,
and a route may be sailed as a return leg. Only a *backwards jump of more than
one position* counts, which is what an inserted or rewritten port call looks
like.
"""

from __future__ import annotations

from core.detection.base import AnalysisContext, register_detector
from core.detection.segments import container_port_calls
from core.models import Evidence
from core.types import EVIDENCE_CODE_TYPE, EvidenceCode, EvidenceType

ENGINE = "route"


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


class RouteEngine:
    name = "route"

    def run(self, ctx: AnalysisContext) -> list[Evidence]:
        out: list[Evidence] = []
        out.extend(self._off_route(ctx))
        out.extend(self._destination(ctx))
        out.extend(self._sequence(ctx))
        return [e for e in out if e.severity > 0.0]

    # -- port not on the declared route ----------------------------------

    def _off_route(self, ctx: AnalysisContext) -> list[Evidence]:
        severity = ctx.cfg.float_("detection.route.off_route_severity")
        out: list[Evidence] = []
        for rec in ctx.records:
            route = ctx.world.routes.get(rec.route_id or "")
            if route is None or rec.port_id is None:
                continue
            if rec.port_id in route.port_sequence:
                continue
            port_name = (
                ctx.world.ports[rec.port_id].name
                if rec.port_id in ctx.world.ports
                else rec.port_id
            )
            leg_names = " -> ".join(
                ctx.world.ports[p].name for p in route.port_sequence if p in ctx.world.ports
            )
            out.append(
                _ev(
                    rec.record_id,
                    EvidenceCode.OFF_ROUTE_PORT,
                    severity,
                    f"Record places the container at {port_name}, which is not a "
                    f"call on its declared route {route.route_id} ({leg_names}).",
                    port_id=rec.port_id,
                    route_id=route.route_id,
                    route_sequence=route.port_sequence,
                )
            )
        return out

    # -- declared destination vs route terminus ---------------------------

    def _destination(self, ctx: AnalysisContext) -> list[Evidence]:
        on_route_severity = ctx.cfg.float_("detection.route.destination_on_route_severity")
        off_route_severity = ctx.cfg.float_("detection.route.destination_off_route_severity")
        out: list[Evidence] = []
        for rec in ctx.records:
            route = ctx.world.routes.get(rec.route_id or "")
            if route is None or not rec.destination:
                continue
            terminus_id = route.port_sequence[-1]
            terminus = ctx.world.ports.get(terminus_id)
            if terminus is None:
                continue
            declared = ctx.resolver.resolve_port(rec.destination)
            if not declared.resolved or declared.entity_id == terminus_id:
                continue
            # A destination that is *earlier on the same route* is a plausible
            # short-shipment rather than a rewrite, so it scores lower.
            on_route = declared.entity_id in route.port_sequence
            severity = on_route_severity if on_route else off_route_severity
            out.append(
                _ev(
                    rec.record_id,
                    EvidenceCode.DESTINATION_CONTRADICTION,
                    severity,
                    f"Declared destination {declared.value} does not match the "
                    f"terminus of route {route.route_id} ({terminus.name})."
                    + (" The declared port is on the route, so this may be a "
                       "short shipment." if on_route else ""),
                    declared_destination=declared.entity_id,
                    route_id=route.route_id,
                    route_terminus=terminus_id,
                    destination_on_route=on_route,
                )
            )
        return out

    # -- visiting order ---------------------------------------------------

    def _sequence(self, ctx: AnalysisContext) -> list[Evidence]:
        severity = ctx.cfg.float_("detection.route.sequence_break_severity")
        out: list[Evidence] = []
        for container_id, calls in container_port_calls(ctx).items():
            if len(calls) < 2:
                continue
            route_id = next(
                (r.route_id for call in calls for r in call.records if r.route_id), None
            )
            route = ctx.world.routes.get(route_id or "")
            if route is None:
                continue

            previous_index: int | None = None
            previous_call = None
            for call in calls:
                index = route.index_of(call.port_id)
                if index is None:
                    continue  # off-route, already reported
                if previous_index is not None and index < previous_index - 1:
                    rec = call.representative
                    from_name = ctx.world.ports[previous_call.port_id].name
                    to_name = ctx.world.ports[call.port_id].name
                    out.append(
                        _ev(
                            rec.record_id,
                            EvidenceCode.ROUTE_SEQUENCE_BREAK,
                            severity,
                            f"Container {container_id} moves backwards along route "
                            f"{route.route_id}: {from_name} (leg {previous_index}) "
                            f"to {to_name} (leg {index}).",
                            supporting=previous_call.record_ids,
                            container_id=container_id,
                            route_id=route.route_id,
                            from_leg=previous_index,
                            to_leg=index,
                        )
                    )
                previous_index = index
                previous_call = call
        return out


register_detector(RouteEngine())

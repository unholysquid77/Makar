"""Forensic API (spec 32).

Every endpoint is a view over one analysis snapshot, so the UI can cross-link
freely: a record found on the map resolves to the same verdict, the same
evidence and the same graph neighbourhood as one found in Bloodhound.

The LLM endpoint is downstream of everything else and cannot write: it
receives deterministic evidence and returns prose (spec 29).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from backend.services.store import store
from core.graph.model import NodeType, node_key
from core.types import Classification, TamperClass
from reporting import build_report_payload

router = APIRouter(prefix="/api")


# ======================================================================
# Request bodies
# ======================================================================


class AnalyzeRequest(BaseModel):
    directory: str | None = Field(None, description="Dataset directory to load.")
    manifest: str | None = Field(None, description="Manifest filename.")
    detectors: list[str] | None = Field(
        None, description="Restrict to these detectors; omit for the configured set."
    )


class StreamStartRequest(BaseModel):
    events: int = Field(200, ge=1, le=5000)
    seed: int | None = None
    generate: bool = Field(
        True, description="Generate a reproducible feed with the novel attack patterns."
    )


class StreamEventRequest(BaseModel):
    row: dict[str, Any] = Field(..., description="One raw manifest row.")


class ExplainRequest(BaseModel):
    record_id: str
    question: str | None = None


# ======================================================================
# Status and analysis
# ======================================================================


@router.get("/status")
def status() -> dict[str, Any]:
    if not store.loaded:
        return {"loaded": False, "directory": str(store.directory)}
    snapshot = store.snapshot
    return {
        "loaded": True,
        "directory": str(snapshot.directory),
        "manifest": store.manifest,
        "run_id": snapshot.result.run_id,
        "seed": snapshot.result.seed,
        "records": snapshot.result.summary.total_records,
        "graph": {
            "nodes": snapshot.graph.node_count,
            "edges": snapshot.graph.edge_count,
        },
        "stream_active": store.stream is not None,
        "timings_ms": snapshot.result.timings_ms,
        "config_sources": snapshot.result.config_sources,
    }


@router.post("/analyze")
def analyze_endpoint(body: AnalyzeRequest) -> dict[str, Any]:
    """Run the full pipeline and install the result."""
    try:
        snapshot = store.load(
            body.directory, body.manifest, enabled_detectors=body.detectors
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {
        "run_id": snapshot.result.run_id,
        "summary": snapshot.result.summary.model_dump(mode="json"),
        "timings_ms": snapshot.result.timings_ms,
        "attack_windows": len(snapshot.result.attack_windows),
        "inferred_deletions": len(snapshot.result.inferred_deletions),
    }


@router.get("/summary")
def summary() -> dict[str, Any]:
    snapshot = store.snapshot
    result = snapshot.result
    return {
        "run_id": result.run_id,
        "created_at": result.created_at.isoformat(),
        "seed": result.seed,
        "summary": result.summary.model_dump(mode="json"),
        "thresholds": {
            "suspicious": snapshot.cfg.float_("fusion.thresholds.suspicious"),
            "high_confidence": snapshot.cfg.float_("fusion.thresholds.high_confidence"),
        },
        "inferred_deletions": len(result.inferred_deletions),
        "attack_windows": len(result.attack_windows),
        "consistency": None
        if result.consistency is None
        else result.consistency.model_dump(mode="json"),
    }


@router.get("/report")
def report(top: int = Query(25, ge=1, le=200)) -> dict[str, Any]:
    snapshot = store.snapshot
    return build_report_payload(snapshot.result, snapshot.cfg, top_n=top)


# ======================================================================
# Records
# ======================================================================


@router.get("/records")
def records(
    limit: int = Query(100, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    suspicious_only: bool = False,
    tamper_class: str | None = None,
    classification: str | None = None,
    owner: str | None = None,
    port_id: str | None = None,
    min_probability: float = Query(0.0, ge=0.0, le=1.0),
    sort: str = Query("probability", pattern="^(probability|record_id|timestamp)$"),
) -> dict[str, Any]:
    """Ranked, filterable record list -- the Records view and the risk table."""
    snapshot = store.snapshot
    threshold = snapshot.cfg.float_("fusion.thresholds.suspicious")
    rows: list[dict[str, Any]] = []

    for rec in snapshot.result.records:
        verdict = snapshot.result.verdicts.get(rec.record_id)
        if verdict is None:
            continue
        if verdict.tampering_probability < min_probability:
            continue
        if suspicious_only and (
            verdict.tampering_probability < threshold
            or verdict.tamper_class in (TamperClass.CLEAN, TamperClass.BENIGN_ANOMALY)
        ):
            continue
        if tamper_class and str(verdict.tamper_class) != tamper_class:
            continue
        recon = snapshot.result.reconstructions.get(rec.record_id)
        if classification and (recon is None or str(recon.classification) != classification):
            continue
        if owner and rec.owner != owner:
            continue
        if port_id and rec.port_id != port_id:
            continue

        rows.append(
            {
                "record_id": rec.record_id,
                "container_id": rec.container_id,
                "shipment_id": rec.shipment_id,
                "owner": rec.owner,
                "cargo_type": rec.cargo_type,
                "port_id": rec.port_id,
                "route_id": rec.route_id,
                "vessel_id": rec.vessel_id,
                "event_type": rec.event_type,
                "status": rec.status,
                "weight": rec.weight,
                "declared_value": rec.declared_value,
                "timestamp": rec.timestamp.isoformat() if rec.timestamp else None,
                "latitude": rec.latitude,
                "longitude": rec.longitude,
                "tampering_probability": verdict.tampering_probability,
                "tamper_class": str(verdict.tamper_class),
                "class_confidence": verdict.class_confidence,
                "classification": str(recon.classification) if recon else None,
                "repair_confidence": recon.confidence if recon else None,
                "evidence_count": len(snapshot.evidence_by_record.get(rec.record_id, [])),
                "top_findings": [
                    str(c.code) for c in verdict.contributions[:3]
                ],
            }
        )

    if sort == "probability":
        rows.sort(key=lambda r: r["tampering_probability"], reverse=True)
    elif sort == "timestamp":
        rows.sort(key=lambda r: r["timestamp"] or "")
    else:
        rows.sort(key=lambda r: r["record_id"])

    return {"total": len(rows), "offset": offset, "limit": limit, "records": rows[offset : offset + limit]}


@router.get("/records/{record_id}")
def record_detail(record_id: str) -> dict[str, Any]:
    """Everything known about one record -- the investigation panel."""
    snapshot = store.snapshot
    rec = snapshot.ctx.by_id.get(record_id)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"unknown record {record_id!r}")

    verdict = snapshot.result.verdicts.get(record_id)
    recon = snapshot.result.reconstructions.get(record_id)
    items = snapshot.evidence_by_record.get(record_id, [])
    timeline = snapshot.ctx.container_timeline(rec.container_id)

    return {
        "record": rec.model_dump(mode="json", exclude={"raw"}),
        "raw": rec.raw,
        "normalization_notes": rec.normalization_notes,
        "verdict": verdict.model_dump(mode="json") if verdict else None,
        "evidence": [e.model_dump(mode="json") for e in sorted(items, key=lambda e: -e.severity)],
        "reconstruction": recon.model_dump(mode="json") if recon else None,
        "corroboration": snapshot.arbitration.corroboration.get(record_id),
        "container_timeline": [
            {
                "record_id": r.record_id,
                "event_type": r.event_type,
                "port_id": r.port_id,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "weight": r.weight,
                "probability": (
                    snapshot.result.verdicts[r.record_id].tampering_probability
                    if r.record_id in snapshot.result.verdicts
                    else None
                ),
            }
            for r in timeline
        ],
        "graph_key": node_key(NodeType.RECORD, record_id),
    }


@router.get("/evidence/{record_id}")
def evidence(record_id: str) -> dict[str, Any]:
    snapshot = store.snapshot
    if record_id not in snapshot.ctx.by_id:
        raise HTTPException(status_code=404, detail=f"unknown record {record_id!r}")
    items = snapshot.evidence_by_record.get(record_id, [])
    verdict = snapshot.result.verdicts.get(record_id)
    return {
        "record_id": record_id,
        "evidence": [e.model_dump(mode="json") for e in sorted(items, key=lambda e: -e.severity)],
        "contributions": [c.model_dump(mode="json") for c in (verdict.contributions if verdict else [])],
        "type_scores": {str(k): v for k, v in (verdict.type_scores if verdict else {}).items()},
        "tampering_probability": verdict.tampering_probability if verdict else None,
        "rationale": verdict.rationale if verdict else None,
    }


@router.post("/reconstruct/{record_id}")
def reconstruct(record_id: str) -> dict[str, Any]:
    """Re-run reconstruction for one record and return every candidate.

    Exposed as POST because it is a computation, and because the counterfactual
    explorer calls it to show candidates that were *not* selected.
    """
    from core.reconstruction.engine import reconstruct_record

    snapshot = store.snapshot
    rec = snapshot.ctx.by_id.get(record_id)
    verdict = snapshot.result.verdicts.get(record_id)
    if rec is None or verdict is None:
        raise HTTPException(status_code=404, detail=f"unknown record {record_id!r}")

    outcome = reconstruct_record(
        snapshot.ctx, rec, verdict, snapshot.evidence_by_record.get(record_id, [])
    )
    return outcome.model_dump(mode="json")


# ======================================================================
# Graph (spec 15)
# ======================================================================


@router.get("/graph/{record_id}")
def graph_neighbourhood(
    record_id: str,
    depth: int = Query(2, ge=1, le=4),
    mode: str = Query("expand", pattern="^(expand|isolate|conflict|trace)$"),
) -> dict[str, Any]:
    """Bloodhound's EXPAND / ISOLATE / CONFLICT views around a record."""
    snapshot = store.snapshot
    key = node_key(NodeType.RECORD, record_id)
    if not snapshot.graph.exists(key):
        raise HTTPException(status_code=404, detail=f"unknown node {record_id!r}")

    if mode == "conflict":
        conflicts = snapshot.graph.conflicts(key)
        keys = {key} | {c["source"] for c in conflicts} | {c["target"] for c in conflicts}
        payload = snapshot.graph.subgraph(keys)
        payload["conflicts"] = conflicts
    elif mode == "isolate":
        payload = snapshot.graph.isolate({key}, depth=1)
    elif mode == "trace":
        payload = {"provenance_chain": snapshot.graph.provenance_chain(record_id)}
        payload.update(snapshot.graph.isolate({key}, depth=depth))
    else:
        payload = snapshot.graph.subgraph(snapshot.graph.neighbourhood(key, depth=depth))

    # Decorate record nodes with their verdicts so the UI can colour them.
    for node in payload.get("nodes", []):
        if node["id"].startswith("record:"):
            rid = node["id"].split(":", 1)[1]
            verdict = snapshot.result.verdicts.get(rid)
            if verdict:
                node["tampering_probability"] = verdict.tampering_probability
                node["tamper_class"] = str(verdict.tamper_class)
    payload["root"] = key
    payload["mode"] = mode
    return payload


@router.get("/graph/path/{source_id}/{target_id}")
def graph_path(source_id: str, target_id: str) -> dict[str, Any]:
    """Shortest evidence path between two records (spec 15.1, 15.4)."""
    snapshot = store.snapshot
    hops = snapshot.graph.evidence_path(
        node_key(NodeType.RECORD, source_id), node_key(NodeType.RECORD, target_id)
    )
    if not hops:
        raise HTTPException(status_code=404, detail="no path between those records")
    return {"source": source_id, "target": target_id, "hops": hops}


# ======================================================================
# World, map layers and timeline
# ======================================================================


@router.get("/ports")
def ports() -> dict[str, Any]:
    """Ports with their forensic statistics (spec 26.3 popup)."""
    snapshot = store.snapshot
    threshold = snapshot.cfg.float_("fusion.thresholds.suspicious")
    out: list[dict[str, Any]] = []

    for port_id, port in snapshot.world.ports.items():
        records = snapshot.ctx.by_port.get(port_id, [])
        suspicious = [
            r
            for r in records
            if (v := snapshot.result.verdicts.get(r.record_id))
            and v.tampering_probability >= threshold
            and v.tamper_class not in (TamperClass.CLEAN, TamperClass.BENIGN_ANOMALY)
        ]
        dwells = [
            (r.departure_timestamp - r.arrival_timestamp).total_seconds() / 3600.0
            for r in records
            if r.arrival_timestamp and r.departure_timestamp
            and r.departure_timestamp > r.arrival_timestamp
        ]
        out.append(
            {
                **port.model_dump(mode="json"),
                "records": len(records),
                "containers": len({r.container_id for r in records if r.container_id}),
                "shipments": len({r.shipment_id for r in records if r.shipment_id}),
                "suspicious": len(suspicious),
                "suspicious_rate": round(len(suspicious) / max(1, len(records)), 4),
                "mean_dwell_hours": round(sum(dwells) / len(dwells), 2) if dwells else None,
            }
        )
    out.sort(key=lambda p: -p["suspicious"])
    return {"ports": out, "geojson": snapshot.world.ports_geojson()}


@router.get("/routes")
def routes() -> dict[str, Any]:
    """Routes with their forensic statistics (spec 26.4 popup)."""
    snapshot = store.snapshot
    threshold = snapshot.cfg.float_("fusion.thresholds.suspicious")
    out: list[dict[str, Any]] = []

    for route_id, route in snapshot.world.routes.items():
        records = snapshot.ctx.by_route.get(route_id, [])
        verdicts = [snapshot.result.verdicts.get(r.record_id) for r in records]
        suspicious = [
            v
            for v in verdicts
            if v
            and v.tampering_probability >= threshold
            and v.tamper_class not in (TamperClass.CLEAN, TamperClass.BENIGN_ANOMALY)
        ]
        by_class: dict[str, int] = {}
        for v in suspicious:
            by_class[str(v.tamper_class)] = by_class.get(str(v.tamper_class), 0) + 1
        out.append(
            {
                **route.model_dump(mode="json"),
                "port_names": [
                    snapshot.world.ports[p].name
                    for p in route.port_sequence
                    if p in snapshot.world.ports
                ],
                "records": len(records),
                "containers": len({r.container_id for r in records if r.container_id}),
                "suspicious": len(suspicious),
                "by_tamper_class": by_class,
            }
        )
    out.sort(key=lambda r: -r["suspicious"])
    return {"routes": out, "geojson": snapshot.world.routes_geojson()}


@router.get("/map/records")
def map_records(
    min_probability: float = Query(0.5, ge=0.0, le=1.0),
    limit: int = Query(1500, ge=1, le=10000),
) -> dict[str, Any]:
    """GeoJSON point layer of records, for the suspicious/attack map layers."""
    snapshot = store.snapshot
    features: list[dict[str, Any]] = []
    for rec in snapshot.result.records:
        verdict = snapshot.result.verdicts.get(rec.record_id)
        if verdict is None or verdict.tampering_probability < min_probability:
            continue
        if rec.latitude is None or rec.longitude is None:
            continue
        recon = snapshot.result.reconstructions.get(rec.record_id)
        features.append(
            {
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [rec.longitude, rec.latitude]},
                "properties": {
                    "record_id": rec.record_id,
                    "container_id": rec.container_id,
                    "port_id": rec.port_id,
                    "owner": rec.owner,
                    "event_type": rec.event_type,
                    "timestamp": rec.timestamp.isoformat() if rec.timestamp else None,
                    "tampering_probability": verdict.tampering_probability,
                    "tamper_class": str(verdict.tamper_class),
                    "classification": str(recon.classification) if recon else None,
                },
            }
        )
        if len(features) >= limit:
            break
    return {"type": "FeatureCollection", "features": features}


@router.get("/containers/{container_id}/trajectory")
def trajectory(container_id: str) -> dict[str, Any]:
    """Observed versus reconstructed path for one container (spec 26.6)."""
    snapshot = store.snapshot
    timeline = snapshot.ctx.container_timeline(container_id)
    if not timeline:
        raise HTTPException(status_code=404, detail=f"unknown container {container_id!r}")

    def point(rec, use_repair: bool) -> dict[str, Any] | None:
        latitude, longitude = rec.latitude, rec.longitude
        recon = snapshot.result.reconstructions.get(rec.record_id)
        if use_repair and recon:
            # A REMOVED record is not in the reconstructed manifest, so it must
            # not appear on the reconstructed path either -- otherwise the map
            # reports "reconstruction matches observed" for a container whose
            # reconstruction dropped a leg.
            if recon.classification is Classification.REMOVED:
                return None
            if recon.reconstructed:
                latitude = recon.reconstructed.get("latitude", latitude)
                longitude = recon.reconstructed.get("longitude", longitude)
        if latitude is None or longitude is None:
            return None
        return {
            "record_id": rec.record_id,
            "port_id": rec.port_id,
            "event_type": rec.event_type,
            "timestamp": rec.timestamp.isoformat() if rec.timestamp else None,
            "coordinates": [longitude, latitude],
        }

    observed = [p for p in (point(r, False) for r in timeline) if p]
    reconstructed = [p for p in (point(r, True) for r in timeline) if p]
    removed = [
        r.record_id
        for r in timeline
        if (recon := snapshot.result.reconstructions.get(r.record_id))
        and recon.classification is Classification.REMOVED
    ]
    return {
        "container_id": container_id,
        "observed": observed,
        "reconstructed": reconstructed,
        "removed_records": removed,
        "differs": observed != reconstructed,
    }


@router.get("/timeline")
def timeline() -> dict[str, Any]:
    """Attack windows and the bucketed anomaly histogram (spec 25)."""
    snapshot = store.snapshot
    windows = [w.model_dump(mode="json") for w in snapshot.result.attack_windows]
    buckets: list[dict[str, Any]] = []
    for window in snapshot.result.attack_windows:
        for bucket in window.buckets:
            buckets.append(
                {
                    "window_id": window.window_id,
                    "start": bucket.start.isoformat(),
                    "end": bucket.end.isoformat(),
                    "total": bucket.total,
                    "by_class": {str(k): v for k, v in bucket.by_class.items()},
                    "record_ids": bucket.record_ids,
                }
            )
    buckets.sort(key=lambda b: b["start"])
    return {"windows": windows, "buckets": buckets}


@router.get("/deletions")
def deletions(limit: int = Query(200, ge=1, le=2000)) -> dict[str, Any]:
    snapshot = store.snapshot
    return {
        "total": len(snapshot.result.inferred_deletions),
        "deletions": snapshot.result.inferred_deletions[:limit],
    }


# ======================================================================
# Provenance
# ======================================================================


@router.get("/blockchain")
def blockchain(limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)) -> dict[str, Any]:
    snapshot = store.snapshot
    chain = snapshot.provenance.chain
    if chain is None:
        return {"height": 0, "blocks": [], "state_root": None}
    verification = chain.verify()
    covered_from, covered_to = chain.covered_time_range()
    blocks = [b.model_dump(mode="json") for b in chain.blocks[offset : offset + limit]]
    return {
        "height": chain.height,
        "state_root": chain.state_root,
        "digest": chain.digest(),
        "valid": verification.valid,
        "problems": verification.problems(),
        "committed_records": len(chain.committed_record_ids()),
        "covered_from": covered_from.isoformat() if covered_from else None,
        "covered_to": covered_to.isoformat() if covered_to else None,
        "sealed_fraction": snapshot.cfg.float_("blockchain.sealed_fraction"),
        "blocks": blocks,
    }


@router.get("/nodes")
def nodes() -> dict[str, Any]:
    """Node integrity (spec 23) -- the A OK / B OK / C WARN / D OK panel."""
    snapshot = store.snapshot
    return snapshot.provenance.node_summary or {
        "nodes": [],
        "divergent": [],
        "agreeing": [],
    }


# ======================================================================
# Live stream (spec 30)
# ======================================================================


@router.post("/stream/start")
def stream_start(body: StreamStartRequest) -> dict[str, Any]:
    """Start a live session, optionally generating the reproducible feed."""
    snapshot = store.snapshot

    queued: list[dict[str, Any]] = []
    injected: dict[str, int] = {}
    if body.generate:
        from generator.stream import build_stream

        plan = build_stream(
            snapshot.cfg,
            snapshot.world,
            snapshot.result.records,
            count=body.events,
            seed=body.seed,
        )
        # Register the feed's bookings BEFORE the processor is constructed.
        # ``StreamProcessor`` builds its ``EntityResolver`` eagerly from the
        # world it is handed, so starting it first left every live container
        # unknown to the resolver and raised UNKNOWN_ENTITY_REFERENCE on each
        # legitimate event -- 16 false alarms in 400 events, against 0 from the
        # CLI scorer, which registers them in the right order.
        store.register_world_additions(plan.new_shipments, plan.new_containers)
        queued = [{"sequence": e.sequence, "row": e.row, "truth": e.truth} for e in plan.events]
        injected = plan.summary

    # The feed is handed to the client, which posts events back one at a time.
    # That keeps the demo's pacing in the UI's hands and keeps the processor
    # honest -- it only ever sees one event at a time.
    processor = store.start_stream()

    return {
        "started": True,
        "alert_threshold": snapshot.cfg.float_(
            "stream.alert_threshold", snapshot.cfg.float_("fusion.thresholds.suspicious")
        ),
        "batch_records": len(processor.records),
        "injected": injected,
        "queued_events": queued,
    }


@router.post("/stream/event")
def stream_event(body: StreamEventRequest) -> dict[str, Any]:
    """Ingest one live event and return its verdict."""
    processor = store.stream
    if processor is None:
        raise HTTPException(status_code=409, detail="no live session; POST /api/stream/start first")
    verdict = processor.ingest(body.row)
    payload = verdict.as_dict()
    store.record_stream_event(payload)
    return payload


@router.get("/stream/status")
def stream_status(limit: int = Query(50, ge=1, le=500)) -> dict[str, Any]:
    processor = store.stream
    if processor is None:
        return {"active": False}
    return {"active": True, **processor.stats(), "recent": store.stream_log(limit)}


# ======================================================================
# Evaluation artifacts (spec 31)
# ======================================================================


@router.get("/evaluation")
def evaluation() -> dict[str, Any]:
    """Serve the offline scorer's output, if it has been run.

    A note on where the line sits: ``scripts/evaluate.py`` is the only thing
    that ever reads ``ground_truth.json``, and it writes its results here. The
    *detector* never sees the answer key. This endpoint lets the console render
    our own scorecard, which is a reporting concern, not a detection one -- and
    it returns 404 rather than inventing numbers when the scorer has not run.
    """
    from core.io import read_json

    snapshot = store.snapshot
    batch_path = snapshot.directory / "evaluation.json"
    stream_path = snapshot.directory / "stream_evaluation.json"

    if not batch_path.exists() and not stream_path.exists():
        raise HTTPException(
            status_code=404,
            detail="No evaluation artifact found.",
            headers={"X-Makar-Hint": "python scripts/evaluate.py --out out --ablation"},
        )

    return {
        "batch": read_json(batch_path) if batch_path.exists() else None,
        "stream": read_json(stream_path) if stream_path.exists() else None,
        "directory": str(snapshot.directory),
        "note": (
            "Produced by scripts/evaluate.py and scripts/stream_sim.py, the only "
            "consumers of the private injection log. Nothing under core/ reads it."
        ),
    }


# ======================================================================
# LLM analyst (spec 29)
# ======================================================================


@router.post("/llm/explain")
def llm_explain(body: ExplainRequest) -> dict[str, Any]:
    """Translate deterministic evidence into prose.

    Strictly downstream: the analyst receives the record, its evidence, its
    candidate repairs and its graph context, and returns an explanation. It
    cannot modify the manifest, the verdict or the chain, and the system is
    fully operational with the provider disabled -- in which case the
    deterministic rationale is returned instead.
    """
    from llm.analyst import explain_record

    snapshot = store.snapshot
    rec = snapshot.ctx.by_id.get(body.record_id)
    verdict = snapshot.result.verdicts.get(body.record_id)
    if rec is None or verdict is None:
        raise HTTPException(status_code=404, detail=f"unknown record {body.record_id!r}")

    return explain_record(
        snapshot.cfg,
        record=rec,
        verdict=verdict,
        evidence=snapshot.evidence_by_record.get(body.record_id, []),
        reconstruction=snapshot.result.reconstructions.get(body.record_id),
        graph=snapshot.graph,
        question=body.question,
    )

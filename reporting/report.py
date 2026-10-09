"""Suspicious activity report (problem statement deliverable).

Renders an analysis run as a self-contained forensic report. Every flag is
accompanied by the evidence that produced it and the arithmetic behind the
score, because the stated expectation is that judges will ask why each record
was flagged or repaired, and "the model said so" is not an answer.

Sections:

1. Headline totals and the reconstructed manifest's disposition.
2. Totals by tampering type.
3. Ranked suspicious records, each with its evidence breakdown, its blame
   arbitration where one occurred, and its reconstruction.
4. Affected owners, ports and routes.
5. Inferred deletions -- reported separately because a deleted record has no
   row to rank.
6. Suspected attack timeline, stated as a hypothesis with confidence.
7. Provenance network integrity.
8. Data-quality findings, i.e. the irregularities we deliberately did *not*
   treat as attacks.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from core.config import MakarConfig
from core.models import AnalysisResult
from core.types import EvidenceType, TamperClass


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def build_report_payload(
    result: AnalysisResult,
    cfg: MakarConfig,
    *,
    top_n: int = 25,
) -> dict[str, Any]:
    """Assemble the report as plain data, for JSON or further rendering."""
    threshold = cfg.float_("fusion.thresholds.suspicious")
    high = cfg.float_("fusion.thresholds.high_confidence")
    records = {r.record_id: r for r in result.records}

    ranked = sorted(
        (
            v
            for v in result.verdicts.values()
            if v.tampering_probability >= threshold
            and v.tamper_class not in (TamperClass.CLEAN, TamperClass.BENIGN_ANOMALY)
        ),
        key=lambda v: v.tampering_probability,
        reverse=True,
    )

    by_class = Counter(str(v.tamper_class) for v in ranked)

    # Affected entities, counted over suspicious records only.
    affected_owners = Counter()
    affected_ports = Counter()
    affected_routes = Counter()
    for verdict in ranked:
        rec = records.get(verdict.record_id)
        if rec is None:
            continue
        if rec.owner:
            affected_owners[rec.owner] += 1
        if rec.port_id:
            affected_ports[rec.port_id] += 1
        if rec.route_id:
            affected_routes[rec.route_id] += 1

    entries: list[dict[str, Any]] = []
    for verdict in ranked[:top_n]:
        rec = records.get(verdict.record_id)
        recon = result.reconstructions.get(verdict.record_id)
        items = result.evidence_for(verdict.record_id)
        arbitrations = [
            i.details["arbitration"]
            for i in items
            if isinstance(i.details.get("arbitration"), dict)
        ]
        entries.append(
            {
                "record_id": verdict.record_id,
                "tampering_probability": verdict.tampering_probability,
                "tamper_class": str(verdict.tamper_class),
                "class_confidence": verdict.class_confidence,
                "confidence_band": "high" if verdict.tampering_probability >= high else "moderate",
                "rationale": verdict.rationale,
                "type_scores": {str(k): v for k, v in verdict.type_scores.items()},
                "contributions": [
                    {
                        "code": str(c.code),
                        "type": str(c.type),
                        "label": c.label,
                        "severity": c.severity,
                        "points": c.points,
                    }
                    for c in verdict.contributions
                ],
                "evidence": [
                    {
                        "code": str(i.code),
                        "type": str(i.type),
                        "severity": i.severity,
                        "description": i.description,
                        "supporting_records": i.supporting_records,
                        "engine": i.engine,
                    }
                    for i in sorted(items, key=lambda i: -i.severity)
                ],
                "arbitration": arbitrations[:2],
                "context": {
                    "container_id": rec.container_id if rec else None,
                    "shipment_id": rec.shipment_id if rec else None,
                    "owner": rec.owner if rec else None,
                    "port_id": rec.port_id if rec else None,
                    "route_id": rec.route_id if rec else None,
                    "event_type": rec.event_type if rec else None,
                    "timestamp": rec.timestamp.isoformat() if rec and rec.timestamp else None,
                },
                "reconstruction": None
                if recon is None
                else {
                    "classification": str(recon.classification),
                    "confidence": recon.confidence,
                    "reason": recon.reason,
                    "selected_candidate_id": recon.selected_candidate_id,
                    "changes": _changes(recon),
                    "candidates": [
                        {
                            "candidate_id": c.candidate_id,
                            "strategy": c.strategy,
                            "remove": c.remove,
                            "changes": c.changes,
                            "score": c.score,
                            "explanation": c.explanation,
                        }
                        for c in recon.candidates
                    ],
                },
            }
        )

    data_quality = Counter(
        str(i.code) for i in result.evidence if EvidenceType(str(i.type)) is EvidenceType.FORMAT
    )
    benign = sum(
        1 for v in result.verdicts.values() if v.tamper_class is TamperClass.BENIGN_ANOMALY
    )

    return {
        "run_id": result.run_id,
        "created_at": result.created_at.isoformat(),
        "seed": result.seed,
        "config_sources": result.config_sources,
        "thresholds": {"suspicious": threshold, "high_confidence": high},
        "totals": {
            "records": result.summary.total_records,
            "suspicious": len(ranked),
            "original": result.summary.original,
            "repaired": result.summary.repaired,
            "removed": result.summary.removed,
            "unrecoverable": result.summary.unrecoverable,
            "benign_anomalies": benign,
            "mean_repair_confidence": result.summary.mean_repair_confidence,
        },
        "by_tamper_class": dict(by_class),
        "by_evidence_type": {str(k): v for k, v in result.summary.by_evidence_type.items()},
        "affected": {
            "owners": affected_owners.most_common(10),
            "ports": affected_ports.most_common(10),
            "routes": affected_routes.most_common(10),
        },
        "ranked_records": entries,
        "inferred_deletions": result.inferred_deletions[:40],
        "inferred_deletion_count": len(result.inferred_deletions),
        "attack_windows": [w.model_dump(mode="json", exclude={"buckets"}) for w in result.attack_windows],
        "provenance": None
        if result.consistency is None
        else {
            "majority_state_root": result.consistency.majority_state_root,
            "agreeing_nodes": result.consistency.agreeing_nodes,
            "divergent_nodes": result.consistency.divergent_nodes,
            "affected_blocks": result.consistency.affected_blocks,
            "affected_records": result.consistency.affected_records,
            "nodes": [n.model_dump(mode="json") for n in result.consistency.nodes],
        },
        "data_quality": dict(data_quality.most_common()),
        "timings_ms": result.timings_ms,
    }


def _changes(recon: Any) -> dict[str, Any]:
    """Field-level before/after for a repaired record."""
    if recon.reconstructed is None:
        return {}
    out: dict[str, Any] = {}
    for key, new_value in recon.reconstructed.items():
        old_value = recon.original.get(key)
        if old_value != new_value:
            out[key] = {"from": old_value, "to": new_value}
    return out


# ======================================================================
# Markdown rendering
# ======================================================================


def render_markdown(payload: dict[str, Any]) -> str:
    """Render the report payload as Markdown."""
    totals = payload["totals"]
    lines: list[str] = []
    add = lines.append

    add("# Makar — Suspicious Activity Report")
    add("")
    add(f"**Run** `{payload['run_id']}` · **Seed** `{payload['seed']}` · "
        f"**Generated** {payload['created_at']}")
    add("")
    add(f"Suspicion threshold {payload['thresholds']['suspicious']:.2f}; "
        f"high-confidence band from {payload['thresholds']['high_confidence']:.2f}.")
    add("")

    # --- 1. headline ---
    add("## 1. Headline")
    add("")
    add("| Metric | Value |")
    add("|---|---:|")
    add(f"| Records analysed | {totals['records']:,} |")
    add(f"| Suspicious (tampering inferred) | {totals['suspicious']:,} |")
    add(f"| Benign anomalies (irregular, **not** tampering) | {totals['benign_anomalies']:,} |")
    add(f"| Inferred deletions | {payload['inferred_deletion_count']:,} |")
    add("")
    add("Reconstructed manifest disposition — every record carries exactly one:")
    add("")
    add("| Classification | Records |")
    add("|---|---:|")
    add(f"| `ORIGINAL` | {totals['original']:,} |")
    add(f"| `REPAIRED` | {totals['repaired']:,} |")
    add(f"| `REMOVED` | {totals['removed']:,} |")
    add(f"| `UNRECOVERABLE` | {totals['unrecoverable']:,} |")
    add("")
    add(f"Mean repair confidence: **{_pct(totals['mean_repair_confidence'])}**.")
    add("")

    # --- 2. by type ---
    add("## 2. Totals by tampering type")
    add("")
    if payload["by_tamper_class"]:
        add("| Type | Records |")
        add("|---|---:|")
        for name, count in sorted(payload["by_tamper_class"].items(), key=lambda kv: -kv[1]):
            add(f"| `{name}` | {count:,} |")
    else:
        add("_No tampering inferred._")
    add("")
    add("Evidence raised by reasoning layer:")
    add("")
    add("| Layer | Findings |")
    add("|---|---:|")
    for name, count in sorted(payload["by_evidence_type"].items(), key=lambda kv: -kv[1]):
        add(f"| `{name}` | {count:,} |")
    add("")

    # --- 3. affected entities ---
    add("## 3. Affected owners, ports and routes")
    add("")
    for label, key in (("Owners", "owners"), ("Ports", "ports"), ("Routes", "routes")):
        rows = payload["affected"][key]
        if not rows:
            continue
        add(f"**{label}**")
        add("")
        add("| Entity | Suspicious records |")
        add("|---|---:|")
        for name, count in rows:
            add(f"| {name} | {count} |")
        add("")

    # --- 4. ranked records ---
    add("## 4. Ranked suspicious records")
    add("")
    add(f"Showing the top {len(payload['ranked_records'])} of "
        f"{totals['suspicious']} by tampering probability. Each entry lists the "
        f"evidence behind the flag and the arithmetic behind the score.")
    add("")
    for entry in payload["ranked_records"]:
        ctx = entry["context"]
        add(f"### `{entry['record_id']}` — {_pct(entry['tampering_probability'])} "
            f"{entry['tamper_class']}")
        add("")
        add(f"- **Container** `{ctx['container_id']}` · **Shipment** `{ctx['shipment_id']}` "
            f"· **Port** `{ctx['port_id']}` · **Route** `{ctx['route_id']}`")
        add(f"- **Owner** {ctx['owner']} · **Event** `{ctx['event_type']}` "
            f"· **Timestamp** `{ctx['timestamp']}`")
        add(f"- **Class confidence** {_pct(entry['class_confidence'])} "
            f"({entry['confidence_band']} band)")
        add("")
        add("**Evidence breakdown**")
        add("")
        add("| Points | Layer | Finding | Severity |")
        add("|---:|---|---|---:|")
        for c in entry["contributions"]:
            add(f"| {c['points']:+d} | `{c['type']}` | {c['label']} | {c['severity']:.2f} |")
        add("")
        add("**Why**")
        add("")
        add(f"> {entry['rationale']}")
        add("")
        add("**Supporting findings**")
        add("")
        for item in entry["evidence"][:6]:
            support = (
                f" (with {', '.join(f'`{s}`' for s in item['supporting_records'][:3])})"
                if item["supporting_records"]
                else ""
            )
            add(f"- `{item['code']}` ({item['severity']:.2f}, {item['engine']}): "
                f"{item['description']}{support}")
        add("")
        for arb in entry["arbitration"]:
            add(f"**Blame arbitration** — outcome `{arb.get('outcome')}`, "
                f"corroboration {arb.get('corroboration')} vs "
                f"`{arb.get('counterpart')}` at {arb.get('counterpart_corroboration')}; "
                f"severity multiplier {arb.get('multiplier')}.")
            for why in arb.get("why", []):
                add(f"  - {why}")
            add("")
        recon = entry["reconstruction"]
        if recon:
            add(f"**Reconstruction** — `{recon['classification']}` "
                f"at {_pct(recon['confidence'])}")
            add("")
            if recon["changes"]:
                add("| Field | Observed | Reconstructed |")
                add("|---|---|---|")
                for field, change in recon["changes"].items():
                    add(f"| `{field}` | `{change['from']}` | `{change['to']}` |")
                add("")
            add(f"> {recon['reason']}")
            add("")
            if len(recon["candidates"]) > 1:
                add("<details><summary>Candidates considered</summary>")
                add("")
                add("| Candidate | Strategy | Score | Proposal |")
                add("|---|---|---:|---|")
                for c in recon["candidates"]:
                    proposal = "remove record" if c["remove"] else ", ".join(
                        f"{k}={v}" for k, v in c["changes"].items()
                    )
                    add(f"| `{c['candidate_id']}` | {c['strategy']} | {c['score']:.3f} "
                        f"| {proposal} |")
                add("")
                add("</details>")
                add("")
        add("---")
        add("")

    # --- 5. deletions ---
    add("## 5. Inferred deletions")
    add("")
    add("A deleted record leaves no row to rank, so deletions are inferred from "
        "the shape of what remains and reported here.")
    add("")
    if payload["inferred_deletions"]:
        add("| Confidence | Container | Port | Missing | Sources | Reason |")
        add("|---:|---|---|---|---|---|")
        for entry in payload["inferred_deletions"]:
            add(f"| {entry.get('confidence', 0):.2f} "
                f"| `{entry.get('container_id') or '—'}` "
                f"| `{entry.get('port_id') or '—'}` "
                f"| `{entry.get('missing_event') or entry.get('record_id') or '—'}` "
                f"| {', '.join(entry.get('sources', [entry.get('source', '')]))} "
                f"| {entry.get('reason', '')} |")
        add("")
        if payload["inferred_deletion_count"] > len(payload["inferred_deletions"]):
            add(f"_…and {payload['inferred_deletion_count'] - len(payload['inferred_deletions'])} "
                f"more._")
            add("")
    else:
        add("_No deletions inferred._")
        add("")

    # --- 6. timeline ---
    add("## 6. Suspected attack timeline")
    add("")
    add("Windows are grouped in **cargo-event time**: the manifest does not "
        "record when the attacker acted, but it does record which events were "
        "targeted. Each window is a hypothesis with a confidence, not an "
        "observed intrusion log.")
    add("")
    if payload["attack_windows"]:
        for window in payload["attack_windows"]:
            add(f"### {window['window_id']} — {window['record_count']} records, "
                f"confidence {_pct(window['confidence'])}")
            add("")
            add(f"- **Span** `{window['start']}` → `{window['end']}`")
            if window["affected_ports"]:
                add(f"- **Ports** {', '.join(f'`{p}`' for p in window['affected_ports'])}")
            if window["affected_owners"]:
                add(f"- **Owners** {', '.join(window['affected_owners'])}")
            if window["affected_vessels"]:
                add(f"- **Vessels** {', '.join(f'`{v}`' for v in window['affected_vessels'])}")
            if window["likely_sequence"]:
                add(f"- **Apparent phase order** "
                    f"{' → '.join(str(s) for s in window['likely_sequence'])}")
            add("")
            add(f"> {window['narrative']}")
            add("")
    else:
        add("_No coordinated window inferred._")
        add("")

    # --- 7. provenance ---
    add("## 7. Provenance network integrity")
    add("")
    provenance = payload["provenance"]
    if provenance:
        add(f"Majority state root `{provenance['majority_state_root'][:24]}…`")
        add("")
        add("| Node | Status | Height | State root | Peers |")
        add("|---|---|---:|---|---|")
        for node in provenance["nodes"]:
            mark = "OK" if node["status"] == "HEALTHY" else "DIVERGENT"
            add(f"| `{node['node_id']}` | {mark} | {node['height']} "
                f"| `{node['state_root'][:16]}…` | {', '.join(node['peers'])} |")
        add("")
        if provenance["divergent_nodes"]:
            add(f"Node(s) **{', '.join(provenance['divergent_nodes'])}** disagree with "
                f"the majority. Affected blocks: "
                f"{', '.join(f'`{b}`' for b in provenance['affected_blocks'])}. "
                f"{len(provenance['affected_records'])} record commitment(s) differ.")
            add("")
            add("Note that the divergent node's chain passes its *own* integrity "
                "check — it was rewritten competently, with every root recomputed. "
                "Only cross-node comparison reveals it.")
            add("")
    else:
        add("_No provenance chain available for this run._")
        add("")

    # --- 8. data quality ---
    add("## 8. Data-quality findings (deliberately not treated as attacks)")
    add("")
    add("These irregularities were recognised, normalised and **discounted**. "
        "`FORMAT` evidence carries a negative fusion weight, so a messy record "
        "is scored as *less* likely to have been deliberately edited, not more. "
        "Not every oddity is an attack.")
    add("")
    if payload["data_quality"]:
        add("| Finding | Count |")
        add("|---|---:|")
        for code, count in payload["data_quality"].items():
            add(f"| `{code}` | {count:,} |")
        add("")
    add(f"{totals['benign_anomalies']:,} records were classified "
        f"`BENIGN_ANOMALY`: irregular, but without evidence of tampering.")
    add("")

    add("## Appendix — pipeline timings")
    add("")
    add("| Stage | ms |")
    add("|---|---:|")
    for stage, ms in sorted(payload["timings_ms"].items(), key=lambda kv: -kv[1]):
        add(f"| `{stage}` | {ms:,.1f} |")
    add("")

    return "\n".join(lines)

"""LLM forensic analyst (spec 29).

The analyst is **downstream of deterministic evidence** and has no authority.
It receives a record, the evidence against it, the candidate repairs, its
graph context and its timeline context, and it returns prose. It cannot modify
the manifest, the verdict, the reconstruction or the chain; the deterministic
system remains the source of truth.

Two properties are enforced structurally rather than by instruction:

* **It is never on the critical path.** ``explain_record`` always returns the
  deterministic rationale. The model's prose is an *additional* field. With
  the provider disabled -- the default -- the endpoint still answers usefully.
* **It is given evidence, not raw data to judge.** The prompt contains the
  findings the engines produced, with severities and the fused arithmetic. The
  model is asked to explain and to flag uncertainty, not to decide.

The system prompt says so explicitly, because a model asked to "analyse this
shipment" will happily invent a verdict, and a verdict that did not come from
the engines is exactly what this architecture exists to prevent.
"""

from __future__ import annotations

import json
from typing import Any

from core.config import MakarConfig
from core.models import Evidence, ManifestRecord, Reconstruction, RecordVerdict
from llm.provider import build_provider

SYSTEM_PROMPT = """You are a forensic analyst's writing assistant inside Makar, a cargo-manifest \
forensics system.

The deterministic engines have already done the analysis. Your job is to explain their \
findings in clear prose for an investigator, and to be honest about uncertainty.

Rules you must follow:
- Do NOT invent findings, numbers, records or entities. Use only what the evidence block gives you.
- Do NOT overturn, re-score or second-guess the verdict. If you think the evidence is weak, say \
that the evidence is weak -- do not assert a different conclusion.
- Do NOT recommend altering the manifest. Repair decisions belong to the reconstruction engine.
- Quote the specific findings and their severities when you explain. An investigator must be able \
to check you against the evidence block.
- Say plainly what is NOT known, and which checks could not run for this record.
- Be concise: four short paragraphs at most, no preamble, no bullet-point padding.
"""


def _evidence_block(
    record: ManifestRecord,
    verdict: RecordVerdict,
    evidence: list[Evidence],
    reconstruction: Reconstruction | None,
    graph_context: dict[str, Any],
) -> dict[str, Any]:
    """The exact structure spec 29 prescribes as LLM input."""
    return {
        "record": record.model_dump(mode="json", exclude={"raw", "normalization_notes"}),
        "normalization_notes": record.normalization_notes,
        "verdict": {
            "tampering_probability": verdict.tampering_probability,
            "tamper_class": str(verdict.tamper_class),
            "class_confidence": verdict.class_confidence,
            "type_scores": {str(k): v for k, v in verdict.type_scores.items()},
            "contributions": [
                {
                    "code": str(c.code),
                    "layer": str(c.type),
                    "finding": c.label,
                    "severity": c.severity,
                    "points": c.points,
                }
                for c in verdict.contributions
            ],
            "deterministic_rationale": verdict.rationale,
        },
        "evidence": [
            {
                "code": str(e.code),
                "layer": str(e.type),
                "severity": e.severity,
                "description": e.description,
                "supporting_records": e.supporting_records,
                "engine": e.engine,
            }
            for e in sorted(evidence, key=lambda e: -e.severity)
        ],
        "candidate_repairs": []
        if reconstruction is None
        else [
            {
                "candidate_id": c.candidate_id,
                "strategy": c.strategy,
                "remove": c.remove,
                "changes": c.changes,
                "score": c.score,
                "explanation": c.explanation,
            }
            for c in reconstruction.candidates
        ],
        "selected_reconstruction": None
        if reconstruction is None
        else {
            "classification": str(reconstruction.classification),
            "confidence": reconstruction.confidence,
            "reason": reconstruction.reason,
            "changes": reconstruction.reconstructed,
        },
        "graph_context": graph_context,
    }


def explain_record(
    cfg: MakarConfig,
    *,
    record: ManifestRecord,
    verdict: RecordVerdict,
    evidence: list[Evidence],
    reconstruction: Reconstruction | None = None,
    graph: Any = None,
    question: str | None = None,
) -> dict[str, Any]:
    """Explain one record. Always returns the deterministic rationale."""
    graph_context: dict[str, Any] = {}
    if graph is not None:
        from core.graph.model import NodeType, node_key

        key = node_key(NodeType.RECORD, record.record_id)
        if graph.exists(key):
            neighbourhood = graph.neighbourhood(key, depth=1)
            graph_context = {
                "connected_entities": sorted(neighbourhood - {key})[:20],
                "conflicts": [
                    {
                        "with": c["target"] if c["source"] == key else c["source"],
                        "relationship": c.get("type"),
                        "evidence_code": c.get("evidence_code"),
                        "confidence": c.get("confidence"),
                    }
                    for c in graph.conflicts(key)[:10]
                ],
                "provenance_chain": [
                    n["node"] for n in graph.provenance_chain(record.record_id)
                ],
            }

    payload = _evidence_block(record, verdict, evidence, reconstruction, graph_context)

    provider = build_provider(cfg)
    prompt_parts = [
        "Explain the system's finding for this record to an investigator.",
        "",
        "EVIDENCE BLOCK (the only facts you may use):",
        json.dumps(payload, indent=2, default=str),
    ]
    if question:
        prompt_parts += ["", f"The investigator specifically asks: {question}"]

    response = provider.complete(
        SYSTEM_PROMPT,
        "\n".join(prompt_parts),
        max_tokens=cfg.int_("llm.max_tokens", 1200),
        temperature=cfg.float_("llm.temperature", 0.1),
    )

    return {
        "record_id": record.record_id,
        # Always present, always the system's own reasoning.
        "deterministic": {
            "tampering_probability": verdict.tampering_probability,
            "tamper_class": str(verdict.tamper_class),
            "rationale": verdict.rationale,
            "contributions": [
                {"finding": c.label, "layer": str(c.type), "points": c.points}
                for c in verdict.contributions
            ],
            "reconstruction": None
            if reconstruction is None
            else {
                "classification": str(reconstruction.classification),
                "confidence": reconstruction.confidence,
                "reason": reconstruction.reason,
            },
        },
        "llm": {
            "available": response.available,
            "provider": response.provider,
            "model": response.model,
            "explanation": response.text,
            "error": response.error,
        },
        "note": (
            "The LLM is an explanation interface only. It cannot modify the "
            "manifest, the verdict or the provenance chain, and the system is "
            "fully operational with it disabled."
        ),
    }

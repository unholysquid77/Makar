"""Provenance detector -- the manifest checked against the chain (spec 21-23).

Four findings, each with a different meaning:

``RECORD_HASH_MISMATCH``
    The record is committed, but its current content hashes differently from
    what was committed. The record was **edited** after observation. This is
    the hardest evidence in the system and carries the highest fusion weight.

``RECORD_NOT_IN_CHAIN``
    The record's event time falls inside the sealed window, yet no commitment
    exists for it. It was **inserted** after the fact -- a duplicate or a
    fabrication. Crucially this is only raised *inside* the sealed window;
    records in the uncommitted tail are expected to be absent and are left
    alone.

``NODE_STATE_DIVERGENCE``
    A node's local chain commits a different hash for this record than the
    majority does. Someone rewrote a node's history to endorse an edit.

Deleted records
    Commitments with no surviving row. A deletion has no record to attach
    evidence to, so it is reported through ``ctx.inferred_deletions``.

**Which chain is trusted.** The detector reads the chain the *majority* of
nodes agree on, never a single node's. That is what stops the compromised
node from laundering its own edits: node C's rewritten chain endorses the
attacker's hashes, but it is outvoted 3-1, so the comparison still finds the
mismatch, and C's disagreement becomes additional evidence in its own right.

**Confidence scales with agreement.** Chain evidence is weighted by the
fraction of nodes agreeing on the majority root. Unanimity is near-certain;
a bare majority is not, and the severity says so.
"""

from __future__ import annotations

from core.detection.base import AnalysisContext, register_detector
from core.models import Evidence
from core.types import EVIDENCE_CODE_TYPE, EvidenceCode, EvidenceType

ENGINE = "provenance"


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


class ProvenanceEngine:
    name = "provenance"

    @staticmethod
    def _records_with_lost_hashed_fields(ctx: AnalysisContext) -> dict[str, set[str]]:
        """Records where normalisation could not recover a *hashed* field.

        A hash commits to a fixed field set. If one of those fields arrived
        blank or unparseable, the current payload necessarily hashes
        differently from the commitment -- whether or not anyone edited it.
        Knowing which records are in that position is what lets the mismatch
        check stay honest.
        """
        from core.models import HASHED_FIELDS

        hashed = set(HASHED_FIELDS)
        out: dict[str, set[str]] = {}
        for item in ctx.prior_evidence:
            field = item.details.get("field")
            if field not in hashed:
                continue
            # Either the value was absent, or the parser gave up on it.
            if item.details.get("nullable") or item.details.get("recovered") is False:
                out.setdefault(item.record_id, set()).add(str(field))
        return out

    def run(self, ctx: AnalysisContext) -> list[Evidence]:
        chain = ctx.chain
        if chain is None or getattr(chain, "height", 0) == 0:
            return []

        cfg = ctx.cfg
        mismatch_severity = cfg.float_("detection.blockchain.hash_mismatch_severity")
        divergence_severity = cfg.float_("detection.blockchain.node_divergence_severity")

        # How much the network agrees determines how much the chain is worth.
        agreement = 1.0
        divergent_nodes: list[str] = []
        divergent_records: set[str] = set()
        if ctx.consistency is not None:
            agreeing = list(getattr(ctx.consistency, "agreeing_nodes", []) or [])
            divergent_nodes = list(getattr(ctx.consistency, "divergent_nodes", []) or [])
            total = len(agreeing) + len(divergent_nodes)
            agreement = (len(agreeing) / total) if total else 1.0
            divergent_records = set(getattr(ctx.consistency, "affected_records", []) or [])

        out: list[Evidence] = []
        committed_ids = chain.committed_record_ids()
        _covered_from, covered_to = chain.covered_time_range()
        lost_fields = self._records_with_lost_hashed_fields(ctx)

        # --- chain integrity itself ---
        verification = chain.verify()
        if not verification.valid:
            # The majority chain should never fail this. If it does, every
            # downstream chain finding is suspect and we say so once rather
            # than silently trusting a broken log.
            for block_id in verification.problems()[:10]:
                out.append(
                    _ev(
                        "__system__",
                        EvidenceCode.BLOCK_CHAIN_BROKEN,
                        0.0,
                        f"Majority provenance chain failed verification: {block_id}. "
                        f"Chain-derived evidence should be treated as unreliable.",
                        detail=block_id,
                    )
                )

        for rec in ctx.records:
            committed = chain.committed_hash(rec.record_id)
            block_id = chain.block_of(rec.record_id)
            when = rec.effective_time()

            if committed is not None:
                current = rec.content_hash()
                if current != committed:
                    lost = lost_fields.get(rec.record_id)
                    if lost:
                        # The mismatch is real but *uninformative*: one of the
                        # hashed fields was lost in the export, and a hash
                        # cannot distinguish "value lost" from "value edited".
                        # Reporting this at full strength would convict every
                        # record with a blank cell, so the honest answer is to
                        # declare the test inconclusive and let the other
                        # layers decide.
                        out.append(
                            _ev(
                                rec.record_id,
                                EvidenceCode.RECORD_HASH_MISMATCH,
                                0.22 * agreement,
                                f"Content hash does not match the commitment in "
                                f"{block_id}, but {', '.join(sorted(lost))} "
                                f"{'was' if len(lost) == 1 else 'were'} lost in the "
                                f"export and {'is' if len(lost) == 1 else 'are'} part "
                                f"of the hashed payload. The mismatch is explained by "
                                f"the missing value, so this check is INCONCLUSIVE "
                                f"for this record rather than evidence of editing.",
                                block_id=block_id,
                                committed_hash=committed,
                                current_hash=current,
                                lost_hashed_fields=sorted(lost),
                                inconclusive=True,
                                network_agreement=round(agreement, 3),
                            )
                        )
                    else:
                        out.append(
                            _ev(
                                rec.record_id,
                                EvidenceCode.RECORD_HASH_MISMATCH,
                                mismatch_severity * agreement,
                                f"Content hash {current[:16]} does not match the hash "
                                f"committed in {block_id} ({committed[:16]}), and every "
                                f"hashed field parsed cleanly. The record has been "
                                f"altered since it was observed.",
                                block_id=block_id,
                                committed_hash=committed,
                                current_hash=current,
                                inconclusive=False,
                                network_agreement=round(agreement, 3),
                            )
                        )
            elif when is not None and covered_to is not None and when <= covered_to:
                # Inside the sealed window with no commitment: inserted.
                out.append(
                    _ev(
                        rec.record_id,
                        EvidenceCode.RECORD_NOT_IN_CHAIN,
                        0.88 * agreement,
                        f"Event time {when.isoformat()} falls inside the sealed "
                        f"provenance window (through {covered_to.isoformat()}), but "
                        f"no commitment for this record exists in the chain. The "
                        f"record was inserted after the fact.",
                        event_time=when.isoformat(),
                        sealed_through=covered_to.isoformat(),
                        chain_height=chain.height,
                        network_agreement=round(agreement, 3),
                    )
                )
            # else: uncommitted tail -- the chain has nothing to say.

            if rec.record_id in divergent_records:
                out.append(
                    _ev(
                        rec.record_id,
                        EvidenceCode.NODE_STATE_DIVERGENCE,
                        divergence_severity * agreement,
                        f"Node(s) {', '.join(divergent_nodes)} commit a different "
                        f"hash for this record than the network majority. A node's "
                        f"local history was rewritten to endorse this version.",
                        divergent_nodes=divergent_nodes,
                        network_agreement=round(agreement, 3),
                    )
                )

        # --- deletions: commitments with no surviving row ---
        present = set(ctx.by_id)
        for record_id in sorted(committed_ids - present):
            ctx.inferred_deletions.append(
                {
                    "record_id": record_id,
                    "source": "provenance",
                    "block_id": chain.block_of(record_id),
                    "committed_hash": chain.committed_hash(record_id),
                    "confidence": round(0.96 * agreement, 3),
                    "reason": (
                        "A commitment for this record exists in the provenance "
                        "chain but no row for it survives in the manifest."
                    ),
                }
            )

        return [e for e in out if e.severity > 0.0 or e.code == EvidenceCode.BLOCK_CHAIN_BROKEN]


register_detector(ProvenanceEngine())

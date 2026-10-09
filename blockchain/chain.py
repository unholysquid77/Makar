"""The provenance chain itself.

A :class:`Chain` is an ordered list of sealed blocks plus the indexes the
provenance detector needs: record id -> committed hash, and record id ->
block id.

Sealing policy (see design decision D9): blocks are sealed over the records
that existed *at observation time*, in event-time order, up to
``blockchain.sealed_fraction`` of the timeline. Records after the cut-off are
genuinely uncommitted — the chain has nothing to say about them, and the
forensic engines must carry them unaided.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from blockchain.block import (
    GENESIS_PREVIOUS_HASH,
    build_block,
    header_digest,
    merkle_root,
    sha256_hex,
)
from core.models import Block, ManifestRecord, RouteManifest


@dataclass
class ChainVerification:
    """Result of verifying a chain's internal integrity."""

    valid: bool = True
    broken_links: list[str] = field(default_factory=list)
    bad_block_hashes: list[str] = field(default_factory=list)
    bad_manifest_roots: list[str] = field(default_factory=list)
    bad_state_roots: list[str] = field(default_factory=list)

    def problems(self) -> list[str]:
        out: list[str] = []
        out += [f"broken link at {b}" for b in self.broken_links]
        out += [f"bad block hash at {b}" for b in self.bad_block_hashes]
        out += [f"bad manifest root at {b}" for b in self.bad_manifest_roots]
        out += [f"bad state root at {b}" for b in self.bad_state_roots]
        return out


def route_manifest_hash(manifest: RouteManifest) -> str:
    """Stable hash over a container's itinerary.

    Commits the *shape* of the journey -- ports and their times -- so a
    rewritten itinerary is caught even if every individual record still
    hashes correctly.
    """
    parts = [manifest.container_id]
    for event in manifest.events:
        parts.append(
            "|".join(
                (
                    event.port,
                    event.arrival.replace(microsecond=0).isoformat() if event.arrival else "",
                    event.departure.replace(microsecond=0).isoformat()
                    if event.departure
                    else "",
                )
            )
        )
    return sha256_hex("::".join(parts))


class Chain:
    """An append-only sequence of sealed provenance blocks."""

    def __init__(self, blocks: list[Block] | None = None) -> None:
        self.blocks: list[Block] = blocks or []
        self._hash_by_record: dict[str, str] = {}
        self._block_by_record: dict[str, str] = {}
        self._reindex()

    # -- construction -----------------------------------------------------

    def _reindex(self) -> None:
        self._hash_by_record.clear()
        self._block_by_record.clear()
        for block in self.blocks:
            for record_id, record_hash in zip(
                block.record_ids, block.record_hashes, strict=False
            ):
                self._hash_by_record[record_id] = record_hash
                self._block_by_record[record_id] = block.header.block_id

    @classmethod
    def build(
        cls,
        records: list[ManifestRecord],
        route_manifests: dict[str, RouteManifest],
        *,
        records_per_block: int,
        genesis_timestamp: datetime,
        sealed_fraction: float = 1.0,
    ) -> Chain:
        """Seal ``records`` into blocks in event-time order.

        ``sealed_fraction`` truncates the chain to a prefix of the timeline,
        modelling blocks that have not reached consensus yet.
        """
        ordered = sorted(
            records, key=lambda r: (r.effective_time() or genesis_timestamp, r.record_id)
        )
        cutoff = max(0, int(len(ordered) * max(0.0, min(1.0, sealed_fraction))))
        ordered = ordered[:cutoff]

        blocks: list[Block] = []
        previous_hash = GENESIS_PREVIOUS_HASH
        previous_state_root = GENESIS_PREVIOUS_HASH
        index = 0

        for start in range(0, len(ordered), records_per_block):
            chunk = ordered[start : start + records_per_block]
            if not chunk:
                continue
            record_ids = [r.record_id for r in chunk]
            record_hashes = [r.content_hash() for r in chunk]

            containers = sorted({r.container_id for r in chunk if r.container_id})
            route_hashes = [
                route_manifest_hash(route_manifests[c]) for c in containers if c in route_manifests
            ]

            timestamp = max(
                (r.effective_time() for r in chunk if r.effective_time()),
                default=genesis_timestamp,
            )
            block = build_block(
                index=index,
                timestamp=timestamp,
                previous_hash=previous_hash,
                previous_state_root=previous_state_root,
                record_ids=record_ids,
                record_hashes=record_hashes,
                route_hashes=route_hashes,
            )
            blocks.append(block)
            previous_hash = block.header.block_hash
            previous_state_root = block.header.state_root
            index += 1

        return cls(blocks)

    # -- queries ----------------------------------------------------------

    @property
    def height(self) -> int:
        return len(self.blocks)

    @property
    def state_root(self) -> str:
        return self.blocks[-1].header.state_root if self.blocks else GENESIS_PREVIOUS_HASH

    @property
    def latest_block_id(self) -> str | None:
        return self.blocks[-1].header.block_id if self.blocks else None

    def committed_hash(self, record_id: str) -> str | None:
        """Hash committed for ``record_id``, or ``None`` if uncommitted."""
        return self._hash_by_record.get(record_id)

    def block_of(self, record_id: str) -> str | None:
        return self._block_by_record.get(record_id)

    def committed_record_ids(self) -> set[str]:
        return set(self._hash_by_record)

    def block(self, block_id: str) -> Block | None:
        for block in self.blocks:
            if block.header.block_id == block_id:
                return block
        return None

    def covered_time_range(self) -> tuple[datetime | None, datetime | None]:
        """Event-time span the sealed blocks cover."""
        if not self.blocks:
            return (None, None)
        return (self.blocks[0].header.timestamp, self.blocks[-1].header.timestamp)

    # -- integrity --------------------------------------------------------

    def verify(self) -> ChainVerification:
        """Re-derive every commitment and report what does not reconcile."""
        result = ChainVerification()
        previous_hash = GENESIS_PREVIOUS_HASH
        previous_state_root = GENESIS_PREVIOUS_HASH

        for block in self.blocks:
            header = block.header
            if header.previous_hash != previous_hash:
                result.broken_links.append(header.block_id)
            if merkle_root(block.record_hashes) != header.manifest_root:
                result.bad_manifest_roots.append(header.block_id)
            expected_state = sha256_hex(
                f"{previous_state_root}|{header.manifest_root}|{header.route_root}"
            )
            if expected_state != header.state_root:
                result.bad_state_roots.append(header.block_id)
            if header_digest(header) != header.block_hash:
                result.bad_block_hashes.append(header.block_id)

            previous_hash = header.block_hash
            previous_state_root = header.state_root

        result.valid = not (
            result.broken_links
            or result.bad_block_hashes
            or result.bad_manifest_roots
            or result.bad_state_roots
        )
        return result

    # -- serialisation ----------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "height": self.height,
            "state_root": self.state_root,
            "blocks": [b.model_dump(mode="json") for b in self.blocks],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Chain:
        return cls([Block.model_validate(b) for b in payload.get("blocks", [])])

    def digest(self) -> str:
        """Short fingerprint of the whole chain, for display."""
        return hashlib.sha256(self.state_root.encode()).hexdigest()[:12]

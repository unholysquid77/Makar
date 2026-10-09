"""Virtual distributed nodes (spec 22).

Each node owns a local database view, its own copy of the chain, an identity
(Ed25519 keypair) and a network endpoint. In the default prototype four nodes
run as separate in-process objects; ``scripts/node.py`` runs one as its own
OS process over TCP for the physical-LAN demo (spec 24). Nothing about the
analysis depends on which deployment is in use.

**The compromised node.** Spec 23 asks for an explicit compromised-node
demonstration, and the interesting version of that is not a node with a
corrupt chain — that would be caught by local verification alone. It is a
node whose chain has been rewritten *competently*: record hashes replaced to
match the attacker's edited records, and every root recomputed so the chain
is internally self-consistent and passes its own integrity check.

Such a node cannot be detected in isolation. It is only revealed by comparing
state roots across the network, which is exactly why node consistency is a
separate layer rather than a property of a single chain.
"""

from __future__ import annotations

import random
from typing import Any

from blockchain.block import build_block, node_keypair, sign_block, verify_signature
from blockchain.chain import Chain
from core.models import NodeView
from core.types import NodeStatus


class Node:
    """One participant in the provenance network."""

    def __init__(
        self,
        node_id: str,
        chain: Chain,
        *,
        seed: int,
        endpoint: str = "",
        peers: list[str] | None = None,
    ) -> None:
        self.node_id = node_id
        self.chain = chain
        self.endpoint = endpoint
        self.peers = peers or []
        self.status = NodeStatus.HEALTHY
        self.seed = seed
        self.signing_seed, self.verify_key = node_keypair(node_id, seed)
        #: Blocks this node rewrote, populated only when compromised. Held so
        #: the report can say which blocks to distrust; the *detector* never
        #: reads it, and learns the same thing from state-root comparison.
        self.rewritten_blocks: list[str] = []
        self.rewritten_records: list[str] = []

    # -- identity ---------------------------------------------------------

    def sign_all(self) -> None:
        """Co-sign every block in the local chain."""
        for block in self.chain.blocks:
            signature = sign_block(block, self.node_id, self.signing_seed)
            if signature:
                block.node_signatures[self.node_id] = signature

    def verify_block_signature(self, block_index: int, node_id: str, verify_key: bytes) -> bool:
        if block_index >= len(self.chain.blocks):
            return False
        return verify_signature(self.chain.blocks[block_index], node_id, verify_key)

    # -- handshake (spec 24) ----------------------------------------------

    def hello(self) -> dict[str, Any]:
        """The HELLO payload: who I am and what I believe."""
        return {
            "message": "HELLO",
            "node_id": self.node_id,
            "version": "1.0",
            "latest_block": self.chain.latest_block_id,
            "height": self.chain.height,
            "state_root": self.chain.state_root,
            "endpoint": self.endpoint,
        }

    def receive_hello(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Respond to a peer's HELLO with our own view and the delta."""
        theirs = payload.get("state_root", "")
        return {
            "message": "HELLO_ACK",
            "node_id": self.node_id,
            "version": "1.0",
            "latest_block": self.chain.latest_block_id,
            "height": self.chain.height,
            "state_root": self.chain.state_root,
            "agrees": theirs == self.chain.state_root,
            "height_delta": self.chain.height - int(payload.get("height", 0) or 0),
        }

    # -- state ------------------------------------------------------------

    def view(self) -> NodeView:
        return NodeView(
            node_id=self.node_id,
            status=self.status,
            endpoint=self.endpoint,
            peers=list(self.peers),
            height=self.chain.height,
            latest_block_id=self.chain.latest_block_id,
            state_root=self.chain.state_root,
            divergent_blocks=list(self.rewritten_blocks),
            divergent_records=list(self.rewritten_records),
        )

    # -- the attack -------------------------------------------------------

    def compromise(
        self,
        replacement_hashes: dict[str, str],
        *,
        max_blocks: int = 3,
        rng: random.Random | None = None,
    ) -> None:
        """Rewrite this node's chain to endorse altered records.

        ``replacement_hashes`` maps record id -> the hash the attacker wants
        committed (i.e. the hash of their edited record). Affected blocks are
        rebuilt from the front so every root and link recomputes, leaving the
        local chain internally valid.
        """
        rng = rng or random.Random(self.seed)
        targets = [
            block
            for block in self.chain.blocks
            if any(rid in replacement_hashes for rid in block.record_ids)
        ]
        if not targets:
            return
        if len(targets) > max_blocks:
            targets = rng.sample(targets, k=max_blocks)
        target_ids = {b.header.block_id for b in targets}

        rebuilt: list = []
        previous_hash = "0" * 64
        previous_state_root = "0" * 64

        for block in self.chain.blocks:
            header = block.header
            record_hashes = list(block.record_hashes)
            changed: list[str] = []

            if header.block_id in target_ids:
                for i, record_id in enumerate(block.record_ids):
                    new_hash = replacement_hashes.get(record_id)
                    if new_hash and new_hash != record_hashes[i]:
                        record_hashes[i] = new_hash
                        changed.append(record_id)

            # Route roots are left untouched: the attacker rewrote record
            # hashes but not the itinerary commitments. That asymmetry is
            # realistic and gives the consistency checker a second handle.
            new_block = build_block(
                index=header.index,
                timestamp=header.timestamp,
                previous_hash=previous_hash,
                previous_state_root=previous_state_root,
                record_ids=block.record_ids,
                record_hashes=record_hashes,
                route_hashes=[],
            )
            new_block.header.route_root = header.route_root
            # Recompute the roots that depend on route_root.
            from blockchain.block import compute_state_root, header_digest

            new_block.header.state_root = compute_state_root(
                previous_state_root, new_block.header.manifest_root, header.route_root
            )
            new_block.header.block_hash = header_digest(new_block.header)
            new_block.node_signatures = {}

            if changed:
                self.rewritten_blocks.append(header.block_id)
                self.rewritten_records.extend(changed)

            rebuilt.append(new_block)
            previous_hash = new_block.header.block_hash
            previous_state_root = new_block.header.state_root

        self.chain = Chain(rebuilt)
        self.sign_all()
        self.status = NodeStatus.DIVERGENT

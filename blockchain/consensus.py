"""Node consistency and majority agreement (spec 23).

The procedure is the one the spec describes: collect every node's state root,
take the majority, and call the rest divergent::

    A = X   B = X   C = Y   D = X     ->   Node C is inconsistent

Then localise it. Comparing state roots alone says *that* a node disagrees;
walking the two chains block by block says *where*, and comparing the record
hashes inside the first differing block says *which records* the divergence
is about. That localisation is what makes the finding actionable — the
provenance detector attributes ``NODE_STATE_DIVERGENCE`` to those specific
records rather than to the whole manifest.

A deliberate limitation, stated plainly: with four nodes and one attacker
this works. With two of four compromised there is no majority, and with three
the majority is *wrong*. The checker reports its own confidence as the
agreeing fraction so a reader can see how much weight the result deserves,
and `fusion` treats a bare majority as weaker evidence than unanimity.
"""

from __future__ import annotations

from collections import Counter

from blockchain.node import Node
from core.models import ConsistencyReport
from core.types import NodeStatus


class ConsistencyChecker:
    """Compares state across the node set and localises disagreement."""

    def __init__(self, nodes: list[Node]) -> None:
        self.nodes = nodes

    # -- majority ---------------------------------------------------------

    def majority_state_root(self) -> tuple[str, int]:
        """Most common state root and how many nodes hold it."""
        online = [n for n in self.nodes if n.status is not NodeStatus.OFFLINE]
        if not online:
            return ("", 0)
        counts = Counter(n.chain.state_root for n in online)
        root, votes = counts.most_common(1)[0]
        return (root, votes)

    def agreement_fraction(self) -> float:
        online = [n for n in self.nodes if n.status is not NodeStatus.OFFLINE]
        if not online:
            return 0.0
        _root, votes = self.majority_state_root()
        return votes / len(online)

    # -- localisation -----------------------------------------------------

    def _first_divergent_block(self, node: Node, reference: Node) -> int | None:
        """Index of the first block where ``node`` and ``reference`` differ."""
        limit = min(node.chain.height, reference.chain.height)
        for i in range(limit):
            if node.chain.blocks[i].header.state_root != reference.chain.blocks[i].header.state_root:
                return i
        if node.chain.height != reference.chain.height:
            return limit
        return None

    def _differing_records(self, node: Node, reference: Node, block_index: int) -> list[str]:
        """Record ids whose committed hash differs inside one block."""
        if block_index >= node.chain.height or block_index >= reference.chain.height:
            return []
        theirs = node.chain.blocks[block_index]
        ours = reference.chain.blocks[block_index]
        mine = dict(zip(theirs.record_ids, theirs.record_hashes, strict=False))
        base = dict(zip(ours.record_ids, ours.record_hashes, strict=False))
        return sorted(
            rid for rid, digest in mine.items() if base.get(rid) not in (None, digest)
        )

    def check(self) -> ConsistencyReport:
        """Full consistency report across the node set."""
        majority_root, _votes = self.majority_state_root()

        agreeing = [n for n in self.nodes if n.chain.state_root == majority_root]
        divergent = [
            n
            for n in self.nodes
            if n.chain.state_root != majority_root and n.status is not NodeStatus.OFFLINE
        ]
        reference = agreeing[0] if agreeing else None

        affected_blocks: list[str] = []
        affected_records: list[str] = []

        for node in divergent:
            node.status = NodeStatus.DIVERGENT
            if reference is None:
                continue
            start = self._first_divergent_block(node, reference)
            if start is None:
                continue
            for index in range(start, min(node.chain.height, reference.chain.height)):
                block_id = node.chain.blocks[index].header.block_id
                differing = self._differing_records(node, reference, index)
                if differing:
                    if block_id not in affected_blocks:
                        affected_blocks.append(block_id)
                    affected_records.extend(differing)

        for node in agreeing:
            if node.status is NodeStatus.DIVERGENT:
                node.status = NodeStatus.HEALTHY

        return ConsistencyReport(
            majority_state_root=majority_root,
            agreeing_nodes=[n.node_id for n in agreeing],
            divergent_nodes=[n.node_id for n in divergent],
            affected_blocks=affected_blocks,
            affected_records=sorted(set(affected_records)),
            nodes=[n.view() for n in self.nodes],
        )

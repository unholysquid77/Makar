"""The virtual node network (spec 22-24).

Builds the four-node topology from config, gives each node its own copy of the
chain, optionally compromises the nodes named in ``nodes.compromised``, and
runs the handshake / sync / verify / join sequence of spec 24.

Topology from the default config::

                 Node A
                /      \\
            Node B ---- Node C
                \\      /
                 Node D

Nodes are separate objects here and separate OS processes under
``scripts/node.py``; the analysis is identical either way, which is the
property spec 24 asks for ("must remain fully functional with all nodes
virtualized on one machine").
"""

from __future__ import annotations

import copy
import random
from typing import Any

from blockchain.chain import Chain
from blockchain.consensus import ConsistencyChecker
from blockchain.node import Node
from core.config import MakarConfig
from core.models import ConsistencyReport


class VirtualNetwork:
    """A set of nodes sharing a provenance chain."""

    def __init__(self, nodes: list[Node]) -> None:
        self.nodes = nodes
        self._by_id = {n.node_id: n for n in nodes}

    # -- construction -----------------------------------------------------

    @classmethod
    def build(
        cls,
        cfg: MakarConfig,
        chain: Chain,
        *,
        seed: int,
        replacement_hashes: dict[str, str] | None = None,
    ) -> VirtualNetwork:
        """Create the configured node set from one canonical chain.

        ``replacement_hashes`` maps record id -> the hash an attacker wants
        committed. When supplied, the nodes listed in ``nodes.compromised``
        rewrite their local chains to endorse those records.
        """
        node_ids = [str(n) for n in cfg.list_("nodes.ids")]
        topology: dict[str, Any] = cfg.get("nodes.topology", {}) or {}
        base_port = cfg.int_("nodes.base_port")
        compromised = {str(n) for n in cfg.list_("nodes.compromised", [])}
        should_sign = cfg.bool_("blockchain.sign_blocks", True)

        nodes: list[Node] = []
        for offset, node_id in enumerate(node_ids):
            node = Node(
                node_id,
                Chain(copy.deepcopy(chain.blocks)),
                seed=seed,
                endpoint=f"127.0.0.1:{base_port + offset}",
                peers=[str(p) for p in topology.get(node_id, [])],
            )
            if should_sign:
                node.sign_all()
            nodes.append(node)

        if replacement_hashes:
            for node in nodes:
                if node.node_id in compromised:
                    node.compromise(
                        replacement_hashes,
                        max_blocks=3,
                        rng=random.Random(seed + ord(node.node_id[0])),
                    )

        return cls(nodes)

    # -- access -----------------------------------------------------------

    def node(self, node_id: str) -> Node | None:
        return self._by_id.get(node_id)

    @property
    def healthy_chain(self) -> Chain:
        """The chain held by the majority -- the one evidence should trust."""
        report = self.check_consistency()
        for node in self.nodes:
            if node.node_id in report.agreeing_nodes:
                return node.chain
        return self.nodes[0].chain

    # -- protocol ---------------------------------------------------------

    def handshake(self, initiator: str, responder: str) -> dict[str, Any]:
        """One HELLO / HELLO_ACK exchange (spec 24)."""
        a, b = self._by_id.get(initiator), self._by_id.get(responder)
        if a is None or b is None:
            return {"error": "unknown node"}
        hello = a.hello()
        ack = b.receive_hello(hello)
        return {"hello": hello, "ack": ack}

    def bootstrap(self) -> list[dict[str, Any]]:
        """Run the full join sequence across the configured topology.

        handshake -> metadata exchange -> chain synchronisation ->
        state verification -> network join.
        """
        log: list[dict[str, Any]] = []
        for node in self.nodes:
            for peer_id in node.peers:
                exchange = self.handshake(node.node_id, peer_id)
                ack = exchange.get("ack", {})
                log.append(
                    {
                        "from": node.node_id,
                        "to": peer_id,
                        "agrees": bool(ack.get("agrees")),
                        "height_delta": ack.get("height_delta"),
                        "their_state_root": (ack.get("state_root") or "")[:16],
                        "stage": "handshake",
                    }
                )
        return log

    def check_consistency(self) -> ConsistencyReport:
        return ConsistencyChecker(self.nodes).check()

    def verify_all(self) -> dict[str, list[str]]:
        """Each node's local integrity check.

        A competently compromised node passes this -- its chain is internally
        consistent. That is the point: local verification is necessary but not
        sufficient, and only cross-node comparison finds it.
        """
        return {n.node_id: n.chain.verify().problems() for n in self.nodes}

    def summary(self) -> dict[str, Any]:
        report = self.check_consistency()
        return {
            "nodes": [n.view().model_dump(mode="json") for n in self.nodes],
            "majority_state_root": report.majority_state_root,
            "agreeing": report.agreeing_nodes,
            "divergent": report.divergent_nodes,
            "agreement_fraction": round(
                ConsistencyChecker(self.nodes).agreement_fraction(), 3
            ),
            "affected_blocks": report.affected_blocks,
            "affected_records": report.affected_records,
            "local_verification": self.verify_all(),
        }

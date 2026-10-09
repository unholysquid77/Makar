"""Permissioned, application-level provenance chain (spec 21-24).

This is a tamper-evident log, not a cryptocurrency. There is no mining, no
token, no economic consensus — four known, named nodes co-sign blocks and
agree by majority on a state root.

The security property that matters forensically: a block header commits to a
Merkle root over its record hashes, and each header commits to the previous
header's hash. Editing a historical record therefore changes its record hash,
which changes the Merkle root, which changes that block's hash, which breaks
every subsequent link. An attacker who rewrites the manifest cannot quietly
rewrite the chain unless they control enough nodes.

Blocks store **hashes only**. The chain can prove a record changed; it cannot
say what the record used to contain. Reconstruction is therefore entirely the
forensic engines' problem.
"""

from blockchain.block import Block, build_block, merkle_root, sign_block, verify_signature
from blockchain.chain import Chain, ChainVerification
from blockchain.consensus import ConsistencyChecker
from blockchain.network import VirtualNetwork
from blockchain.node import Node

__all__ = [
    "Block",
    "Chain",
    "ChainVerification",
    "ConsistencyChecker",
    "Node",
    "VirtualNetwork",
    "build_block",
    "merkle_root",
    "sign_block",
    "verify_signature",
]

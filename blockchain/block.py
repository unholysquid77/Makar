"""Block construction, Merkle roots and Ed25519 signatures (spec 21.1).

Header layout follows the spec exactly::

    Block ID
    Timestamp
    Previous Hash
    Manifest Root Hash
    Route Root Hash
    State Root Hash
    Record Hashes
    Node Signatures

The three roots serve different purposes and are deliberately separate:

* ``manifest_root`` -- Merkle root over this block's record hashes. Supports a
  per-record inclusion proof, which is what lets the provenance detector say
  "this exact record was committed" rather than only "something in this block
  changed".
* ``route_root`` -- Merkle root over the route histories touched by the block,
  so a rewritten *itinerary* is caught even when every individual record
  still hashes correctly.
* ``state_root`` -- cumulative: ``H(previous_state_root || manifest_root ||
  route_root)``. This is the single value nodes compare to decide whether they
  agree (spec 23). One differing record anywhere in history gives a different
  state root forever after.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from core.models import Block, BlockHeader

GENESIS_PREVIOUS_HASH = "0" * 64


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def merkle_root(leaves: list[str]) -> str:
    """Merkle root over hex-encoded leaf hashes.

    An empty list yields the all-zero hash. An odd level duplicates its last
    node, which is the conventional construction.
    """
    if not leaves:
        return GENESIS_PREVIOUS_HASH
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256_hex(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_proof(leaves: list[str], index: int) -> list[tuple[str, str]]:
    """Inclusion proof for ``leaves[index]`` as ``(side, hash)`` pairs.

    Lets the provenance layer prove a specific record was committed without
    re-hashing the whole block.
    """
    if not leaves or index < 0 or index >= len(leaves):
        return []
    proof: list[tuple[str, str]] = []
    level = list(leaves)
    position = index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sibling = position + 1 if position % 2 == 0 else position - 1
        side = "right" if position % 2 == 0 else "left"
        proof.append((side, level[sibling]))
        level = [sha256_hex(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        position //= 2
    return proof


def verify_merkle_proof(leaf: str, proof: list[tuple[str, str]], root: str) -> bool:
    computed = leaf
    for side, sibling in proof:
        computed = (
            sha256_hex(computed + sibling) if side == "right" else sha256_hex(sibling + computed)
        )
    return computed == root


def header_digest(header: BlockHeader) -> str:
    """Hash over the header's committing fields.

    ``block_hash`` and ``node_signatures`` are excluded: a hash cannot commit
    to itself, and signatures are over the digest rather than part of it.
    """
    payload: dict[str, Any] = {
        "block_id": header.block_id,
        "index": header.index,
        "timestamp": header.timestamp.replace(microsecond=0).isoformat(),
        "previous_hash": header.previous_hash,
        "manifest_root": header.manifest_root,
        "route_root": header.route_root,
        "state_root": header.state_root,
        "record_count": header.record_count,
    }
    return sha256_hex(json.dumps(payload, sort_keys=True))


def compute_state_root(previous_state_root: str, manifest_root: str, route_root: str) -> str:
    """Cumulative state commitment -- the value nodes compare (spec 23)."""
    return sha256_hex(f"{previous_state_root}|{manifest_root}|{route_root}")


def build_block(
    *,
    index: int,
    timestamp: datetime,
    previous_hash: str,
    previous_state_root: str,
    record_ids: list[str],
    record_hashes: list[str],
    route_hashes: list[str],
) -> Block:
    """Assemble a sealed block from committed record hashes."""
    manifest_root = merkle_root(record_hashes)
    route_root = merkle_root(route_hashes)
    state_root = compute_state_root(previous_state_root, manifest_root, route_root)

    header = BlockHeader(
        block_id=f"BLOCK_{index:04d}",
        index=index,
        timestamp=timestamp,
        previous_hash=previous_hash,
        manifest_root=manifest_root,
        route_root=route_root,
        state_root=state_root,
        record_count=len(record_hashes),
    )
    header.block_hash = header_digest(header)
    return Block(header=header, record_hashes=record_hashes, record_ids=list(record_ids))


# ======================================================================
# Signatures (spec 33: "Ed25519 signatures (optional)")
# ======================================================================


def node_keypair(node_id: str, seed: int) -> tuple[bytes, bytes]:
    """Deterministic Ed25519 keypair for a virtual node.

    Derived from the world seed so a run is reproducible. Real deployments
    would use generated keys held per node; determinism here is what lets the
    demo be replayed exactly.
    """
    try:
        from nacl.signing import SigningKey
    except ImportError:  # pragma: no cover - optional dependency
        return b"", b""
    material = hashlib.sha256(f"makar|{seed}|{node_id}".encode()).digest()
    key = SigningKey(material)
    return bytes(key), bytes(key.verify_key)


def sign_block(block: Block, node_id: str, signing_seed: bytes) -> str:
    """Sign a block's hash as ``node_id``; returns a hex signature."""
    if not signing_seed:
        return ""
    try:
        from nacl.signing import SigningKey
    except ImportError:  # pragma: no cover
        return ""
    key = SigningKey(signing_seed)
    return key.sign(block.header.block_hash.encode("utf-8")).signature.hex()


def verify_signature(block: Block, node_id: str, verify_key: bytes) -> bool:
    """Verify ``node_id``'s signature over the block hash."""
    signature = block.node_signatures.get(node_id)
    if not signature or not verify_key:
        return False
    try:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey
    except ImportError:  # pragma: no cover
        return False
    try:
        VerifyKey(verify_key).verify(
            block.header.block_hash.encode("utf-8"), bytes.fromhex(signature)
        )
    except (BadSignatureError, ValueError):
        return False
    return True

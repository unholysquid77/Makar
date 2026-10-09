"""Unit tests for the parsing, geometry, statistics and provenance layers."""

from __future__ import annotations

import math
import random
from datetime import datetime, timedelta

import pytest

from core.config import ConfigError, load_config
from core.geo import haversine_km, required_speed_knots, sea_distance_nm
from core.models import ManifestRecord
from core.normalization.parsers import is_blank, parse_float, parse_int, parse_timestamp
from core.stats import mad, median, robust_sigma, robust_z, severity_from_ratio

# ======================================================================
# Parsers
# ======================================================================

CANONICAL = datetime(2026, 1, 3, 4, 0, 0)


@pytest.mark.parametrize(
    "text",
    [
        "2026-01-03T04:00:00Z",
        "2026-01-03T04:00:00",
        "2026-01-03 04:00:00",
        "2026-01-03T04:00:00.000Z",
        "2026-01-03T04:00:00+00:00",
        "01/03/2026 04:00:00",
        "03-01-2026 04:00:00",
        "1767412800",
    ],
)
def test_every_timestamp_format_parses_to_the_same_instant(text: str) -> None:
    """All eight export formats must agree, including the day/month-first pair.

    The epoch case is the one that bit us: ``dt.timestamp()`` treats a naive
    datetime as machine-local, which shifted every epoch value by the host
    timezone offset and silently corrupted the generated dataset.
    """
    parsed, _note = parse_timestamp(text)
    assert parsed == CANONICAL, f"{text!r} parsed to {parsed}"


def test_day_first_is_disambiguated_when_the_day_exceeds_twelve() -> None:
    parsed, note = parse_timestamp("25-12-2026 11:30:00")
    assert parsed == datetime(2026, 12, 25, 11, 30)
    assert note == "dash_dayfirst"


@pytest.mark.parametrize(
    "text,expected",
    [
        ("12500.5", 12500.5),
        ("12,500.50", 12500.5),
        ("  12500.50  ", 12500.5),
        ("12500.50 kg", 12500.5),
        ("1.2500000000e+04", 12500.0),
        ("$1,250.00", 1250.0),
    ],
)
def test_numeric_formats_are_lossless(text: str, expected: float) -> None:
    parsed, _note = parse_float(text)
    assert parsed == pytest.approx(expected)


@pytest.mark.parametrize(
    "token", ["", "-", "--", "?", "N/A", "n/a", "NULL", "null", "none", "unknown", "nan"]
)
def test_blank_tokens_are_absent_not_unknown(token: str) -> None:
    """A blank cell must never read as a reference to a nonexistent entity.

    The first implementation reported ``vessel_id = "N/A"`` as *"Vessel 'N/A'
    does not exist in the world model"* at severity 0.68 -- nineteen confident
    false alarms generated purely by empty cells.
    """
    assert is_blank(token)
    assert parse_float(token) == (None, "blank")
    assert parse_timestamp(token) == (None, "blank")


def test_unparseable_values_are_reported_not_raised() -> None:
    assert parse_float("abc") == (None, "unparseable")
    assert parse_timestamp("garbage") == (None, "unparseable")


def test_integers_tolerate_decimal_notation() -> None:
    assert parse_int("3") == (3, None)
    assert parse_int("3.0") == (3, None)
    assert parse_int("3.4")[0] == 3


# ======================================================================
# Geometry
# ======================================================================


def test_haversine_matches_a_known_distance() -> None:
    """Mumbai to Singapore is about 3,900 km great-circle."""
    mumbai = (19.0760, 72.8777)
    singapore = (1.2644, 103.8200)
    assert haversine_km(mumbai, singapore) == pytest.approx(3900, rel=0.03)


def test_sea_distance_exceeds_great_circle() -> None:
    """No ship sails through land, so the sea lane must be longer.

    Under-estimating here manufactures false IMPOSSIBLE_TRANSIT findings,
    which is the expensive kind of error.
    """
    a, b = (19.0760, 72.8777), (1.2644, 103.8200)
    assert sea_distance_nm(a, b, 1.25) > haversine_km(a, b) / 1.852


def test_required_speed_declines_to_divide_by_zero() -> None:
    """Non-positive elapsed time is a *temporal* contradiction, not a speed."""
    assert required_speed_knots(100.0, 0) is None
    assert required_speed_knots(100.0, -60) is None
    assert required_speed_knots(100.0, 3600) == pytest.approx(100.0)


# ======================================================================
# Robust statistics
# ======================================================================


def test_median_survives_contamination_that_destroys_the_mean() -> None:
    """The baseline is learned from data that was itself tampered with."""
    clean = [10_000.0] * 20
    contaminated = [*clean, 70_000.0, 80_000.0]
    assert median(contaminated) == 10_000.0
    assert sum(contaminated) / len(contaminated) > 15_000.0


def test_robust_sigma_falls_back_when_mad_is_zero() -> None:
    """MAD is exactly zero when most of a sample shares one value.

    Common for ``container_count``. A zero scale would make every non-modal
    value infinitely extreme.
    """
    values = [3.0] * 30 + [4.0, 5.0, 9.0]
    assert mad(values) == 0.0
    assert robust_sigma(values) > 0.0
    assert math.isfinite(robust_z(9.0, values))


def test_robust_z_is_zero_without_spread() -> None:
    """With no spread there is no basis for calling anything an outlier."""
    assert robust_z(5.0, [5.0] * 10) == 0.0


def test_severity_ramp_is_monotonic_and_bounded() -> None:
    previous = -1.0
    for ratio in [0.0, 0.05, 0.1, 0.5, 1.0, 5.0]:
        severity = severity_from_ratio(ratio, 0.02, 1.0, ceiling=0.88)
        assert 0.0 <= severity <= 0.88
        assert severity >= previous
        previous = severity


# ======================================================================
# Record hashing
# ======================================================================


def test_content_hash_ignores_formatting_but_not_content() -> None:
    """Canonicalisation must absorb format noise and nothing else.

    A replay attack that re-exported a row with a different date format is
    still a replay, so the hash has to see through formatting. It must not see
    through a changed weight.
    """
    base = ManifestRecord(
        record_id="R000001",
        weight=12_500.0,
        owner="Acme Freight",
        timestamp=datetime(2026, 1, 3, 4, 0, 0),
    )
    reformatted = base.model_copy(update={"timestamp": datetime(2026, 1, 3, 4, 0, 0, 999)})
    padded = base.model_copy(update={"owner": "  Acme Freight  "})
    altered = base.model_copy(update={"weight": 12_501.0})

    assert base.content_hash() == reformatted.content_hash()
    assert base.content_hash() == padded.content_hash()
    assert base.content_hash() != altered.content_hash()


def test_provenance_fields_are_outside_the_hash() -> None:
    """The hash describes the cargo claim, not where the row was stored."""
    base = ManifestRecord(record_id="R1", weight=1.0)
    moved = base.model_copy(update={"source_node": "C", "block_id": "BLOCK_0007"})
    assert base.content_hash() == moved.content_hash()


# ======================================================================
# Configuration
# ======================================================================


def test_missing_config_path_fails_loudly() -> None:
    """A typo in a detector must not silently disable a check."""
    cfg = load_config()
    with pytest.raises(ConfigError):
        cfg.get("detection.nonexistent.threshold")
    assert cfg.get("detection.nonexistent.threshold", 0.5) == 0.5


def test_overrides_apply_by_dotted_path() -> None:
    cfg = load_config().with_overrides({"fusion.prior_tampering_rate": 0.2})
    assert cfg.float_("fusion.prior_tampering_rate") == 0.2
    assert "override:fusion.prior_tampering_rate=0.2" in cfg.sources


# ======================================================================
# Provenance chain
# ======================================================================


def _chain_fixture(count: int = 120):
    from blockchain.chain import Chain
    from core.models import RouteEvent, RouteManifest

    rng = random.Random(7)
    start = datetime(2026, 1, 1)
    records = [
        ManifestRecord(
            record_id=f"R{i:06d}",
            container_id=f"CONT_{i % 12:06d}",
            weight=round(rng.uniform(5_000, 25_000), 1),
            timestamp=start + timedelta(hours=i),
        )
        for i in range(1, count + 1)
    ]
    manifests = {
        f"CONT_{i:06d}": RouteManifest(
            container_id=f"CONT_{i:06d}",
            events=[RouteEvent(port="PORT_SIN", arrival=start, departure=start + timedelta(hours=8))],
        )
        for i in range(12)
    }
    chain = Chain.build(
        records,
        manifests,
        records_per_block=25,
        genesis_timestamp=start,
        sealed_fraction=1.0,
    )
    return records, chain


def test_chain_verifies_and_links() -> None:
    _records, chain = _chain_fixture()
    verification = chain.verify()
    assert verification.valid, verification.problems()
    assert chain.height == 120 // 25 + (1 if 120 % 25 else 0)


def test_editing_a_record_breaks_its_commitment() -> None:
    """The property the whole provenance layer rests on."""
    records, chain = _chain_fixture()
    target = records[10]
    committed = chain.committed_hash(target.record_id)
    assert committed == target.content_hash()

    tampered = target.model_copy(update={"weight": (target.weight or 0) * 3})
    assert chain.committed_hash(target.record_id) != tampered.content_hash()


def test_sealed_fraction_leaves_a_genuinely_uncommitted_tail() -> None:
    from blockchain.chain import Chain

    records, _ = _chain_fixture()
    partial = Chain.build(
        records,
        {},
        records_per_block=25,
        genesis_timestamp=datetime(2026, 1, 1),
        sealed_fraction=0.5,
    )
    committed = partial.committed_record_ids()
    assert len(committed) < len(records)
    # The tail must be absent, not merely unverified.
    assert records[-1].record_id not in committed


def test_a_compromised_node_passes_its_own_check_but_diverges() -> None:
    """The point of spec 23: local verification is necessary, not sufficient."""
    from blockchain.consensus import ConsistencyChecker
    from blockchain.node import Node

    records, chain = _chain_fixture()
    nodes = [
        Node(name, chain.__class__(list(chain.blocks)), seed=1) for name in ("A", "B", "C", "D")
    ]

    victim = records[5]
    attacker_hash = victim.model_copy(update={"weight": 99_999.0}).content_hash()
    nodes[2].compromise({victim.record_id: attacker_hash}, rng=random.Random(3))

    # Rewritten competently: every root recomputed, so it is internally valid.
    assert nodes[2].chain.verify().valid

    report = ConsistencyChecker(nodes).check()
    assert report.divergent_nodes == ["C"]
    assert sorted(report.agreeing_nodes) == ["A", "B", "D"]
    assert victim.record_id in report.affected_records


def test_merkle_proof_round_trips() -> None:
    from blockchain.block import merkle_proof, merkle_root, sha256_hex, verify_merkle_proof

    leaves = [sha256_hex(f"leaf-{i}") for i in range(9)]
    root = merkle_root(leaves)
    for index, leaf in enumerate(leaves):
        assert verify_merkle_proof(leaf, merkle_proof(leaves, index), root)
    assert not verify_merkle_proof(sha256_hex("forged"), merkle_proof(leaves, 0), root)

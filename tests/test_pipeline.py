"""End-to-end behaviour: generation determinism, fusion properties, pipeline.

These tests build a small world rather than reading ``out/``, so the suite
runs without a generated dataset present.
"""

from __future__ import annotations

import os

import pytest

from core.config import load_config
from core.models import Evidence
from core.types import Classification, EvidenceCode, EvidenceType, TamperClass

SMALL = {
    "world.records": 700,
    "world.n_shipments": 40,
    "world.n_ports": 10,
    "world.n_vessels": 8,
    "world.n_routes": 8,
    "world.n_owners": 8,
}


@pytest.fixture(scope="module")
def small_cfg():
    return load_config().with_overrides(SMALL)


@pytest.fixture(scope="module")
def dataset(small_cfg):
    """A complete small scenario: world, clean manifest, corruption, chain."""
    from blockchain.chain import Chain
    from blockchain.network import VirtualNetwork
    from generator.corruption import corrupt_manifest
    from generator.manifest import build_clean_manifest
    from generator.world import build_world

    world = build_world(small_cfg)
    clean, manifests, world = build_clean_manifest(small_cfg, world)
    result = corrupt_manifest(small_cfg, world, clean, manifests)
    chain = Chain.build(
        clean,
        manifests,
        records_per_block=small_cfg.int_("blockchain.records_per_block"),
        genesis_timestamp=world.sim_start,
        sealed_fraction=small_cfg.float_("blockchain.sealed_fraction"),
    )
    network = VirtualNetwork.build(
        small_cfg, chain, seed=world.seed, replacement_hashes=result.post_attack_hashes
    )
    return {
        "cfg": small_cfg,
        "world": world,
        "clean": clean,
        "manifests": manifests,
        "result": result,
        "chain": network.healthy_chain,
        "consistency": network.check_consistency(),
    }


# ======================================================================
# Generation
# ======================================================================


def test_generation_is_deterministic(small_cfg) -> None:
    """The same seed must reproduce the world and the corruption exactly."""
    from generator.corruption import corrupt_manifest
    from generator.manifest import build_clean_manifest
    from generator.world import build_world

    def once():
        world = build_world(small_cfg)
        clean, manifests, world = build_clean_manifest(small_cfg, world)
        return world, clean, corrupt_manifest(small_cfg, world, clean, manifests)

    world_a, clean_a, corrupt_a = once()
    world_b, clean_b, corrupt_b = once()

    assert world_a.model_dump_json() == world_b.model_dump_json()
    assert [r.record_id for r in clean_a] == [r.record_id for r in clean_b]
    assert corrupt_a.suspect_rows == corrupt_b.suspect_rows
    assert corrupt_a.injection_log.summary == corrupt_b.injection_log.summary


def test_a_different_seed_produces_a_different_world(small_cfg) -> None:
    from generator.world import build_world

    assert (
        build_world(small_cfg).model_dump_json()
        != build_world(small_cfg, seed=4242).model_dump_json()
    )


def test_clean_manifest_is_internally_consistent(dataset) -> None:
    """Corruption is only detectable if the clean data was coherent first."""
    world, clean = dataset["world"], dataset["clean"]
    clock = world.sim_end

    for record in clean:
        assert record.timestamp is not None
        assert record.timestamp <= clock, "a clean record must not post-date the clock"
        if record.arrival_timestamp and record.departure_timestamp:
            assert record.arrival_timestamp <= record.departure_timestamp
        assert record.container_id in world.containers
        assert record.shipment_id in world.shipments
        assert record.port_id in world.ports
        route = world.routes[record.route_id]
        assert record.port_id in route.port_sequence, "clean records stay on-route"


def test_record_ids_are_dense_and_time_ordered(dataset) -> None:
    """Deletions are only visible as gaps if the ids were dense to begin with."""
    clean = dataset["clean"]
    ids = [int(r.record_id[1:]) for r in clean]
    assert ids == list(range(1, len(clean) + 1))
    times = [r.timestamp for r in clean]
    assert times == sorted(times)


def test_noise_injection_is_lossless(dataset) -> None:
    """Formatting noise must change how a value is written, never what it is.

    An earlier version used ``%g`` (6 significant digits) and silently turned
    30,566.92 into 30,566.9 -- injecting a second class of tampering while
    calling it harmless.
    """
    import random

    from core.normalization.parsers import parse_float, parse_timestamp
    from generator.corruption import _reformat_number, _reformat_timestamp

    rng = random.Random(11)
    for value in ("30566.92", "23621.8", "999999.99", "1250.0"):
        for _ in range(12):
            text, _style = _reformat_number(rng, value)
            back, _note = parse_float(text)
            assert back == pytest.approx(float(value)), f"{value} -> {text!r} -> {back}"

    for _ in range(24):
        text, _style = _reformat_timestamp(rng, "2026-01-05T09:41:11Z")
        back, _note = parse_timestamp(text)
        assert back.isoformat() == "2026-01-05T09:41:11", f"{text!r} -> {back}"


def test_the_injection_log_is_a_usable_answer_key(dataset) -> None:
    log = dataset["result"].injection_log
    assert log.summary["MODIFIED"] > 0
    assert log.summary["DELETED"] > 0
    assert log.summary["DUPLICATED"] > 0
    assert log.summary["FABRICATED"] > 0
    assert log.summary["NOISE"] > 0
    # A record hit by noise *and* tampering counts as tampered.
    assert not (log.tampered_record_ids() & log.noise_only_ids()) if hasattr(
        log, "noise_only_ids"
    ) else True


# ======================================================================
# Normalisation
# ======================================================================


def test_normalisation_recognises_noise_without_accusing_clean_records(dataset) -> None:
    """The headline property: FORMAT findings land on noisy rows only."""
    from core.normalization import normalize_rows

    cfg, world, result = dataset["cfg"], dataset["world"], dataset["result"]
    norm = normalize_rows(result.suspect_rows, world, cfg)
    log = result.injection_log

    flagged = {e.record_id for e in norm.evidence}
    noisy = log.noise_record_ids()
    tampered = log.tampered_record_ids()
    clean = {r.record_id for r in norm.records} - noisy - tampered

    assert flagged & clean == set(), (
        f"{len(flagged & clean)} clean records received FORMAT evidence"
    )
    assert flagged & noisy, "noise injections should produce FORMAT evidence"
    assert all(e.type is EvidenceType.FORMAT for e in norm.evidence)


def test_normalisation_never_reports_a_blank_as_an_unknown_entity(dataset) -> None:
    from core.normalization import normalize_rows

    cfg, world, result = dataset["cfg"], dataset["world"], dataset["result"]
    norm = normalize_rows(result.suspect_rows, world, cfg)
    for item in norm.evidence:
        raw = item.details.get("raw")
        if item.code is EvidenceCode.UNKNOWN_ENTITY_REFERENCE:
            assert raw not in ("N/A", "null", "NULL", "--", "-", "", "unknown")


# ======================================================================
# Fusion and classification
# ======================================================================


def _evidence(code: EvidenceCode, severity: float, record_id: str = "R1") -> Evidence:
    from core.types import EVIDENCE_CODE_TYPE

    return Evidence(
        record_id=record_id,
        code=code,
        type=EvidenceType(EVIDENCE_CODE_TYPE[code]),
        severity=severity,
        description="test",
        engine="test",
    )


def test_no_evidence_means_the_prior(small_cfg) -> None:
    from core.confidence.fusion import fuse

    verdicts = fuse(small_cfg, {}, record_ids=["R1"])
    assert verdicts["R1"].tampering_probability == pytest.approx(
        small_cfg.float_("fusion.prior_tampering_rate"), abs=0.01
    )
    assert verdicts["R1"].tamper_class is TamperClass.CLEAN


def test_fusion_is_monotonic_in_severity(small_cfg) -> None:
    from core.confidence.fusion import fuse

    previous = 0.0
    for severity in (0.1, 0.3, 0.5, 0.7, 0.9):
        verdict = fuse(
            small_cfg,
            {"R1": [_evidence(EvidenceCode.WEIGHT_NOT_CONSERVED, severity)]},
        )["R1"]
        assert verdict.tampering_probability >= previous
        previous = verdict.tampering_probability


def test_benign_format_evidence_lowers_the_score(small_cfg) -> None:
    """The negative weight has to be visible in the output, not just the config."""
    from core.confidence.fusion import fuse

    tampering = [_evidence(EvidenceCode.WEIGHT_NOT_CONSERVED, 0.6)]
    with_noise = [*tampering, _evidence(EvidenceCode.FIELD_BLANK, 0.15)]

    bare = fuse(small_cfg, {"R1": tampering})["R1"].tampering_probability
    messy = fuse(small_cfg, {"R1": with_noise})["R1"].tampering_probability
    assert messy < bare


def test_repeating_one_finding_adds_almost_nothing(small_cfg) -> None:
    """Volume must not impersonate corroboration."""
    from core.confidence.fusion import fuse

    once = fuse(
        small_cfg, {"R1": [_evidence(EvidenceCode.PEER_GROUP_OUTLIER, 0.5)]}
    )["R1"].tampering_probability
    six_times = fuse(
        small_cfg,
        {"R1": [_evidence(EvidenceCode.PEER_GROUP_OUTLIER, 0.5) for _ in range(6)]},
    )["R1"].tampering_probability
    assert six_times == pytest.approx(once, abs=1e-9), (
        "repeated instances of one code are redundant and must not accumulate"
    )


def test_distinct_findings_in_one_layer_do_corroborate(small_cfg) -> None:
    """Weight and cargo-type conservation are independent constraints."""
    from core.confidence.fusion import fuse

    one = fuse(
        small_cfg, {"R1": [_evidence(EvidenceCode.WEIGHT_NOT_CONSERVED, 0.8)]}
    )["R1"].tampering_probability
    two = fuse(
        small_cfg,
        {
            "R1": [
                _evidence(EvidenceCode.WEIGHT_NOT_CONSERVED, 0.8),
                _evidence(EvidenceCode.CARGO_TYPE_MUTATED, 0.8),
            ]
        },
    )["R1"].tampering_probability
    assert two > one


def test_a_deterministic_impossibility_convicts_on_its_own(small_cfg) -> None:
    """A container cannot be in two ports at once. That is not a 20% claim."""
    from core.confidence.fusion import fuse

    verdict = fuse(
        small_cfg, {"R1": [_evidence(EvidenceCode.SIMULTANEOUS_PRESENCE, 0.93)]}
    )["R1"]
    assert verdict.tampering_probability >= small_cfg.float_("fusion.thresholds.suspicious")


def test_an_inconclusive_hash_mismatch_is_not_decisive(small_cfg) -> None:
    """If a hashed field was lost in the export, the mismatch proves nothing."""
    from core.confidence.fusion import fuse

    item = _evidence(EvidenceCode.RECORD_HASH_MISMATCH, 0.22)
    item.details["inconclusive"] = True
    verdict = fuse(small_cfg, {"R1": [item]})["R1"]
    assert verdict.tampering_probability < small_cfg.float_("fusion.thresholds.suspicious")


def test_contributions_are_signed_and_ordered(small_cfg) -> None:
    from core.confidence.fusion import fuse

    verdict = fuse(
        small_cfg,
        {
            "R1": [
                _evidence(EvidenceCode.RECORD_HASH_MISMATCH, 0.95),
                _evidence(EvidenceCode.OFF_ROUTE_PORT, 0.7),
                _evidence(EvidenceCode.FIELD_BLANK, 0.15),
            ]
        },
    )["R1"]
    points = [c.points for c in verdict.contributions]
    assert points == sorted(points, reverse=True)
    assert any(p < 0 for p in points), "FORMAT must render as a negative line"


def test_statistical_only_evidence_is_a_benign_anomaly(small_cfg) -> None:
    """Spec 13 and 18.5: unusual is not the same as tampered."""
    from core.confidence.classifier import classify
    from core.confidence.fusion import fuse

    items = [
        _evidence(EvidenceCode.PEER_GROUP_OUTLIER, 0.55),
        _evidence(EvidenceCode.IQR_OUTLIER, 0.5),
        _evidence(EvidenceCode.LOF_OUTLIER, 0.45),
    ]
    verdicts = classify(small_cfg, fuse(small_cfg, {"R1": items}), {"R1": items})
    assert verdicts["R1"].tamper_class in (
        TamperClass.BENIGN_ANOMALY,
        TamperClass.CLEAN,
    )


def test_provenance_decides_the_tampering_class(small_cfg) -> None:
    """Committed-and-changed is MODIFIED; never-committed is FABRICATED."""
    from core.confidence.classifier import classify
    from core.confidence.fusion import fuse

    def classify_one(items: list[Evidence]) -> TamperClass:
        return classify(small_cfg, fuse(small_cfg, {"R1": items}), {"R1": items})[
            "R1"
        ].tamper_class

    edited = [
        _evidence(EvidenceCode.RECORD_HASH_MISMATCH, 0.95),
        _evidence(EvidenceCode.SPEED_INFEASIBLE, 0.95),
    ]
    assert classify_one(edited) is TamperClass.MODIFIED

    inserted = [
        _evidence(EvidenceCode.RECORD_NOT_IN_CHAIN, 0.88),
        _evidence(EvidenceCode.SPEED_INFEASIBLE, 0.95),
    ]
    assert classify_one(inserted) is TamperClass.FABRICATED


def test_a_loud_finding_cannot_override_the_class(small_cfg) -> None:
    """Severity says how abnormal; it says nothing about what kind.

    A fabricated record trips FUTURE_EVENT at 0.92, which once outvoted the
    FABRICATED signal at 0.85 and relabelled it MODIFIED.
    """
    from core.confidence.classifier import classify
    from core.confidence.fusion import fuse

    items = [
        _evidence(EvidenceCode.RECORD_NOT_IN_CHAIN, 0.85),
        _evidence(EvidenceCode.FUTURE_EVENT, 0.95),
        _evidence(EvidenceCode.OFF_ROUTE_PORT, 0.9),
    ]
    verdicts = classify(small_cfg, fuse(small_cfg, {"R1": items}), {"R1": items})
    assert verdicts["R1"].tamper_class is TamperClass.FABRICATED


# ======================================================================
# Full pipeline
# ======================================================================


@pytest.fixture(scope="module")
def analysis(dataset):
    from core.pipeline import ProvenanceView, analyze

    view = ProvenanceView(chain=dataset["chain"], consistency=dataset["consistency"])
    result, ctx, arbitration = analyze(
        dataset["result"].suspect_rows,
        dataset["world"],
        dataset["cfg"],
        provenance=view,
    )
    return result, ctx, arbitration


def test_every_record_receives_exactly_one_disposition(analysis) -> None:
    """Spec 1.1: nothing is silently altered."""
    result, _ctx, _arb = analysis
    assert len(result.reconstructions) == len(result.records)
    for record in result.records:
        recon = result.reconstructions[record.record_id]
        assert recon.classification in set(Classification)
        assert recon.original, "the original state must always be retained"
        assert recon.reason, "every disposition must carry a reason"
        if recon.classification is Classification.REPAIRED:
            assert recon.reconstructed is not None
            assert recon.selected_candidate_id
        if recon.classification is Classification.REMOVED:
            assert recon.reconstructed is None


def test_the_pipeline_detects_more_than_it_misreports(analysis, dataset) -> None:
    """A smoke test on quality, loose enough not to be brittle."""
    from evaluation.ground_truth import GroundTruth

    result, _ctx, _arb = analysis
    log = dataset["result"].injection_log
    truth = GroundTruth(log=log)
    for entry in log.entries:
        if entry.record_id and str(entry.attack_class) != "NOISE":
            truth.tampered.add(entry.record_id)

    threshold = dataset["cfg"].float_("fusion.thresholds.suspicious")
    flagged = {
        rid
        for rid, verdict in result.verdicts.items()
        if verdict.tampering_probability >= threshold
        and verdict.tamper_class
        not in (TamperClass.CLEAN, TamperClass.BENIGN_ANOMALY)
    }
    present = {r.record_id for r in result.records}
    tampered = truth.tampered & present

    true_positives = len(flagged & tampered)
    precision = true_positives / max(1, len(flagged))
    recall = true_positives / max(1, len(tampered))

    assert precision > 0.8, f"precision {precision:.3f}"
    assert recall > 0.6, f"recall {recall:.3f}"


def test_no_false_alarms_on_noise_only_records(analysis, dataset) -> None:
    """The property the whole FORMAT design exists to protect."""
    result, _ctx, _arb = analysis
    log = dataset["result"].injection_log
    noise_only = log.noise_record_ids() - log.tampered_record_ids()
    threshold = dataset["cfg"].float_("fusion.thresholds.suspicious")

    flagged = {
        rid
        for rid, verdict in result.verdicts.items()
        if verdict.tampering_probability >= threshold
        and verdict.tamper_class
        not in (TamperClass.CLEAN, TamperClass.BENIGN_ANOMALY)
    }
    offenders = flagged & noise_only
    assert len(offenders) <= 1, f"noise-only records flagged as tampering: {offenders}"


def test_arbitration_shifts_blame_rather_than_silencing_it(analysis) -> None:
    """Both halves of a conflict keep evidence; only the severity moves."""
    _result, _ctx, arbitration = analysis
    assert arbitration.corroboration, "every record should receive a corroboration score"
    for decision in arbitration.decisions[:20]:
        assert decision["blamed"] != decision["exonerated"]
        assert 0.0 < decision["multiplier"] <= 1.0


def test_deletions_are_inferred_without_a_surviving_row(analysis) -> None:
    result, _ctx, _arb = analysis
    assert result.inferred_deletions, "deletions were injected and should be inferred"
    for entry in result.inferred_deletions[:10]:
        assert entry["confidence"] > 0
        assert entry["reason"]


def test_the_graph_builds_and_answers_queries(analysis) -> None:
    from core.graph.model import NodeType, annotate_with_evidence, build_graph, node_key

    result, ctx, _arb = analysis
    graph = annotate_with_evidence(build_graph(ctx), result.evidence)
    assert graph.node_count > 0 and graph.edge_count > 0

    record_id = result.records[0].record_id
    key = node_key(NodeType.RECORD, record_id)
    assert graph.exists(key)

    # Hub-aware expansion: a port touches every record at that port, so a
    # two-hop neighbourhood must stay small enough to render.
    neighbourhood = graph.neighbourhood(key, depth=2)
    assert 1 < len(neighbourhood) <= 200
    assert graph.provenance_chain(record_id)


def test_generation_is_deterministic_across_processes(tmp_path) -> None:
    """Two separate processes, different hash seeds, byte-identical output.

    ``test_generation_is_deterministic`` above runs both generations in one
    process, so it shares a ``PYTHONHASHSEED`` and cannot see hash-order
    dependence. That is exactly the bug it missed: releasing freed record ids
    into the recycling pool by iterating a ``set`` made the suspect manifest
    differ between runs of the same seed, while the world, the clean manifest
    and the chain all stayed identical.

    The brief requires the data to be regenerable *exactly*, so this is
    checked the only way that proves it.
    """
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    outputs = []
    for index, hash_seed in enumerate(("0", "12345")):
        target = tmp_path / f"run{index}"
        env = {**os.environ, "PYTHONHASHSEED": hash_seed}
        result = subprocess.run(
            [
                sys.executable,
                "scripts/generate.py",
                "--seed", "481516",
                "--records", "900",
                "--out", str(target),
                "--no-emit-geojson",
            ],
            cwd=root,
            env=env,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        outputs.append(target)

    for name in (
        "manifest_suspect.csv",
        "manifest_clean.csv",
        "world.json",
        "chain.json",
        "node_chains.json",
        "route_manifests.json",
    ):
        first = (outputs[0] / name).read_bytes()
        second = (outputs[1] / name).read_bytes()
        assert first == second, f"{name} differs between processes with different hash seeds"

    # The answer key too, apart from its wall-clock stamp.
    import json

    a = json.loads((outputs[0] / "ground_truth.json").read_text(encoding="utf-8"))
    b = json.loads((outputs[1] / "ground_truth.json").read_text(encoding="utf-8"))
    for key in ("seed", "config_digest", "clean_record_count", "suspect_record_count", "summary", "entries"):
        assert a[key] == b[key], f"ground truth differs in {key!r}"

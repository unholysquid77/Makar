"""The Shifting Waters twist: live revisions, operator load, live manifest.

The twist states the attacker is inside the system editing records in real
time, and that the feed carries "incoming *and updated* records". These tests
pin the three properties that answer it: after-the-fact edits are caught,
legitimate corrections are not, and the operator sees problems rather than
events.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from core.alerting import AlertAction, AlertManager
from core.config import load_config
from core.models import ManifestRecord, RecordVerdict
from core.types import EvidenceType, TamperClass


@pytest.fixture(scope="module")
def cfg():
    return load_config()


# ======================================================================
# Alert management -- "how did you stop flooding operators"
# ======================================================================


def _verdict(probability: float, layers: set[str]) -> RecordVerdict:
    return RecordVerdict(
        record_id="R1",
        tampering_probability=probability,
        tamper_class=TamperClass.MODIFIED,
        type_scores={EvidenceType(layer): 0.8 for layer in layers},
    )


def _record(record_id: str, container_id: str) -> ManifestRecord:
    return ManifestRecord(
        record_id=record_id,
        container_id=container_id,
        port_id="PORT_SIN",
        timestamp=datetime(2026, 3, 1, 12, 0),
    )


def test_a_campaign_on_one_container_is_one_alert(cfg) -> None:
    """Forty findings on one container must not be forty notifications."""
    manager = AlertManager(cfg)
    outcomes = [
        manager.observe(
            _record(f"R{i:04d}", "CONT_000001"),
            _verdict(0.70, {"CARGO"}),
            layers={"CARGO"},
            codes={"WEIGHT_NOT_CONSERVED"},
        )
        for i in range(40)
    ]

    assert outcomes[0].action is AlertAction.RAISED
    assert all(o.action is AlertAction.SUPPRESSED for o in outcomes[1:])

    stats = manager.stats()
    assert stats["flagged_events"] == 40
    assert stats["notifications"] == 1
    assert stats["suppressed"] == 39
    assert stats["open_alerts"] == 1

    # Suppression hides the interruption, never the information.
    alert = manager.open_alerts()[0]
    assert alert.event_count == 40
    assert alert.suppressed_count == 39


def test_a_new_evidence_layer_escalates(cfg) -> None:
    """Suppression must not swallow genuinely new information."""
    manager = AlertManager(cfg)
    manager.observe(
        _record("R1", "CONT_1"), _verdict(0.70, {"CARGO"}), layers={"CARGO"}, codes={"A"}
    )
    same = manager.observe(
        _record("R2", "CONT_1"), _verdict(0.71, {"CARGO"}), layers={"CARGO"}, codes={"A"}
    )
    new_layer = manager.observe(
        _record("R3", "CONT_1"),
        _verdict(0.72, {"CARGO", "BLOCKCHAIN"}),
        layers={"CARGO", "BLOCKCHAIN"},
        codes={"A", "B"},
    )
    assert same.action is AlertAction.SUPPRESSED
    assert new_layer.action is AlertAction.ESCALATED
    assert "BLOCKCHAIN" in new_layer.reason


def test_a_large_probability_jump_escalates(cfg) -> None:
    manager = AlertManager(cfg)
    manager.observe(
        _record("R1", "CONT_1"), _verdict(0.50, {"CARGO"}), layers={"CARGO"}, codes={"A"}
    )
    jumped = manager.observe(
        _record("R2", "CONT_1"), _verdict(0.95, {"CARGO"}), layers={"CARGO"}, codes={"A"}
    )
    assert jumped.action is AlertAction.ESCALATED


def test_clean_records_raise_nothing(cfg) -> None:
    manager = AlertManager(cfg)
    outcome = manager.observe(
        _record("R1", "CONT_1"),
        RecordVerdict(
            record_id="R1", tampering_probability=0.02, tamper_class=TamperClass.CLEAN
        ),
    )
    assert outcome.action is AlertAction.IGNORED
    assert manager.stats()["notifications"] == 0


def test_separate_containers_are_separate_problems(cfg) -> None:
    manager = AlertManager(cfg)
    for i in range(5):
        manager.observe(
            _record(f"R{i}", f"CONT_{i}"),
            _verdict(0.70, {"CARGO"}),
            layers={"CARGO"},
            codes={"A"},
        )
    assert manager.stats()["notifications"] == 5
    assert manager.stats()["open_alerts"] == 5


def test_stale_alerts_close_themselves(cfg) -> None:
    manager = AlertManager(cfg)
    start = datetime(2026, 3, 1)
    manager.observe(
        _record("R1", "CONT_1"),
        _verdict(0.70, {"CARGO"}),
        layers={"CARGO"},
        codes={"A"},
        now=start,
    )
    assert manager.stats()["open_alerts"] == 1

    cooldown = cfg.float_("stream.alerting.cooldown_minutes")
    manager.observe(
        _record("R2", "CONT_2"),
        _verdict(0.70, {"CARGO"}),
        layers={"CARGO"},
        codes={"A"},
        now=start + timedelta(minutes=cooldown + 60),
    )
    assert "container_id:CONT_1" not in manager.alerts


# ======================================================================
# Live revisions -- the attacker editing in real time
# ======================================================================


@pytest.fixture(scope="module")
def live(cfg):
    """A live session over a small generated world, replayed to completion."""
    from blockchain.chain import Chain
    from blockchain.network import VirtualNetwork
    from core.normalization import normalize_rows
    from core.pipeline import ProvenanceView
    from core.streaming import StreamProcessor
    from generator.corruption import corrupt_manifest
    from generator.manifest import build_clean_manifest
    from generator.stream import build_stream
    from generator.world import build_world

    small = cfg.with_overrides(
        {
            "world.records": 700,
            "world.n_shipments": 40,
            "world.n_ports": 10,
            "world.n_vessels": 8,
            "world.n_routes": 8,
            "world.n_owners": 8,
        }
    )
    world = build_world(small)
    clean, manifests, world = build_clean_manifest(small, world)
    corrupted = corrupt_manifest(small, world, clean, manifests)
    chain = Chain.build(
        clean,
        manifests,
        records_per_block=small.int_("blockchain.records_per_block"),
        genesis_timestamp=world.sim_start,
        sealed_fraction=small.float_("blockchain.sealed_fraction"),
    )
    network = VirtualNetwork.build(
        small, chain, seed=world.seed, replacement_hashes=corrupted.post_attack_hashes
    )
    view = ProvenanceView(
        chain=network.healthy_chain, consistency=network.check_consistency()
    )

    batch = normalize_rows(corrupted.suspect_rows, world, small)
    plan = build_stream(small, world, batch.records, count=400)
    for shipment in plan.new_shipments:
        world.shipments[shipment.shipment_id] = shipment
    for container in plan.new_containers:
        world.containers[container.container_id] = container

    processor = StreamProcessor(
        small, world, batch.records, chain=view.chain, consistency=view.consistency
    )
    results = [
        (event, processor.ingest(event.row, sequence=event.sequence))
        for event in plan.events
    ]
    return {
        "cfg": small,
        "processor": processor,
        "results": results,
        "threshold": small.float_("stream.alert_threshold"),
    }


def test_the_feed_carries_updates_not_only_inserts(live) -> None:
    revisions = [v for _e, v in live["results"] if v.is_revision]
    assert revisions, "the feed must carry updates to records already delivered"
    assert live["processor"].revisions == len(revisions)


def test_after_the_fact_edits_are_caught(live) -> None:
    """A populated value rewritten after the event is an edit of history.

    Re-running the consistency engines cannot see most of these on its own:
    conservation stands down across a port call containing a cargo event,
    which is exactly where the attacker is working.
    """
    threshold = live["threshold"]
    edits = [
        (event, verdict)
        for event, verdict in live["results"]
        if event.truth.get("attack") == "live_revision"
    ]
    assert edits, "no live revisions were injected"
    caught = [
        v
        for _e, v in edits
        if v.verdict.tampering_probability >= threshold and v.is_suspicious
    ]
    assert len(caught) / len(edits) >= 0.85, (
        f"only {len(caught)}/{len(edits)} after-the-fact edits were caught"
    )


def test_operator_corrections_do_not_alert(live) -> None:
    """A late-arriving value must not disrupt real operations.

    This is the precision half of the twist. Alerting whenever anything
    changes would bury the operator the first time someone supplied a field
    that was missing from the original delivery.
    """
    threshold = live["threshold"]
    corrections = [
        (event, verdict)
        for event, verdict in live["results"]
        if event.truth.get("correction")
    ]
    assert corrections, "no corrections were injected"
    alerted = [
        v
        for _e, v in corrections
        if v.verdict.tampering_probability >= threshold and v.is_suspicious
    ]
    assert not alerted, f"{len(alerted)} legitimate corrections raised an alert"


def test_a_revision_reports_what_changed(live) -> None:
    """An investigator needs the before, the after, and the consequence."""
    revisions = [v for _e, v in live["results"] if v.is_revision and v.revision]
    assert revisions
    detail = revisions[0].revision
    for key in (
        "fields_changed",
        "filled",
        "altered",
        "before",
        "after",
        "anomaly_before",
        "anomaly_after",
        "anomaly_delta",
        "verdict",
    ):
        assert key in detail


# ======================================================================
# Live reconstructed manifest and report
# ======================================================================


def test_the_live_manifest_holds_one_row_per_record(live) -> None:
    """A revision replaces its record in place; it does not append a second."""
    processor = live["processor"]
    manifest = processor.live_manifest()
    ids = [row["record_id"] for row in manifest]
    assert len(ids) == len(set(ids)), "a revised record appears twice in the manifest"
    assert processor.revisions > 0
    assert any(row["revisions"] > 0 for row in manifest)


def test_every_live_record_carries_a_disposition(live) -> None:
    manifest = live["processor"].live_manifest()
    allowed = {"ORIGINAL", "REPAIRED", "REMOVED", "UNRECOVERABLE"}
    assert all(row["classification"] in allowed for row in manifest)


def test_the_live_report_is_current_and_complete(live) -> None:
    report = live["processor"].live_report(top=10)
    assert report["live"] is True
    for key in ("summary", "alerts", "ranked_records", "affected", "corrections"):
        assert key in report
    assert report["summary"]["total_records"] > 0
    assert report["alerts"]["notifications"] <= report["alerts"]["flagged_events"]


def test_latency_is_measured_in_milliseconds(live) -> None:
    """"Delay measured in seconds, not hours" -- with three orders to spare."""
    latency = live["processor"].stats()["latency_ms"]
    assert latency["p95"] < 1000, f"p95 latency {latency['p95']} ms"
    assert latency["mean"] < 100, f"mean latency {latency['mean']} ms"


def test_the_live_path_reuses_the_batch_weights(live) -> None:
    """No second, weaker rule set for the live path.

    If the live path had its own tuning it would drift from the batch path,
    and the claim that detection generalises would be untestable.
    """
    processor = live["processor"]
    assert processor.cfg.get("fusion.weights") == load_config().get("fusion.weights")

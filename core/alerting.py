"""Alert management for the live feed.

The twist asks explicitly how a streaming system avoids flooding operators
with false alerts. Precision alone does not answer that: a *correct* alert
repeated forty times for the same container is still a flood, and an operator
who starts ignoring the feed is no better off than one being lied to.

So alerts are not events. A finding is folded into an **open alert** for the
entity it concerns, and that alert updates in place. A second finding on the
same container raises no new notification unless it carries genuinely new
information:

* the fused probability rose by at least ``escalation_delta``, or
* an evidence *layer* appeared that was not in the alert before, or
* the probability crossed ``critical_probability``.

Everything else is absorbed silently. The alert's own record of itself still
grows -- event count, peak probability, every code seen -- so nothing is lost;
it simply stops interrupting anyone.

The metric that matters is the **compression ratio**: flagged events divided
by notifications raised. A system that flags 40 events on 9 containers and
notifies 9 times has done its job; one that notifies 40 times has not.

Grouping is by container, because that is the unit a campaign targets and the
unit an investigator actions. A siphon across twelve events is one problem,
not twelve.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from core.config import MakarConfig
from core.models import ManifestRecord, RecordVerdict
from core.types import TamperClass


class AlertStatus(StrEnum):
    OPEN = "OPEN"
    ESCALATED = "ESCALATED"
    CRITICAL = "CRITICAL"
    CLOSED = "CLOSED"


class AlertAction(StrEnum):
    """What the operator's console should do with an observation."""

    #: A new alert was raised. Notify.
    RAISED = "RAISED"
    #: An existing alert materially escalated. Notify.
    ESCALATED = "ESCALATED"
    #: Folded into an existing alert without new information. Do not notify.
    SUPPRESSED = "SUPPRESSED"
    #: Below the alert threshold entirely. Nothing to show.
    IGNORED = "IGNORED"


@dataclass
class Alert:
    """One open investigation, spanning however many events it takes."""

    alert_id: str
    key: str
    entity_type: str
    first_seen: datetime
    last_seen: datetime
    status: AlertStatus = AlertStatus.OPEN
    peak_probability: float = 0.0
    latest_probability: float = 0.0
    tamper_class: TamperClass = TamperClass.CLEAN
    event_count: int = 0
    #: How many findings were absorbed without notifying. The flood that
    #: would have happened.
    suppressed_count: int = 0
    notify_count: int = 0
    record_ids: list[str] = field(default_factory=list)
    evidence_layers: set[str] = field(default_factory=set)
    evidence_codes: set[str] = field(default_factory=set)
    narrative: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "key": self.key,
            "entity_type": self.entity_type,
            "status": str(self.status),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "peak_probability": round(self.peak_probability, 4),
            "latest_probability": round(self.latest_probability, 4),
            "tamper_class": str(self.tamper_class),
            "event_count": self.event_count,
            "suppressed_count": self.suppressed_count,
            "notify_count": self.notify_count,
            "record_ids": self.record_ids[-25:],
            "evidence_layers": sorted(self.evidence_layers),
            "evidence_codes": sorted(self.evidence_codes),
            "narrative": self.narrative,
        }


@dataclass
class AlertOutcome:
    action: AlertAction
    alert: Alert | None = None
    reason: str = ""

    @property
    def should_notify(self) -> bool:
        return self.action in (AlertAction.RAISED, AlertAction.ESCALATED)


class AlertManager:
    """Folds findings into open alerts, so operators see problems not events."""

    def __init__(self, cfg: MakarConfig) -> None:
        self.cfg = cfg
        self._group_by = [str(k) for k in cfg.list_("stream.alerting.group_by", ["container_id"])]
        self._escalation_delta = cfg.float_("stream.alerting.escalation_delta", 0.12)
        self._critical = cfg.float_("stream.alerting.critical_probability", 0.90)
        self._cooldown = timedelta(minutes=cfg.float_("stream.alerting.cooldown_minutes", 2880))
        self._max_open = cfg.int_("stream.alerting.max_open", 500)
        self._threshold = cfg.float_(
            "stream.alert_threshold", cfg.float_("fusion.thresholds.suspicious")
        )

        self.alerts: dict[str, Alert] = {}
        self.closed: list[Alert] = []
        self._counter = 0

        # Running totals, for the compression ratio.
        self.flagged_events = 0
        self.notifications = 0
        self.suppressed = 0

    # -- grouping ---------------------------------------------------------

    def _key_for(self, record: ManifestRecord) -> tuple[str, str]:
        """Entity this finding belongs to, by configured preference."""
        for field_name in self._group_by:
            value = getattr(record, field_name, None)
            if value:
                return f"{field_name}:{value}", field_name
        return f"record_id:{record.record_id}", "record_id"

    # -- lifecycle --------------------------------------------------------

    def _close_stale(self, now: datetime) -> None:
        stale = [
            key for key, alert in self.alerts.items() if now - alert.last_seen > self._cooldown
        ]
        for key in stale:
            alert = self.alerts.pop(key)
            alert.status = AlertStatus.CLOSED
            self.closed.append(alert)

    def _evict_if_needed(self) -> None:
        if len(self.alerts) <= self._max_open:
            return
        # Keep the worst; an operator cannot act on 500 alerts anyway, and
        # dropping the least severe is better than dropping the newest.
        ordered = sorted(self.alerts.items(), key=lambda kv: kv[1].peak_probability)
        for key, alert in ordered[: len(self.alerts) - self._max_open]:
            self.alerts.pop(key, None)
            alert.status = AlertStatus.CLOSED
            self.closed.append(alert)

    # -- the one method that matters --------------------------------------

    def observe(
        self,
        record: ManifestRecord,
        verdict: RecordVerdict,
        *,
        layers: set[str] | None = None,
        codes: set[str] | None = None,
        now: datetime | None = None,
    ) -> AlertOutcome:
        """Fold one scored record into the alert set."""
        now = now or record.effective_time() or datetime.now()
        self._close_stale(now)

        below_threshold = (
            verdict.tampering_probability < self._threshold
            or verdict.tamper_class in (TamperClass.CLEAN, TamperClass.BENIGN_ANOMALY)
        )
        if below_threshold:
            return AlertOutcome(AlertAction.IGNORED, None, "below the alert threshold")

        self.flagged_events += 1
        key, entity_type = self._key_for(record)
        layers = layers or {str(t) for t in verdict.type_scores}
        codes = codes or {str(c.code) for c in verdict.contributions}

        existing = self.alerts.get(key)

        # --- a new problem ---
        if existing is None:
            self._counter += 1
            alert = Alert(
                alert_id=f"ALERT_{self._counter:05d}",
                key=key,
                entity_type=entity_type,
                first_seen=now,
                last_seen=now,
                peak_probability=verdict.tampering_probability,
                latest_probability=verdict.tampering_probability,
                tamper_class=verdict.tamper_class,
                event_count=1,
                notify_count=1,
                record_ids=[record.record_id],
                evidence_layers=set(layers),
                evidence_codes=set(codes),
            )
            alert.status = (
                AlertStatus.CRITICAL
                if verdict.tampering_probability >= self._critical
                else AlertStatus.OPEN
            )
            alert.narrative = self._narrate(alert, record)
            self.alerts[key] = alert
            self._evict_if_needed()
            self.notifications += 1
            return AlertOutcome(
                AlertAction.RAISED,
                alert,
                f"first finding for {key}",
            )

        # --- an existing problem: does this add anything? ---
        new_layers = set(layers) - existing.evidence_layers
        rose_by = verdict.tampering_probability - existing.peak_probability
        crossed_critical = (
            verdict.tampering_probability >= self._critical
            and existing.status is not AlertStatus.CRITICAL
        )

        existing.event_count += 1
        existing.last_seen = now
        existing.latest_probability = verdict.tampering_probability
        existing.record_ids.append(record.record_id)
        existing.evidence_codes |= set(codes)
        existing.evidence_layers |= set(layers)
        if verdict.tampering_probability > existing.peak_probability:
            existing.peak_probability = verdict.tampering_probability
            existing.tamper_class = verdict.tamper_class

        escalates = crossed_critical or rose_by >= self._escalation_delta or bool(new_layers)
        if not escalates:
            existing.suppressed_count += 1
            self.suppressed += 1
            return AlertOutcome(
                AlertAction.SUPPRESSED,
                existing,
                f"folded into {existing.alert_id}; no new layer, probability "
                f"{rose_by:+.2f}",
            )

        existing.status = (
            AlertStatus.CRITICAL
            if existing.peak_probability >= self._critical
            else AlertStatus.ESCALATED
        )
        existing.notify_count += 1
        existing.narrative = self._narrate(existing, record)
        self.notifications += 1

        if crossed_critical:
            reason = f"crossed the critical threshold at {verdict.tampering_probability:.0%}"
        elif new_layers:
            reason = f"new evidence layer: {', '.join(sorted(new_layers))}"
        else:
            reason = f"probability rose {rose_by:+.2f}"
        return AlertOutcome(AlertAction.ESCALATED, existing, reason)

    # -- presentation -----------------------------------------------------

    def _narrate(self, alert: Alert, record: ManifestRecord) -> str:
        entity = alert.key.split(":", 1)[1]
        parts = [
            f"{alert.tamper_class} on {alert.entity_type.replace('_', ' ')} {entity}, "
            f"peak {alert.peak_probability:.0%} across {alert.event_count} event(s)."
        ]
        if alert.evidence_layers:
            parts.append(f"Layers: {', '.join(sorted(alert.evidence_layers))}.")
        if record.port_id:
            parts.append(f"Latest at {record.port_id}.")
        if alert.suppressed_count:
            parts.append(
                f"{alert.suppressed_count} further finding(s) folded in without "
                f"re-notifying."
            )
        return " ".join(parts)

    def open_alerts(self) -> list[Alert]:
        return sorted(
            self.alerts.values(), key=lambda a: a.peak_probability, reverse=True
        )

    def stats(self) -> dict[str, Any]:
        """The anti-flooding numbers."""
        compression = (
            self.flagged_events / self.notifications if self.notifications else 0.0
        )
        by_status: dict[str, int] = {}
        for alert in self.alerts.values():
            by_status[str(alert.status)] = by_status.get(str(alert.status), 0) + 1
        return {
            "flagged_events": self.flagged_events,
            "notifications": self.notifications,
            "suppressed": self.suppressed,
            "open_alerts": len(self.alerts),
            "closed_alerts": len(self.closed),
            "by_status": by_status,
            # Findings per notification. 1.0 means every finding interrupted
            # someone; higher means the operator saw problems, not events.
            "compression_ratio": round(compression, 2),
            "suppression_rate": round(
                self.suppressed / max(1, self.flagged_events), 4
            ),
        }


__all__ = ["Alert", "AlertAction", "AlertManager", "AlertOutcome", "AlertStatus"]

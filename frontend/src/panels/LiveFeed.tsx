/**
 * Live stream mode (spec 30, and spec 36 step 9 of the demonstration).
 *
 * Events are replayed through the incremental processor one at a time, over
 * the same detectors and the same fusion weights as the batch path. That
 * matters: the live feed carries attack patterns the batch data never held, so
 * if detection rested on learned signatures of known attacks it would find
 * nothing. It rests on consistency constraints instead, which is why it works
 * on patterns it has never seen.
 *
 * The alert threshold is lower than the batch threshold on purpose. A live
 * alert is triage — it prompts an analyst to look. A batch verdict holds a
 * shipment at a port. Those deserve different bars.
 *
 * The feed is generated server-side with its own private answer key, then
 * handed to this client, which posts events back one at a time. The processor
 * therefore only ever sees one event, and the ground truth stays here for
 * scoring rather than reaching the detector.
 */

import { useCallback, useEffect, useRef, useState } from "react";

import { useApp } from "../App";
import {
  Badge,
  DatumLine,
  Metric,
  Panel,
  SectionLabel,
  Spinner,
  TamperBadge,
} from "../components/primitives";
import { api } from "../lib/api";
import { TAMPER_COLOUR, num, pct, severityColour, ts } from "../lib/format";
import type {
  AlertStats,
  LiveAlert,
  LiveSummary,
  StreamStartResponse,
  StreamVerdictPayload,
} from "../lib/types";

interface FeedRow extends StreamVerdictPayload {
  truth: string | null;
  flagged: boolean;
}

interface Tally {
  processed: number;
  attacks: number;
  caught: number;
  collateral: number;
  falseAlarms: number;
  latencyTotal: number;
  attackedContainers: Set<string>;
  byPattern: Map<string, { total: number; caught: number }>;
  /** pattern -> container -> whether that campaign was caught at least once */
  campaigns: Map<string, Map<string, boolean>>;
}

const emptyTally = (): Tally => ({
  processed: 0,
  attacks: 0,
  caught: 0,
  collateral: 0,
  falseAlarms: 0,
  latencyTotal: 0,
  attackedContainers: new Set(),
  byPattern: new Map(),
  campaigns: new Map(),
});

const SPEEDS: Array<[string, number]> = [
  ["1×", 240],
  ["4×", 60],
  ["16×", 15],
  ["Max", 0],
];

export function LiveFeed() {
  const { select } = useApp();

  const [session, setSession] = useState<StreamStartResponse | null>(null);
  const [rows, setRows] = useState<FeedRow[]>([]);
  const [running, setRunning] = useState(false);
  const [delay, setDelay] = useState(60);
  const [cursor, setCursor] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [eventCount, setEventCount] = useState(400);

  // Scoring is tallied cumulatively rather than derived from `rows`. The feed
  // list is capped so the DOM stays small, and deriving the tally from it
  // silently mis-scored: once an early attack scrolled out of that window its
  // container was no longer known to have been attacked, so that container's
  // later legitimate events were counted as false alarms rather than as
  // collateral. Measured against the CLI scorer, that turned 0 false alarms
  // into 27.
  const [tally, setTally] = useState<Tally>(emptyTally);
  const [alerts, setAlerts] = useState<LiveAlert[]>([]);
  const [alertStats, setAlertStats] = useState<AlertStats | null>(null);
  const [liveSummary, setLiveSummary] = useState<LiveSummary | null>(null);

  // Refs so the replay loop reads live values without being re-created.
  const runningRef = useRef(false);
  const cursorRef = useRef(0);
  const delayRef = useRef(delay);
  delayRef.current = delay;

  const refreshLiveViews = useCallback(async () => {
    try {
      const [alertPayload, manifest] = await Promise.all([
        api.streamAlerts(),
        api.streamManifest(1),
      ]);
      setAlerts(alertPayload.open);
      setAlertStats(alertPayload.stats);
      setLiveSummary(manifest.summary);
    } catch {
      /* a view refresh must never interrupt the replay */
    }
  }, []);

  const start = useCallback(async () => {
    setBusy(true);
    setError(null);
    setRows([]);
    setTally(emptyTally());
    setAlerts([]);
    setAlertStats(null);
    setLiveSummary(null);
    setCursor(0);
    cursorRef.current = 0;
    try {
      const response = await api.streamStart({ events: eventCount, generate: true });
      setSession(response);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  }, [eventCount]);

  const step = useCallback(async (): Promise<boolean> => {
    if (!session) return false;
    const index = cursorRef.current;
    const event = session.queued_events[index];
    if (!event) return false;

    try {
      const verdict = await api.streamEvent(event.row);
      const truth = (event.truth?.attack as string | undefined) ?? null;
      const flagged = verdict.tampering_probability >= session.alert_threshold;
      const container = verdict.container_id;

      setTally((current) => {
        const attackedContainers = new Set(current.attackedContainers);
        if (truth && container) attackedContainers.add(container);

        const byPattern = new Map(current.byPattern);
        const campaigns = new Map(
          [...current.campaigns].map(([key, value]) => [key, new Map(value)]),
        );

        if (truth) {
          const stat = byPattern.get(truth) ?? { total: 0, caught: 0 };
          byPattern.set(truth, {
            total: stat.total + 1,
            caught: stat.caught + (flagged ? 1 : 0),
          });
          const group = campaigns.get(truth) ?? new Map<string, boolean>();
          const key = container ?? `seq${verdict.sequence}`;
          group.set(key, (group.get(key) ?? false) || flagged);
          campaigns.set(truth, group);
        }

        const isCollateral = Boolean(
          !truth && flagged && container && attackedContainers.has(container),
        );

        return {
          processed: current.processed + 1,
          attacks: current.attacks + (truth ? 1 : 0),
          caught: current.caught + (truth && flagged ? 1 : 0),
          collateral: current.collateral + (isCollateral ? 1 : 0),
          falseAlarms:
            current.falseAlarms + (!truth && flagged && !isCollateral ? 1 : 0),
          latencyTotal: current.latencyTotal + verdict.latency_ms,
          attackedContainers,
          byPattern,
          campaigns,
        };
      });

      setRows((current) => [{ ...verdict, truth, flagged }, ...current.slice(0, 199)]);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
      return false;
    }
    cursorRef.current = index + 1;
    setCursor(index + 1);

    // The alert set and the live manifest are whole-session views, so
    // they are refreshed every 20 events rather than on every one --
    // polling them per event would dominate the latency we are
    // measuring.
    if ((index + 1) % 20 === 0 || index + 1 === session.queued_events.length) {
      void refreshLiveViews();
    }
    return true;
  }, [session]);

  // --- replay loop ---
  useEffect(() => {
    if (!running) return;
    let cancelled = false;

    const loop = async () => {
      while (!cancelled && runningRef.current) {
        const advanced = await step();
        if (!advanced) {
          setRunning(false);
          runningRef.current = false;
          break;
        }
        if (delayRef.current > 0) {
          await new Promise((resolve) => setTimeout(resolve, delayRef.current));
        }
      }
    };
    void loop();

    return () => {
      cancelled = true;
    };
  }, [running, step]);

  const toggle = () => {
    const next = !running;
    setRunning(next);
    runningRef.current = next;
  };

  // --- live scoring against the feed's own answer key ---
  // A flag on a legitimate event is only a false alarm if that container was
  // never attacked: once an injected record sits in a container's history,
  // later legitimate records genuinely contradict it, and noticing that is
  // correct behaviour rather than a miss.
  const precision = tally.caught / Math.max(1, tally.caught + tally.falseAlarms);
  const recall = tally.caught / Math.max(1, tally.attacks);
  const meanLatency = tally.processed > 0 ? tally.latencyTotal / tally.processed : 0;
  const total = session?.queued_events.length ?? 0;

  return (
    <div className="h-full min-h-0 overflow-y-auto p-3 space-y-3">
      {/* ---------------------------------------------- controls */}
      <Panel
        title="Live stream"
        actions={
          <>
            <label className="flex items-center gap-1.5 text-2xs text-ink-500">
              <span className="uppercase tracking-[0.1em]">events</span>
              <input
                type="number"
                min={50}
                max={3000}
                step={50}
                className="input w-20"
                value={eventCount}
                onChange={(event) => setEventCount(Number(event.target.value))}
                disabled={running}
              />
            </label>
            <button type="button" className="btn" onClick={() => void start()} disabled={busy || running}>
              {session ? "Regenerate feed" : "Generate feed"}
            </button>
            <button
              type="button"
              className={`btn ${running ? "btn-active" : ""}`}
              onClick={toggle}
              disabled={!session || cursor >= total}
            >
              {running ? "Pause" : "Play"}
            </button>
            <button
              type="button"
              className="btn"
              onClick={() => void step()}
              disabled={!session || running || cursor >= total}
            >
              Step
            </button>
            {SPEEDS.map(([label, value]) => (
              <button
                key={label}
                type="button"
                className={`btn ${delay === value ? "btn-active" : ""}`}
                onClick={() => setDelay(value)}
              >
                {label}
              </button>
            ))}
          </>
        }
      >
        {busy && <Spinner label="Generating a reproducible feed…" />}
        {error && <div className="text-2xs text-anomaly-critical">{error}</div>}

        {!session && !busy && (
          <p className="text-xs text-ink-500 leading-relaxed max-w-2xl">
            The feed carries three attack patterns <em>absent from the batch data</em>,
            each defeating a different batch assumption: a{" "}
            <span className="text-ink-100">weight siphon</span> whose every step sits
            inside the per-transition conservation tolerance, a{" "}
            <span className="text-ink-100">ghost transfer</span> at a port the container
            never reached, and an{" "}
            <span className="text-ink-100">identity swap</span> between two containers
            mid-voyage. Nothing in the detectors knows about any of them.
          </p>
        )}

        {session && (
          <div className="space-y-3">
            <div>
              <div className="flex items-baseline justify-between text-2xs text-ink-500">
                <span className="uppercase tracking-[0.1em]">Replay progress</span>
                <span className="font-mono tnum">
                  {num(cursor)} / {num(total)}
                </span>
              </div>
              <DatumLine
                value={total ? cursor / total : 0}
                colour="#4cc2ff"
                className="mt-1.5 h-[4px]"
              />
            </div>

            <div className="flex flex-wrap gap-x-5 gap-y-1.5 text-2xs">
              <span className="text-ink-500">
                alert threshold{" "}
                <span className="font-mono text-ink-100">
                  {pct(session.alert_threshold, 0)}
                </span>{" "}
                <span className="text-ink-700">(live triage)</span>
              </span>
              <span className="text-ink-500">
                batch records in state{" "}
                <span className="font-mono text-ink-100">{num(session.batch_records)}</span>
              </span>
              {Object.entries(session.injected)
                .filter(([key]) => !["total", "legitimate"].includes(key))
                .map(([pattern, count]) => (
                  <Badge key={pattern} colour="#e5563d">
                    {pattern} × {count}
                  </Badge>
                ))}
            </div>
          </div>
        )}
      </Panel>

      {/* ---------------------------------------------- live metrics */}
      {session && rows.length > 0 && (
        <>
          <div className="panel">
            <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 divide-x divide-hairline">
              <Metric label="Events processed" value={num(tally.processed)} emphasis />
              <Metric
                label="Attacks in feed"
                value={num(tally.attacks)}
                accent="#e5563d"
                emphasis
              />
              <Metric label="Caught" value={num(tally.caught)} accent="#2fa36b" emphasis />
              <Metric
                label="False alarms"
                value={num(tally.falseAlarms)}
                sub={`${tally.collateral} collateral on attacked containers`}
                accent={tally.falseAlarms > 0 ? "#d9a21b" : "#2fa36b"}
                emphasis
              />
              <Metric label="Precision / recall" value={`${pct(precision, 0)} / ${pct(recall, 0)}`} emphasis />
              <Metric
                label="Mean latency"
                value={`${meanLatency.toFixed(1)} ms`}
                sub="per event, incremental"
                accent="#4cc2ff"
                emphasis
              />
            </div>
          </div>

          <Panel title="Recall by novel pattern">
            {tally.byPattern.size === 0 ? (
              <div className="text-2xs text-ink-700">No attack events replayed yet.</div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {[...tally.byPattern.entries()].map(([pattern, stat]) => {
                  const group = tally.campaigns.get(pattern);
                  const campaigns = group ? group.size : 0;
                  const caughtCampaigns = group
                    ? [...group.values()].filter(Boolean).length
                    : 0;
                  return (
                    <div key={pattern}>
                      <div className="flex items-baseline justify-between gap-2">
                        <span className="text-xs text-ink-100">{pattern}</span>
                        <span className="font-mono tnum text-2xs text-ink-500">
                          {stat.caught}/{stat.total} events
                        </span>
                      </div>
                      <DatumLine
                        value={stat.caught / Math.max(1, stat.total)}
                        colour={stat.caught === stat.total ? "#2fa36b" : "#d9a21b"}
                        className="mt-1.5"
                      />
                      <div className="mt-1.5 flex items-baseline justify-between gap-2">
                        <span className="text-2xs text-ink-500">campaigns</span>
                        <span className="font-mono tnum text-2xs text-ink-300">
                          {caughtCampaigns}/{campaigns} ·{" "}
                          {pct(caughtCampaigns / Math.max(1, campaigns), 0)}
                        </span>
                      </div>
                      <DatumLine
                        value={caughtCampaigns / Math.max(1, campaigns)}
                        colour={caughtCampaigns === campaigns ? "#2fa36b" : "#4cc2ff"}
                        className="mt-1"
                      />
                    </div>
                  );
                })}
              </div>
            )}
            <p className="mt-3 text-2xs text-ink-700 leading-relaxed">
              The siphon and the identity swap are campaigns spanning many events for one
              container. Their <em>onset</em> is detectable because it contradicts prior
              history; once the state is consistently wrong, later events are internally
              consistent and there is nothing left to contradict. Per-event recall
              therefore understates both.
            </p>
          </Panel>
        </>
      )}


      {/* ---------------------------------------------- the twist */}
      {session && liveSummary && (
        <div className="grid grid-cols-1 xl:grid-cols-[1fr_1fr] gap-3">
          <Panel title="Live reconstructed manifest">
            <p className="text-2xs text-ink-700 leading-relaxed mb-2.5">
              Maintained in place as records arrive, not rebuilt. Every record
              carries exactly one disposition, exactly as the batch output does.
            </p>
            <div className="grid grid-cols-4 gap-2">
              {(
                [
                  ["ORIGINAL", "#394353"],
                  ["REPAIRED", "#4cc2ff"],
                  ["REMOVED", "#e5563d"],
                  ["UNRECOVERABLE", "#d9a21b"],
                ] as Array<[keyof LiveSummary["disposition"], string]>
              ).map(([label, colour]) => (
                <div key={label} className="rounded-xs border border-hairline px-2 py-2">
                  <div className="font-mono tnum text-lg" style={{ color: colour }}>
                    {num(liveSummary.disposition[label])}
                  </div>
                  <div className="text-[0.625rem] uppercase tracking-[0.1em] text-ink-500 mt-0.5">
                    {label}
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-3 grid grid-cols-2 gap-x-5 gap-y-1.5">
              {(
                [
                  ["Records revised on the feed", num(liveSummary.records_revised)],
                  ["Revisions seen", num(liveSummary.revisions_seen)],
                  ["Corrections accepted silently", num(liveSummary.corrections_accepted)],
                  ["Mean repair confidence", pct(liveSummary.mean_repair_confidence, 0)],
                ] as Array<[string, string]>
              ).map(([label, value]) => (
                <div key={label} className="flex items-baseline justify-between gap-2">
                  <span className="text-2xs text-ink-500">{label}</span>
                  <span className="font-mono tnum text-xs text-ink-100">{value}</span>
                </div>
              ))}
            </div>
          </Panel>

          <Panel title="Operator load">
            <p className="text-2xs text-ink-700 leading-relaxed mb-2.5">
              Findings are folded into one open alert per entity. A campaign
              spanning forty events is one problem to action, not forty
              notifications to triage.
            </p>
            {alertStats && (
              <>
                <div className="grid grid-cols-3 gap-2">
                  <Metric label="Findings" value={num(alertStats.flagged_events)} />
                  <Metric
                    label="Notifications"
                    value={num(alertStats.notifications)}
                    accent="#4cc2ff"
                  />
                  <Metric
                    label="Folded in"
                    value={num(alertStats.suppressed)}
                    accent="#2fa36b"
                  />
                </div>
                <div className="mt-2">
                  <div className="flex items-baseline justify-between text-2xs">
                    <span className="text-ink-500 uppercase tracking-[0.1em]">
                      Findings per notification
                    </span>
                    <span className="font-mono tnum text-ink-100">
                      {alertStats.compression_ratio.toFixed(2)}×
                    </span>
                  </div>
                  <DatumLine
                    value={Math.min(1, (alertStats.compression_ratio - 1) / 2)}
                    colour="#2fa36b"
                    className="mt-1.5"
                  />
                </div>
              </>
            )}
            {alerts.length > 0 && (
              <ul className="mt-3 space-y-1.5 max-h-56 overflow-y-auto">
                {alerts.slice(0, 12).map((alert) => (
                  <li
                    key={alert.alert_id}
                    className="rounded-xs border border-hairline bg-obsidian-850 px-2.5 py-2"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="flex items-center gap-1.5 min-w-0">
                        <Badge
                          colour={
                            alert.status === "CRITICAL"
                              ? "#e5484d"
                              : alert.status === "ESCALATED"
                                ? "#e8821f"
                                : "#4cc2ff"
                          }
                        >
                          {alert.status}
                        </Badge>
                        <span className="font-mono text-2xs text-ink-300 truncate">
                          {alert.key.split(":")[1]}
                        </span>
                      </span>
                      <span
                        className="font-mono tnum text-2xs shrink-0"
                        style={{ color: severityColour(alert.peak_probability) }}
                      >
                        {pct(alert.peak_probability, 0)}
                      </span>
                    </div>
                    <div className="mt-1 text-2xs text-ink-500">
                      {alert.event_count} event(s)
                      {alert.suppressed_count > 0 && (
                        <span className="text-verified">
                          {" "}
                          · {alert.suppressed_count} folded in
                        </span>
                      )}{" "}
                      · {alert.evidence_layers.join(", ")}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      )}

      {/* ---------------------------------------------- the feed */}
      {session && (
        <Panel title={`Event feed — newest first`} dense>
          {rows.length === 0 ? (
            <div className="p-4 text-2xs text-ink-700">
              Press Play to begin replaying the feed.
            </div>
          ) : (
            <div className="max-h-[480px] overflow-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Seq</th>
                    <th>Record</th>
                    <th>Probability</th>
                    <th>Class</th>
                    <th>Kind</th>
                    <th>Ground truth</th>
                    <th>Container</th>
                    <th>Port</th>
                    <th>Event</th>
                    <th>Leading finding</th>
                    <th className="text-right">Latency</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => {
                    const correct = row.truth ? row.flagged : !row.flagged;
                    return (
                      <tr
                        key={`${row.sequence}-${row.record_id}`}
                        onClick={() => select(row.record_id, row.container_id, "investigate")}
                      >
                        <td className="font-mono tnum text-2xs text-ink-700">{row.sequence}</td>
                        <td className="font-mono text-xs text-signal">{row.record_id}</td>
                        <td>
                          <span
                            className="font-mono tnum text-xs"
                            style={{ color: severityColour(row.tampering_probability) }}
                          >
                            {pct(row.tampering_probability)}
                          </span>
                        </td>
                        <td>
                          <TamperBadge value={row.tamper_class} />
                        </td>
                        <td>
                          {row.is_revision ? (
                            <Badge colour="#7c8cff">revision</Badge>
                          ) : (
                            <span className="text-2xs text-ink-700">new</span>
                          )}
                        </td>
                        <td>
                          {row.truth ? (
                            <Badge colour={correct ? "#2fa36b" : "#e5484d"}>{row.truth}</Badge>
                          ) : (
                            <span
                              className={`text-2xs ${
                                row.flagged ? "text-anomaly-low" : "text-ink-700"
                              }`}
                            >
                              legitimate
                            </span>
                          )}
                        </td>
                        <td className="font-mono text-2xs text-ink-300">
                          {row.container_id ?? "—"}
                        </td>
                        <td className="font-mono text-2xs text-ink-500">
                          {row.port_id ?? "—"}
                        </td>
                        <td className="text-2xs text-ink-500">{row.event_type ?? "—"}</td>
                        <td className="font-mono text-2xs text-ink-300">
                          {row.evidence[0]?.code ?? "—"}
                        </td>
                        <td className="font-mono tnum text-2xs text-ink-700 text-right">
                          {row.latency_ms.toFixed(1)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      )}

      {/* ---------------------------------------------- most recent detection */}
      {rows.find((row) => row.flagged) && (
        <Panel title="Most recent detection">
          <LatestDetection row={rows.find((row) => row.flagged)!} />
        </Panel>
      )}
    </div>
  );
}

function LatestDetection({ row }: { row: FeedRow }) {
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-baseline gap-3">
        <span className="font-mono text-base text-ink-50">{row.record_id}</span>
        <TamperBadge value={row.tamper_class} />
        <span
          className="font-mono tnum text-lg"
          style={{ color: severityColour(row.tampering_probability) }}
        >
          {pct(row.tampering_probability)}
        </span>
        {row.truth && <Badge colour={TAMPER_COLOUR.FABRICATED}>injected: {row.truth}</Badge>}
        <span className="font-mono text-2xs text-ink-700">{ts(row.timestamp)}</span>
      </div>

      <div>
        <SectionLabel>Findings</SectionLabel>
        <ul className="space-y-1.5">
          {row.evidence.map((item, index) => (
            <li key={`${item.code}-${index}`} className="flex items-start gap-2.5">
              <span
                className="font-mono tnum text-2xs w-9 text-right shrink-0"
                style={{ color: severityColour(item.severity) }}
              >
                {item.severity.toFixed(2)}
              </span>
              <span className="min-w-0">
                <span className="font-mono text-2xs text-ink-100">{item.code}</span>
                <span className="ml-2 text-2xs text-ink-700">{item.engine}</span>
                <p className="text-2xs text-ink-500 leading-relaxed">{item.description}</p>
              </span>
            </li>
          ))}
        </ul>
      </div>

      <div className="pt-2.5 border-t border-hairline">
        <SectionLabel>Rationale</SectionLabel>
        <p className="text-xs text-ink-300 leading-relaxed">{row.rationale}</p>
      </div>

      {row.reconstruction && (
        <div className="pt-2.5 border-t border-hairline">
          <SectionLabel>Live disposition</SectionLabel>
          <p className="text-2xs text-ink-500 leading-relaxed">
            <span className="text-ink-100">{row.reconstruction.classification}</span> at{" "}
            {pct(row.reconstruction.confidence)} — {row.reconstruction.reason}
          </p>
        </div>
      )}
    </div>
  );
}

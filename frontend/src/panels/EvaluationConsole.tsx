/**
 * Evaluation console (spec 31).
 *
 * Renders the offline scorer's output. The line this sits on is worth stating:
 * `scripts/evaluate.py` is the only thing that ever reads the private
 * injection log, and it writes its results to disk. The detector never sees
 * the answer key — this view is our own scorecard, which is a reporting
 * concern.
 *
 * Two things here are deliberately uncomfortable to show, and are shown
 * anyway:
 *
 * - **The ablation.** The provenance chain is the strongest single evidence
 *   source, so the headline number alone would hide how much work the forensic
 *   engines actually do. Both rows are displayed side by side.
 * - **The calibration gap.** Above 0.5 the system is systematically
 *   *under*-confident. Correcting that would mean fitting against the answer
 *   key, which would make every number on this screen circular, so the curve
 *   is reported as measured.
 */

import {
  Badge,
  DatumLine,
  Empty,
  ErrorState,
  Metric,
  Panel,
  SectionLabel,
  Spinner,
} from "../components/primitives";
import { api } from "../lib/api";
import { num, pct, severityColour } from "../lib/format";
import { useAsync } from "../lib/useAsync";

interface BinaryMetrics {
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
  precision: number;
  recall: number;
  f1: number;
  false_positive_rate: number;
  false_negative_rate: number;
}

interface BatchReport {
  detection: BinaryMetrics;
  false_alarms: Record<string, number>;
  recall_by_attack: Record<string, { population: number; detected: number; recall: number }>;
  classification: {
    scored: number;
    correct: number;
    accuracy: number;
    confusion: Record<string, Record<string, number>>;
    note?: string;
  };
  repair: Record<string, number | Record<string, { scored: number; correct: number; accuracy: number }>>;
  deletions: Record<string, number>;
  calibration: Array<{
    bin: string;
    count: number;
    mean_predicted: number;
    observed_rate: number;
    gap: number;
  }>;
  disposition: Record<string, number>;
}

interface StreamReport {
  stream_seed: number;
  injected: Record<string, number>;
  detection: Record<string, number>;
  campaign_recall?: Record<string, { campaigns: number; caught: number; recall: number }>;
  recall_by_pattern: Record<string, { injected: number; detected: number; recall: number }>;
  throughput: { latency_ms: { mean: number; p50: number; p95: number; max: number } };
  evidence_codes: Record<string, number>;
}

export function EvaluationConsole() {
  const evaluation = useAsync(() => api.evaluation(), []);

  if (evaluation.loading) {
    return (
      <div className="h-full flex items-center justify-center">
        <Spinner label="Loading evaluation artifacts…" />
      </div>
    );
  }
  if (evaluation.error) {
    return evaluation.error.message.includes("No evaluation artifact") ? (
      <Empty
        title="The scorer has not been run for this dataset."
        hint={
          <>
            Run it to populate this console:
            <code className="block mt-2 text-ink-300">
              python scripts/evaluate.py --out out --ablation
            </code>
            <code className="block mt-1 text-ink-300">
              python scripts/stream_sim.py --out out --events 900
            </code>
          </>
        }
      />
    ) : (
      <ErrorState error={evaluation.error} onRetry={evaluation.reload} />
    );
  }

  const payload = evaluation.data as
    | { batch: Record<string, BatchReport> | null; stream: StreamReport | null; note: string }
    | null;
  const batch = payload?.batch ?? null;
  const stream = payload?.stream ?? null;
  const configurations = batch ? Object.entries(batch) : [];
  const primary = configurations[0]?.[1] ?? null;

  return (
    <div className="h-full min-h-0 overflow-y-auto p-3 space-y-3">
      {primary && (
        <div className="panel">
          <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 divide-x divide-hairline">
            <Metric label="Precision" value={pct(primary.detection.precision, 1)} emphasis />
            <Metric label="Recall" value={pct(primary.detection.recall, 1)} emphasis />
            <Metric label="F1" value={primary.detection.f1.toFixed(3)} accent="#4cc2ff" emphasis />
            <Metric
              label="False alarms — clean"
              value={num(primary.false_alarms.on_clean_records ?? 0)}
              sub={`of ${num(primary.false_alarms.clean_population ?? 0)} clean records`}
              accent={(primary.false_alarms.on_clean_records ?? 0) > 5 ? "#d9a21b" : "#2fa36b"}
              emphasis
            />
            <Metric
              label="False alarms — noisy"
              value={num(primary.false_alarms.on_noise_only_records ?? 0)}
              sub={`of ${num(primary.false_alarms.noise_only_population ?? 0)} noise-only records`}
              accent={(primary.false_alarms.on_noise_only_records ?? 0) > 0 ? "#d9a21b" : "#2fa36b"}
              emphasis
            />
            <Metric
              label="Classification"
              value={pct(primary.classification.accuracy, 1)}
              sub={`${primary.classification.correct}/${primary.classification.scored} detected`}
              emphasis
            />
          </div>
        </div>
      )}

      {/* ---------------------------------------------- ablation */}
      {configurations.length > 1 && (
        <Panel title="Ablation — how much work do the forensic engines do?">
          <table className="data-table">
            <thead>
              <tr>
                <th>Configuration</th>
                <th className="text-right">Precision</th>
                <th className="text-right">Recall</th>
                <th className="text-right">F1</th>
                <th className="text-right">FP clean</th>
                <th className="text-right">FP noisy</th>
                <th className="text-right">FN</th>
              </tr>
            </thead>
            <tbody>
              {configurations.map(([label, report]) => (
                <tr key={label} className="cursor-default">
                  <td className="text-xs text-ink-100">{label}</td>
                  <td className="font-mono tnum text-xs text-right">
                    {pct(report.detection.precision, 1)}
                  </td>
                  <td className="font-mono tnum text-xs text-right">
                    {pct(report.detection.recall, 1)}
                  </td>
                  <td className="font-mono tnum text-xs text-right text-signal">
                    {report.detection.f1.toFixed(3)}
                  </td>
                  <td className="font-mono tnum text-xs text-right">
                    {num(report.false_alarms.on_clean_records ?? 0)}
                  </td>
                  <td className="font-mono tnum text-xs text-right">
                    {num(report.false_alarms.on_noise_only_records ?? 0)}
                  </td>
                  <td className="font-mono tnum text-xs text-right">
                    {num(report.detection.false_negatives)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-2.5 text-2xs text-ink-700 leading-relaxed">
            The provenance chain commits hashes, never values, and covers only a prefix
            of the timeline — but where it reaches, a hash mismatch is near-proof, so it
            dominates recall. Showing the ablation is the honest way to present a system
            with one strong feature: the second row is what the consistency engines
            achieve with no chain at all.
          </p>
        </Panel>
      )}

      {primary && (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
          {/* ------------------------------------------ recall by attack */}
          <Panel title="Recall by attack type">
            <ul className="space-y-2.5">
              {Object.entries(primary.recall_by_attack).map(([attack, stat]) => (
                <li key={attack}>
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="text-xs text-ink-100">{attack}</span>
                    <span className="font-mono tnum text-2xs text-ink-500">
                      {stat.detected}/{stat.population} · {pct(stat.recall, 1)}
                    </span>
                  </div>
                  <DatumLine
                    value={stat.recall}
                    colour={stat.recall >= 0.9 ? "#2fa36b" : stat.recall >= 0.7 ? "#4cc2ff" : "#d9a21b"}
                    className="mt-1.5"
                  />
                </li>
              ))}
              {primary.deletions.slot_recall !== undefined && (
                <li className="pt-2 border-t border-hairline-faint">
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="text-xs text-ink-100">DELETED (by slot)</span>
                    <span className="font-mono tnum text-2xs text-ink-500">
                      {primary.deletions.slots_matched}/{primary.deletions.injected_slots} ·{" "}
                      {pct(primary.deletions.slot_recall, 1)}
                    </span>
                  </div>
                  <DatumLine value={primary.deletions.slot_recall} colour="#7c8cff" className="mt-1.5" />
                  <p className="mt-1.5 text-2xs text-ink-700">
                    Scored on slots — container, port, missing event — because a deleted
                    record has no row to label.
                  </p>
                </li>
              )}
            </ul>
          </Panel>

          {/* ------------------------------------------ classification */}
          <Panel title={`Tampering classification — ${pct(primary.classification.accuracy, 1)}`}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Injected</th>
                  <th>Predicted</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(primary.classification.confusion).map(([expected, predictions]) => {
                  const total = Object.values(predictions).reduce((a, b) => a + b, 0);
                  return (
                    <tr key={expected} className="cursor-default">
                      <td className="text-xs text-ink-100">{expected}</td>
                      <td>
                        <div className="flex flex-wrap gap-1.5">
                          {Object.entries(predictions)
                            .sort((a, b) => b[1] - a[1])
                            .map(([predicted, count]) => (
                              <Badge
                                key={predicted}
                                colour={predicted === expected ? "#2fa36b" : "#e5563d"}
                              >
                                {predicted} ×{count} ({pct(count / total, 0)})
                              </Badge>
                            ))}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {primary.classification.note && (
              <p className="mt-2.5 text-2xs text-ink-700 leading-relaxed">
                {primary.classification.note}
              </p>
            )}
          </Panel>

          {/* ------------------------------------------ repair */}
          <Panel title="Reconstruction accuracy">
            <div className="grid grid-cols-2 gap-x-5 gap-y-2">
              {(
                [
                  ["repaired_records", "Records repaired"],
                  ["verifiable_records", "Verifiable against key"],
                  ["exact_record_matches", "Exact record matches"],
                  ["record_accuracy", "Record accuracy"],
                  ["fields_scored", "Fields scored"],
                  ["field_accuracy", "Field accuracy"],
                  ["mean_repair_confidence", "Mean confidence"],
                ] as Array<[string, string]>
              ).map(([key, label]) => {
                const value = primary.repair[key];
                if (typeof value !== "number") return null;
                const isRate = key.includes("accuracy") || key.includes("confidence");
                return (
                  <div key={key} className="flex items-baseline justify-between gap-2">
                    <span className="text-2xs text-ink-500">{label}</span>
                    <span className="font-mono tnum text-xs text-ink-100">
                      {isRate ? pct(value, 1) : num(value)}
                    </span>
                  </div>
                );
              })}
            </div>

            {typeof primary.repair.by_field === "object" && (
              <div className="mt-3.5 pt-3 border-t border-hairline">
                <SectionLabel>By field</SectionLabel>
                <ul className="space-y-1.5">
                  {Object.entries(
                    primary.repair.by_field as Record<
                      string,
                      { scored: number; correct: number; accuracy: number }
                    >,
                  )
                    .sort((a, b) => b[1].scored - a[1].scored)
                    .map(([field, stat]) => (
                      <li key={field}>
                        <div className="flex items-baseline justify-between gap-2">
                          <span className="text-2xs text-ink-300">{field}</span>
                          <span className="font-mono tnum text-2xs text-ink-500">
                            {stat.correct}/{stat.scored} · {pct(stat.accuracy, 0)}
                          </span>
                        </div>
                        <DatumLine
                          value={stat.accuracy}
                          colour={stat.accuracy >= 0.9 ? "#2fa36b" : stat.accuracy >= 0.6 ? "#4cc2ff" : "#d9a21b"}
                          className="mt-1"
                        />
                      </li>
                    ))}
                </ul>
                <p className="mt-2.5 text-2xs text-ink-700 leading-relaxed">
                  Timestamps are the weakest field, and that is expected: a neighbour's
                  weight is the value that was overwritten, but a neighbour's timestamp
                  only bounds the correct one.
                </p>
              </div>
            )}
          </Panel>

          {/* ------------------------------------------ calibration */}
          <Panel title="Calibration — does a stated probability mean what it says?">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Bin</th>
                  <th className="text-right">Records</th>
                  <th className="text-right">Predicted</th>
                  <th className="text-right">Observed</th>
                  <th className="text-right">Gap</th>
                </tr>
              </thead>
              <tbody>
                {primary.calibration.map((row) => (
                  <tr key={row.bin} className="cursor-default">
                    <td className="font-mono text-2xs text-ink-300">{row.bin}</td>
                    <td className="font-mono tnum text-2xs text-right text-ink-500">
                      {num(row.count)}
                    </td>
                    <td className="font-mono tnum text-2xs text-right text-ink-300">
                      {row.mean_predicted.toFixed(3)}
                    </td>
                    <td className="font-mono tnum text-2xs text-right text-ink-100">
                      {row.observed_rate.toFixed(3)}
                    </td>
                    <td
                      className="font-mono tnum text-2xs text-right"
                      style={{ color: severityColour(Math.abs(row.gap)) }}
                    >
                      {row.gap >= 0 ? "+" : ""}
                      {row.gap.toFixed(3)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="mt-2.5 text-2xs text-ink-700 leading-relaxed">
              Positive gaps above 0.5 mean the system is <em>under</em>-confident: a
              stated 70% is right more often than 70% of the time. That is the safe
              direction, and it is reported rather than corrected — fitting a correction
              would require the answer key and make every number here circular.
            </p>
          </Panel>
        </div>
      )}

      {/* ---------------------------------------------- live stream */}
      {stream && (
        <Panel title="Live stream — attack patterns absent from the batch data">
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
            <div>
              <SectionLabel>Recall by pattern</SectionLabel>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Pattern</th>
                    <th className="text-right">Events</th>
                    <th className="text-right">Event recall</th>
                    <th className="text-right">Campaigns</th>
                    <th className="text-right">Campaign recall</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(stream.recall_by_pattern).map(([pattern, stat]) => {
                    const campaign = stream.campaign_recall?.[pattern];
                    return (
                      <tr key={pattern} className="cursor-default">
                        <td className="text-xs text-ink-100">{pattern}</td>
                        <td className="font-mono tnum text-2xs text-right text-ink-500">
                          {stat.detected}/{stat.injected}
                        </td>
                        <td className="font-mono tnum text-2xs text-right">
                          {pct(stat.recall, 0)}
                        </td>
                        <td className="font-mono tnum text-2xs text-right text-ink-500">
                          {campaign ? `${campaign.caught}/${campaign.campaigns}` : "—"}
                        </td>
                        <td
                          className="font-mono tnum text-2xs text-right"
                          style={{ color: campaign ? severityColour(1 - campaign.recall) : undefined }}
                        >
                          {campaign ? pct(campaign.recall, 0) : "—"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1.5 text-2xs text-ink-500">
                <span>
                  precision{" "}
                  <span className="font-mono text-ink-100">
                    {pct(stream.detection.precision ?? 0, 1)}
                  </span>
                </span>
                <span>
                  false alarms{" "}
                  <span className="font-mono text-ink-100">
                    {num(stream.detection.false_positives ?? 0)}
                  </span>
                </span>
                <span>
                  collateral{" "}
                  <span className="font-mono text-ink-100">
                    {num(stream.detection.collateral_flags_on_attacked_containers ?? 0)}
                  </span>
                </span>
                <span>
                  mean latency{" "}
                  <span className="font-mono text-ink-100">
                    {stream.throughput.latency_ms.mean.toFixed(2)} ms
                  </span>
                </span>
              </div>
            </div>

            <div>
              <SectionLabel>Evidence that caught them</SectionLabel>
              <ul className="space-y-1.5">
                {Object.entries(stream.evidence_codes)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 10)
                  .map(([code, count]) => (
                    <li key={code} className="flex items-baseline justify-between gap-2">
                      <span className="font-mono text-2xs text-ink-300">{code}</span>
                      <span className="font-mono tnum text-2xs text-ink-500">{count}</span>
                    </li>
                  ))}
              </ul>
              <p className="mt-3 text-2xs text-ink-700 leading-relaxed">
                Every one of these is a consistency constraint, not a signature of a
                known attack. That is the whole reason the live path works on patterns
                the batch data never contained.
              </p>
            </div>
          </div>
        </Panel>
      )}

      {payload?.note && (
        <p className="px-1 text-2xs text-ink-700 leading-relaxed">{payload.note}</p>
      )}
    </div>
  );
}

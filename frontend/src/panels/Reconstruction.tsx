/**
 * Reconstruction workspace (spec 19, 20) and counterfactual explorer.
 *
 * Shows every candidate original state the engine *generated*, not only the
 * one it selected, with the per-criterion scores behind each. That is the
 * point of the view: a repair is only defensible if the alternatives it beat
 * are visible, and "why this value and not that one" is the hardest question
 * the system has to answer.
 *
 * One property worth reading off the screen: where a candidate's hash matches
 * the provenance commitment, the repair is *confirmed* rather than merely
 * scored. The chain commits hashes and not values, so it cannot be read for
 * the original weight — but once the forensic engines have constructed a
 * candidate, hashing it either certifies the answer or refutes it.
 */

import { useApp } from "../App";
import {
  Badge,
  ClassificationBadge,
  DatumLine,
  Empty,
  ErrorState,
  Panel,
  SectionLabel,
  Spinner,
} from "../components/primitives";
import { api } from "../lib/api";
import { pct, severityColour } from "../lib/format";
import { useAsync } from "../lib/useAsync";
import type { CandidateRepair, Reconstruction as ReconstructionModel } from "../lib/types";

const CRITERIA: Array<[string, string]> = [
  ["blockchain_state", "Provenance"],
  ["cargo_conservation", "Conservation"],
  ["temporal_consistency", "Temporal"],
  ["route_consistency", "Route"],
  ["neighbor_agreement", "Neighbours"],
  ["graph_consistency", "Lineage"],
  ["historical_pattern", "Peer pattern"],
];

export function Reconstruction() {
  const { selection, select } = useApp();
  const recordId = selection.recordId;

  const outcome = useAsync(
    () => (recordId ? api.reconstruct(recordId) : Promise.resolve(null)),
    [recordId],
  );

  if (!recordId) {
    return (
      <Empty
        title="No record selected."
        hint="Pick a record whose disposition you want to inspect — REPAIRED, REMOVED or UNRECOVERABLE."
      />
    );
  }
  if (outcome.error) return <ErrorState error={outcome.error} onRetry={outcome.reload} />;
  if (outcome.loading || !outcome.data) {
    return (
      <div className="h-full flex items-center justify-center">
        <Spinner label={`Reconstructing ${recordId}…`} />
      </div>
    );
  }

  const data = outcome.data;
  const changes = diff(data);

  return (
    <div className="h-full min-h-0 overflow-y-auto p-3 space-y-3">
      {/* ---------------------------------------------- decision */}
      <Panel
        title="Disposition"
        actions={
          <>
            <button
              type="button"
              className="btn"
              onClick={() => select(recordId, selection.containerId, "investigate")}
            >
              Investigation
            </button>
            <button
              type="button"
              className="btn"
              onClick={() => select(recordId, selection.containerId, "graph")}
            >
              Trace in graph
            </button>
          </>
        }
      >
        <div className="flex flex-wrap items-start justify-between gap-5">
          <div className="min-w-0">
            <div className="font-mono text-lg text-ink-50">{recordId}</div>
            <div className="mt-1.5 flex items-center gap-2">
              <ClassificationBadge value={data.classification} />
              {data.selected_candidate_id && (
                <Badge className="border-hairline text-ink-500">
                  candidate {data.selected_candidate_id}
                </Badge>
              )}
            </div>
          </div>
          <div className="text-right">
            <div
              className="font-mono tnum text-3xl leading-none"
              style={{ color: severityColour(1 - data.confidence) }}
            >
              {pct(data.confidence)}
            </div>
            <div className="text-2xs uppercase tracking-[0.14em] text-ink-500 mt-1">
              confidence
            </div>
          </div>
        </div>
        <p className="mt-3.5 pt-3 border-t border-hairline text-xs text-ink-300 leading-relaxed">
          {data.reason}
        </p>
      </Panel>

      {/* ---------------------------------------------- observed vs reconstructed */}
      {data.classification === "REPAIRED" && changes.length > 0 && (
        <Panel title="Observed versus reconstructed">
          <table className="data-table">
            <thead>
              <tr>
                <th>Field</th>
                <th>Observed</th>
                <th />
                <th>Reconstructed</th>
              </tr>
            </thead>
            <tbody>
              {changes.map(([field, before, after]) => (
                <tr key={field} className="cursor-default">
                  <td className="text-2xs uppercase tracking-[0.08em] text-ink-500">
                    {field}
                  </td>
                  <td className="font-mono tnum text-xs text-anomaly-high">{before}</td>
                  <td className="text-ink-700 text-center w-8">→</td>
                  <td className="font-mono tnum text-xs text-signal">{after}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-2.5 text-2xs text-ink-700 leading-relaxed">
            The original state is retained in full alongside the reconstruction. Nothing
            is silently altered — every output record carries its disposition, its
            confidence and the reason for the change.
          </p>
        </Panel>
      )}

      {data.classification === "REMOVED" && (
        <Panel title="Removal">
          <p className="text-xs text-ink-300 leading-relaxed">
            This row is not present in the reconstructed manifest. The original is
            retained below so the removal is auditable rather than destructive.
          </p>
          <div className="mt-3">
            <SectionLabel>Original state</SectionLabel>
            <StatePrint state={data.original} />
          </div>
        </Panel>
      )}

      {data.classification === "UNRECOVERABLE" && (
        <Panel title="Unrecoverable">
          <p className="text-xs text-ink-300 leading-relaxed">
            The record is suspect but no candidate reconstruction cleared the repair
            threshold. It is reported as unrecoverable rather than altered on weak
            evidence — guessing here would replace a known-bad value with an invented
            one, which is worse.
          </p>
        </Panel>
      )}

      {/* ---------------------------------------------- counterfactual explorer */}
      <Panel
        title={`Candidates considered — ${data.candidates.length}`}
        actions={
          <span className="text-2xs text-ink-700">
            every candidate the engine generated, scored
          </span>
        }
      >
        {data.candidates.length === 0 ? (
          <div className="text-2xs text-ink-700">
            No candidate could be constructed: the evidence does not implicate a
            specific field.
          </div>
        ) : (
          <ul className="space-y-2.5">
            {data.candidates.map((candidate) => (
              <CandidateCard
                key={candidate.candidate_id}
                candidate={candidate}
                selected={candidate.candidate_id === data.selected_candidate_id}
              />
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}

function CandidateCard({
  candidate,
  selected,
}: {
  candidate: CandidateRepair;
  selected: boolean;
}) {
  const certified = candidate.criterion_scores.blockchain_state === 1;

  return (
    <li
      className={`rounded-xs border p-3 ${
        selected
          ? "border-signal/50 bg-signal/[0.07]"
          : "border-hairline bg-obsidian-850"
      }`}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-2xs text-ink-300">{candidate.candidate_id}</span>
            <Badge className="border-hairline text-ink-500">{candidate.strategy}</Badge>
            {candidate.remove && <Badge colour="#e5563d">remove record</Badge>}
            {selected && <Badge colour="#4cc2ff">selected</Badge>}
            {certified && (
              <Badge
                colour="#2fa36b"
                title="The repaired record hashes to the value committed in the provenance chain"
              >
                chain-confirmed
              </Badge>
            )}
          </div>

          {!candidate.remove && Object.keys(candidate.changes).length > 0 && (
            <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
              {Object.entries(candidate.changes).map(([field, value]) => (
                <span key={field} className="text-2xs">
                  <span className="text-ink-500 uppercase tracking-[0.08em]">{field}</span>
                  <span className="ml-1.5 font-mono tnum text-ink-100">{format(value)}</span>
                </span>
              ))}
            </div>
          )}

          <p className="mt-2 text-2xs text-ink-500 leading-relaxed">{candidate.explanation}</p>
        </div>

        <div className="shrink-0 w-16 text-right">
          <div
            className="font-mono tnum text-base"
            style={{ color: candidate.score >= 0.7 ? "#4cc2ff" : "#6f7d91" }}
          >
            {pct(candidate.score, 0)}
          </div>
          <DatumLine
            value={candidate.score}
            colour={candidate.score >= 0.7 ? "#4cc2ff" : "#5f6b7d"}
            className="mt-1"
          />
        </div>
      </div>

      {Object.keys(candidate.criterion_scores).length > 1 && (
        <div className="mt-3 pt-2.5 border-t border-hairline-faint grid grid-cols-2 md:grid-cols-4 gap-x-4 gap-y-1.5">
          {CRITERIA.filter(([key]) => key in candidate.criterion_scores).map(
            ([key, label]) => {
              const score = candidate.criterion_scores[key] ?? 0;
              return (
                <div key={key}>
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="text-2xs text-ink-500 truncate">{label}</span>
                    <span className="font-mono tnum text-2xs text-ink-300">
                      {score.toFixed(2)}
                    </span>
                  </div>
                  <DatumLine
                    value={score}
                    colour={score >= 0.8 ? "#2fa36b" : score >= 0.5 ? "#4cc2ff" : "#5f6b7d"}
                    className="mt-0.5"
                  />
                </div>
              );
            },
          )}
        </div>
      )}
    </li>
  );
}

function StatePrint({ state }: { state: Record<string, unknown> }) {
  const entries = Object.entries(state).filter(
    ([, value]) => value !== null && value !== undefined && value !== "",
  );
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 gap-x-5 gap-y-1 max-h-60 overflow-y-auto">
      {entries.map(([key, value]) => (
        <div key={key} className="flex items-baseline justify-between gap-2 min-w-0">
          <span className="text-2xs uppercase tracking-[0.08em] text-ink-500 shrink-0">
            {key}
          </span>
          <span className="font-mono tnum text-2xs text-ink-300 truncate text-right">
            {format(value)}
          </span>
        </div>
      ))}
    </div>
  );
}

function diff(data: ReconstructionModel): Array<[string, string, string]> {
  if (!data.reconstructed) return [];
  const rows: Array<[string, string, string]> = [];
  for (const [key, after] of Object.entries(data.reconstructed)) {
    const before = data.original[key];
    if (JSON.stringify(before) !== JSON.stringify(after)) {
      rows.push([key, format(before), format(after)]);
    }
  }
  return rows;
}

function format(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "number") {
    return Number.isInteger(value) ? value.toLocaleString() : value.toLocaleString(undefined, {
      maximumFractionDigits: 2,
    });
  }
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

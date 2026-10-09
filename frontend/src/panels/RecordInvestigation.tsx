/**
 * Record investigation (spec 15.4, 17, 37).
 *
 * The screen that answers "why did you flag this?". It lays out the
 * Observation → Evidence → Inference → Decision chain of spec 38 top to
 * bottom, so the reasoning reads in the order it was performed:
 *
 *   the record as delivered   (observation, including the raw export row)
 *   every finding against it  (evidence, with the engine that produced it)
 *   the fused breakdown       (inference, with the arithmetic shown)
 *   the disposition           (decision, with the candidates considered)
 *
 * Blame arbitration gets its own block, because "we flagged this one and not
 * that one" is the question a judge is most likely to press on, and the
 * answer — corroboration scores from independent layers — should not be
 * buried in a tooltip.
 */

import { useState } from "react";

import { useApp } from "../App";
import { BenignNote, EvidenceBreakdown } from "../components/EvidenceBreakdown";
import {
  Badge,
  ClassificationBadge,
  DatumLine,
  Empty,
  ErrorState,
  KeyValue,
  Panel,
  SectionLabel,
  Spinner,
  TamperBadge,
} from "../components/primitives";
import { api } from "../lib/api";
import {
  LAYER_COLOUR,
  kg,
  money,
  pct,
  severityColour,
  ts,
} from "../lib/format";
import { useAsync } from "../lib/useAsync";
import type { Evidence, LlmExplainResponse, RecordDetail } from "../lib/types";

export function RecordInvestigation() {
  const { selection, select } = useApp();
  const recordId = selection.recordId;

  const detail = useAsync(
    () => (recordId ? api.record(recordId) : Promise.resolve(null)),
    [recordId],
  );

  if (!recordId) {
    return (
      <Empty
        title="No record selected."
        hint="Pick a record from the ledger, the Command Center risk table, or the map."
      />
    );
  }
  if (detail.error) return <ErrorState error={detail.error} onRetry={detail.reload} />;
  if (detail.loading || !detail.data) {
    return (
      <div className="h-full flex items-center justify-center">
        <Spinner label={`Loading ${recordId}…`} />
      </div>
    );
  }

  const data = detail.data;
  const verdict = data.verdict;
  const record = data.record as Record<string, unknown>;
  const containerId = (record.container_id as string | null) ?? null;

  return (
    <div className="h-full min-h-0 overflow-y-auto p-3">
      <div className="grid grid-cols-1 2xl:grid-cols-[1.25fr_1fr] gap-3">
        {/* ============================================ left column */}
        <div className="space-y-3 min-w-0">
          {/* --- header: identity and verdict --- */}
          <Panel
            title="Record"
            actions={
              <>
                <button
                  type="button"
                  className="btn"
                  onClick={() => select(recordId, containerId, "graph")}
                >
                  Trace in graph
                </button>
                <button
                  type="button"
                  className="btn"
                  onClick={() => select(recordId, containerId, "map")}
                >
                  Locate on map
                </button>
                <button
                  type="button"
                  className="btn"
                  onClick={() => select(recordId, containerId, "reconstruct")}
                >
                  Rebuild
                </button>
              </>
            }
          >
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="min-w-0">
                <div className="font-mono text-lg text-ink-50">{recordId}</div>
                <div className="mt-1 flex flex-wrap items-center gap-1.5">
                  {verdict && <TamperBadge value={verdict.tamper_class} />}
                  <ClassificationBadge value={data.reconstruction?.classification ?? null} />
                  {verdict && (
                    <Badge className="border-hairline text-ink-500">
                      class confidence {pct(verdict.class_confidence, 0)}
                    </Badge>
                  )}
                  {data.corroboration !== null && (
                    <Badge
                      colour={severityColour(1 - (data.corroboration ?? 0))}
                      title="How well the rest of the manifest supports this record"
                    >
                      corroboration {(data.corroboration ?? 0).toFixed(2)}
                    </Badge>
                  )}
                </div>
              </div>
              {verdict && (
                <div className="text-right">
                  <div
                    className="font-mono tnum text-4xl leading-none"
                    style={{ color: severityColour(verdict.tampering_probability) }}
                  >
                    {pct(verdict.tampering_probability)}
                  </div>
                  <div className="text-2xs uppercase tracking-[0.14em] text-ink-500 mt-1">
                    tampering probability
                  </div>
                </div>
              )}
            </div>

            <div className="mt-4 pt-3 border-t border-hairline">
              <SectionLabel>Observation — the record as delivered</SectionLabel>
              <KeyValue
                columns={2}
                rows={[
                  ["container", String(record.container_id ?? "—")],
                  ["shipment", String(record.shipment_id ?? "—")],
                  ["owner", String(record.owner ?? "—")],
                  ["cargo", String(record.cargo_type ?? "—")],
                  ["origin", String(record.origin ?? "—")],
                  ["destination", String(record.destination ?? "—")],
                  ["location", String(record.current_location ?? "—")],
                  ["port", String(record.port_id ?? "—")],
                  ["route", String(record.route_id ?? "—")],
                  ["vessel", String(record.vessel_id ?? "—")],
                  ["event", String(record.event_type ?? "—")],
                  ["status", String(record.status ?? "—")],
                  ["weight", kg(record.weight as number | null)],
                  ["declared value", money(record.declared_value as number | null)],
                  ["timestamp", ts(record.timestamp as string | null, true)],
                  ["arrival", ts(record.arrival_timestamp as string | null, true)],
                  ["departure", ts(record.departure_timestamp as string | null, true)],
                  ["source node", String(record.source_node ?? "—")],
                ]}
              />
              {data.normalization_notes.length > 0 && (
                <div className="mt-3 pt-2.5 border-t border-hairline-faint">
                  <SectionLabel>Normalisation applied</SectionLabel>
                  <ul className="space-y-0.5">
                    {data.normalization_notes.map((note) => (
                      <li key={note} className="text-2xs text-ink-500">
                        · {note}
                      </li>
                    ))}
                  </ul>
                  <p className="mt-1.5 text-2xs text-ink-700">
                    These were recovered from the export, not altered. They are reported
                    as benign data-quality findings and reduce the tampering score.
                  </p>
                </div>
              )}
            </div>
          </Panel>

          {/* --- evidence list --- */}
          <Panel title={`Evidence — ${data.evidence.length} finding(s)`}>
            {data.evidence.length === 0 ? (
              <div className="text-2xs text-ink-700">
                No detector raised evidence against this record.
              </div>
            ) : (
              <ul className="space-y-2.5">
                {data.evidence.map((item, index) => (
                  <EvidenceRow
                    key={`${item.code}-${index}`}
                    item={item}
                    onSelectRecord={(id) => select(id, containerId, "investigate")}
                  />
                ))}
              </ul>
            )}
          </Panel>

          {/* --- container timeline --- */}
          <Panel title="Container event chain">
            <ContainerChain
              points={data.container_timeline}
              activeId={recordId}
              onSelect={(id) => select(id, containerId, "investigate")}
            />
          </Panel>
        </div>

        {/* ============================================ right column */}
        <div className="space-y-3 min-w-0">
          {verdict && (
            <Panel title="Inference — fused breakdown">
              <EvidenceBreakdown verdict={verdict} />
              <div className="mt-4 pt-3 border-t border-hairline space-y-2.5">
                <SectionLabel>Deterministic rationale</SectionLabel>
                <p className="text-xs text-ink-300 leading-relaxed">{verdict.rationale}</p>
                <BenignNote />
              </div>
            </Panel>
          )}

          <ArbitrationBlock evidence={data.evidence} />

          {data.reconstruction && (
            <Panel title="Decision — disposition">
              <div className="flex items-center justify-between gap-3">
                <ClassificationBadge value={data.reconstruction.classification} />
                <div className="text-right">
                  <div className="font-mono tnum text-lg text-ink-100">
                    {pct(data.reconstruction.confidence)}
                  </div>
                  <div className="text-2xs text-ink-700 uppercase tracking-[0.1em]">
                    confidence
                  </div>
                </div>
              </div>
              <p className="mt-3 text-xs text-ink-300 leading-relaxed">
                {data.reconstruction.reason}
              </p>
              <button
                type="button"
                className="btn mt-3"
                onClick={() => select(recordId, containerId, "reconstruct")}
              >
                Open reconstruction workspace
              </button>
            </Panel>
          )}

          <AnalystBlock recordId={recordId} />

          <Panel title="Raw export row">
            <div className="max-h-56 overflow-auto">
              <table className="w-full text-2xs">
                <tbody>
                  {Object.entries(data.raw).map(([key, value]) => (
                    <tr key={key} className="border-b border-hairline-faint">
                      <td className="py-1 pr-3 text-ink-500 uppercase tracking-[0.08em] whitespace-nowrap align-top">
                        {key}
                      </td>
                      <td className="py-1 font-mono text-ink-300 break-all">
                        {value === "" ? (
                          <span className="text-ink-700">(blank)</span>
                        ) : (
                          value
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="mt-2 text-2xs text-ink-700">
              Exactly what was in the file, before normalisation.
            </p>
          </Panel>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- pieces

function EvidenceRow({
  item,
  onSelectRecord,
}: {
  item: Evidence;
  onSelectRecord: (id: string) => void;
}) {
  const arbitration = item.details?.arbitration as
    | { outcome?: string; multiplier?: number; original_severity?: number }
    | undefined;

  return (
    <li className="rounded-xs border border-hairline bg-obsidian-850 p-2.5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span
              className="font-mono text-2xs"
              style={{ color: LAYER_COLOUR[item.type] }}
            >
              {item.code}
            </span>
            <Badge colour={LAYER_COLOUR[item.type]}>{item.type}</Badge>
            <span className="text-2xs text-ink-700">{item.engine}</span>
            {arbitration?.outcome === "exonerated" && (
              <Badge colour="#2fa36b" title="Blame was attributed to the counterpart record">
                arbitrated down ×{arbitration.multiplier?.toFixed(2)}
              </Badge>
            )}
          </div>
          <p className="mt-1.5 text-xs text-ink-300 leading-relaxed">{item.description}</p>
          {item.supporting_records.length > 0 && (
            <div className="mt-1.5 flex flex-wrap items-center gap-1">
              <span className="text-2xs text-ink-700">corroborated by</span>
              {item.supporting_records.slice(0, 6).map((id) => (
                <button
                  key={id}
                  type="button"
                  className="font-mono text-2xs text-signal hover:underline"
                  onClick={() => onSelectRecord(id)}
                >
                  {id}
                </button>
              ))}
              {item.supporting_records.length > 6 && (
                <span className="text-2xs text-ink-700">
                  +{item.supporting_records.length - 6}
                </span>
              )}
            </div>
          )}
        </div>
        <div className="shrink-0 w-14 text-right">
          <div
            className="font-mono tnum text-sm"
            style={{ color: severityColour(item.severity) }}
          >
            {item.severity.toFixed(2)}
          </div>
          <DatumLine value={item.severity} className="mt-1" />
        </div>
      </div>
    </li>
  );
}

/** Blame arbitration (design decision D7), surfaced as a first-class block. */
function ArbitrationBlock({ evidence }: { evidence: Evidence[] }) {
  const decisions = evidence
    .map((item) => item.details?.arbitration as Record<string, unknown> | undefined)
    .filter((value): value is Record<string, unknown> => Boolean(value));

  if (decisions.length === 0) return null;
  const first = decisions[0];
  const outcome = String(first.outcome ?? "");
  const why = (first.why as string[] | undefined) ?? [];

  return (
    <Panel title="Blame arbitration">
      <div className="flex items-center gap-2 flex-wrap">
        <Badge colour={outcome === "blamed" ? "#e5484d" : "#2fa36b"}>
          {outcome === "blamed" ? "blamed" : "exonerated"}
        </Badge>
        <span className="text-2xs text-ink-500">
          corroboration{" "}
          <span className="font-mono text-ink-100">
            {Number(first.corroboration ?? 0).toFixed(2)}
          </span>{" "}
          vs{" "}
          <span className="font-mono text-signal">{String(first.counterpart ?? "—")}</span> at{" "}
          <span className="font-mono text-ink-100">
            {Number(first.counterpart_corroboration ?? 0).toFixed(2)}
          </span>
        </span>
      </div>
      {why.length > 0 && (
        <ul className="mt-2.5 space-y-0.5">
          {why.map((reason) => (
            <li key={reason} className="text-2xs text-ink-300">
              · {reason}
            </li>
          ))}
        </ul>
      )}
      <p className="mt-2.5 text-2xs text-ink-700 leading-relaxed">
        When two records contradict each other, both carry the evidence but only one
        is usually the lie. Blame goes to whichever the rest of the manifest supports
        less — measured against the provenance chain, route membership, the company
        it keeps at that port call, and its own lineage.
      </p>
    </Panel>
  );
}

function ContainerChain({
  points,
  activeId,
  onSelect,
}: {
  points: RecordDetail["container_timeline"];
  activeId: string;
  onSelect: (id: string) => void;
}) {
  if (points.length === 0) {
    return <div className="text-2xs text-ink-700">No container history available.</div>;
  }
  return (
    <ol className="space-y-px">
      {points.map((point) => {
        const active = point.record_id === activeId;
        const probability = point.probability ?? 0;
        return (
          <li key={point.record_id}>
            <button
              type="button"
              onClick={() => onSelect(point.record_id)}
              className={`w-full flex items-center gap-3 px-2 py-1.5 rounded-xs text-left
                          transition-colors duration-120
                          ${active ? "bg-signal/10" : "hover:bg-obsidian-800"}`}
              style={active ? { boxShadow: "inset 2px 0 0 0 #4cc2ff" } : undefined}
            >
              <span
                className="w-1.5 h-1.5 rounded-full shrink-0"
                style={{ background: severityColour(probability) }}
              />
              <span className="font-mono text-2xs text-signal w-[66px] shrink-0">
                {point.record_id}
              </span>
              <span className="text-2xs text-ink-300 w-[78px] shrink-0">
                {point.event_type ?? "—"}
              </span>
              <span className="font-mono text-2xs text-ink-500 w-[72px] shrink-0">
                {point.port_id ?? "—"}
              </span>
              <span className="font-mono tnum text-2xs text-ink-500 flex-1 truncate">
                {ts(point.timestamp)}
              </span>
              <span className="font-mono tnum text-2xs w-12 text-right" style={{ color: severityColour(probability) }}>
                {point.probability === null ? "—" : pct(probability, 0)}
              </span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}

/** The optional LLM analyst (spec 29), always beside the deterministic answer. */
function AnalystBlock({ recordId }: { recordId: string }) {
  const [result, setResult] = useState<LlmExplainResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [question, setQuestion] = useState("");

  const run = async () => {
    setBusy(true);
    try {
      setResult(await api.explain(recordId, question || undefined));
    } catch (error) {
      setResult(null);
      console.error(error);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel
      title="Forensic analyst"
      actions={
        <button type="button" className="btn" onClick={run} disabled={busy}>
          {busy ? "Asking…" : "Explain"}
        </button>
      }
    >
      <input
        className="input w-full"
        placeholder="Optional question for the analyst…"
        value={question}
        onChange={(event) => setQuestion(event.target.value)}
      />
      {result ? (
        <div className="mt-3 space-y-3">
          {result.llm.available ? (
            <div>
              <SectionLabel>
                {result.llm.provider} · {result.llm.model}
              </SectionLabel>
              <p className="text-xs text-ink-300 leading-relaxed whitespace-pre-wrap">
                {result.llm.explanation}
              </p>
            </div>
          ) : (
            <div className="rounded-xs border border-hairline bg-obsidian-850 p-2.5">
              <div className="text-2xs text-ink-500">{result.llm.error}</div>
            </div>
          )}
          <div className="pt-2.5 border-t border-hairline">
            <SectionLabel>Deterministic answer (always available)</SectionLabel>
            <p className="text-xs text-ink-300 leading-relaxed">
              {result.deterministic.rationale}
            </p>
          </div>
          <p className="text-2xs text-ink-700 leading-relaxed">{result.note}</p>
        </div>
      ) : (
        <p className="mt-2.5 text-2xs text-ink-700 leading-relaxed">
          The analyst is downstream of the evidence and read-only: it explains the
          findings in prose and cannot change the manifest, the verdict or the chain.
          With no provider configured it returns the deterministic rationale, which
          is the system's own reasoning.
        </p>
      )}
    </Panel>
  );
}

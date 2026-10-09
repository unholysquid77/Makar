/**
 * Attack timeline (spec 25).
 *
 * Windows are inferred from the distribution of suspicious records in
 * *cargo-event* time — the manifest does not record when the attacker acted,
 * but it does record which events were targeted. Every window is therefore
 * presented as a hypothesis with a confidence, and the narrative says so in
 * words rather than leaving the reader to infer it from a number.
 *
 * Affected entities are listed by *lift*, not by count: the busiest port in a
 * window is usually just the busiest port overall, so naming it would restate
 * traffic volume rather than make a claim.
 */

import { useState } from "react";

import { useApp } from "../App";
import { BucketHistogram } from "./CommandCenter";
import {
  Badge,
  Empty,
  ErrorState,
  Panel,
  SectionLabel,
  Spinner,
} from "../components/primitives";
import { api } from "../lib/api";
import { TAMPER_COLOUR, num, pct, severityColour, span, ts } from "../lib/format";
import { useAsync } from "../lib/useAsync";
import type { AttackWindow, TamperClass, TimelineBucket } from "../lib/types";

export function Timeline() {
  const { select } = useApp();
  const timeline = useAsync(() => api.timeline(), []);
  const deletions = useAsync(() => api.deletions(60), []);
  const [active, setActive] = useState<string | null>(null);
  const [bucket, setBucket] = useState<TimelineBucket | null>(null);

  if (timeline.error) return <ErrorState error={timeline.error} onRetry={timeline.reload} />;
  if (timeline.loading) {
    return (
      <div className="h-full flex items-center justify-center">
        <Spinner label="Reconstructing attack timeline…" />
      </div>
    );
  }

  const windows = timeline.data?.windows ?? [];
  const buckets = timeline.data?.buckets ?? [];
  const selected = windows.find((w) => w.window_id === active) ?? windows[0] ?? null;

  if (windows.length === 0) {
    return (
      <Empty
        title="No coordinated attack window was inferred."
        hint="Tampering in this manifest is not concentrated enough in cargo-event time to support a window hypothesis. That is a finding, not a gap."
      />
    );
  }

  return (
    <div className="h-full min-h-0 overflow-y-auto p-3 space-y-3">
      {/* ---------------------------------------------- global histogram */}
      <Panel
        title={`Anomaly distribution — ${num(buckets.length)} buckets across ${num(
          windows.length,
        )} window(s)`}
      >
        <BucketHistogram buckets={buckets} height={96} onSelect={setBucket} />
        <div className="mt-2.5 flex flex-wrap gap-x-4 gap-y-1">
          {(Object.keys(TAMPER_COLOUR) as TamperClass[])
            .filter((klass) => klass !== "CLEAN")
            .map((klass) => (
              <span key={klass} className="flex items-center gap-1.5 text-2xs text-ink-500">
                <span
                  className="w-2 h-2 rounded-sm"
                  style={{ background: TAMPER_COLOUR[klass] }}
                />
                {klass}
              </span>
            ))}
        </div>
        <p className="mt-2 text-2xs text-ink-700 leading-relaxed">
          Bars are counts of suspicious records in each three-hour bucket of cargo-event
          time. Click a bar to list its records.
        </p>
      </Panel>

      {/* ---------------------------------------------- window list + detail */}
      <div className="grid grid-cols-1 xl:grid-cols-[300px_1fr] gap-3">
        <Panel title="Inferred windows" dense>
          <ul className="divide-y divide-hairline-faint">
            {windows.map((window) => {
              const isActive = selected?.window_id === window.window_id;
              return (
                <li key={window.window_id}>
                  <button
                    type="button"
                    onClick={() => setActive(window.window_id)}
                    className={`w-full text-left px-3 py-2.5 transition-colors duration-120
                                ${isActive ? "bg-signal/10" : "hover:bg-obsidian-800"}`}
                    style={isActive ? { boxShadow: "inset 2px 0 0 0 #4cc2ff" } : undefined}
                  >
                    <div className="flex items-baseline justify-between gap-2">
                      <span className="font-mono text-xs text-signal">{window.window_id}</span>
                      <span
                        className="font-mono tnum text-xs"
                        style={{ color: severityColour(window.confidence) }}
                      >
                        {pct(window.confidence, 0)}
                      </span>
                    </div>
                    <div className="mt-1 flex items-baseline justify-between gap-2 text-2xs">
                      <span className="text-ink-300">{num(window.record_count)} records</span>
                      <span className="text-ink-700 font-mono">
                        {span(window.start, window.end)}
                      </span>
                    </div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {window.likely_sequence.slice(0, 4).map((klass, index) => (
                        <span
                          key={`${klass}-${index}`}
                          className="w-1.5 h-1.5 rounded-full"
                          style={{ background: TAMPER_COLOUR[klass] }}
                          title={klass}
                        />
                      ))}
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>
        </Panel>

        {selected && <WindowDetail window={selected} onSelectRecord={(id) => select(id, null, "investigate")} />}
      </div>

      {/* ---------------------------------------------- bucket drilldown */}
      {bucket && (
        <Panel
          title={`Bucket ${ts(bucket.start)} — ${bucket.total} record(s)`}
          actions={
            <button type="button" className="btn" onClick={() => setBucket(null)}>
              Close
            </button>
          }
        >
          <div className="flex flex-wrap gap-1.5">
            {bucket.record_ids.map((id) => (
              <button
                key={id}
                type="button"
                className="btn font-mono"
                onClick={() => select(id, null, "investigate")}
              >
                {id}
              </button>
            ))}
          </div>
        </Panel>
      )}

      {/* ---------------------------------------------- inferred deletions */}
      <Panel
        title={`Inferred deletions — ${num(deletions.data?.total ?? 0)}`}
        dense
      >
        <div className="px-3 py-2 border-b border-hairline">
          <p className="text-2xs text-ink-700 leading-relaxed">
            A deleted record leaves no row to rank, so deletions are inferred from the
            shape of what remains: an incomplete port call, a route leg with no records,
            or a commitment in the provenance chain with nothing to match it. Entries
            found by two independent routes carry higher confidence.
          </p>
        </div>
        {deletions.loading ? (
          <div className="p-3">
            <Spinner />
          </div>
        ) : (
          <div className="max-h-[320px] overflow-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Confidence</th>
                  <th>Container</th>
                  <th>Port</th>
                  <th>Missing</th>
                  <th>Sources</th>
                  <th>Bracketed by</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {(deletions.data?.deletions ?? []).map((entry, index) => (
                  <tr key={index} className="cursor-default">
                    <td>
                      <span
                        className="font-mono tnum text-xs"
                        style={{ color: severityColour(entry.confidence) }}
                      >
                        {pct(entry.confidence, 0)}
                      </span>
                    </td>
                    <td className="font-mono text-2xs text-ink-300">
                      {entry.container_id ?? "—"}
                    </td>
                    <td className="font-mono text-2xs text-ink-500">{entry.port_id ?? "—"}</td>
                    <td>
                      <Badge className="border-hairline text-ink-300">
                        {entry.missing_event ?? entry.record_id ?? "—"}
                      </Badge>
                    </td>
                    <td className="text-2xs text-ink-500">
                      {(entry.sources ?? [entry.source ?? ""]).filter(Boolean).join(", ")}
                    </td>
                    <td className="font-mono text-2xs">
                      {(entry.between ?? [])
                        .filter(Boolean)
                        .map((id) => (
                          <button
                            key={String(id)}
                            type="button"
                            className="text-signal hover:underline mr-1.5"
                            onClick={() => select(String(id), entry.container_id ?? null, "investigate")}
                          >
                            {String(id)}
                          </button>
                        ))}
                    </td>
                    <td className="text-2xs text-ink-500 max-w-[420px]">{entry.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}

function WindowDetail({
  window,
  onSelectRecord,
}: {
  window: AttackWindow;
  onSelectRecord: (id: string) => void;
}) {
  const recordIds = (window.buckets ?? []).flatMap((bucket) => bucket.record_ids);

  return (
    <Panel
      title={`${window.window_id} — hypothesis`}
      actions={
        <Badge colour={severityColour(window.confidence)}>
          {pct(window.confidence, 0)} confidence
        </Badge>
      }
    >
      <div className="space-y-3.5">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-x-5 gap-y-2 text-xs">
          <Field label="From" value={ts(window.start)} />
          <Field label="To" value={ts(window.end)} />
          <Field label="Span" value={span(window.start, window.end)} />
          <Field label="Records" value={num(window.record_count)} />
        </div>

        {window.likely_sequence.length > 0 && (
          <div>
            <SectionLabel>Apparent phase order</SectionLabel>
            <div className="flex flex-wrap items-center gap-1.5">
              {window.likely_sequence.map((klass, index) => (
                <span key={`${klass}-${index}`} className="flex items-center gap-1.5">
                  {index > 0 && <span className="text-ink-700">→</span>}
                  <Badge colour={TAMPER_COLOUR[klass]}>{klass}</Badge>
                </span>
              ))}
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <EntityList label="Ports" items={window.affected_ports} mono />
          <EntityList label="Owners" items={window.affected_owners} />
          <EntityList label="Vessels" items={window.affected_vessels} mono />
        </div>

        <div className="rounded-xs border border-hairline bg-obsidian-850 p-2.5">
          <SectionLabel>Narrative</SectionLabel>
          <p className="text-xs text-ink-300 leading-relaxed">{window.narrative}</p>
        </div>

        {(window.buckets?.length ?? 0) > 0 && (
          <div>
            <SectionLabel>Window profile</SectionLabel>
            <BucketHistogram buckets={window.buckets ?? []} height={64} />
          </div>
        )}

        {recordIds.length > 0 && (
          <div>
            <SectionLabel>Records in this window — {recordIds.length}</SectionLabel>
            <div className="flex flex-wrap gap-1 max-h-32 overflow-y-auto">
              {recordIds.slice(0, 120).map((id) => (
                <button
                  key={id}
                  type="button"
                  className="font-mono text-2xs text-signal hover:underline"
                  onClick={() => onSelectRecord(id)}
                >
                  {id}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </Panel>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-2xs uppercase tracking-[0.1em] text-ink-500">{label}</div>
      <div className="font-mono tnum text-xs text-ink-100 mt-0.5">{value}</div>
    </div>
  );
}

function EntityList({
  label,
  items,
  mono = false,
}: {
  label: string;
  items: string[];
  mono?: boolean;
}) {
  return (
    <div>
      <SectionLabel>{label}</SectionLabel>
      {items.length === 0 ? (
        <div className="text-2xs text-ink-700">none over-represented</div>
      ) : (
        <ul className="space-y-0.5">
          {items.slice(0, 5).map((item) => (
            <li
              key={item}
              className={`text-2xs text-ink-300 truncate ${mono ? "font-mono" : ""}`}
            >
              {item}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

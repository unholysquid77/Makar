/**
 * Command Center (spec 27.2).
 *
 *   ┌──────────────────────────────────────────────┐
 *   │ metric strip                                 │
 *   ├──────────────────────────────────────────────┤
 *   │ live geo map                                 │
 *   ├────────────────────────┬─────────────────────┤
 *   │ attack timeline        │ node integrity      │
 *   ├────────────────────────┴─────────────────────┤
 *   │ highest-risk records                         │
 *   └──────────────────────────────────────────────┘
 *
 * The brief says explicitly that this must not be a generic collection of
 * metric cards. The organising idea here is that the strip states *what the
 * manifest now is* — a disposition, not a score — because the deliverable is a
 * reconstructed manifest where every record is ORIGINAL, REPAIRED, REMOVED or
 * UNRECOVERABLE. Everything below it exists to answer "why" for any one of
 * them, and every row is a jump into the view that answers it.
 */

import { useApp } from "../App";
import { ForensicMap } from "../components/ForensicMap";
import {
  Badge,
  ClassificationBadge,
  DatumLine,
  ErrorState,
  Metric,
  Panel,
  ProbabilityCell,
  SectionLabel,
  Spinner,
  TamperBadge,
} from "../components/primitives";
import { api } from "../lib/api";
import {
  TAMPER_COLOUR,
  dateOnly,
  num,
  pct,
  severityColour,
  span,
  ts,
} from "../lib/format";
import { useAsync } from "../lib/useAsync";
import type { AttackWindow, NodesResponse, TimelineBucket } from "../lib/types";

export function CommandCenter() {
  const { select } = useApp();

  const summary = useAsync(() => api.summary(), []);
  const ports = useAsync(() => api.ports(), []);
  const routes = useAsync(() => api.routes(), []);
  const suspicious = useAsync(() => api.mapRecords(0.5, 1200), []);
  const timeline = useAsync(() => api.timeline(), []);
  const nodes = useAsync(() => api.nodes(), []);
  const risky = useAsync(
    () => api.records({ suspicious_only: true, limit: 12, sort: "probability" }),
    [],
  );

  if (summary.error) return <ErrorState error={summary.error} onRetry={summary.reload} />;

  const s = summary.data?.summary;
  const threshold = summary.data?.thresholds.suspicious ?? 0.5;

  return (
    <div className="h-full min-h-0 overflow-y-auto p-3 space-y-3">
      {/* ---------------------------------------------- metric strip */}
      <div className="panel">
        <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 divide-x divide-hairline">
          <Metric
            label="Records analysed"
            value={s ? num(s.total_records) : "—"}
            sub={summary.data ? `seed ${summary.data.seed ?? "—"}` : undefined}
            emphasis
          />
          <Metric
            label="Suspicious"
            value={s ? num(s.suspicious) : "—"}
            sub={s ? `${pct(s.suspicious / Math.max(1, s.total_records))} of manifest` : undefined}
            accent="#e5563d"
            emphasis
          />
          <Metric
            label="Repaired"
            value={s ? num(s.repaired) : "—"}
            sub={s ? `mean confidence ${pct(s.mean_repair_confidence)}` : undefined}
            accent="#4cc2ff"
            emphasis
          />
          <Metric
            label="Removed"
            value={s ? num(s.removed) : "—"}
            sub="no legitimate lineage"
            accent="#e5484d"
            emphasis
          />
          <Metric
            label="Unrecoverable"
            value={s ? num(s.unrecoverable) : "—"}
            sub="flagged, not altered"
            accent="#d9a21b"
            emphasis
          />
          <Metric
            label="Inferred deletions"
            value={summary.data ? num(summary.data.inferred_deletions) : "—"}
            sub="no surviving row"
            accent="#7c8cff"
            emphasis
          />
        </div>
        {s && (
          <div className="px-3.5 pb-3 pt-1">
            <DispositionBar
              original={s.original}
              repaired={s.repaired}
              removed={s.removed}
              unrecoverable={s.unrecoverable}
            />
          </div>
        )}
      </div>

      {/* ---------------------------------------------- live geo map */}
      <Panel
        title="Live geo map"
        dense
        className="h-[380px]"
        actions={
          <>
            <span className="text-2xs text-ink-700">
              records above {pct(threshold, 0)} tampering probability
            </span>
            <button type="button" className="btn" onClick={() => select(null, null, "map")}>
              Open forensic map
            </button>
          </>
        }
      >
        {ports.data && routes.data ? (
          <ForensicMap
            compact
            ports={ports.data.ports}
            routes={routes.data.routes}
            routeGeojson={routes.data.geojson}
            suspicious={suspicious.data ?? undefined}
          />
        ) : (
          <div className="h-full flex items-center justify-center">
            <Spinner label="Loading world geometry…" />
          </div>
        )}
      </Panel>

      {/* ---------------------------------------------- timeline + nodes */}
      <div className="grid grid-cols-1 xl:grid-cols-[1.7fr_1fr] gap-3">
        <Panel
          title="Attack timeline"
          actions={
            <button type="button" className="btn" onClick={() => select(null, null, "timeline")}>
              Open timeline
            </button>
          }
        >
          {timeline.loading ? (
            <Spinner />
          ) : timeline.data && timeline.data.windows.length > 0 ? (
            <TimelineSummary
              windows={timeline.data.windows}
              buckets={timeline.data.buckets}
            />
          ) : (
            <div className="text-2xs text-ink-700">
              No coordinated window was inferred for this manifest.
            </div>
          )}
        </Panel>

        <Panel
          title="Node integrity"
          actions={
            <button type="button" className="btn" onClick={() => select(null, null, "nodes")}>
              Open monitor
            </button>
          }
        >
          {nodes.loading ? <Spinner /> : <NodeIntegrity data={nodes.data} />}
        </Panel>
      </div>

      {/* ---------------------------------------------- highest-risk records */}
      <Panel
        title="Highest-risk records"
        dense
        actions={
          <button type="button" className="btn" onClick={() => select(null, null, "records")}>
            Open ledger
          </button>
        }
      >
        {risky.loading ? (
          <div className="p-3">
            <Spinner />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Record</th>
                  <th>Probability</th>
                  <th>Class</th>
                  <th>Disposition</th>
                  <th>Container</th>
                  <th>Owner</th>
                  <th>Port</th>
                  <th>Leading findings</th>
                  <th>When</th>
                </tr>
              </thead>
              <tbody>
                {(risky.data?.records ?? []).map((row) => (
                  <tr
                    key={row.record_id}
                    onClick={() => select(row.record_id, row.container_id, "investigate")}
                    title="Open the investigation panel for this record"
                  >
                    <td className="font-mono text-xs text-signal">{row.record_id}</td>
                    <td>
                      <ProbabilityCell value={row.tampering_probability} />
                    </td>
                    <td>
                      <TamperBadge value={row.tamper_class} />
                    </td>
                    <td>
                      <ClassificationBadge value={row.classification} />
                    </td>
                    <td className="font-mono text-2xs text-ink-300">{row.container_id ?? "—"}</td>
                    <td className="text-2xs text-ink-300 max-w-[150px] truncate">
                      {row.owner ?? "—"}
                    </td>
                    <td className="font-mono text-2xs text-ink-300">{row.port_id ?? "—"}</td>
                    <td>
                      <div className="flex flex-wrap gap-1">
                        {row.top_findings.slice(0, 3).map((code) => (
                          <Badge key={code} className="border-hairline text-ink-500">
                            {code}
                          </Badge>
                        ))}
                      </div>
                    </td>
                    <td className="font-mono text-2xs text-ink-500">{ts(row.timestamp)}</td>
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

// ---------------------------------------------------------------- pieces

/** One stacked bar: what the reconstructed manifest actually consists of. */
function DispositionBar({
  original,
  repaired,
  removed,
  unrecoverable,
}: {
  original: number;
  repaired: number;
  removed: number;
  unrecoverable: number;
}) {
  const total = Math.max(1, original + repaired + removed + unrecoverable);
  const parts: Array<[string, number, string]> = [
    ["ORIGINAL", original, "#394353"],
    ["REPAIRED", repaired, "#4cc2ff"],
    ["REMOVED", removed, "#e5563d"],
    ["UNRECOVERABLE", unrecoverable, "#d9a21b"],
  ];
  return (
    <div>
      <div className="flex h-[5px] rounded-full overflow-hidden bg-obsidian-800">
        {parts.map(([label, value, colour]) => (
          <div
            key={label}
            title={`${label}: ${num(value)} (${pct(value / total)})`}
            style={{ width: `${(value / total) * 100}%`, background: colour }}
          />
        ))}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-2xs text-ink-500">
        {parts.map(([label, value, colour]) => (
          <span key={label} className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full" style={{ background: colour }} />
            <span className="uppercase tracking-[0.1em]">{label}</span>
            <span className="font-mono tnum text-ink-300">{num(value)}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

/** Compact histogram plus the leading inferred windows. */
function TimelineSummary({
  windows,
  buckets,
}: {
  windows: AttackWindow[];
  buckets: TimelineBucket[];
}) {
  return (
    <div className="space-y-3">
      <BucketHistogram buckets={buckets} height={56} />
      <div className="space-y-2">
        {windows.slice(0, 3).map((window) => (
          <div key={window.window_id} className="flex items-start gap-3">
            <div className="shrink-0 w-[70px]">
              <div className="font-mono tnum text-xs text-ink-100">
                {num(window.record_count)}
              </div>
              <div className="text-2xs text-ink-700">records</div>
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-baseline gap-2 flex-wrap">
                <span className="font-mono text-2xs text-signal">{window.window_id}</span>
                <span className="text-2xs text-ink-500">
                  {dateOnly(window.start)} → {dateOnly(window.end)} ·{" "}
                  {span(window.start, window.end)}
                </span>
                <Badge colour={severityColour(window.confidence)}>
                  {pct(window.confidence, 0)} confidence
                </Badge>
              </div>
              <div className="mt-1 flex flex-wrap gap-1">
                {window.likely_sequence.map((klass, index) => (
                  <span key={`${klass}-${index}`} className="flex items-center gap-1">
                    {index > 0 && <span className="text-ink-700 text-2xs">→</span>}
                    <Badge colour={TAMPER_COLOUR[klass]}>{klass}</Badge>
                  </span>
                ))}
                {window.affected_ports.slice(0, 2).map((port) => (
                  <Badge key={port} className="border-hairline text-ink-500">
                    {port}
                  </Badge>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
      <p className="text-2xs text-ink-700 leading-relaxed">
        Windows are grouped in cargo-event time and presented as hypotheses with
        confidence, not as an observed intrusion log.
      </p>
    </div>
  );
}

export function BucketHistogram({
  buckets,
  height = 72,
  onSelect,
}: {
  buckets: TimelineBucket[];
  height?: number;
  onSelect?: (bucket: TimelineBucket) => void;
}) {
  if (buckets.length === 0) {
    return <div className="text-2xs text-ink-700">No anomaly buckets.</div>;
  }
  const max = Math.max(...buckets.map((b) => b.total), 1);

  return (
    <div className="flex items-end gap-[2px]" style={{ height }}>
      {buckets.map((bucket) => {
        const classes = Object.entries(bucket.by_class).filter(([, n]) => (n ?? 0) > 0);
        return (
          <button
            key={`${bucket.start}-${bucket.window_id ?? ""}`}
            type="button"
            onClick={() => onSelect?.(bucket)}
            title={`${ts(bucket.start)} — ${bucket.total} record(s)\n${classes
              .map(([k, n]) => `${k}: ${n}`)
              .join("\n")}`}
            className="flex-1 min-w-[3px] flex flex-col justify-end group"
            style={{ height }}
          >
            {classes.map(([klass, count]) => (
              <span
                key={klass}
                className="w-full transition-opacity duration-120 group-hover:opacity-80"
                style={{
                  height: `${((count ?? 0) / max) * height}px`,
                  background: TAMPER_COLOUR[klass as keyof typeof TAMPER_COLOUR],
                }}
              />
            ))}
          </button>
        );
      })}
    </div>
  );
}

/** Spec 36 step 7: A OK · B OK · C WARN · D OK. */
function NodeIntegrity({ data }: { data: NodesResponse | null }) {
  const nodes = data?.nodes ?? [];
  if (nodes.length === 0) {
    return <div className="text-2xs text-ink-700">No provenance network for this run.</div>;
  }
  const divergent = data?.divergent ?? [];

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-4 gap-2">
        {nodes.map((node) => {
          const healthy = node.status === "HEALTHY";
          const colour = healthy ? "#2fa36b" : "#e5484d";
          return (
            <div
              key={node.node_id}
              className="rounded-xs border px-2 py-2 text-center"
              style={{ borderColor: `${colour}44`, background: `${colour}0f` }}
              title={`state root ${node.state_root.slice(0, 20)}…`}
            >
              <div className="font-mono text-base" style={{ color: colour }}>
                {node.node_id}
              </div>
              <div className="text-[0.625rem] uppercase tracking-[0.1em] mt-0.5" style={{ color: colour }}>
                {healthy ? "ok" : "warn"}
              </div>
              <div className="text-2xs text-ink-700 mt-1 font-mono tnum">h{node.height}</div>
            </div>
          );
        })}
      </div>

      {data?.agreement_fraction !== undefined && (
        <div>
          <div className="flex items-baseline justify-between text-2xs">
            <span className="text-ink-500 uppercase tracking-[0.1em]">Network agreement</span>
            <span className="font-mono tnum text-ink-100">{pct(data.agreement_fraction, 0)}</span>
          </div>
          <DatumLine
            value={data.agreement_fraction}
            colour={data.agreement_fraction >= 0.75 ? "#2fa36b" : "#e5484d"}
            className="mt-1"
          />
        </div>
      )}

      {divergent.length > 0 && (
        <div className="rounded-xs border border-anomaly-critical/35 bg-anomaly-critical/[0.07] p-2.5">
          <SectionLabel>Divergence localised</SectionLabel>
          <p className="text-2xs text-ink-300 leading-relaxed">
            Node{divergent.length > 1 ? "s" : ""}{" "}
            <span className="font-mono text-anomaly-critical">{divergent.join(", ")}</span>{" "}
            commit different record hashes from the majority across{" "}
            <span className="font-mono">{data?.affected_blocks?.length ?? 0}</span> block(s),
            affecting{" "}
            <span className="font-mono">{data?.affected_records?.length ?? 0}</span> record
            commitment(s).
          </p>
          <p className="mt-1.5 text-2xs text-ink-700 leading-relaxed">
            The divergent chain passes its own integrity check — it was rewritten
            competently, with every root recomputed. Only cross-node comparison
            reveals it.
          </p>
        </div>
      )}
    </div>
  );
}

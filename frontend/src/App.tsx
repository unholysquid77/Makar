/**
 * Application shell.
 *
 * One analysis snapshot, eight views over it (spec 40), and a shared
 * selection so the views cross-link rather than sitting in isolation
 * (spec 28): a record found on the map opens the same investigation panel and
 * the same graph neighbourhood as one found in Bloodhound, and "locate on
 * map" / "trace in graph" are one click from anywhere.
 *
 * Navigation is local state rather than a router. There is one document and
 * no deep-linking requirement, so a router would add a dependency and a build
 * step for nothing.
 */

import { createContext, useCallback, useContext, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { Bloodhound } from "./panels/Bloodhound";
import { CommandCenter } from "./panels/CommandCenter";
import { EvaluationConsole } from "./panels/EvaluationConsole";
import { LiveFeed } from "./panels/LiveFeed";
import { GeoMap } from "./panels/GeoMap";
import { NodeMonitor } from "./panels/NodeMonitor";
import { RecordInvestigation } from "./panels/RecordInvestigation";
import { Records } from "./panels/Records";
import { Reconstruction } from "./panels/Reconstruction";
import { Timeline } from "./panels/Timeline";
import { ErrorState, Spinner } from "./components/primitives";
import { api } from "./lib/api";
import { useAsync } from "./lib/useAsync";

// ---------------------------------------------------------------- selection

export type ViewId =
  | "command"
  | "map"
  | "graph"
  | "timeline"
  | "records"
  | "investigate"
  | "reconstruct"
  | "nodes"
  | "live"
  | "evaluation";

interface Selection {
  recordId: string | null;
  containerId: string | null;
}

interface AppContextValue {
  selection: Selection;
  /** Select a record and optionally jump to a view in one action. */
  select: (recordId: string | null, containerId?: string | null, view?: ViewId) => void;
  view: ViewId;
  setView: (view: ViewId) => void;
  runId: string | null;
  reloadAnalysis: () => void;
}

const AppContext = createContext<AppContextValue | null>(null);

export function useApp(): AppContextValue {
  const value = useContext(AppContext);
  if (!value) throw new Error("useApp must be used inside the application shell");
  return value;
}

// ---------------------------------------------------------------- navigation

const VIEWS: Array<{ id: ViewId; label: string; glyph: string; hint: string }> = [
  { id: "command", label: "Command", glyph: "◎", hint: "Command Center" },
  { id: "map", label: "Geo", glyph: "⬡", hint: "Geo Forensic Map" },
  { id: "graph", label: "Bloodhound", glyph: "⌘", hint: "Forensic graph" },
  { id: "timeline", label: "Timeline", glyph: "▚", hint: "Attack timeline" },
  { id: "records", label: "Records", glyph: "▤", hint: "Record ledger" },
  { id: "investigate", label: "Investigate", glyph: "◈", hint: "Record investigation" },
  { id: "reconstruct", label: "Rebuild", glyph: "⟲", hint: "Reconstruction workspace" },
  { id: "nodes", label: "Provenance", glyph: "⛓", hint: "Chain & node monitor" },
  { id: "live", label: "Live", glyph: "◉", hint: "Live stream mode" },
  { id: "evaluation", label: "Evaluate", glyph: "⊞", hint: "Evaluation console" },
];

export default function App() {
  const [view, setView] = useState<ViewId>("command");
  const [selection, setSelection] = useState<Selection>({
    recordId: null,
    containerId: null,
  });

  const status = useAsync(() => api.status(), []);

  const select = useCallback(
    (recordId: string | null, containerId?: string | null, nextView?: ViewId) => {
      setSelection((current) => ({
        recordId,
        containerId: containerId !== undefined ? containerId : current.containerId,
      }));
      if (nextView) setView(nextView);
    },
    [],
  );

  const context = useMemo<AppContextValue>(
    () => ({
      selection,
      select,
      view,
      setView,
      runId: status.data?.run_id ?? null,
      reloadAnalysis: status.reload,
    }),
    [selection, select, view, status.data?.run_id, status.reload],
  );

  return (
    <AppContext.Provider value={context}>
      <div className="h-full flex flex-col bg-obsidian-950">
        <TopRail status={status} />
        <div className="flex-1 min-h-0 flex">
          <NavRail view={view} setView={setView} />
          <main className="flex-1 min-w-0 min-h-0 bg-grid bg-[length:32px_32px]">
            {status.loading && !status.data ? (
              <div className="h-full flex items-center justify-center">
                <Spinner label="Connecting to the forensic API…" />
              </div>
            ) : status.error ? (
              <ErrorState error={status.error} onRetry={status.reload} />
            ) : (
              <ViewRouter view={view} />
            )}
          </main>
        </div>
      </div>
    </AppContext.Provider>
  );
}

function ViewRouter({ view }: { view: ViewId }) {
  switch (view) {
    case "command":
      return <CommandCenter />;
    case "map":
      return <GeoMap />;
    case "graph":
      return <Bloodhound />;
    case "timeline":
      return <Timeline />;
    case "records":
      return <Records />;
    case "investigate":
      return <RecordInvestigation />;
    case "reconstruct":
      return <Reconstruction />;
    case "nodes":
      return <NodeMonitor />;
    case "live":
      return <LiveFeed />;
    case "evaluation":
      return <EvaluationConsole />;
    default:
      return <CommandCenter />;
  }
}

// ---------------------------------------------------------------- chrome

function TopRail({ status }: { status: ReturnType<typeof useAsync<Awaited<ReturnType<typeof api.status>>>> }) {
  const data = status.data;
  return (
    <header className="shrink-0 h-12 flex items-center gap-4 px-3 border-b border-hairline bg-obsidian-900 lit-edge">
      <div className="flex items-baseline gap-2.5 shrink-0">
        <span className="font-semibold tracking-[0.2em] text-ink-50 text-sm">MAKAR</span>
        <span className="hidden md:inline text-2xs uppercase tracking-[0.18em] text-ink-500">
          maritime forensic intelligence
        </span>
      </div>

      <div className="flex-1" />

      {data?.loaded && (
        <div className="hidden lg:flex items-center gap-4 text-2xs text-ink-500">
          <Stat label="run" value={data.run_id?.slice(0, 8) ?? "—"} />
          <Stat label="seed" value={String(data.seed ?? "—")} />
          <Stat label="records" value={(data.records ?? 0).toLocaleString()} />
          <Stat
            label="graph"
            value={`${(data.graph?.nodes ?? 0).toLocaleString()}n / ${(
              data.graph?.edges ?? 0
            ).toLocaleString()}e`}
          />
        </div>
      )}

      <div className="flex items-center gap-2 shrink-0">
        {status.loading && <Spinner />}
        <span
          className="w-1.5 h-1.5 rounded-full"
          style={{
            background: status.error ? "#e5484d" : data?.loaded ? "#2fa36b" : "#d9a21b",
          }}
          title={status.error ? "API unreachable" : data?.loaded ? "Analysis loaded" : "Idle"}
        />
        <span className="text-2xs text-ink-500 font-mono">
          {data?.directory ?? "—"}
        </span>
      </div>
    </header>
  );
}

function Stat({ label, value }: { label: string; value: ReactNode }) {
  return (
    <span className="flex items-baseline gap-1.5">
      <span className="uppercase tracking-[0.12em] text-ink-700">{label}</span>
      <span className="font-mono tnum text-ink-300">{value}</span>
    </span>
  );
}

function NavRail({ view, setView }: { view: ViewId; setView: (v: ViewId) => void }) {
  return (
    <nav className="shrink-0 w-[62px] border-r border-hairline bg-obsidian-900 flex flex-col py-2">
      {VIEWS.map((item) => {
        const active = view === item.id;
        return (
          <button
            key={item.id}
            type="button"
            onClick={() => setView(item.id)}
            title={item.hint}
            aria-current={active ? "page" : undefined}
            className={`relative flex flex-col items-center gap-1 py-2.5 transition-colors duration-120
                        ${active ? "text-signal" : "text-ink-500 hover:text-ink-100"}`}
          >
            {active && (
              <span className="absolute left-0 top-1.5 bottom-1.5 w-[2px] bg-signal rounded-r" />
            )}
            <span className="text-base leading-none">{item.glyph}</span>
            <span className="text-[0.625rem] uppercase tracking-[0.08em]">{item.label}</span>
          </button>
        );
      })}
    </nav>
  );
}

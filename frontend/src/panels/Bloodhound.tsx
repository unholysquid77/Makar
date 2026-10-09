/**
 * Bloodhound — the forensic graph interface (spec 15).
 *
 * The point is not to draw nodes. It is to let an investigator *follow
 * evidence through the system*: from a record, to the container it concerns,
 * to the port where the contradiction happened, to the record that contradicts
 * it, to the block that committed the original (spec 15.4).
 *
 * Investigation modes (spec 15.3):
 *
 *   EXPAND          reveal connected evidence
 *   ISOLATE         hide everything unrelated
 *   CONFLICT        show only contradictory relationships
 *   TRACE           follow the provenance chain
 *   TIMELINE        order the neighbourhood chronologically
 *   GEO             jump the selection to the map
 *   RECONSTRUCTION  jump to observed vs reconstructed state
 *
 * Layout notes that matter for legibility: contradiction edges are red and
 * drawn thicker than structural ones, because a conflict is the thing worth
 * seeing; structural edges recede into the background. Node colour is *kind*,
 * node ring is *severity*, so an investigator can tell what something is and
 * how bad it is without reading a label.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import cytoscape from "cytoscape";
import type { Core, EdgeSingular, NodeSingular } from "cytoscape";
// @ts-expect-error -- the layout package ships no types
import coseBilkent from "cytoscape-cose-bilkent";

import { useApp } from "../App";
import {
  Badge,
  Empty,
  ErrorState,
  Panel,
  SectionLabel,
  Spinner,
} from "../components/primitives";
import { api } from "../lib/api";
import {
  EDGE_COLOUR,
  NODE_COLOUR,
  nodeIdOf,
  nodeKindOf,
  pct,
  severityColour,
  ts,
} from "../lib/format";
import { useAsync } from "../lib/useAsync";
import type { GraphResponse, PathHop } from "../lib/types";

cytoscape.use(coseBilkent);

type Mode = "expand" | "isolate" | "conflict" | "trace";

const MODES: Array<{ id: Mode; label: string; hint: string }> = [
  { id: "expand", label: "Expand", hint: "Reveal connected evidence" },
  { id: "isolate", label: "Isolate", hint: "Hide unrelated nodes" },
  { id: "conflict", label: "Conflict", hint: "Only contradictory relationships" },
  { id: "trace", label: "Trace", hint: "Follow the provenance chain" },
];

export function Bloodhound() {
  const { selection, select } = useApp();
  const recordId = selection.recordId;

  const [mode, setMode] = useState<Mode>("expand");
  const [depth, setDepth] = useState(2);
  const [chronological, setChronological] = useState(false);
  const [pathTarget, setPathTarget] = useState("");
  const [path, setPath] = useState<{ hops: PathHop[]; target: string } | null>(null);
  const [hovered, setHovered] = useState<string | null>(null);

  const graph = useAsync(
    () => (recordId ? api.graph(recordId, { depth, mode }) : Promise.resolve(null)),
    [recordId, depth, mode],
  );

  const container = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);

  // --- highlight the shortest evidence path, when one has been traced ---
  const pathEdgeKeys = useMemo(() => {
    const keys = new Set<string>();
    for (const hop of path?.hops ?? []) {
      keys.add(`${hop.from}->${hop.to}`);
      keys.add(`${hop.to}->${hop.from}`);
    }
    return keys;
  }, [path]);

  // --- build / rebuild the cytoscape instance ---
  useEffect(() => {
    if (!container.current) return;
    const instance = cytoscape({
      container: container.current,
      wheelSensitivity: 0.25,
      minZoom: 0.15,
      maxZoom: 3.5,
      style: [
        {
          selector: "node",
          style: {
            "background-color": (node: NodeSingular) =>
              NODE_COLOUR[nodeKindOf(node.id())] ?? "#6f7d91",
            width: (node: NodeSingular) => (node.data("isRoot") ? 26 : 16),
            height: (node: NodeSingular) => (node.data("isRoot") ? 26 : 16),
            label: "data(label)",
            color: "#a6b1c2",
            "font-size": 9,
            "font-family": "IBM Plex Mono, monospace",
            "text-valign": "bottom",
            "text-margin-y": 5,
            "text-outline-color": "#06080b",
            "text-outline-width": 2,
            "border-width": (node: NodeSingular) => (node.data("probability") ? 2.5 : 1),
            "border-color": (node: NodeSingular) =>
              node.data("probability") ? severityColour(node.data("probability")) : "#1b2230",
            "overlay-opacity": 0,
          },
        },
        {
          selector: "node[?isRoot]",
          style: { "border-width": 3, "border-color": "#4cc2ff", "font-size": 11 },
        },
        {
          selector: "edge",
          style: {
            width: (edge: EdgeSingular) =>
              edge.data("contradictory") ? 2 : edge.data("onPath") ? 2.5 : 0.8,
            "line-color": (edge: EdgeSingular) =>
              edge.data("onPath")
                ? "#4cc2ff"
                : (EDGE_COLOUR[edge.data("type")] ?? "#2a3240"),
            "target-arrow-color": (edge: EdgeSingular) =>
              edge.data("onPath") ? "#4cc2ff" : (EDGE_COLOUR[edge.data("type")] ?? "#2a3240"),
            "target-arrow-shape": "triangle",
            "arrow-scale": 0.55,
            "curve-style": "bezier",
            opacity: (edge: EdgeSingular) =>
              edge.data("contradictory") || edge.data("onPath") ? 0.95 : 0.4,
            "line-style": (edge: EdgeSingular) =>
              edge.data("type") === "SUPPORTS" ? "dashed" : "solid",
          },
        },
        {
          selector: "node:selected",
          style: { "border-color": "#ffffff", "border-width": 3 },
        },
        { selector: ".dimmed", style: { opacity: 0.12 } },
      ],
    });

    cy.current = instance;

    instance.on("tap", "node", (event) => {
      const node = event.target as NodeSingular;
      const key = node.id();
      if (nodeKindOf(key) === "record") {
        const id = nodeIdOf(key);
        select(id, (node.data("container_id") as string | null) ?? selection.containerId);
      }
    });
    instance.on("mouseover", "node", (event) => setHovered((event.target as NodeSingular).id()));
    instance.on("mouseout", "node", () => setHovered(null));

    return () => {
      instance.destroy();
      cy.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // --- load elements whenever the graph response changes ---
  useEffect(() => {
    const instance = cy.current;
    const data = graph.data;
    if (!instance || !data) return;

    const rootKey = data.root;
    const contradictory = new Set(["CONFLICTS_WITH", "DUPLICATES"]);

    instance.elements().remove();
    instance.add([
      ...data.nodes.map((node) => ({
        group: "nodes" as const,
        data: {
          id: node.id,
          label: shortLabel(node),
          isRoot: node.id === rootKey,
          probability: node.tampering_probability ?? 0,
          container_id: node.container_id ?? null,
          kind: nodeKindOf(node.id),
          timestamp: node.timestamp ?? null,
          raw: node,
        },
      })),
      ...data.edges
        .filter((edge) => edge.source !== edge.target)
        .map((edge, index) => ({
          group: "edges" as const,
          data: {
            id: `e${index}`,
            source: edge.source,
            target: edge.target,
            type: edge.type,
            contradictory: contradictory.has(edge.type),
            onPath: pathEdgeKeys.has(`${edge.source}->${edge.target}`),
            raw: edge,
          },
        })),
    ]);

    if (chronological) {
      // TIMELINE mode: order the neighbourhood by event time on the x axis.
      const withTime = instance
        .nodes()
        .filter((node) => Boolean(node.data("timestamp")))
        .sort(
          (a, b) =>
            new Date(String(a.data("timestamp"))).getTime() -
            new Date(String(b.data("timestamp"))).getTime(),
        );
      const width = instance.width() || 900;
      const height = instance.height() || 600;
      withTime.forEach((node, index) => {
        node.position({
          x: 60 + (index / Math.max(1, withTime.length - 1)) * (width - 120),
          y: height / 2 + (index % 2 === 0 ? -1 : 1) * (40 + (index % 7) * 18),
        });
      });
      const rest = instance.nodes().filter((node) => !node.data("timestamp"));
      rest.forEach((node, index) => {
        node.position({ x: 60 + (index % 10) * 80, y: 70 + Math.floor(index / 10) * 70 });
      });
      instance.layout({ name: "preset", fit: true, padding: 50 }).run();
    } else {
      instance
        .layout({
          name: "cose-bilkent",
          animate: false,
          fit: true,
          padding: 45,
          nodeRepulsion: 9000,
          idealEdgeLength: 70,
          nestingFactor: 0.1,
          gravity: 0.3,
          numIter: 1800,
          tile: true,
        } as cytoscape.LayoutOptions)
        .run();
    }
  }, [graph.data, chronological, pathEdgeKeys]);

  const tracePath = useCallback(async () => {
    if (!recordId || !pathTarget.trim()) return;
    try {
      const result = await api.graphPath(recordId, pathTarget.trim());
      setPath({ hops: result.hops, target: result.target });
    } catch {
      setPath(null);
    }
  }, [recordId, pathTarget]);

  if (!recordId) {
    return (
      <Empty
        title="Bloodhound needs a starting point."
        hint="Select a record from the ledger, the Command Center or the map, then follow its evidence outward."
      />
    );
  }

  return (
    <div className="h-full min-h-0 p-3 grid grid-cols-1 xl:grid-cols-[1fr_340px] gap-3">
      {/* ---------------------------------------------- canvas */}
      <Panel
        dense
        className="min-h-0"
        title={
          <span className="flex items-center gap-2">
            <span>Bloodhound</span>
            <span className="font-mono text-2xs text-signal normal-case tracking-normal">
              {recordId}
            </span>
          </span>
        }
        actions={
          <>
            {MODES.map((item) => (
              <button
                key={item.id}
                type="button"
                title={item.hint}
                className={`btn ${mode === item.id ? "btn-active" : ""}`}
                onClick={() => setMode(item.id)}
              >
                {item.label}
              </button>
            ))}
            <button
              type="button"
              title="Reorder the neighbourhood chronologically"
              className={`btn ${chronological ? "btn-active" : ""}`}
              onClick={() => setChronological((value) => !value)}
            >
              Timeline
            </button>
            <button
              type="button"
              className="btn"
              onClick={() => select(recordId, selection.containerId, "map")}
            >
              Geo
            </button>
            <button
              type="button"
              className="btn"
              onClick={() => select(recordId, selection.containerId, "reconstruct")}
            >
              Reconstruction
            </button>
          </>
        }
      >
        <div className="relative h-full min-h-[460px]">
          <div ref={container} className="absolute inset-0 bg-grid-fine bg-[length:8px_8px]" />

          {graph.loading && (
            <div className="absolute inset-0 flex items-center justify-center bg-obsidian-950/60">
              <Spinner label="Resolving neighbourhood…" />
            </div>
          )}
          {graph.error && (
            <div className="absolute inset-0 bg-obsidian-950/90">
              <ErrorState error={graph.error} onRetry={graph.reload} />
            </div>
          )}

          {/* depth control */}
          <div className="absolute left-2 top-2 flex items-center gap-1.5 px-2 py-1 rounded-xs bg-obsidian-950/85 border border-hairline">
            <span className="text-2xs uppercase tracking-[0.1em] text-ink-500">depth</span>
            {[1, 2, 3].map((value) => (
              <button
                key={value}
                type="button"
                className={`btn !px-1.5 ${depth === value ? "btn-active" : ""}`}
                onClick={() => setDepth(value)}
              >
                {value}
              </button>
            ))}
          </div>

          {/* hover readout */}
          {hovered && <HoverCard nodeKey={hovered} data={graph.data} />}

          <GraphLegend nodes={graph.data?.nodes.length ?? 0} edges={graph.data?.edges.length ?? 0} />
        </div>
      </Panel>

      {/* ---------------------------------------------- side rail */}
      <div className="min-h-0 overflow-y-auto space-y-3">
        <Panel title="Evidence path">
          <p className="text-2xs text-ink-700 leading-relaxed">
            The shortest relationship path between two records, hop by hop, with the
            justification on each hop.
          </p>
          <div className="mt-2.5 flex gap-1.5">
            <input
              className="input flex-1"
              placeholder="Target record, e.g. R000912"
              value={pathTarget}
              onChange={(event) => setPathTarget(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") void tracePath();
              }}
            />
            <button type="button" className="btn" onClick={() => void tracePath()}>
              Trace
            </button>
          </div>
          {path && (
            <ol className="mt-3 space-y-1.5">
              {path.hops.map((hop, index) => (
                <li key={`${hop.from}-${hop.to}-${index}`} className="text-2xs">
                  <div className="flex items-center gap-1.5">
                    <span className="font-mono text-ink-500 w-4">{index + 1}</span>
                    <span className="font-mono text-ink-300 truncate">
                      {nodeIdOf(hop.from)}
                    </span>
                    <span className="text-ink-700">→</span>
                    <span className="font-mono text-signal truncate">{nodeIdOf(hop.to)}</span>
                  </div>
                  <div className="ml-5 flex items-center gap-1.5 flex-wrap">
                    <Badge className="border-hairline text-ink-500">{hop.relationship}</Badge>
                    {hop.evidence_type && (
                      <span className="text-ink-700">{hop.evidence_type}</span>
                    )}
                    {hop.confidence !== null && (
                      <span className="font-mono text-ink-700">
                        {Number(hop.confidence).toFixed(2)}
                      </span>
                    )}
                  </div>
                </li>
              ))}
            </ol>
          )}
        </Panel>

        {graph.data?.provenance_chain && graph.data.provenance_chain.length > 0 && (
          <Panel title="Provenance chain">
            <ol className="space-y-1">
              {graph.data.provenance_chain.map((entry, index) => {
                const key = String((entry as { node?: string }).node ?? "");
                return (
                  <li key={`${key}-${index}`} className="flex items-center gap-2 text-2xs">
                    <span
                      className="w-1.5 h-1.5 rounded-full shrink-0"
                      style={{ background: NODE_COLOUR[nodeKindOf(key)] ?? "#6f7d91" }}
                    />
                    <span className="text-ink-700 uppercase tracking-[0.08em] w-[62px]">
                      {nodeKindOf(key)}
                    </span>
                    <span className="font-mono text-ink-300 truncate">{nodeIdOf(key)}</span>
                  </li>
                );
              })}
            </ol>
            <p className="mt-2 text-2xs text-ink-700 leading-relaxed">
              Record → container → shipment → owner → route → vessel → block. The last
              hop is the commitment that proves what the record used to hash to.
            </p>
          </Panel>
        )}

        {graph.data?.conflicts && graph.data.conflicts.length > 0 && (
          <Panel title={`Contradictions — ${graph.data.conflicts.length}`}>
            <ul className="space-y-1.5">
              {graph.data.conflicts.map((edge, index) => {
                const other = edge.source === graph.data?.root ? edge.target : edge.source;
                return (
                  <li key={index} className="flex items-center justify-between gap-2 text-2xs">
                    <button
                      type="button"
                      className="font-mono text-signal hover:underline truncate"
                      onClick={() => select(nodeIdOf(other), selection.containerId)}
                    >
                      {nodeIdOf(other)}
                    </button>
                    <span className="flex items-center gap-1.5 shrink-0">
                      <Badge colour={EDGE_COLOUR[edge.type] ?? "#6f7d91"}>{edge.type}</Badge>
                      {edge.confidence !== undefined && (
                        <span className="font-mono text-ink-500">
                          {Number(edge.confidence).toFixed(2)}
                        </span>
                      )}
                    </span>
                  </li>
                );
              })}
            </ul>
          </Panel>
        )}

        <Panel title="Reading the graph">
          <ul className="space-y-1.5 text-2xs text-ink-500 leading-relaxed">
            <li>
              <span className="text-ink-300">Node colour</span> is what a thing is;
              its <span className="text-ink-300">ring</span> is how suspect it is.
            </li>
            <li>
              <span style={{ color: "#e5484d" }}>Red edges</span> are contradictions —
              drawn heavier because they are the finding.
            </li>
            <li>
              <span style={{ color: "#2fa36b" }}>Dashed green</span> edges are
              corroboration.
            </li>
            <li>Faint edges are structure: ownership, containment, sequence.</li>
            <li>
              Hub nodes such as ports appear but are not expanded through, so one
              busy port cannot drag the whole manifest onto the canvas.
            </li>
          </ul>
        </Panel>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- pieces

function shortLabel(node: GraphResponse["nodes"][number]): string {
  const kind = nodeKindOf(node.id);
  const id = nodeIdOf(node.id);
  if (kind === "record") return id;
  if (kind === "port") return String(node.label ?? id);
  if (kind === "block") return id.replace("BLOCK_", "B");
  return id.replace(/^(CONT|SHIP|VESSEL|ROUTE|OWNER)_/, "");
}

function HoverCard({ nodeKey, data }: { nodeKey: string; data: GraphResponse | null }) {
  const node = data?.nodes.find((item) => item.id === nodeKey);
  if (!node) return null;
  const kind = nodeKindOf(nodeKey);
  const probability = node.tampering_probability;

  return (
    <div className="absolute right-2 top-2 w-[216px] px-2.5 py-2 rounded-xs bg-obsidian-950/92 border border-hairline-strong">
      <div className="flex items-center gap-1.5">
        <span
          className="w-1.5 h-1.5 rounded-full"
          style={{ background: NODE_COLOUR[kind] ?? "#6f7d91" }}
        />
        <span className="text-2xs uppercase tracking-[0.1em] text-ink-500">{kind}</span>
      </div>
      <div className="mt-1 font-mono text-xs text-ink-100 break-all">{nodeIdOf(nodeKey)}</div>
      {probability !== undefined && probability > 0 && (
        <div className="mt-1.5 flex items-center justify-between text-2xs">
          <span className="text-ink-500">tampering</span>
          <span className="font-mono tnum" style={{ color: severityColour(probability) }}>
            {pct(probability)}
          </span>
        </div>
      )}
      {node.tamper_class && (
        <div className="mt-1 text-2xs text-ink-500">{String(node.tamper_class)}</div>
      )}
      {Boolean(node.timestamp) && (
        <div className="mt-1 font-mono text-2xs text-ink-700">
          {ts(String(node.timestamp))}
        </div>
      )}
    </div>
  );
}

function GraphLegend({ nodes, edges }: { nodes: number; edges: number }) {
  const kinds = ["record", "container", "shipment", "port", "vessel", "route", "owner", "block"];
  return (
    <div className="absolute left-2 bottom-2 right-2 flex items-center justify-between gap-3">
      <div className="flex flex-wrap items-center gap-2.5 px-2 py-1 rounded-xs bg-obsidian-950/85 border border-hairline">
        {kinds.map((kind) => (
          <span key={kind} className="flex items-center gap-1 text-2xs text-ink-500">
            <span
              className="w-1.5 h-1.5 rounded-full"
              style={{ background: NODE_COLOUR[kind] }}
            />
            {kind}
          </span>
        ))}
      </div>
      <div className="shrink-0 px-2 py-1 rounded-xs bg-obsidian-950/85 border border-hairline">
        <SectionLabel>
          <span className="font-mono">{nodes}</span> nodes ·{" "}
          <span className="font-mono">{edges}</span> edges
        </SectionLabel>
      </div>
    </div>
  );
}

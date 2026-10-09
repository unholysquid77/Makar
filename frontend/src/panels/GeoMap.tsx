/**
 * Geo Forensic Map (spec 26).
 *
 * A first-class investigation surface, not an illustration. Layer toggles,
 * a confidence floor, a tampering-class filter and a timeline slider that
 * controls the displayed world state (spec 26.2, 26.6).
 *
 * The timeline slider filters *client-side* over the already-loaded point
 * layer rather than refetching per frame. Scrubbing must feel continuous, and
 * a round trip per tick would make it stutter — the whole suspicious layer is
 * a few hundred features, so filtering it in the browser is free.
 */

import { useCallback, useMemo, useState } from "react";

import { useApp } from "../App";
import { DEFAULT_LAYERS, ForensicMap } from "../components/ForensicMap";
import type { MapLayers } from "../components/ForensicMap";
import {
  Badge,
  DatumLine,
  ErrorState,
  Panel,
  SectionLabel,
  Spinner,
} from "../components/primitives";
import { api } from "../lib/api";
import { TAMPER_COLOUR, dateOnly, num, pct, ts } from "../lib/format";
import { useAsync } from "../lib/useAsync";
import type { GeoJSONFeatureCollection, TamperClass } from "../lib/types";

const CLASSES: TamperClass[] = ["MODIFIED", "DUPLICATED", "FABRICATED", "DELETED"];

export function GeoMap() {
  const { selection, select } = useApp();

  const [layers, setLayers] = useState<MapLayers>(DEFAULT_LAYERS);
  const [floor, setFloor] = useState(0.5);
  const [classes, setClasses] = useState<Set<TamperClass>>(new Set());
  const [owner, setOwner] = useState("");
  const [cursor, setCursor] = useState(1); // 0..1 across the event window

  const ports = useAsync(() => api.ports(), []);
  const routes = useAsync(() => api.routes(), []);
  const records = useAsync(() => api.mapRecords(0.3, 4000), []);
  const trajectory = useAsync(
    () =>
      selection.containerId
        ? api.trajectory(selection.containerId)
        : Promise.resolve(null),
    [selection.containerId],
  );

  // --- the event-time window the slider scrubs across ---
  const window_ = useMemo(() => {
    const times = (records.data?.features ?? [])
      .map((feature) => String(feature.properties.timestamp ?? ""))
      .filter(Boolean)
      .sort();
    return times.length > 0 ? { from: times[0], to: times[times.length - 1] } : null;
  }, [records.data]);

  const cursorTime = useMemo(() => {
    if (!window_) return null;
    const from = new Date(`${window_.from}Z`).getTime();
    const to = new Date(`${window_.to}Z`).getTime();
    return new Date(from + (to - from) * cursor).toISOString();
  }, [window_, cursor]);

  // --- filtered point layer ---
  const filtered = useMemo<GeoJSONFeatureCollection>(() => {
    const features = (records.data?.features ?? []).filter((feature) => {
      const p = feature.properties;
      if (Number(p.tampering_probability ?? 0) < floor) return false;
      if (classes.size > 0 && !classes.has(p.tamper_class as TamperClass)) return false;
      if (owner && !String(p.owner ?? "").toLowerCase().includes(owner.toLowerCase())) {
        return false;
      }
      if (cursorTime && String(p.timestamp ?? "") > cursorTime) return false;
      return true;
    });
    return { type: "FeatureCollection", features };
  }, [records.data, floor, classes, owner, cursorTime]);

  const toggleLayer = useCallback((key: keyof MapLayers) => {
    setLayers((current) => ({ ...current, [key]: !current[key] }));
  }, []);

  const toggleClass = useCallback((klass: TamperClass) => {
    setClasses((current) => {
      const next = new Set(current);
      if (next.has(klass)) next.delete(klass);
      else next.add(klass);
      return next;
    });
  }, []);

  if (ports.error) return <ErrorState error={ports.error} onRetry={ports.reload} />;

  return (
    <div className="h-full min-h-0 p-3 grid grid-cols-1 xl:grid-cols-[1fr_320px] gap-3">
      {/* ---------------------------------------------- map */}
      <Panel
        dense
        className="min-h-0"
        title="Geo forensic map"
        actions={
          <>
            {(
              [
                ["ports", "Ports"],
                ["routes", "Routes"],
                ["suspicious", "Suspicious"],
                ["trajectory", "Trajectory"],
              ] as Array<[keyof MapLayers, string]>
            ).map(([key, label]) => (
              <button
                key={key}
                type="button"
                className={`btn ${layers[key] ? "btn-active" : ""}`}
                onClick={() => toggleLayer(key)}
              >
                {label}
              </button>
            ))}
          </>
        }
      >
        <div className="relative h-full min-h-[480px]">
          {ports.data && routes.data ? (
            <ForensicMap
              ports={ports.data.ports}
              routes={routes.data.routes}
              routeGeojson={routes.data.geojson}
              suspicious={filtered}
              trajectory={trajectory.data}
              layers={layers}
              onSelectRecord={(recordId, containerId) => select(recordId, containerId)}
            />
          ) : (
            <div className="h-full flex items-center justify-center">
              <Spinner label="Loading world geometry…" />
            </div>
          )}

          {/* timeline slider (spec 26.6) */}
          {window_ && (
            <div className="absolute left-2 right-2 top-2 px-2.5 py-2 rounded-xs bg-obsidian-950/90 border border-hairline">
              <div className="flex items-center gap-3">
                <span className="text-2xs uppercase tracking-[0.12em] text-ink-500 shrink-0">
                  world state
                </span>
                <input
                  type="range"
                  min={0}
                  max={1}
                  step={0.002}
                  value={cursor}
                  onChange={(event) => setCursor(Number(event.target.value))}
                  className="flex-1 accent-signal"
                />
                <span className="font-mono tnum text-2xs text-ink-100 shrink-0 w-[118px] text-right">
                  {cursorTime ? ts(cursorTime) : "—"}
                </span>
                <button
                  type="button"
                  className="btn shrink-0"
                  onClick={() => setCursor(1)}
                  disabled={cursor === 1}
                >
                  Now
                </button>
              </div>
              <div className="mt-1 flex justify-between text-2xs text-ink-700 font-mono">
                <span>{dateOnly(window_.from)}</span>
                <span>
                  {num(filtered.features.length)} of {num(records.data?.features.length ?? 0)}{" "}
                  events shown
                </span>
                <span>{dateOnly(window_.to)}</span>
              </div>
            </div>
          )}
        </div>
      </Panel>

      {/* ---------------------------------------------- controls + stats */}
      <div className="min-h-0 overflow-y-auto space-y-3">
        <Panel title="Filters">
          <div className="space-y-3">
            <div>
              <div className="flex items-baseline justify-between">
                <SectionLabel>Confidence floor</SectionLabel>
                <span className="font-mono tnum text-2xs text-ink-100">{pct(floor, 0)}</span>
              </div>
              <input
                type="range"
                min={0.3}
                max={1}
                step={0.05}
                value={floor}
                onChange={(event) => setFloor(Number(event.target.value))}
                className="w-full accent-signal"
              />
            </div>

            <div>
              <SectionLabel>Tampering type</SectionLabel>
              <div className="flex flex-wrap gap-1">
                {CLASSES.map((klass) => (
                  <button
                    key={klass}
                    type="button"
                    className={`btn ${classes.has(klass) ? "btn-active" : ""}`}
                    style={
                      classes.has(klass)
                        ? {
                            color: TAMPER_COLOUR[klass],
                            borderColor: `${TAMPER_COLOUR[klass]}66`,
                            background: `${TAMPER_COLOUR[klass]}1a`,
                          }
                        : undefined
                    }
                    onClick={() => toggleClass(klass)}
                  >
                    {klass}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <SectionLabel>Owner</SectionLabel>
              <input
                className="input w-full"
                placeholder="Filter by owner…"
                value={owner}
                onChange={(event) => setOwner(event.target.value)}
              />
            </div>
          </div>
        </Panel>

        {selection.containerId && (
          <Panel
            title="Selected container"
            actions={
              selection.recordId && (
                <button
                  type="button"
                  className="btn"
                  onClick={() => select(selection.recordId, selection.containerId, "graph")}
                >
                  Trace in graph
                </button>
              )
            }
          >
            <div className="font-mono text-xs text-ink-100">{selection.containerId}</div>
            {trajectory.loading ? (
              <div className="mt-2">
                <Spinner />
              </div>
            ) : trajectory.data ? (
              <div className="mt-2.5 space-y-2">
                <div className="flex items-center gap-2 text-2xs">
                  <Badge colour={trajectory.data.differs ? "#4cc2ff" : "#5f6b7d"}>
                    {trajectory.data.differs
                      ? "reconstructed path differs"
                      : "reconstruction matches observed"}
                  </Badge>
                </div>
                <div className="text-2xs text-ink-500">
                  {trajectory.data.observed.length} observed point(s)
                  {trajectory.data.removed_records.length > 0 && (
                    <>
                      {" · "}
                      <span className="text-anomaly-high">
                        {trajectory.data.removed_records.length} record(s) removed
                      </span>
                    </>
                  )}
                </div>
                <ol className="space-y-0.5 max-h-56 overflow-y-auto">
                  {trajectory.data.observed.map((point) => (
                    <li key={point.record_id}>
                      <button
                        type="button"
                        className="w-full flex items-center gap-2 text-2xs text-left hover:bg-obsidian-800 rounded-xs px-1 py-0.5"
                        onClick={() =>
                          select(point.record_id, selection.containerId, "investigate")
                        }
                      >
                        <span className="font-mono text-signal w-[64px]">
                          {point.record_id}
                        </span>
                        <span className="text-ink-300 w-[70px]">{point.event_type}</span>
                        <span className="font-mono text-ink-500 w-[66px]">
                          {point.port_id}
                        </span>
                        <span className="font-mono text-ink-700 truncate">
                          {ts(point.timestamp)}
                        </span>
                      </button>
                    </li>
                  ))}
                </ol>
              </div>
            ) : null}
          </Panel>
        )}

        <Panel title="Ports by suspicion">
          {ports.loading ? (
            <Spinner />
          ) : (
            <ul className="space-y-1.5">
              {(ports.data?.ports ?? []).slice(0, 12).map((port) => (
                <li key={port.port_id}>
                  <div className="flex items-baseline justify-between gap-2 text-2xs">
                    <span className="text-ink-300 truncate">{port.name}</span>
                    <span className="font-mono tnum text-ink-500 shrink-0">
                      {port.suspicious}/{num(port.records)}
                    </span>
                  </div>
                  <DatumLine value={Math.min(1, port.suspicious_rate * 8)} className="mt-1" />
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Routes by suspicion">
          {routes.loading ? (
            <Spinner />
          ) : (
            <ul className="space-y-2">
              {(routes.data?.routes ?? []).slice(0, 8).map((route) => (
                <li key={route.route_id}>
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="font-mono text-2xs text-signal">{route.route_id}</span>
                    <span className="font-mono tnum text-2xs text-ink-500">
                      {route.suspicious} suspicious
                    </span>
                  </div>
                  <div className="text-2xs text-ink-500 truncate">
                    {route.port_names.join(" → ")}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}

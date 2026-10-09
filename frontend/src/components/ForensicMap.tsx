/**
 * The forensic map (spec 8, 26).
 *
 * MapLibre GL over a CARTO dark basemap, with the layer stack spec 8.3 lists:
 * ports, planned routes, suspicious records, attack events, and observed vs
 * reconstructed trajectories.
 *
 * Two deliberate rendering choices:
 *
 * - **Routes are drawn as planned lines, records as points.** A route is a
 *   schedule; a record is a claim about a moment. Drawing both as lines would
 *   imply the records were observed as a continuous track, which they were not.
 * - **Reconstructed paths are dashed, observed paths solid** (spec 26.6). The
 *   map must distinguish what the manifest *said* from what the system
 *   *believes*, or it is asserting a repair as an observation.
 *
 * Point colour is severity, not category, so the eye goes to the worst record
 * on screen rather than to whichever class happens to be most colourful.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import maplibregl from "maplibre-gl";
import type {
  GeoJSONSource,
  MapLayerMouseEvent,
  Map as MapLibreMap,
} from "maplibre-gl";

import { pct, severityColour, ts } from "../lib/format";
import type { GeoJSONFeatureCollection, PortStat, RouteStat, Trajectory } from "../lib/types";
const APIKEYCARTO=import.meta.env.VITE_CARTO_API_KEY;

const CARTO_DARK =
  "https://basemaps.cartocdn.com/gl/dark-matter-nolabels-gl-style/style.json?key="+APIKEYCARTO;

export interface MapLayers {
  ports: boolean;
  routes: boolean;
  suspicious: boolean;
  trajectory: boolean;
}

export const DEFAULT_LAYERS: MapLayers = {
  ports: true,
  routes: true,
  suspicious: true,
  trajectory: true,
};

const EMPTY: GeoJSONFeatureCollection = { type: "FeatureCollection", features: [] };

export function ForensicMap({
  ports,
  routes,
  routeGeojson,
  suspicious,
  trajectory,
  layers = DEFAULT_LAYERS,
  onSelectRecord,
  onSelectPort,
  compact = false,
  className = "",
}: {
  ports: PortStat[];
  routes: RouteStat[];
  routeGeojson?: GeoJSONFeatureCollection;
  suspicious?: GeoJSONFeatureCollection;
  trajectory?: Trajectory | null;
  layers?: MapLayers;
  onSelectRecord?: (recordId: string, containerId: string | null) => void;
  onSelectPort?: (portId: string) => void;
  compact?: boolean;
  className?: string;
}) {
  const container = useRef<HTMLDivElement>(null);
  const map = useRef<MapLibreMap | null>(null);
  const [ready, setReady] = useState(false);
  const [styleFailed, setStyleFailed] = useState(false);

  // --- port points, carrying their forensic statistics ---
  const portGeojson = useMemo<GeoJSONFeatureCollection>(
    () => ({
      type: "FeatureCollection",
      features: ports.map((port) => ({
        type: "Feature" as const,
        geometry: {
          type: "Point" as const,
          coordinates: [port.longitude, port.latitude] as [number, number],
        },
        properties: {
          port_id: port.port_id,
          name: port.name,
          country: port.country,
          records: port.records,
          containers: port.containers,
          shipments: port.shipments,
          suspicious: port.suspicious,
          suspicious_rate: port.suspicious_rate,
          mean_dwell_hours: port.mean_dwell_hours,
        },
      })),
    }),
    [ports],
  );

  const trajectoryGeojson = useMemo<GeoJSONFeatureCollection>(() => {
    if (!trajectory) return EMPTY;
    const features: GeoJSONFeatureCollection["features"] = [];
    if (trajectory.observed.length > 1) {
      features.push({
        type: "Feature",
        geometry: {
          type: "LineString" as const,
          coordinates: trajectory.observed.map((p) => p.coordinates),
        },
        properties: { kind: "observed", container_id: trajectory.container_id },
      });
    }
    if (trajectory.differs && trajectory.reconstructed.length > 1) {
      features.push({
        type: "Feature",
        geometry: {
          type: "LineString" as const,
          coordinates: trajectory.reconstructed.map((p) => p.coordinates),
        },
        properties: { kind: "reconstructed", container_id: trajectory.container_id },
      });
    }
    return { type: "FeatureCollection", features };
  }, [trajectory]);

  // --- map lifecycle ---
  useEffect(() => {
    if (!container.current || map.current) return;

    const instance = new maplibregl.Map({
    container: container.current!,
    style: CARTO_DARK,
    center: [78, 14],
    zoom: compact ? 2.1 : 2.8,
    attributionControl: compact ? false : { compact: true },
    dragRotate: false,
    pitchWithRotate: false,

    transformRequest: (url) => {
      if (!url.includes("basemaps.cartocdn.com")) {
        return { url };
      }

      const resourceUrl = new URL(url);
      resourceUrl.searchParams.set("key", APIKEYCARTO);

      return { url: resourceUrl.toString() };
    },
    });

    map.current = instance;
    (window as any).__MAKAR_MAP__ = instance;

    if (!compact) {
      instance.addControl(new maplibregl.NavigationControl({ showCompass: false }), "top-right");
      instance.addControl(new maplibregl.ScaleControl({ unit: "nautical" }), "bottom-left");
    }

    instance.on("error", (event) => {
      // A style fetch failure must not blank the panel.
      if (String(event?.error?.message ?? "").includes("style")) setStyleFailed(true);
    });

    instance.on("load", () => {
      // --- sources ---
      instance.addSource("ports", { type: "geojson", data: EMPTY as unknown as GeoJSON.FeatureCollection });
      instance.addSource("routes", { type: "geojson", data: EMPTY as unknown as GeoJSON.FeatureCollection });
      instance.addSource("suspicious", { type: "geojson", data: EMPTY as unknown as GeoJSON.FeatureCollection });
      instance.addSource("trajectory", { type: "geojson", data: EMPTY as unknown as GeoJSON.FeatureCollection });

      // --- planned routes: thin cold lines, underneath everything ---
      instance.addLayer({
        id: "routes-line",
        type: "line",
        source: "routes",
        paint: {
          "line-color": "#2b8fd4",
          "line-width": compact ? 0.5 : 0.8,
          "line-opacity": 0.3,
        },
      });

      // --- trajectories: observed solid, reconstructed dashed ---
      instance.addLayer({
        id: "trajectory-observed",
        type: "line",
        source: "trajectory",
        filter: ["==", ["get", "kind"], "observed"],
        paint: { "line-color": "#e8821f", "line-width": 1.8, "line-opacity": 0.95 },
      });
      instance.addLayer({
        id: "trajectory-reconstructed",
        type: "line",
        source: "trajectory",
        filter: ["==", ["get", "kind"], "reconstructed"],
        paint: {
          "line-color": "#4cc2ff",
          "line-width": 1.8,
          "line-opacity": 0.95,
          "line-dasharray": [2, 1.6],
        },
      });

      // --- ports: radius by traffic, ring by suspicion rate ---
      instance.addLayer({
        id: "ports-halo",
        type: "circle",
        source: "ports",
        paint: {
          "circle-radius": [
            "interpolate",
            ["linear"],
            ["get", "suspicious"],
            0,
            compact ? 3 : 4,
            40,
            compact ? 9 : 14,
          ],
          "circle-color": "#e5484d",
          "circle-opacity": [
            "interpolate",
            ["linear"],
            ["get", "suspicious_rate"],
            0,
            0,
            0.12,
            0.3,
          ],
          "circle-blur": 0.6,
        },
      });
      instance.addLayer({
        id: "ports-point",
        type: "circle",
        source: "ports",
        paint: {
          "circle-radius": compact ? 2.4 : 3.4,
          "circle-color": "#9aa8bd",
          "circle-stroke-width": 1,
          "circle-stroke-color": "#06080b",
        },
      });
      if (!compact) {
        instance.addLayer({
          id: "ports-label",
          type: "symbol",
          source: "ports",
          layout: {
            "text-field": ["get", "name"],
            "text-size": 10,
            "text-offset": [0, 1.1],
            "text-anchor": "top",
            "text-font": ["Open Sans Regular", "Arial Unicode MS Regular"],
          },
          paint: {
            "text-color": "#6f7d91",
            "text-halo-color": "#06080b",
            "text-halo-width": 1.2,
          },
        });
      }

      // --- suspicious records: colour and size by severity ---
      instance.addLayer({
        id: "suspicious-point",
        type: "circle",
        source: "suspicious",
        paint: {
          "circle-radius": [
            "interpolate",
            ["linear"],
            ["get", "tampering_probability"],
            0.5,
            compact ? 2 : 3,
            1,
            compact ? 4.5 : 7,
          ],
          "circle-color": [
            "interpolate",
            ["linear"],
            ["get", "tampering_probability"],
            0.5,
            "#d9a21b",
            0.7,
            "#e8821f",
            0.85,
            "#e5563d",
            1,
            "#e5484d",
          ],
          "circle-opacity": 0.85,
          "circle-stroke-width": compact ? 0 : 0.6,
          "circle-stroke-color": "#06080b",
        },
      });

      setReady(true);
    });

    return () => {
      instance.remove();
      map.current = null;
      setReady(false);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [compact]);

  // --- data updates ---
  const setData = useCallback((id: string, data: GeoJSONFeatureCollection) => {
    const instance = map.current;
    if (!instance || !instance.getSource(id)) return;
    (instance.getSource(id) as GeoJSONSource).setData(
      data as unknown as GeoJSON.FeatureCollection,
    );
  }, []);

  useEffect(() => {
    if (ready) setData("ports", layers.ports ? portGeojson : EMPTY);
  }, [ready, layers.ports, portGeojson, setData]);

  useEffect(() => {
    if (ready) setData("routes", layers.routes && routeGeojson ? routeGeojson : EMPTY);
  }, [ready, layers.routes, routeGeojson, setData]);

  useEffect(() => {
    if (ready) setData("suspicious", layers.suspicious && suspicious ? suspicious : EMPTY);
  }, [ready, layers.suspicious, suspicious, setData]);

  useEffect(() => {
    if (ready) setData("trajectory", layers.trajectory ? trajectoryGeojson : EMPTY);
  }, [ready, layers.trajectory, trajectoryGeojson, setData]);

  // --- fit to the selected trajectory, so "locate on map" actually locates ---
  useEffect(() => {
    const instance = map.current;
    if (!instance || !ready || !trajectory || trajectory.observed.length === 0) return;
    const bounds = new maplibregl.LngLatBounds();
    for (const point of trajectory.observed) bounds.extend(point.coordinates);
    instance.fitBounds(bounds, { padding: compact ? 40 : 90, maxZoom: 5.5, duration: 700 });
  }, [ready, trajectory, compact]);

  // --- interaction ---
  useEffect(() => {
    const instance = map.current;
    if (!instance || !ready || compact) return;

    const popup = new maplibregl.Popup({ closeButton: true, maxWidth: "320px", offset: 10 });

    const onRecordClick = (event: MapLayerMouseEvent) => {
      const feature = (event.features ?? [])[0];
      if (!feature) return;
      const p = (feature.properties ?? {}) as Record<string, string | number>;
      popup
        .setLngLat(event.lngLat)
        .setHTML(shipmentPopup(p))
        .addTo(instance);
      onSelectRecord?.(String(p.record_id), (p.container_id as string) ?? null);
    };

    const onPortClick = (event: MapLayerMouseEvent) => {
      const feature = (event.features ?? [])[0];
      if (!feature) return;
      const p = (feature.properties ?? {}) as Record<string, string | number>;
      popup.setLngLat(event.lngLat).setHTML(portPopup(p)).addTo(instance);
      onSelectPort?.(String(p.port_id));
    };

    const pointer = () => {
      instance.getCanvas().style.cursor = "pointer";
    };
    const reset = () => {
      instance.getCanvas().style.cursor = "";
    };

    instance.on("click", "suspicious-point", onRecordClick);
    instance.on("click", "ports-point", onPortClick);
    for (const layer of ["suspicious-point", "ports-point"]) {
      instance.on("mouseenter", layer, pointer);
      instance.on("mouseleave", layer, reset);
    }

    return () => {
      instance.off("click", "suspicious-point", onRecordClick);
      instance.off("click", "ports-point", onPortClick);
      for (const layer of ["suspicious-point", "ports-point"]) {
        instance.off("mouseenter", layer, pointer);
        instance.off("mouseleave", layer, reset);
      }
      popup.remove();
    };
  }, [ready, compact, onSelectRecord, onSelectPort]);

  // Keep the route count referenced so the prop is meaningful to callers.
  const routeCount = routes.length;

  return (
    <div className={`relative h-full w-full ${className}`}>
      <div ref={container} className="absolute inset-0 h-full w-full"/>
      {styleFailed && (
        <div className="absolute inset-0 flex items-center justify-center bg-obsidian-950/80">
          <div className="text-center max-w-xs">
            <div className="text-2xs uppercase tracking-[0.14em] text-anomaly-low">
              Basemap unavailable
            </div>
            <div className="mt-1.5 text-2xs text-ink-500">
              The CARTO basemap could not be fetched. Geometry still renders; only
              the background tiles are missing.
            </div>
          </div>
        </div>
      )}
      {!compact && (
        <div className="absolute left-2 bottom-2 flex items-center gap-3 px-2 py-1 rounded-xs
                        bg-obsidian-950/85 border border-hairline text-2xs text-ink-500">
          <LegendDot colour="#9aa8bd" label="Port" />
          <LegendDot colour="#2b8fd4" label={`Route (${routeCount})`} />
          <LegendDot colour="#e5563d" label="Suspicious" />
          <span className="flex items-center gap-1">
            <span className="inline-block w-4 h-[2px]" style={{ background: "#e8821f" }} />
            observed
          </span>
          <span className="flex items-center gap-1">
            <span
              className="inline-block w-4 h-[2px]"
              style={{
                background:
                  "repeating-linear-gradient(to right,#4cc2ff 0 4px,transparent 4px 7px)",
              }}
            />
            reconstructed
          </span>
        </div>
      )}
    </div>
  );
}

function LegendDot({ colour, label }: { colour: string; label: string }) {
  return (
    <span className="flex items-center gap-1">
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: colour }} />
      {label}
    </span>
  );
}

// ---------------------------------------------------------------- popups

function row(label: string, value: string): string {
  return `<div style="display:flex;justify-content:space-between;gap:14px">
    <span style="color:#6f7d91;font-size:10.5px;text-transform:uppercase;letter-spacing:.1em">${label}</span>
    <span style="color:#e4e9f1;font-family:'IBM Plex Mono',monospace;font-size:11.5px">${value}</span>
  </div>`;
}

/** Spec 26.5 shipment popup. */
function shipmentPopup(p: Record<string, string | number>): string {
  const probability = Number(p.tampering_probability ?? 0);
  return `<div style="padding:10px 11px;min-width:240px">
    <div style="font-family:'IBM Plex Mono',monospace;font-size:12px;color:#e4e9f1">${p.record_id}</div>
    <div style="margin:7px 0 9px;font-family:'IBM Plex Mono',monospace;font-size:21px;color:${severityColour(
      probability,
    )}">${pct(probability)}</div>
    <div style="display:grid;gap:3px">
      ${row("class", String(p.tamper_class ?? "—"))}
      ${row("disposition", String(p.classification ?? "—"))}
      ${row("container", String(p.container_id ?? "—"))}
      ${row("port", String(p.port_id ?? "—"))}
      ${row("owner", String(p.owner ?? "—"))}
      ${row("event", String(p.event_type ?? "—"))}
      ${row("time", ts(p.timestamp as string))}
    </div>
    <div style="margin-top:9px;font-size:10.5px;color:#6f7d91">
      Selected — open Investigate, Bloodhound or Rebuild for this record.
    </div>
  </div>`;
}

/** Spec 26.3 port popup. */
function portPopup(p: Record<string, string | number>): string {
  const rate = Number(p.suspicious_rate ?? 0);
  const dwell = p.mean_dwell_hours;
  return `<div style="padding:10px 11px;min-width:230px">
    <div style="font-size:12.5px;color:#e4e9f1;font-weight:600">${p.name}</div>
    <div style="font-family:'IBM Plex Mono',monospace;font-size:10.5px;color:#6f7d91;margin-bottom:9px">
      ${p.port_id} · ${p.country}
    </div>
    <div style="display:grid;gap:3px">
      ${row("records", Number(p.records ?? 0).toLocaleString())}
      ${row("containers", Number(p.containers ?? 0).toLocaleString())}
      ${row("shipments", Number(p.shipments ?? 0).toLocaleString())}
      ${row("suspicious", String(p.suspicious ?? 0))}
      ${row("suspicious rate", pct(rate))}
      ${row("mean dwell", dwell == null ? "—" : `${Number(dwell).toFixed(1)}h`)}
    </div>
  </div>`;
}

/**
 * Typed client for the forensic API.
 *
 * Deliberately thin: no caching layer, no state library. Every panel is a view
 * over one analysis snapshot that only changes when the user re-runs the
 * analysis, so a `useAsync` hook plus explicit refresh is the whole data
 * story — adding a cache would mean reasoning about staleness for no benefit.
 */

import type {
  BlockchainResponse,
  StreamAlertsResponse,
  StreamManifestResponse,
  EvaluationArtifacts,
  GeoJSONFeatureCollection,
  GraphResponse,
  InferredDeletion,
  LlmExplainResponse,
  NodesResponse,
  PathHop,
  PortStat,
  RecordDetail,
  RecordsResponse,
  Reconstruction,
  ReportPayload,
  RouteStat,
  StatusResponse,
  StreamStartResponse,
  StreamStatusResponse,
  StreamVerdictPayload,
  SummaryResponse,
  TimelineResponse,
  Trajectory,
} from "./types";

const BASE = import.meta.env.VITE_API_BASE ?? "";

export class ApiError extends Error {
  readonly status: number;
  readonly hint?: string;

  constructor(status: number, message: string, hint?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.hint = hint;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${BASE}${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    });
  } catch {
    throw new ApiError(
      0,
      "Cannot reach the Makar API.",
      "Start it with: python -m backend.main",
    );
  }

  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    let hint: string | undefined;
    try {
      const body = await response.json();
      if (typeof body?.detail === "string") detail = body.detail;
      if (typeof body?.hint === "string") hint = body.hint;
    } catch {
      /* non-JSON error body; keep the status line */
    }
    throw new ApiError(response.status, detail, hint);
  }
  return (await response.json()) as T;
}

function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      search.set(key, String(value));
    }
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

export const api = {
  status: () => request<StatusResponse>("/api/status"),

  analyze: (body: { directory?: string; manifest?: string; detectors?: string[] } = {}) =>
    request<{ run_id: string; timings_ms: Record<string, number> }>("/api/analyze", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  summary: () => request<SummaryResponse>("/api/summary"),

  report: (top = 25) => request<ReportPayload>(`/api/report${qs({ top })}`),

  records: (params: {
    limit?: number;
    offset?: number;
    suspicious_only?: boolean;
    tamper_class?: string;
    classification?: string;
    owner?: string;
    port_id?: string;
    min_probability?: number;
    sort?: "probability" | "record_id" | "timestamp";
  } = {}) => request<RecordsResponse>(`/api/records${qs(params)}`),

  record: (id: string) => request<RecordDetail>(`/api/records/${encodeURIComponent(id)}`),

  reconstruct: (id: string) =>
    request<Reconstruction>(`/api/reconstruct/${encodeURIComponent(id)}`, { method: "POST" }),

  graph: (id: string, params: { depth?: number; mode?: string } = {}) =>
    request<GraphResponse>(`/api/graph/${encodeURIComponent(id)}${qs(params)}`),

  graphPath: (source: string, target: string) =>
    request<{ source: string; target: string; hops: PathHop[] }>(
      `/api/graph/path/${encodeURIComponent(source)}/${encodeURIComponent(target)}`,
    ),

  ports: () => request<{ ports: PortStat[]; geojson: GeoJSONFeatureCollection }>("/api/ports"),

  routes: () => request<{ routes: RouteStat[]; geojson: GeoJSONFeatureCollection }>("/api/routes"),

  mapRecords: (minProbability = 0.5, limit = 1500) =>
    request<GeoJSONFeatureCollection>(
      `/api/map/records${qs({ min_probability: minProbability, limit })}`,
    ),

  trajectory: (containerId: string) =>
    request<Trajectory>(`/api/containers/${encodeURIComponent(containerId)}/trajectory`),

  timeline: () => request<TimelineResponse>("/api/timeline"),

  deletions: (limit = 200) => request<{ total: number; deletions: InferredDeletion[] }>(
    `/api/deletions${qs({ limit })}`,
  ),

  blockchain: (limit = 50, offset = 0) =>
    request<BlockchainResponse>(`/api/blockchain${qs({ limit, offset })}`),

  nodes: () => request<NodesResponse>("/api/nodes"),

  /** The offline scorer's artifact. 404 when it has not been run. */
  evaluation: () => request<EvaluationArtifacts>("/api/evaluation"),

  streamStart: (body: { events?: number; seed?: number; generate?: boolean } = {}) =>
    request<StreamStartResponse>("/api/stream/start", {
      method: "POST",
      body: JSON.stringify({ events: 250, generate: true, ...body }),
    }),

  streamEvent: (row: Record<string, string>) =>
    request<StreamVerdictPayload>("/api/stream/event", {
      method: "POST",
      body: JSON.stringify({ row }),
    }),

  streamStatus: (limit = 50) =>
    request<StreamStatusResponse>(`/api/stream/status${qs({ limit })}`),


  /** Open alerts and the flooding-control numbers (live session only). */
  streamAlerts: () => request<StreamAlertsResponse>("/api/stream/alerts"),

  /** The reconstructed manifest, current as of the last live event. */
  streamManifest: (limit = 200) =>
    request<StreamManifestResponse>(`/api/stream/manifest${qs({ limit })}`),

  /** The suspicious activity report, current as of the last live event. */
  streamReport: (top = 20) =>
    request<Record<string, unknown>>(`/api/stream/report${qs({ top })}`),

  explain: (recordId: string, question?: string) =>
    request<LlmExplainResponse>("/api/llm/explain", {
      method: "POST",
      body: JSON.stringify({ record_id: recordId, question }),
    }),
};

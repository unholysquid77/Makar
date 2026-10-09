/** Wire types mirroring the forensic API (spec 32). */

export type TamperClass =
  | "MODIFIED"
  | "DELETED"
  | "DUPLICATED"
  | "FABRICATED"
  | "BENIGN_ANOMALY"
  | "CLEAN";

export type Classification = "ORIGINAL" | "REPAIRED" | "REMOVED" | "UNRECOVERABLE";

export type EvidenceType =
  | "TEMPORAL"
  | "SPATIAL"
  | "ROUTE"
  | "CARGO"
  | "DUPLICATE"
  | "STATISTICAL"
  | "GRAPH"
  | "BLOCKCHAIN"
  | "IDENTITY"
  | "FORMAT";

export interface Contribution {
  code: string;
  type: EvidenceType;
  label: string;
  severity: number;
  log_odds?: number;
  points: number;
}

export interface Evidence {
  record_id: string;
  code: string;
  type: EvidenceType;
  severity: number;
  description: string;
  supporting_records: string[];
  details: Record<string, unknown>;
  engine: string;
}

export interface Verdict {
  record_id: string;
  type_scores: Partial<Record<EvidenceType, number>>;
  anomaly_score: number;
  tampering_probability: number;
  tamper_class: TamperClass;
  class_confidence: number;
  contributions: Contribution[];
  rationale: string;
}

export interface CandidateRepair {
  candidate_id: string;
  strategy: string;
  changes: Record<string, unknown>;
  remove: boolean;
  criterion_scores: Record<string, number>;
  score: number;
  explanation: string;
}

export interface Reconstruction {
  record_id: string;
  classification: Classification;
  original: Record<string, unknown>;
  reconstructed: Record<string, unknown> | null;
  confidence: number;
  candidates: CandidateRepair[];
  selected_candidate_id: string | null;
  reason: string;
}

export interface ManifestSummary {
  total_records: number;
  suspicious: number;
  original: number;
  repaired: number;
  removed: number;
  unrecoverable: number;
  by_tamper_class: Partial<Record<TamperClass, number>>;
  by_evidence_type: Partial<Record<EvidenceType, number>>;
  mean_repair_confidence: number;
}

export interface SummaryResponse {
  run_id: string;
  created_at: string;
  seed: number | null;
  summary: ManifestSummary;
  thresholds: { suspicious: number; high_confidence: number };
  inferred_deletions: number;
  attack_windows: number;
  consistency: ConsistencyReport | null;
}

export interface RecordRow {
  record_id: string;
  container_id: string | null;
  shipment_id: string | null;
  owner: string | null;
  cargo_type: string | null;
  port_id: string | null;
  route_id: string | null;
  vessel_id: string | null;
  event_type: string | null;
  status: string | null;
  weight: number | null;
  declared_value: number | null;
  timestamp: string | null;
  latitude: number | null;
  longitude: number | null;
  tampering_probability: number;
  tamper_class: TamperClass;
  class_confidence: number;
  classification: Classification | null;
  repair_confidence: number | null;
  evidence_count: number;
  top_findings: string[];
}

export interface RecordsResponse {
  total: number;
  offset: number;
  limit: number;
  records: RecordRow[];
}

export interface TimelinePoint {
  record_id: string;
  event_type: string | null;
  port_id: string | null;
  timestamp: string | null;
  weight: number | null;
  probability: number | null;
}

export interface RecordDetail {
  record: Record<string, unknown>;
  raw: Record<string, string>;
  normalization_notes: string[];
  verdict: Verdict | null;
  evidence: Evidence[];
  reconstruction: Reconstruction | null;
  corroboration: number | null;
  container_timeline: TimelinePoint[];
  graph_key: string;
}

export interface GraphNode {
  id: string;
  type: string;
  label?: string;
  kind?: string;
  tampering_probability?: number;
  tamper_class?: TamperClass;
  [key: string]: unknown;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: string;
  evidence_code?: string;
  evidence_type?: string;
  confidence?: number;
  [key: string]: unknown;
}

export interface GraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
  root: string;
  mode: string;
  conflicts?: GraphEdge[];
  provenance_chain?: Array<Record<string, unknown>>;
}

export interface PathHop {
  from: string;
  to: string;
  relationship: string;
  evidence_type: string | null;
  confidence: number | null;
  source_record: string | null;
  timestamp: string | null;
}

export interface PortStat {
  port_id: string;
  name: string;
  country: string;
  latitude: number;
  longitude: number;
  capacity_teu: number;
  records: number;
  containers: number;
  shipments: number;
  suspicious: number;
  suspicious_rate: number;
  mean_dwell_hours: number | null;
}

export interface RouteStat {
  route_id: string;
  port_sequence: string[];
  port_names: string[];
  vessel_id: string | null;
  records: number;
  containers: number;
  suspicious: number;
  by_tamper_class: Partial<Record<TamperClass, number>>;
}

export type Coordinate = [number, number];

export interface GeoFeature {
  type: "Feature";
  geometry: {
    type: "Point" | "LineString" | "Polygon" | string;
    coordinates: Coordinate | Coordinate[] | Coordinate[][];
  };
  properties: Record<string, string | number | boolean | null>;
}

export interface GeoJSONFeatureCollection {
  type: "FeatureCollection";
  features: GeoFeature[];
}

export interface AttackWindow {
  window_id: string;
  start: string;
  end: string;
  record_count: number;
  affected_ports: string[];
  affected_owners: string[];
  affected_vessels: string[];
  likely_sequence: TamperClass[];
  confidence: number;
  narrative: string;
  buckets?: TimelineBucket[];
}

export interface TimelineBucket {
  window_id?: string;
  start: string;
  end: string;
  total: number;
  by_class: Partial<Record<TamperClass, number>>;
  record_ids: string[];
}

export interface TimelineResponse {
  windows: AttackWindow[];
  buckets: TimelineBucket[];
}

export interface NodeView {
  node_id: string;
  status: "HEALTHY" | "DIVERGENT" | "OFFLINE" | "SYNCING";
  endpoint: string;
  peers: string[];
  height: number;
  latest_block_id: string | null;
  state_root: string;
  divergent_blocks: string[];
  divergent_records: string[];
}

export interface ConsistencyReport {
  majority_state_root: string;
  agreeing_nodes: string[];
  divergent_nodes: string[];
  affected_blocks: string[];
  affected_records: string[];
  nodes: NodeView[];
}

export interface NodesResponse {
  nodes: NodeView[];
  majority_state_root?: string;
  agreeing?: string[];
  divergent?: string[];
  agreement_fraction?: number;
  affected_blocks?: string[];
  affected_records?: string[];
  local_verification?: Record<string, string[]>;
}

export interface BlockHeader {
  block_id: string;
  index: number;
  timestamp: string;
  previous_hash: string;
  manifest_root: string;
  route_root: string;
  state_root: string;
  record_count: number;
  block_hash: string;
}

export interface Block {
  header: BlockHeader;
  record_hashes: string[];
  record_ids: string[];
  node_signatures: Record<string, string>;
}

export interface BlockchainResponse {
  height: number;
  state_root: string | null;
  digest?: string;
  valid?: boolean;
  problems?: string[];
  committed_records?: number;
  covered_from?: string | null;
  covered_to?: string | null;
  sealed_fraction?: number;
  blocks: Block[];
}

export interface InferredDeletion {
  record_id: string | null;
  source?: string;
  sources?: string[];
  container_id?: string | null;
  port_id?: string | null;
  missing_event?: string | null;
  between?: Array<string | null>;
  confidence: number;
  reason: string;
  block_id?: string | null;
}

export interface Trajectory {
  container_id: string;
  observed: Array<{
    record_id: string;
    port_id: string | null;
    event_type: string | null;
    timestamp: string | null;
    coordinates: [number, number];
  }>;
  reconstructed: Trajectory["observed"];
  removed_records: string[];
  differs: boolean;
}

export interface StreamVerdictPayload {
  sequence: number;
  record_id: string;
  container_id: string | null;
  port_id: string | null;
  event_type: string | null;
  timestamp: string | null;
  weight: number | null;
  tampering_probability: number;
  tamper_class: TamperClass;
  class_confidence: number;
  rationale: string;
  contributions: Array<{ code: string; type: EvidenceType; label: string; points: number }>;
  evidence: Array<{
    code: string;
    type: EvidenceType;
    severity: number;
    description: string;
    engine: string;
  }>;
  reconstruction: { classification: Classification; confidence: number; reason: string } | null;
  /** True when this event revised a record already on the feed. */
  is_revision: boolean;
  /** The before/after diff and the consistency delta, when it was a revision. */
  revision: {
    fields_changed: string[];
    filled: string[];
    altered: string[];
    material_fields_altered: string[];
    before: Record<string, unknown>;
    after: Record<string, unknown>;
    anomaly_before: number;
    anomaly_after: number;
    anomaly_delta: number;
    revision_number: number;
    verdict: string;
  } | null;
  /** What the alert manager did: raised, escalated, suppressed or ignored. */
  alert: {
    action: "RAISED" | "ESCALATED" | "SUPPRESSED" | "IGNORED";
    reason: string;
    alert_id: string | null;
    should_notify: boolean;
  } | null;
  latency_ms: number;
}

export interface StreamStartResponse {
  started: boolean;
  alert_threshold: number;
  batch_records: number;
  injected: Record<string, number>;
  queued_events: Array<{
    sequence: number;
    row: Record<string, string>;
    truth: Record<string, unknown>;
  }>;
}

export interface StreamStatusResponse {
  active: boolean;
  processed?: number;
  suspicious?: number;
  records_total?: number;
  latency_ms?: { mean: number; p50: number; p95: number; max: number };
  clock?: string;
  recent?: StreamVerdictPayload[];
}

export interface StatusResponse {
  loaded: boolean;
  directory: string;
  manifest?: string;
  run_id?: string;
  seed?: number | null;
  records?: number;
  graph?: { nodes: number; edges: number };
  stream_active?: boolean;
  timings_ms?: Record<string, number>;
  config_sources?: string[];
}

export interface ReportPayload {
  run_id: string;
  created_at: string;
  seed: number | null;
  thresholds: { suspicious: number; high_confidence: number };
  totals: {
    records: number;
    suspicious: number;
    original: number;
    repaired: number;
    removed: number;
    unrecoverable: number;
    benign_anomalies: number;
    mean_repair_confidence: number;
  };
  by_tamper_class: Record<string, number>;
  by_evidence_type: Record<string, number>;
  affected: {
    owners: Array<[string, number]>;
    ports: Array<[string, number]>;
    routes: Array<[string, number]>;
  };
  inferred_deletion_count: number;
  attack_windows: AttackWindow[];
  data_quality: Record<string, number>;
  timings_ms: Record<string, number>;
}

export interface LlmExplainResponse {
  record_id: string;
  deterministic: {
    tampering_probability: number;
    tamper_class: TamperClass;
    rationale: string;
    contributions: Array<{ finding: string; layer: string; points: number }>;
    reconstruction: { classification: string; confidence: number; reason: string } | null;
  };
  llm: {
    available: boolean;
    provider: string;
    model: string;
    explanation: string;
    error: string | null;
  };
  note: string;
}

/** Whatever scripts/evaluate.py and scripts/stream_sim.py wrote to disk.
 *
 * Typed loosely on purpose: these are reporting artifacts whose shape is owned
 * by the scorer, and the console renders what it finds rather than asserting a
 * schema the scorer would then have to honour.
 */
export interface EvaluationArtifacts {
  batch: Record<string, unknown> | null;
  stream: unknown | null;
  directory: string;
  note: string;
}

export interface LiveAlert {
  alert_id: string;
  key: string;
  entity_type: string;
  status: "OPEN" | "ESCALATED" | "CRITICAL" | "CLOSED";
  first_seen: string;
  last_seen: string;
  peak_probability: number;
  latest_probability: number;
  tamper_class: TamperClass;
  event_count: number;
  suppressed_count: number;
  notify_count: number;
  record_ids: string[];
  evidence_layers: string[];
  evidence_codes: string[];
  narrative: string;
}

export interface AlertStats {
  flagged_events: number;
  notifications: number;
  suppressed: number;
  open_alerts: number;
  closed_alerts: number;
  compression_ratio: number;
  suppression_rate: number;
  by_status: Record<string, number>;
}

export interface StreamAlertsResponse {
  active: boolean;
  open: LiveAlert[];
  closed?: number;
  stats: AlertStats;
}

export interface LiveSummary {
  total_records: number;
  disposition: Record<"ORIGINAL" | "REPAIRED" | "REMOVED" | "UNRECOVERABLE", number>;
  by_tamper_class: Record<string, number>;
  suspicious: number;
  revisions_seen: number;
  records_revised: number;
  corrections_accepted: number;
  mean_repair_confidence: number;
}

export interface StreamManifestResponse {
  summary: LiveSummary;
  records: Array<{
    record_id: string;
    container_id: string | null;
    classification: string;
    confidence: number | null;
    tampering_probability: number;
    tamper_class: TamperClass;
    revisions: number;
  }>;
}

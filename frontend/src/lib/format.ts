/** Formatting and colour-mapping helpers.
 *
 * Colour decisions live here, in one place, because the rule the design
 * depends on — colour means state, never decoration — only holds if every
 * panel derives its colours from the same functions.
 */

import type { Classification, EvidenceType, TamperClass } from "./types";

export const pct = (value: number | null | undefined, digits = 1): string =>
  value === null || value === undefined ? "—" : `${(value * 100).toFixed(digits)}%`;

export const num = (value: number | null | undefined, digits = 0): string =>
  value === null || value === undefined
    ? "—"
    : value.toLocaleString(undefined, {
        minimumFractionDigits: digits,
        maximumFractionDigits: digits,
      });

export const kg = (value: number | null | undefined): string =>
  value === null || value === undefined ? "—" : `${num(value, 0)} kg`;

export const money = (value: number | null | undefined): string =>
  value === null || value === undefined ? "—" : `$${num(value, 0)}`;

export const shortHash = (value: string | null | undefined, chars = 10): string =>
  !value ? "—" : `${value.slice(0, chars)}…`;

export function ts(value: string | null | undefined, withSeconds = false): string {
  if (!value) return "—";
  const date = new Date(value.endsWith("Z") ? value : `${value}Z`);
  if (Number.isNaN(date.getTime())) return value;
  const d = date.toISOString();
  return withSeconds ? d.slice(0, 19).replace("T", " ") : d.slice(0, 16).replace("T", " ");
}

export function dateOnly(value: string | null | undefined): string {
  if (!value) return "—";
  return value.slice(0, 10);
}

/** Duration between two ISO instants, in a compact human form. */
export function span(start: string, end: string): string {
  const ms = new Date(`${end}Z`).getTime() - new Date(`${start}Z`).getTime();
  if (!Number.isFinite(ms) || ms <= 0) return "—";
  const hours = ms / 3_600_000;
  if (hours < 1) return `${Math.round(hours * 60)}m`;
  if (hours < 48) return `${hours.toFixed(1)}h`;
  return `${(hours / 24).toFixed(1)}d`;
}

// ---------------------------------------------------------------------
// Severity → colour. One ramp, used by every panel.
// ---------------------------------------------------------------------

export function severityColour(value: number): string {
  if (value >= 0.85) return "#e5484d"; // critical
  if (value >= 0.7) return "#e5563d"; // high
  if (value >= 0.5) return "#e8821f"; // mid
  if (value >= 0.3) return "#d9a21b"; // low
  return "#6f7d91"; // informational only
}

export function severityClass(value: number): string {
  if (value >= 0.85) return "text-anomaly-critical";
  if (value >= 0.7) return "text-anomaly-high";
  if (value >= 0.5) return "text-anomaly-mid";
  if (value >= 0.3) return "text-anomaly-low";
  return "text-ink-500";
}

export const TAMPER_COLOUR: Record<TamperClass, string> = {
  MODIFIED: "#e8821f",
  DELETED: "#7c8cff",
  DUPLICATED: "#4cc2ff",
  FABRICATED: "#e5484d",
  BENIGN_ANOMALY: "#6f7d91",
  CLEAN: "#454f5e",
};

export const CLASSIFICATION_COLOUR: Record<Classification, string> = {
  ORIGINAL: "#5f6b7d",
  REPAIRED: "#4cc2ff",
  REMOVED: "#e5563d",
  UNRECOVERABLE: "#d9a21b",
};

/** Evidence layers, in the order the breakdown should list them. */
export const EVIDENCE_LAYERS: EvidenceType[] = [
  "BLOCKCHAIN",
  "TEMPORAL",
  "SPATIAL",
  "ROUTE",
  "CARGO",
  "DUPLICATE",
  "GRAPH",
  "IDENTITY",
  "STATISTICAL",
  "FORMAT",
];

export const LAYER_COLOUR: Record<EvidenceType, string> = {
  BLOCKCHAIN: "#7c8cff",
  TEMPORAL: "#4cc2ff",
  SPATIAL: "#2b8fd4",
  ROUTE: "#45b0a0",
  CARGO: "#d9a21b",
  DUPLICATE: "#b48ead",
  GRAPH: "#8fa3bf",
  IDENTITY: "#c08a5e",
  STATISTICAL: "#6f7d91",
  FORMAT: "#2fa36b",
};

/** Graph node kinds → colour, used by Bloodhound. */
export const NODE_COLOUR: Record<string, string> = {
  record: "#4cc2ff",
  container: "#d9a21b",
  shipment: "#45b0a0",
  port: "#8fa3bf",
  vessel: "#c08a5e",
  route: "#2b8fd4",
  owner: "#b48ead",
  cargo: "#2fa36b",
  block: "#7c8cff",
  event: "#6f7d91",
};

export const EDGE_COLOUR: Record<string, string> = {
  CONFLICTS_WITH: "#e5484d",
  DUPLICATES: "#e8821f",
  SUPPORTS: "#2fa36b",
  PRECEDES: "#3a4454",
  DERIVED_FROM: "#4a5568",
  OWNS: "#5a4a68",
  CONTAINS: "#44525f",
  TRAVELS_TO: "#2b4a5e",
  ARRIVED_AT: "#3a5568",
  DEPARTED_FROM: "#3a5568",
  TRANSFERRED_TO: "#6a5540",
  CARRIED_BY: "#4a4a5e",
};

/** Human label for an evidence code, when the API did not supply one. */
export function humanise(code: string): string {
  return code
    .toLowerCase()
    .split("_")
    .map((word, index) => (index === 0 ? word.charAt(0).toUpperCase() + word.slice(1) : word))
    .join(" ");
}

export function nodeKindOf(key: string): string {
  return key.split(":", 1)[0] ?? "record";
}

export function nodeIdOf(key: string): string {
  const index = key.indexOf(":");
  return index === -1 ? key : key.slice(index + 1);
}

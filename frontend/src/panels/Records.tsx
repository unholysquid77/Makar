/**
 * Record ledger.
 *
 * The full manifest, filterable by everything the report is organised around:
 * tampering class, disposition, owner, port, probability floor. This is the
 * view an analyst works a queue from, so it is dense, keyboard-navigable and
 * one click from the investigation panel.
 */

import { useMemo, useState } from "react";

import { useApp } from "../App";
import {
  Badge,
  ClassificationBadge,
  Empty,
  ErrorState,
  Panel,
  ProbabilityCell,
  Spinner,
  TamperBadge,
} from "../components/primitives";
import { api } from "../lib/api";
import { kg, money, num, pct, ts } from "../lib/format";
import { useAsync } from "../lib/useAsync";
import type { Classification, TamperClass } from "../lib/types";

const TAMPER_CLASSES: TamperClass[] = [
  "MODIFIED",
  "DELETED",
  "DUPLICATED",
  "FABRICATED",
  "BENIGN_ANOMALY",
  "CLEAN",
];

const CLASSIFICATIONS: Classification[] = [
  "ORIGINAL",
  "REPAIRED",
  "REMOVED",
  "UNRECOVERABLE",
];

const PAGE = 60;

export function Records() {
  const { selection, select } = useApp();
  const [suspiciousOnly, setSuspiciousOnly] = useState(true);
  const [tamperClass, setTamperClass] = useState<string>("");
  const [classification, setClassification] = useState<string>("");
  const [minProbability, setMinProbability] = useState(0);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [sort, setSort] = useState<"probability" | "record_id" | "timestamp">("probability");

  const query = useAsync(
    () =>
      api.records({
        suspicious_only: suspiciousOnly,
        tamper_class: tamperClass || undefined,
        classification: classification || undefined,
        min_probability: minProbability,
        limit: PAGE,
        offset: page * PAGE,
        sort,
      }),
    [suspiciousOnly, tamperClass, classification, minProbability, page, sort],
  );

  // Free-text search is applied client-side over the current page: the API
  // filters on structured fields, and adding a server-side text index would be
  // over-engineering for a manifest that fits in memory.
  const rows = useMemo(() => {
    const data = query.data?.records ?? [];
    if (!search.trim()) return data;
    const needle = search.trim().toLowerCase();
    return data.filter((row) =>
      [row.record_id, row.container_id, row.shipment_id, row.owner, row.port_id, row.cargo_type]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(needle)),
    );
  }, [query.data, search]);

  const total = query.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE));

  const reset = () => {
    setTamperClass("");
    setClassification("");
    setMinProbability(0);
    setSearch("");
    setPage(0);
  };

  return (
    <div className="h-full min-h-0 p-3">
      <Panel
        title={`Record ledger — ${num(total)} matching`}
        dense
        className="h-full"
        actions={
          <>
            <input
              className="input w-44"
              placeholder="Search id, container, owner…"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
            <button type="button" className="btn" onClick={reset}>
              Reset
            </button>
          </>
        }
      >
        <div className="h-full min-h-0 flex flex-col">
          {/* ---------------------------------------- filter bar */}
          <div className="shrink-0 flex flex-wrap items-center gap-x-5 gap-y-2 px-3 py-2 border-b border-hairline">
            <label className="flex items-center gap-1.5 text-2xs text-ink-300 cursor-pointer">
              <input
                type="checkbox"
                checked={suspiciousOnly}
                onChange={(event) => {
                  setSuspiciousOnly(event.target.checked);
                  setPage(0);
                }}
                className="accent-signal"
              />
              Suspicious only
            </label>

            <FilterGroup
              label="Class"
              options={TAMPER_CLASSES}
              value={tamperClass}
              onChange={(value) => {
                setTamperClass(value);
                setPage(0);
              }}
            />

            <FilterGroup
              label="Disposition"
              options={CLASSIFICATIONS}
              value={classification}
              onChange={(value) => {
                setClassification(value);
                setPage(0);
              }}
            />

            <label className="flex items-center gap-2 text-2xs text-ink-500">
              <span className="uppercase tracking-[0.1em]">Min P</span>
              <input
                type="range"
                min={0}
                max={1}
                step={0.05}
                value={minProbability}
                onChange={(event) => {
                  setMinProbability(Number(event.target.value));
                  setPage(0);
                }}
                className="w-24 accent-signal"
              />
              <span className="font-mono tnum text-ink-300 w-10">{pct(minProbability, 0)}</span>
            </label>

            <label className="flex items-center gap-1.5 text-2xs text-ink-500">
              <span className="uppercase tracking-[0.1em]">Sort</span>
              <select
                className="input py-0.5"
                value={sort}
                onChange={(event) => setSort(event.target.value as typeof sort)}
              >
                <option value="probability">probability</option>
                <option value="record_id">record id</option>
                <option value="timestamp">timestamp</option>
              </select>
            </label>
          </div>

          {/* ---------------------------------------- table */}
          <div className="flex-1 min-h-0 overflow-auto">
            {query.error ? (
              <ErrorState error={query.error} onRetry={query.reload} />
            ) : query.loading ? (
              <div className="p-4">
                <Spinner label="Loading records…" />
              </div>
            ) : rows.length === 0 ? (
              <Empty
                title="No records match these filters."
                hint="Widen the probability floor or clear the class filters."
              />
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Record</th>
                    <th>Probability</th>
                    <th>Class</th>
                    <th>Disposition</th>
                    <th>Repair</th>
                    <th>Container</th>
                    <th>Owner</th>
                    <th>Cargo</th>
                    <th className="text-right">Weight</th>
                    <th className="text-right">Value</th>
                    <th>Port</th>
                    <th>Event</th>
                    <th>Timestamp</th>
                    <th className="text-right">Findings</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => (
                    <tr
                      key={row.record_id}
                      data-selected={selection.recordId === row.record_id}
                      onClick={() => select(row.record_id, row.container_id, "investigate")}
                    >
                      <td className="font-mono text-xs text-signal whitespace-nowrap">
                        {row.record_id}
                      </td>
                      <td>
                        <ProbabilityCell value={row.tampering_probability} />
                      </td>
                      <td>
                        <TamperBadge value={row.tamper_class} />
                      </td>
                      <td>
                        <ClassificationBadge value={row.classification} />
                      </td>
                      <td className="font-mono tnum text-2xs text-ink-300">
                        {row.repair_confidence === null ? "—" : pct(row.repair_confidence, 0)}
                      </td>
                      <td className="font-mono text-2xs text-ink-300">
                        {row.container_id ?? "—"}
                      </td>
                      <td className="text-2xs text-ink-300 max-w-[150px] truncate">
                        {row.owner ?? "—"}
                      </td>
                      <td className="text-2xs text-ink-500">{row.cargo_type ?? "—"}</td>
                      <td className="font-mono tnum text-2xs text-ink-300 text-right">
                        {kg(row.weight)}
                      </td>
                      <td className="font-mono tnum text-2xs text-ink-300 text-right">
                        {money(row.declared_value)}
                      </td>
                      <td className="font-mono text-2xs text-ink-500">{row.port_id ?? "—"}</td>
                      <td className="text-2xs text-ink-500">{row.event_type ?? "—"}</td>
                      <td className="font-mono text-2xs text-ink-500 whitespace-nowrap">
                        {ts(row.timestamp)}
                      </td>
                      <td className="text-right">
                        <Badge className="border-hairline text-ink-500">
                          {row.evidence_count}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* ---------------------------------------- pager */}
          <div className="shrink-0 flex items-center justify-between px-3 py-2 border-t border-hairline text-2xs text-ink-500">
            <span>
              Showing {num(rows.length)} of {num(total)}
              {search && " (filtered on this page)"}
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                className="btn"
                disabled={page === 0}
                onClick={() => setPage((value) => Math.max(0, value - 1))}
              >
                Previous
              </button>
              <span className="font-mono tnum">
                {page + 1} / {pages}
              </span>
              <button
                type="button"
                className="btn"
                disabled={page + 1 >= pages}
                onClick={() => setPage((value) => value + 1)}
              >
                Next
              </button>
            </div>
          </div>
        </div>
      </Panel>
    </div>
  );
}

function FilterGroup({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: string[];
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-2xs uppercase tracking-[0.1em] text-ink-500">{label}</span>
      <div className="flex gap-1">
        {options.map((option) => (
          <button
            key={option}
            type="button"
            className={`btn ${value === option ? "btn-active" : ""}`}
            onClick={() => onChange(value === option ? "" : option)}
          >
            {option.replace("_", " ")}
          </button>
        ))}
      </div>
    </div>
  );
}

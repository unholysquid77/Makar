/** Shared UI atoms.
 *
 * Kept small and unopinionated. The panels do the composing; these just
 * enforce the surface treatment and the one-ramp colour rule so a dense
 * screen stays coherent.
 */

import type { ReactNode } from "react";

import { CLASSIFICATION_COLOUR, TAMPER_COLOUR, pct, severityColour } from "../lib/format";
import type { Classification, TamperClass } from "../lib/types";

// ---------------------------------------------------------------- surfaces

export function Panel({
  title,
  actions,
  children,
  className = "",
  bodyClassName = "",
  dense = false,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  dense?: boolean;
}) {
  return (
    <section className={`panel flex flex-col min-h-0 ${className}`}>
      {(title || actions) && (
        <header className="panel-header shrink-0">
          <h2 className="panel-title truncate">{title}</h2>
          {actions && <div className="flex items-center gap-1.5 shrink-0">{actions}</div>}
        </header>
      )}
      <div
        className={`min-h-0 flex-1 ${dense ? "" : "p-3"} ${bodyClassName}`}
      >
        {children}
      </div>
    </section>
  );
}

// ---------------------------------------------------------------- metrics

export function Metric({
  label,
  value,
  sub,
  accent,
  emphasis = false,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  accent?: string;
  emphasis?: boolean;
}) {
  return (
    <div className="px-3.5 py-2.5 min-w-0">
      <div
        className={`font-mono tnum leading-none ${emphasis ? "text-[1.75rem]" : "text-xl"}`}
        style={accent ? { color: accent } : undefined}
      >
        {value}
      </div>
      <div className="mt-1.5 text-2xs uppercase tracking-[0.13em] text-ink-500 truncate">
        {label}
      </div>
      {sub && <div className="mt-0.5 text-2xs text-ink-700 truncate">{sub}</div>}
    </div>
  );
}

/** A thin horizontal data line. Severity, share, confidence — all use this. */
export function DatumLine({
  value,
  colour,
  className = "",
}: {
  value: number;
  colour?: string;
  className?: string;
}) {
  const clamped = Math.max(0, Math.min(1, value));
  return (
    <div className={`datum-line ${className}`}>
      <div
        className="h-full rounded-full transition-[width] duration-120"
        style={{ width: `${clamped * 100}%`, background: colour ?? severityColour(clamped) }}
      />
    </div>
  );
}

/** Probability with its own line underneath — the standard risk cell. */
export function ProbabilityCell({ value }: { value: number }) {
  return (
    <div className="w-[76px]">
      <div className="font-mono tnum text-xs" style={{ color: severityColour(value) }}>
        {pct(value)}
      </div>
      <DatumLine value={value} className="mt-1" />
    </div>
  );
}

// ---------------------------------------------------------------- badges

export function Badge({
  children,
  colour,
  title,
  className = "",
}: {
  children: ReactNode;
  colour?: string;
  title?: string;
  className?: string;
}) {
  return (
    <span
      title={title}
      className={`inline-flex items-center px-1.5 py-[2px] rounded-xs text-2xs font-medium
                  border whitespace-nowrap ${className}`}
      style={
        colour
          ? { color: colour, borderColor: `${colour}55`, background: `${colour}14` }
          : undefined
      }
    >
      {children}
    </span>
  );
}

export function TamperBadge({ value }: { value: TamperClass }) {
  return (
    <Badge colour={TAMPER_COLOUR[value]} title={`Tampering class: ${value}`}>
      {value}
    </Badge>
  );
}

export function ClassificationBadge({ value }: { value: Classification | null }) {
  if (!value) return <span className="text-ink-700">—</span>;
  return (
    <Badge colour={CLASSIFICATION_COLOUR[value]} title={`Disposition: ${value}`}>
      {value}
    </Badge>
  );
}

// ---------------------------------------------------------------- states

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-2xs text-ink-500">
      <span className="inline-block w-3 h-3 border border-hairline-strong border-t-signal rounded-full animate-spin" />
      {label ?? "Working…"}
    </div>
  );
}

export function Centered({ children }: { children: ReactNode }) {
  return (
    <div className="h-full w-full flex items-center justify-center p-6 text-center">
      {children}
    </div>
  );
}

export function Empty({ title, hint }: { title: string; hint?: ReactNode }) {
  return (
    <Centered>
      <div className="max-w-sm">
        <div className="text-sm text-ink-300">{title}</div>
        {hint && <div className="mt-1.5 text-2xs text-ink-500 leading-relaxed">{hint}</div>}
      </div>
    </Centered>
  );
}

export function ErrorState({
  error,
  onRetry,
}: {
  error: { message: string; hint?: string };
  onRetry?: () => void;
}) {
  return (
    <Centered>
      <div className="max-w-md">
        <div className="text-2xs uppercase tracking-[0.14em] text-anomaly-critical">
          Error
        </div>
        <div className="mt-2 text-sm text-ink-100">{error.message}</div>
        {error.hint && (
          <code className="mt-3 block text-2xs text-ink-300 bg-obsidian-850 border border-hairline rounded-xs px-2.5 py-2 text-left">
            {error.hint}
          </code>
        )}
        {onRetry && (
          <button type="button" className="btn mt-3" onClick={onRetry}>
            Retry
          </button>
        )}
      </div>
    </Centered>
  );
}

// ---------------------------------------------------------------- layout

export function KeyValue({
  rows,
  columns = 2,
}: {
  rows: Array<[string, ReactNode]>;
  columns?: number;
}) {
  return (
    <dl
      className="grid gap-x-5 gap-y-1.5 text-xs"
      style={{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }}
    >
      {rows.map(([key, value]) => (
        <div key={key} className="min-w-0 flex items-baseline justify-between gap-3">
          <dt className="text-2xs uppercase tracking-[0.1em] text-ink-500 shrink-0">{key}</dt>
          <dd className="font-mono tnum text-ink-100 truncate text-right">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <div className="text-2xs font-semibold uppercase tracking-[0.14em] text-ink-500 mb-2">
      {children}
    </div>
  );
}

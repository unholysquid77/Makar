/**
 * The evidence breakdown (spec 17).
 *
 *     94.2% TAMPERING PROBABILITY
 *     +23  Impossible route transition
 *     +19  Temporal contradiction
 *     ...
 *     -05  Benign formatting anomaly
 *
 * The points are signed log-odds rescaled, so the lines genuinely sum toward
 * the stated probability rather than being a decorative ranking. Negative
 * lines are real: FORMAT evidence argues *against* deliberate tampering, and
 * showing that is the clearest way to make "not every oddity is an attack"
 * visible in the interface.
 */

import { DatumLine, SectionLabel } from "./primitives";
import { LAYER_COLOUR, pct, severityColour } from "../lib/format";
import type { Contribution, EvidenceType, Verdict } from "../lib/types";

export function EvidenceBreakdown({
  verdict,
  compact = false,
}: {
  verdict: Verdict;
  compact?: boolean;
}) {
  const contributions = verdict.contributions;
  const maxMagnitude = Math.max(1, ...contributions.map((c) => Math.abs(c.points)));

  return (
    <div className="space-y-3">
      {!compact && (
        <div className="flex items-baseline gap-2.5">
          <div
            className="font-mono tnum text-3xl leading-none"
            style={{ color: severityColour(verdict.tampering_probability) }}
          >
            {pct(verdict.tampering_probability)}
          </div>
          <div className="text-2xs uppercase tracking-[0.14em] text-ink-500 pb-0.5">
            tampering probability
          </div>
        </div>
      )}

      <div>
        {!compact && <SectionLabel>Evidence contribution</SectionLabel>}
        {contributions.length === 0 ? (
          <div className="text-2xs text-ink-700">No evidence was raised.</div>
        ) : (
          <ul className="space-y-1">
            {contributions.map((c) => (
              <ContributionRow key={`${c.type}-${c.code}`} c={c} scale={maxMagnitude} />
            ))}
          </ul>
        )}
      </div>

      {!compact && Object.keys(verdict.type_scores).length > 0 && (
        <div>
          <SectionLabel>Per-layer score</SectionLabel>
          <div className="grid grid-cols-2 gap-x-5 gap-y-1">
            {Object.entries(verdict.type_scores)
              .sort((a, b) => (b[1] ?? 0) - (a[1] ?? 0))
              .map(([layer, score]) => (
                <div key={layer} className="flex items-center gap-2 min-w-0">
                  <span
                    className="w-1.5 h-1.5 rounded-full shrink-0"
                    style={{ background: LAYER_COLOUR[layer as EvidenceType] }}
                  />
                  <span className="text-2xs text-ink-300 truncate flex-1">{layer}</span>
                  <span className="font-mono tnum text-2xs text-ink-100">
                    {(score ?? 0).toFixed(2)}
                  </span>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ContributionRow({ c, scale }: { c: Contribution; scale: number }) {
  const negative = c.points < 0;
  const colour = negative ? "#2fa36b" : LAYER_COLOUR[c.type];
  const magnitude = Math.abs(c.points) / scale;

  return (
    <li className="flex items-center gap-2.5 group" title={`${c.code} · severity ${c.severity.toFixed(2)}`}>
      <span
        className="font-mono tnum text-xs w-9 text-right shrink-0"
        style={{ color: colour }}
      >
        {negative ? "" : "+"}
        {String(Math.abs(c.points)).padStart(2, "0")}
      </span>
      <span className="flex-1 min-w-0">
        <span className="flex items-baseline gap-2">
          <span className="text-xs text-ink-100 truncate">{c.label}</span>
          <span className="text-2xs text-ink-700 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity duration-120">
            {c.type}
          </span>
        </span>
        <DatumLine value={magnitude} colour={colour} className="mt-1" />
      </span>
    </li>
  );
}

/** The negative-weight note, shown where benign evidence appears. */
export function BenignNote() {
  return (
    <p className="text-2xs text-ink-500 leading-relaxed">
      Green lines are <span className="text-verified">exculpatory</span>: formatting
      and data-quality findings carry a negative weight, so a messy record is scored
      as <em>less</em> likely to have been deliberately edited. Not every oddity is an
      attack.
    </p>
  );
}

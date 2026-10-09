/**
 * Makar design tokens (spec 27.1 / 40).
 *
 * OBSIDIAN · FORENSIC · MARITIME · GRAPH-DRIVEN · DATA-DENSE · PRECISE
 *
 * The palette is built on one rule: colour means *state*, never decoration.
 * Neutrals carry all structure, so the only saturated pixels on screen are
 * carrying forensic meaning — anomaly severity, classification, node health.
 * That is what lets a dense screen stay readable.
 */

/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // --- obsidian foundation ---
        obsidian: {
          950: "#06080b", // page
          900: "#0a0d12", // panel
          850: "#0e1218", // raised panel
          800: "#131922", // control
          700: "#1b2230", // hover
          600: "#232c3c", // active
        },
        // --- hairlines ---
        hairline: {
          DEFAULT: "rgba(255,255,255,0.07)",
          strong: "rgba(255,255,255,0.13)",
          faint: "rgba(255,255,255,0.035)",
        },
        // --- typography ---
        ink: {
          50: "#f2f5f9", // headline
          100: "#e4e9f1", // body
          300: "#a6b1c2", // secondary
          500: "#6f7d91", // muted
          700: "#454f5e", // disabled
        },
        // --- anomaly: amber -> red, severity rising ---
        anomaly: {
          low: "#d9a21b",
          mid: "#e8821f",
          high: "#e5563d",
          critical: "#e5484d",
        },
        // --- cold neutral informational accents ---
        signal: {
          DEFAULT: "#4cc2ff",
          deep: "#2b8fd4",
          indigo: "#7c8cff",
        },
        // --- confirmed / healthy ---
        verified: {
          DEFAULT: "#2fa36b",
          deep: "#1d7a4e",
        },
        // --- classification semantics ---
        klass: {
          original: "#5f6b7d",
          repaired: "#4cc2ff",
          removed: "#e5563d",
          unrecoverable: "#d9a21b",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["IBM Plex Mono", "ui-monospace", "monospace"],
      },
      fontSize: {
        // Dense scale: a forensic console shows more rows, not bigger text.
        "2xs": ["0.6875rem", { lineHeight: "1rem", letterSpacing: "0.01em" }],
        xs: ["0.75rem", { lineHeight: "1.125rem" }],
        sm: ["0.8125rem", { lineHeight: "1.25rem" }],
      },
      spacing: { px2: "2px", 4.5: "1.125rem" },
      borderRadius: { xs: "3px", DEFAULT: "5px" },
      boxShadow: {
        // Minimal glass: one soft lift, never a drop shadow stack.
        panel: "0 1px 0 0 rgba(255,255,255,0.04) inset, 0 8px 24px -16px rgba(0,0,0,0.9)",
        focus: "0 0 0 1px rgba(76,194,255,0.55)",
      },
      backgroundImage: {
        // Subtle topology texture (spec 27.1), as a hairline grid.
        grid: `linear-gradient(to right, rgba(255,255,255,0.028) 1px, transparent 1px),
               linear-gradient(to bottom, rgba(255,255,255,0.028) 1px, transparent 1px)`,
        "grid-fine": `linear-gradient(to right, rgba(255,255,255,0.02) 1px, transparent 1px),
               linear-gradient(to bottom, rgba(255,255,255,0.02) 1px, transparent 1px)`,
      },
      backgroundSize: { grid: "32px 32px", "grid-fine": "8px 8px" },
      transitionDuration: { 120: "120ms" },
    },
  },
  plugins: [],
};

// ─── Shared Typography Constants ─────────────────────────────────────
// Single source of truth for recurring text patterns used across the
// dashboard.  Import as `T` and compose with `cn()` when you need to
// append contextual colours or overrides.
//
//   import { T } from "@/lib/typography";
//   <h2 className={T.pageTitle}>…</h2>
//   <span className={cn(T.statValue, "text-cyan-400")}>…</span>

export const T = {
  // ── Page-level ────────────────────────────────────────────────────
  pageTitle: "text-lg font-semibold",
  pageDescription: "text-sm text-muted-foreground",

  // ── Cards ─────────────────────────────────────────────────────────
  cardTitle: "text-sm",

  // ── Section headings ──────────────────────────────────────────────
  sectionHeading: "text-sm font-semibold",
  sectionLabel:
    "text-xs font-medium uppercase tracking-wider text-muted-foreground",

  // ── Stat values & labels ──────────────────────────────────────────
  statValue: "text-2xl font-bold tabular-nums",
  statValueSm: "text-xl font-bold tabular-nums",
  statLabel: "text-xs text-muted-foreground",
  statLabelUpper:
    "text-xs font-medium uppercase tracking-wider text-muted-foreground",

  // ── Form labels ───────────────────────────────────────────────────
  formLabel: "text-xs uppercase tracking-wider text-muted-foreground",

  // ── Inline badges ─────────────────────────────────────────────────
  badgeMono: "text-xs px-1.5 py-0 font-mono",

  // ── Table cells ───────────────────────────────────────────────────
  tableCell: "text-xs",
  tableCellMono: "text-xs font-mono",
  tableCellNumeric: "text-xs font-mono tabular-nums text-right",
  tableRowName: "text-xs font-medium",

  // ── Muted helpers ─────────────────────────────────────────────────
  muted: "text-xs text-muted-foreground",
  mutedSm: "text-sm text-muted-foreground",

  // ── Chart font sizes (px) ────────────────────────────────────────
  chartAxisTick: 10,
  chartAxisTitle: 11,
  chartLabel: 11,
  chartLabelSm: 10,
} as const;

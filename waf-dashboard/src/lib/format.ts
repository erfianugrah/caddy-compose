// ─── Shared formatting helpers ──────────────────────────────────────
// Extracted from OverviewDashboard, EventsTable, AnalyticsDashboard,
// and BlocklistPanel to eliminate duplication.

/** Abbreviate large numbers: 1234 → "1.2K", 1234567 → "1.2M". */
export function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

/** Format with locale commas: 12345 → "12,345". */
export function formatNumberLocale(n: number): string {
  return n.toLocaleString();
}

/** "14:32:07" — 24-hour time with seconds. */
export function formatTime(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return ts;
  }
}

/** "Feb 25" — short month + day. */
export function formatDate(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
  } catch {
    return "";
  }
}

/** "Feb 25, 14:32" — date + time without seconds. */
export function formatDateTime(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    });
  } catch {
    return ts;
  }
}

/** Convert ISO 3166-1 alpha-2 code to regional indicator flag emoji. */
export function countryFlag(code: string): string {
  if (!code || code.length !== 2) return "";
  const upper = code.toUpperCase();
  return String.fromCodePoint(
    0x1f1e6 + upper.charCodeAt(0) - 65,
    0x1f1e6 + upper.charCodeAt(1) - 65,
  );
}

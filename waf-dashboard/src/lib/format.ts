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
export function formatTime(ts: string | null | undefined): string {
  if (!ts) return "—";
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return "—";
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
export function formatDate(ts: string | null | undefined): string {
  if (!ts) return "";
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return "";
    return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
  } catch {
    return "";
  }
}

/** "Feb 25, 14:32" — date + time without seconds. */
export function formatDateTime(ts: string | null | undefined): string {
  if (!ts) return "—";
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return "—";
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

/**
 * Format a Go time.Duration string ("72h3m10s") into a human-friendly form.
 * Output examples: "3d 0h", "14h 23m", "45m 12s", "12s"
 */
export function formatUptime(dur: string): string {
  const re = /(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?/;
  const m = dur.match(re);
  if (!m) return dur;
  let hours = parseInt(m[1] || "0", 10);
  const mins = parseInt(m[2] || "0", 10);
  const secs = parseInt(m[3] || "0", 10);
  if (hours >= 24) {
    const days = Math.floor(hours / 24);
    hours = hours % 24;
    return `${days}d ${hours}h`;
  }
  if (hours > 0) return `${hours}h ${mins}m`;
  if (mins > 0) return `${mins}m ${secs}s`;
  return `${secs}s`;
}

/** Validate a duration window string like "3m", "45s", "2h". */
export function isValidWindow(s: string): boolean {
  return /^\d+[smh]$/.test(s.trim().toLowerCase());
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

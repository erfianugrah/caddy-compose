import { ACTION_COLORS, ACTION_LABELS, CHART_TOOLTIP_STYLE } from "@/lib/utils";
import { T } from "@/lib/typography";
import type { WAFEvent } from "@/lib/api";

// ─── Formatters ─────────────────────────────────────────────────────

export function formatHourTick(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return ts;
  }
}

export function formatTooltipLabel(ts: string): string {
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

// ─── Chart helpers ──────────────────────────────────────────────────

/** Custom Y-axis tick renderer that wraps the label in a clickable link. */
export function LinkTickRenderer({
  x,
  y,
  payload,
  buildHref,
}: {
  x: number;
  y: number;
  payload: { value: string };
  buildHref: (value: string) => string;
}) {
  return (
    <a href={buildHref(payload.value)}>
      <text
        x={x}
        y={y}
        dy={4}
        textAnchor="end"
        fill="#bdbdc1"
        fontSize={T.chartLabel}
        className="hover:fill-lv-green cursor-pointer"
        style={{ textDecoration: "none" }}
      >
        {payload.value}
      </text>
    </a>
  );
}

export const chartTooltipStyle = CHART_TOOLTIP_STYLE;

export const DONUT_COLOR_MAP: Record<string, string> = {
  [ACTION_LABELS.total_blocked]: ACTION_COLORS.total_blocked,
  [ACTION_LABELS.logged]:        ACTION_COLORS.logged,
  [ACTION_LABELS.rate_limited]:  ACTION_COLORS.rate_limited,
  [ACTION_LABELS.policy_block]:  ACTION_COLORS.policy_block,
  [ACTION_LABELS.detect_block]:  ACTION_COLORS.detect_block,
  [ACTION_LABELS.policy_allow]:  ACTION_COLORS.policy_allow,
  [ACTION_LABELS.policy_skip]:   ACTION_COLORS.policy_skip,
  [ACTION_LABELS.ddos_blocked]:  ACTION_COLORS.ddos_blocked,
};

// ─── Event link builder ─────────────────────────────────────────────

/** Build a deep-link URL that opens the Events tab with a narrow time window
 *  centered on the event and comprehensive filters to find the exact row. */
export function buildViewInEventsHref(evt: WAFEvent): string {
  const ts = new Date(evt.timestamp);
  const start = new Date(ts.getTime() - 5 * 60_000).toISOString();
  const end = new Date(ts.getTime() + 5 * 60_000).toISOString();
  const params = new URLSearchParams();
  params.set("event_id", evt.id);
  params.set("start", start);
  params.set("end", end);
  if (evt.service) params.set("service", evt.service);
  if (evt.event_type) params.set("type", evt.event_type);
  if (evt.client_ip) params.set("ip", evt.client_ip);
  if (evt.method) params.set("method", evt.method);
  if (evt.rule_id) params.set("rule_id", String(evt.rule_id));
  return `/events?${params.toString()}`;
}

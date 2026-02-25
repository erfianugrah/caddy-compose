import { Badge } from "@/components/ui/badge";
import { ACTION_BADGE_CLASSES } from "@/lib/utils";

// ─── Event type → display label mapping ─────────────────────────────
const EVENT_TYPE_LABELS: Record<string, string> = {
  honeypot: "HONEYPOT",
  scanner: "SCANNER",
  ipsum_blocked: "IPSUM",
  rate_limited: "RATE LIMITED",
  policy_skip: "SKIPPED",
  policy_allow: "ALLOWED",
  policy_block: "POLICY BLOCK",
  blocked: "CRS BLOCKED",
  logged: "LOGGED",
};

interface EventTypeBadgeProps {
  /** The event_type string from the WAF event. */
  eventType: string;
  /** Fallback: if true and eventType isn't "blocked", still show BLOCKED. */
  blocked?: boolean;
}

/**
 * Renders a colored badge for a WAF event type.
 * Replaces the identical if/else chains that were duplicated in
 * OverviewDashboard, AnalyticsDashboard, and EventsTable.
 */
export function EventTypeBadge({ eventType, blocked }: EventTypeBadgeProps) {
  // Resolve the key: use event_type directly, fallback to "blocked" if
  // the boolean flag is set, otherwise "logged".
  let key = eventType;
  if (!EVENT_TYPE_LABELS[key]) {
    key = blocked ? "blocked" : "logged";
  }

  const label = EVENT_TYPE_LABELS[key] ?? "LOGGED";
  const classes = ACTION_BADGE_CLASSES[key] ?? ACTION_BADGE_CLASSES.logged;

  return (
    <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${classes}`}>
      {label}
    </Badge>
  );
}

import { Badge } from "@/components/ui/badge";
import { ACTION_BADGE_CLASSES } from "@/lib/utils";

// ─── Event type → display label mapping ─────────────────────────────
const EVENT_TYPE_LABELS: Record<string, string> = {
  rate_limited: "RATE LIMITED",
  policy_skip: "SKIPPED",
  policy_allow: "ALLOWED",
  policy_block: "POLICY BLOCK",
  detect_block: "CRS BLOCKED",
  logged: "LOGGED",
};

interface EventTypeBadgeProps {
  /** The event_type string from the WAF event. */
  eventType: string;
  /** Fallback: if true and eventType isn't recognized, show BLOCKED. */
  blocked?: boolean;
}

/**
 * Renders a colored badge for a WAF event type.
 * Replaces the identical if/else chains that were duplicated in
 * OverviewDashboard, AnalyticsDashboard, and EventsTable.
 */
export function EventTypeBadge({ eventType, blocked }: EventTypeBadgeProps) {
  // Resolve the key: use event_type directly, fallback to "detect_block" if
  // the boolean flag is set, otherwise "logged".
  let key = eventType;
  if (!EVENT_TYPE_LABELS[key]) {
    key = blocked ? "detect_block" : "logged";
  }

  const label = EVENT_TYPE_LABELS[key] ?? "LOGGED";
  const classes = ACTION_BADGE_CLASSES[key] ?? ACTION_BADGE_CLASSES.logged;

  return (
    <Badge variant="outline" className={`text-xs px-1.5 py-0 ${classes}`}>
      {label}
    </Badge>
  );
}

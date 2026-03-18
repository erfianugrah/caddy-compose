import { Badge } from "@/components/ui/badge";
import { ACTION_LABELS, ACTION_BADGE_CLASSES } from "@/lib/utils";

interface EventTypeBadgeProps {
  /** The event_type string from the WAF event. */
  eventType: string;
  /** Fallback: if true and eventType isn't recognized, show BLOCKED. */
  blocked?: boolean;
}

/**
 * Renders a colored badge for a WAF event type.
 * Labels derived from the canonical ACTION_LABELS map in utils.ts;
 * rendered in uppercase via CSS to keep the single source of truth.
 */
export function EventTypeBadge({ eventType, blocked }: EventTypeBadgeProps) {
  // Resolve the key: use event_type directly, fallback to "detect_block" if
  // the boolean flag is set, otherwise "logged".
  let key = eventType;
  if (!ACTION_LABELS[key]) {
    key = blocked ? "detect_block" : "logged";
  }

  const label = ACTION_LABELS[key] ?? ACTION_LABELS.logged;
  const classes = ACTION_BADGE_CLASSES[key] ?? ACTION_BADGE_CLASSES.logged;

  return (
    <Badge variant="outline" className={`text-xs px-1.5 py-0 uppercase ${classes}`}>
      {label}
    </Badge>
  );
}

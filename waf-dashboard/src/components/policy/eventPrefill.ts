import type { WAFEvent, Condition, ConditionOperator } from "@/lib/api";

// ─── Event Prefill ──────────────────────────────────────────────────

export interface EventPrefill {
  action: "allow" | "block" | "detect";
  name: string;
  description: string;
  ruleIds: string;        // Space-separated rule IDs
  conditions: Condition[];
  sourceEvent: WAFEvent;
}

/** Extract prefill data from a WAF event for the Quick Actions form.
 *  Populates ALL available conditions from the event JSON so the user
 *  can remove the ones they don't need via the "X" buttons. */
export function extractPrefillFromEvent(event: WAFEvent): EventPrefill {
  // Collect rule IDs from matched_rules, or fall back to primary rule_id.
  // Prefer the string `name` field (e.g., "920350") over numeric `id` (which
  // is 0 for legacy PE events). Strip any "PE-" prefix for clean display.
  const ruleIds: string[] = [];
  if (event.matched_rules && event.matched_rules.length > 0) {
    for (const r of event.matched_rules) {
      const rid = r.name
        ? r.name.replace(/^PE-/, "")
        : r.id ? String(r.id) : "";
      if (rid && rid !== "0" && !ruleIds.includes(rid)) {
        ruleIds.push(rid);
      }
    }
  } else if (event.rule_id) {
    ruleIds.push(String(event.rule_id));
  }

  // Build conditions from ALL available event context.
  // The user can remove unwanted conditions via the "X" button.
  const conditions: Condition[] = [];

  // Path condition — use the path without query string
  if (event.uri) {
    const path = event.uri.split("?")[0];
    // Use begins_with for paths that look like prefixes (e.g., /socket.io/)
    // Use eq for exact paths
    const op: ConditionOperator = path.endsWith("/") ? "begins_with" : "eq";
    conditions.push({ field: "path", operator: op, value: path });
  }

  // Host / service condition — this is the hostname the request was sent to
  if (event.service) {
    conditions.push({ field: "host", operator: "eq", value: event.service });
  }

  // Method condition
  if (event.method) {
    conditions.push({ field: "method", operator: "eq", value: event.method });
  }

  // IP condition
  if (event.client_ip) {
    conditions.push({ field: "ip", operator: "eq", value: event.client_ip });
  }

  // User agent condition
  if (event.user_agent) {
    conditions.push({ field: "user_agent", operator: "contains", value: event.user_agent });
  }

  // Country condition (GeoIP via Cf-Ipcountry header)
  if (event.country) {
    conditions.push({ field: "country", operator: "eq", value: event.country });
  }

  // Smart action default:
  // - If the event was a block (policy_block, detect_block, blocked), the user
  //   likely wants to CREATE AN ALLOW exception (the block was a false positive).
  // - If the event was a skip (policy_skip), keep detect as default.
  // - Otherwise default to block (the event was logged but should be blocked).
  const isBlockEvent = event.event_type === "policy_block"
    || event.event_type === "detect_block"
    || event.blocked;
  const isSkipEvent = event.event_type === "policy_skip";
  const action: "allow" | "block" | "detect" = isBlockEvent ? "allow" : isSkipEvent ? "detect" : "block";

  // Action label for the auto-generated name
  const actionLabel = action === "allow" ? "Allow" : action === "detect" ? "Detect" : "Block";

  // Auto-generate name — handle missing rule IDs gracefully for policy events
  const ruleSnippet = ruleIds.length > 0
    ? ruleIds.slice(0, 3).join(", ") + (ruleIds.length > 3 ? "..." : "")
    : "";
  const pathSnippet = event.uri ? event.uri.split("?")[0] : "";
  const serviceSnippet = event.service ? `on ${event.service}` : "";
  // For policy events without rule IDs, use the rule_msg as context
  const contextSnippet = !ruleSnippet && event.rule_msg
    ? event.rule_msg.replace(/^(Policy Block|Rate Limited|Detected):\s*/i, "")
    : ruleSnippet;
  const name = [actionLabel, contextSnippet, "for", pathSnippet, serviceSnippet]
    .filter(Boolean)
    .join(" ")
    .replace(/\s+/g, " ")
    .trim();

  // Description from the primary rule message
  const description = event.rule_msg
    ? `Auto-created from event: ${event.rule_msg}`
    : `Auto-created from event ${event.id}`;

  return {
    action,
    name,
    description,
    ruleIds: ruleIds.join(" "),
    conditions,
    sourceEvent: event,
  };
}

/** Read and consume a prefill event from sessionStorage (if present). */
export function consumePrefillEvent(): EventPrefill | null {
  if (typeof window === "undefined") return null;

  const params = new URLSearchParams(window.location.search);
  if (!params.has("from_event")) return null;

  const raw = sessionStorage.getItem("waf:prefill-event");
  if (!raw) return null;

  try {
    const event = JSON.parse(raw) as WAFEvent;
    sessionStorage.removeItem("waf:prefill-event");
    // Clean up URL param without reload
    const url = new URL(window.location.href);
    url.searchParams.delete("from_event");
    window.history.replaceState({}, "", url.pathname + url.search);
    return extractPrefillFromEvent(event);
  } catch {
    return null;
  }
}

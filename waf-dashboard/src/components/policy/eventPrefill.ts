import type { WAFEvent, Condition, ConditionOperator } from "@/lib/api";

// ─── Event Prefill ──────────────────────────────────────────────────

export interface EventPrefill {
  action: "allow" | "block" | "skip_rule";
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
  // Collect rule IDs from matched_rules, or fall back to primary rule_id
  const ruleIds: string[] = [];
  if (event.matched_rules && event.matched_rules.length > 0) {
    for (const r of event.matched_rules) {
      if (r.id && !ruleIds.includes(String(r.id))) {
        ruleIds.push(String(r.id));
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

  // Auto-generate name
  const ruleSnippet = ruleIds.length > 0
    ? ruleIds.slice(0, 3).join(", ") + (ruleIds.length > 3 ? "..." : "")
    : "";
  const pathSnippet = event.uri ? event.uri.split("?")[0] : "";
  const serviceSnippet = event.service ? `on ${event.service}` : "";
  const name = ["Skip", ruleSnippet, "for", pathSnippet, serviceSnippet].filter(Boolean).join(" ");

  // Description from the primary rule message
  const description = event.rule_msg
    ? `Auto-created from event: ${event.rule_msg}`
    : `Auto-created from event ${event.id}`;

  return {
    action: "skip_rule",
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

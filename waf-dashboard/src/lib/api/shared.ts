export const API_BASE = "/api";

// ─── HTTP Helpers ───────────────────────────────────────────────────

/** Strip HTML tags and collapse whitespace for error display. */
function sanitizeErrorBody(raw: string, maxLen = 500): string {
  // Strip tags, decode common entities, collapse whitespace
  const text = raw
    .replace(/<[^>]*>/g, " ")
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/\s+/g, " ")
    .trim();
  if (!text) return "";
  return text.length > maxLen ? text.slice(0, maxLen) + "…" : text;
}

export async function fetchJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  if (!res.ok) {
    const raw = await res.text().catch(() => "");
    const detail = sanitizeErrorBody(raw);
    throw new Error(`API error: ${res.status} ${res.statusText}${detail ? ` — ${detail}` : ""}`);
  }
  // 204 No Content — used by DELETE endpoints. Callers expecting void
  // discard the return value; callers expecting data never get 204.
  if (res.status === 204) return undefined as unknown as T;
  return res.json();
}

export async function postJSON<T>(url: string, body: unknown): Promise<T> {
  return fetchJSON<T>(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function putJSON<T>(url: string, body: unknown): Promise<T> {
  return fetchJSON<T>(url, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function deleteJSON<T>(url: string): Promise<T> {
  return fetchJSON<T>(url, { method: "DELETE" });
}

// ─── Shared Types ───────────────────────────────────────────────────

export type FilterOp = "eq" | "neq" | "contains" | "in" | "regex";

export interface TimeRangeParams {
  hours?: number;
  start?: string; // ISO 8601
  end?: string;   // ISO 8601
}

export interface SummaryParams extends FilterableParams {}

/** Minimal shape for applyFilterParams — accepts SummaryParams, EventsParams, or any superset. */
export interface FilterableParams extends TimeRangeParams {
  service?: string;
  service_op?: FilterOp;
  client?: string;
  client_op?: FilterOp;
  method?: string;
  method_op?: FilterOp;
  event_type?: string | null;
  event_type_op?: FilterOp;
  rule_name?: string;
  rule_name_op?: FilterOp;
  uri?: string;
  uri_op?: FilterOp;
  status_code?: string;
  status_code_op?: FilterOp;
  country?: string;
  country_op?: FilterOp;
  request_id?: string;
  request_id_op?: FilterOp;
  tag?: string;
  tag_op?: FilterOp;
  blocked_by?: string;
  blocked_by_op?: FilterOp;
}

/** Apply shared filter and time-range params to URLSearchParams. */
export function applyFilterParams(sp: URLSearchParams, params?: FilterableParams): void {
  if (!params) return;
  if (params.start && params.end) {
    sp.set("start", params.start);
    sp.set("end", params.end);
  } else if (params.hours) {
    sp.set("hours", String(params.hours));
  }
  const filters: [string, string | undefined, FilterOp | undefined][] = [
    ["service", params.service, params.service_op],
    ["client", params.client, params.client_op],
    ["method", params.method, params.method_op],
    ["event_type", params.event_type ?? undefined, params.event_type_op],
    ["rule_name", params.rule_name, params.rule_name_op],
    ["uri", params.uri, params.uri_op],
    ["status_code", params.status_code, params.status_code_op],
    ["country", params.country, params.country_op],
    ["request_id", params.request_id, params.request_id_op],
    ["tag", params.tag, params.tag_op],
    ["blocked_by", params.blocked_by, params.blocked_by_op],
  ];
  for (const [field, value, op] of filters) {
    if (value) sp.set(field, value);
    if (op && op !== "eq") sp.set(`${field}_op`, op);
  }
}

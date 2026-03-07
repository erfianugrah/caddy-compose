import { API_BASE, fetchJSON, applyFilterParams } from "./shared";
import type { FilterOp, FilterableParams } from "./shared";

// ─── Summary / Overview ─────────────────────────────────────────────

export interface SummaryData {
  total_events: number;
  blocked: number;
  logged: number;
  rate_limited: number;
  ipsum_blocked: number;
  policy_events: number;
  honeypot_events: number;
  scanner_events: number;
  unique_clients: number;
  unique_services: number;
  timeline: TimelinePoint[];
  top_services: ServiceStat[];
  top_clients: ClientStat[];
  top_countries: CountryCount[];
  recent_events: WAFEvent[];
  service_breakdown: ServiceBreakdown[];
}

export interface TimelinePoint {
  hour: string;
  total: number;
  blocked: number;
  logged: number;
  rate_limited: number;
  ipsum_blocked: number;
  honeypot: number;
  scanner: number;
  policy: number;
}

export interface ServiceStat {
  service: string;
  total: number;
  blocked: number;
  logged: number;
  rate_limited: number;
  ipsum_blocked: number;
  honeypot: number;
  scanner: number;
  policy: number;
  block_rate: number;
}

export interface ClientStat {
  client_ip: string;
  country?: string;
  total: number;
  blocked: number;
  rate_limited: number;
  ipsum_blocked: number;
  honeypot: number;
  scanner: number;
  policy: number;
}

export interface ServiceBreakdown {
  service: string;
  total: number;
  blocked: number;
  logged: number;
  rate_limited: number;
  ipsum_blocked: number;
  honeypot: number;
  scanner: number;
  policy: number;
}

// ─── Events ─────────────────────────────────────────────────────────

export type EventType = "blocked" | "logged" | "rate_limited" | "ipsum_blocked" | "policy_skip" | "policy_allow" | "policy_block" | "honeypot" | "scanner";

export interface WAFEvent {
  id: string;
  timestamp: string;
  service: string;
  method: string;
  uri: string;
  client_ip: string;
  country?: string;
  status: number;
  blocked: boolean;
  event_type: EventType;
  rule_id: number;
  rule_msg: string;
  severity: number;
  anomaly_score: number;
  outbound_anomaly_score: number;
  blocked_by?: "anomaly_inbound" | "anomaly_outbound" | "direct";
  matched_data?: string;
  rule_tags?: string[];
  user_agent?: string;
  // All matched rules (not just primary)
  matched_rules?: MatchedRuleInfo[];
  // Request context for full payload inspection
  request_headers?: Record<string, string[]>;
  request_body?: string;
  request_args?: Record<string, string>;
}

export interface MatchedRuleInfo {
  id: number;
  msg: string;
  severity: number;
  matched_data?: string;
  file?: string;
  tags?: string[];
}

export interface EventsResponse {
  events: WAFEvent[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

export interface EventsParams extends FilterableParams {
  id?: string;        // Lookup a single event by ID (fast path)
  page?: number;
  per_page?: number;
  blocked?: boolean | null;
  event_type?: EventType | null;
  search?: string;
}

// ─── Services ───────────────────────────────────────────────────────

export interface ServiceDetail {
  service: string;
  total_events: number;
  blocked: number;
  logged: number;
  rate_limited: number;
  ipsum_blocked: number;
  honeypot: number;
  scanner: number;
  policy: number;
  block_rate: number;
  top_uris: { uri: string; count: number; blocked: number }[];
  top_rules: { rule_id: string; rule_msg: string; count: number }[];
}

// ─── CountryCount (used by Summary and Analytics) ───────────────────

export interface CountryCount {
  country: string;
  count: number;
  blocked: number;
}

// ─── Raw types & mappers ────────────────────────────────────────────

// Go API returns different field names — transform to match frontend types.
interface RawSummary {
  total_events: number;
  blocked_events: number;
  logged_events: number;
  rate_limited: number;
  ipsum_blocked: number;
  policy_events: number;
  honeypot_events: number;
  scanner_events: number;
  unique_clients: number;
  unique_services: number;
  events_by_hour: { hour: string; count: number; blocked: number; logged: number; rate_limited: number; ipsum_blocked: number; honeypot: number; scanner: number; policy: number }[];
  top_services: { service: string; count: number; blocked: number; logged: number; rate_limited: number; ipsum_blocked: number; honeypot: number; scanner: number; policy: number }[];
  top_clients: { client: string; country?: string; count: number; blocked: number; rate_limited: number; ipsum_blocked: number; honeypot: number; scanner: number; policy: number }[];
  top_countries: { country: string; count: number; blocked: number }[];
  top_uris: { uri: string; count: number }[];
  service_breakdown: { service: string; total: number; blocked: number; logged: number; rate_limited: number; ipsum_blocked: number; honeypot: number; scanner: number; policy: number }[];
  recent_events: RawEvent[];
}

// Go API uses offset/limit pagination and different field names (is_blocked, response_status).
interface RawEvent {
  id: string;
  timestamp: string;
  service: string;
  method: string;
  uri: string;
  client_ip: string;
  country?: string;
  is_blocked: boolean;
  response_status: number;
  event_type?: string;
  user_agent?: string;
  rule_id?: number;
  rule_msg?: string;
  severity?: number;
  anomaly_score?: number;
  outbound_anomaly_score?: number;
  blocked_by?: string;
  matched_data?: string;
  rule_tags?: string[];
  matched_rules?: MatchedRuleInfo[];
  request_headers?: Record<string, string[]>;
  request_body?: string;
  request_args?: Record<string, string>;
}

export function mapEvent(raw: RawEvent): WAFEvent {
  // Derive event_type from the API field, falling back to is_blocked.
  let eventType: EventType = raw.is_blocked ? "blocked" : "logged";
  const validEventTypes: string[] = ["blocked", "logged", "rate_limited", "ipsum_blocked", "policy_skip", "policy_allow", "policy_block", "honeypot", "scanner"];
  if (raw.event_type && validEventTypes.includes(raw.event_type)) {
    eventType = raw.event_type as EventType;
  }

  return {
    id: raw.id,
    timestamp: raw.timestamp,
    service: raw.service,
    method: raw.method,
    uri: raw.uri,
    client_ip: raw.client_ip,
    country: raw.country,
    status: raw.response_status ?? 0,
    blocked: raw.is_blocked ?? false,
    event_type: eventType,
    rule_id: raw.rule_id ?? 0,
    rule_msg: raw.rule_msg ?? "",
    severity: raw.severity ?? 0,
    anomaly_score: raw.anomaly_score ?? 0,
    outbound_anomaly_score: raw.outbound_anomaly_score ?? 0,
    blocked_by: raw.blocked_by as WAFEvent["blocked_by"],
    matched_data: raw.matched_data,
    rule_tags: raw.rule_tags,
    user_agent: raw.user_agent,
    matched_rules: raw.matched_rules,
    request_headers: raw.request_headers,
    request_body: raw.request_body,
    request_args: raw.request_args,
  };
}

// ─── API Functions ──────────────────────────────────────────────────

export async function fetchSummary(params?: FilterableParams): Promise<SummaryData> {
  const searchParams = new URLSearchParams();
  applyFilterParams(searchParams, params);
  const qs = searchParams.toString() ? `?${searchParams}` : "";
  const raw = await fetchJSON<RawSummary>(`${API_BASE}/summary${qs}`);
  return {
    total_events: raw.total_events ?? 0,
    blocked: raw.blocked_events ?? 0,
    logged: raw.logged_events ?? 0,
    rate_limited: raw.rate_limited ?? 0,
    ipsum_blocked: raw.ipsum_blocked ?? 0,
    policy_events: raw.policy_events ?? 0,
    honeypot_events: raw.honeypot_events ?? 0,
    scanner_events: raw.scanner_events ?? 0,
    unique_clients: raw.unique_clients ?? 0,
    unique_services: raw.unique_services ?? 0,
    timeline: (raw.events_by_hour ?? []).map((h) => ({
      hour: h.hour,
      total: h.count ?? 0,
      blocked: h.blocked ?? 0,
      logged: h.logged ?? 0,
      rate_limited: h.rate_limited ?? 0,
      ipsum_blocked: h.ipsum_blocked ?? 0,
      honeypot: h.honeypot ?? 0,
      scanner: h.scanner ?? 0,
      policy: h.policy ?? 0,
    })),
    top_services: (raw.top_services ?? []).map((s) => ({
      service: s.service,
      total: s.count ?? 0,
      blocked: s.blocked ?? 0,
      logged: s.logged ?? 0,
      rate_limited: s.rate_limited ?? 0,
      ipsum_blocked: s.ipsum_blocked ?? 0,
      honeypot: s.honeypot ?? 0,
      scanner: s.scanner ?? 0,
      policy: s.policy ?? 0,
      block_rate: s.count > 0 ? (s.blocked / s.count) * 100 : 0,
    })),
    top_clients: (raw.top_clients ?? []).map((c) => ({
      client_ip: c.client,
      country: c.country,
      total: c.count ?? 0,
      blocked: c.blocked ?? 0,
      rate_limited: c.rate_limited ?? 0,
      ipsum_blocked: c.ipsum_blocked ?? 0,
      honeypot: c.honeypot ?? 0,
      scanner: c.scanner ?? 0,
      policy: c.policy ?? 0,
    })),
    top_countries: (raw.top_countries ?? []).map((c) => ({
      country: c.country,
      count: c.count ?? 0,
      blocked: c.blocked ?? 0,
    })),
    recent_events: (raw.recent_events ?? []).map(mapEvent),
    service_breakdown: (raw.service_breakdown ?? []).map((s) => ({
      service: s.service,
      total: s.total ?? 0,
      blocked: s.blocked ?? 0,
      logged: s.logged ?? 0,
      rate_limited: s.rate_limited ?? 0,
      ipsum_blocked: s.ipsum_blocked ?? 0,
      honeypot: s.honeypot ?? 0,
      scanner: s.scanner ?? 0,
      policy: s.policy ?? 0,
    })),
  };
}

export async function fetchEvents(params: EventsParams = {}): Promise<EventsResponse> {
  const searchParams = new URLSearchParams();
  if (params.id) searchParams.set("id", params.id);
  const page = params.page ?? 1;
  const perPage = params.per_page ?? 25;
  // Convert page/per_page to offset/limit for the Go API
  const offset = (page - 1) * perPage;
  searchParams.set("limit", String(perPage));
  searchParams.set("offset", String(offset));
  if (params.blocked !== null && params.blocked !== undefined)
    searchParams.set("blocked", String(params.blocked));
  applyFilterParams(searchParams, params);

  const qs = searchParams.toString();
  const raw = await fetchJSON<{ total: number; events: RawEvent[] }>(
    `${API_BASE}/events${qs ? `?${qs}` : ""}`
  );

  const total = raw.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / perPage));

  return {
    events: (raw.events ?? []).map(mapEvent),
    total,
    page,
    per_page: perPage,
    total_pages: totalPages,
  };
}

/** Fetch all events matching the current filters (export mode, no pagination limit). */
export async function fetchAllEvents(params: EventsParams = {}): Promise<WAFEvent[]> {
  const searchParams = new URLSearchParams();
  searchParams.set("export", "true");
  if (params.blocked !== null && params.blocked !== undefined)
    searchParams.set("blocked", String(params.blocked));
  applyFilterParams(searchParams, params);

  const qs = searchParams.toString();
  const raw = await fetchJSON<{ total: number; events: RawEvent[] }>(
    `${API_BASE}/events${qs ? `?${qs}` : ""}`
  );
  return (raw.events ?? []).map(mapEvent);
}

// Services
// Go API returns {"services":[{service, total, blocked, logged, ..., top_uris, top_rules}]} — unwrap and compute derived fields.
export async function fetchServices(hours?: number): Promise<ServiceDetail[]> {
  const qs = hours ? `?hours=${hours}` : "";
  const raw = await fetchJSON<{ services: { service: string; total: number; blocked: number; logged: number; rate_limited: number; ipsum_blocked: number; honeypot: number; scanner: number; policy: number; top_uris?: { uri: string; count: number; blocked: number }[]; top_rules?: { rule_id: number; rule_msg: string; count: number }[] }[] }>(
    `${API_BASE}/services${qs}`
  );
  return (raw.services ?? []).map((s) => ({
    service: s.service,
    total_events: s.total,
    blocked: s.blocked,
    logged: s.logged,
    rate_limited: s.rate_limited ?? 0,
    ipsum_blocked: s.ipsum_blocked ?? 0,
    honeypot: s.honeypot ?? 0,
    scanner: s.scanner ?? 0,
    policy: s.policy ?? 0,
    block_rate: s.total > 0 ? (s.blocked / s.total) * 100 : 0,
    top_uris: (s.top_uris ?? []).map((u) => ({ uri: u.uri, count: u.count, blocked: u.blocked })),
    top_rules: (s.top_rules ?? []).map((r) => ({ rule_id: String(r.rule_id), rule_msg: r.rule_msg, count: r.count })),
  }));
}

export async function fetchServiceDetail(service: string): Promise<ServiceDetail> {
  return fetchJSON<ServiceDetail>(
    `${API_BASE}/services/${encodeURIComponent(service)}`
  );
}

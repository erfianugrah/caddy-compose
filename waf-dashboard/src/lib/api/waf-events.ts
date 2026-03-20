import { API_BASE, fetchJSON, applyFilterParams } from "./shared";
import type { FilterOp, FilterableParams } from "./shared";

// ─── Summary / Overview ─────────────────────────────────────────────

export interface TagCount {
  tag: string;
  count: number;
}

export interface SummaryData {
  total_events: number;
  total_blocked: number;
  logged: number;
  rate_limited: number;
  policy_events: number;
  policy_blocked: number;
  detect_blocked: number;
  ddos_blocked: number;
  policy_allowed: number;
  policy_skipped: number;
  challenge_issued: number;
  challenge_passed: number;
  challenge_failed: number;
  unique_clients: number;
  unique_services: number;
  tag_counts: TagCount[];
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
  total_blocked: number;
  logged: number;
  rate_limited: number;
  policy_block: number;
  detect_block: number;
  ddos_blocked: number;
  policy_allow: number;
  policy_skip: number;
  challenge_issued: number;
  challenge_passed: number;
  challenge_failed: number;
}

export interface ServiceStat {
  service: string;
  total: number;
  total_blocked: number;
  logged: number;
  rate_limited: number;
  policy_block: number;
  detect_block: number;
  ddos_blocked: number;
  policy_allow: number;
  policy_skip: number;
  block_rate: number;
}

export interface ClientStat {
  client_ip: string;
  country?: string;
  total: number;
  total_blocked: number;
  rate_limited: number;
  policy_block: number;
  detect_block: number;
  ddos_blocked: number;
  policy_allow: number;
  policy_skip: number;
}

export interface ServiceBreakdown {
  service: string;
  total: number;
  total_blocked: number;
  logged: number;
  rate_limited: number;
  policy_block: number;
  detect_block: number;
  ddos_blocked: number;
  policy_allow: number;
  policy_skip: number;
}

// ─── Events ─────────────────────────────────────────────────────────

export type EventType = "detect_block" | "logged" | "rate_limited" | "policy_skip" | "policy_allow" | "policy_block" | "ddos_blocked" | "ddos_jailed" | "challenge_issued" | "challenge_passed" | "challenge_failed" | "challenge_bypassed";

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
  // Caddy-generated UUID for request correlation
  request_id?: string;
  tags?: string[];
  // JA4 TLS fingerprint + challenge fields
  ja4?: string;
  challenge_bot_score?: number;
  challenge_jti?: string;
  // DDoS mitigator fields (ddos_blocked/ddos_jailed events)
  ddos_action?: string;
  ddos_fingerprint?: string;
  ddos_score?: string;
}

export interface MatchedRuleDetailInfo {
  field: string;        // condition field (e.g., "all_args_values", "header")
  var_name: string;     // CRS-style variable name (e.g., "ARGS:username", "REQUEST_HEADERS:User-Agent")
  value?: string;       // actual input value that was tested (truncated)
  matched_data?: string; // regex group 0, phrase_match hit, or matched literal
  operator?: string;     // operator name (e.g., "regex", "phrase_match")
}

export interface MatchedRuleInfo {
  id: number;
  name?: string;   // rule ID string (e.g., "920350", "9100034") — used for PE detect rules
  msg: string;
  severity: number;
  matched_data?: string;
  file?: string;
  tags?: string[];
  matches?: MatchedRuleDetailInfo[]; // per-condition match details (detect rules only)
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
  total_blocked: number;
  logged: number;
  rate_limited: number;
  policy_block: number;
  detect_block: number;
  policy_allow: number;
  policy_skip: number;
  block_rate: number;
  top_uris: { uri: string; count: number; total_blocked: number }[];
  top_rules: { rule_id: string; rule_msg: string; count: number }[];
}

// ─── CountryCount (used by Summary and Analytics) ───────────────────

export interface CountryCount {
  country: string;
  count: number;
  total_blocked: number;
}

// ─── Raw types & mappers ────────────────────────────────────────────

// Go API returns different field names — transform to match frontend types.
interface RawSummary {
  total_events: number;
  total_blocked: number;
  logged_events: number;
  rate_limited: number;
  policy_events: number;
  policy_blocked: number;
  detect_blocked: number;
  ddos_blocked: number;
  policy_allowed: number;
  policy_skipped: number;
  unique_clients: number;
  unique_services: number;
  tag_counts?: { tag: string; count: number }[];
  events_by_hour: { hour: string; count: number; total_blocked: number; logged: number; rate_limited: number; policy_block: number; detect_block: number; ddos_blocked: number; policy_allow: number; policy_skip: number }[];
  top_services: { service: string; count: number; total_blocked: number; logged: number; rate_limited: number; policy_block: number; detect_block: number; ddos_blocked: number; policy_allow: number; policy_skip: number }[];
  top_clients: { client: string; country?: string; count: number; total_blocked: number; rate_limited: number; policy_block: number; detect_block: number; ddos_blocked: number; policy_allow: number; policy_skip: number }[];
  top_countries: { country: string; count: number; total_blocked: number }[];
  top_uris: { uri: string; count: number }[];
  service_breakdown: { service: string; total: number; total_blocked: number; logged: number; rate_limited: number; policy_block: number; detect_block: number; ddos_blocked: number; policy_allow: number; policy_skip: number }[];
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
  request_id?: string;
  tags?: string[];
  ja4?: string;
  challenge_bot_score?: number;
  challenge_jti?: string;
  ddos_action?: string;
  ddos_fingerprint?: string;
  ddos_score?: string;
}

export function mapEvent(raw: RawEvent): WAFEvent {
  // Derive event_type from the API field, falling back to is_blocked.
  let eventType: EventType = raw.is_blocked ? "detect_block" : "logged";
  const validEventTypes: string[] = ["detect_block", "logged", "rate_limited", "policy_skip", "policy_allow", "policy_block", "ddos_blocked", "ddos_jailed", "challenge_issued", "challenge_passed", "challenge_failed", "challenge_bypassed"];
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
    request_id: raw.request_id,
    tags: raw.tags,
    ja4: raw.ja4,
    challenge_bot_score: raw.challenge_bot_score,
    challenge_jti: raw.challenge_jti,
    ddos_action: raw.ddos_action,
    ddos_fingerprint: raw.ddos_fingerprint,
    ddos_score: raw.ddos_score,
  };
}

// ─── API Functions ──────────────────────────────────────────────────

export async function fetchSummary(params?: FilterableParams, init?: RequestInit): Promise<SummaryData> {
  const searchParams = new URLSearchParams();
  applyFilterParams(searchParams, params);
  const qs = searchParams.toString() ? `?${searchParams}` : "";
  const raw = await fetchJSON<RawSummary>(`${API_BASE}/summary${qs}`, init);
  return {
    total_events: raw.total_events ?? 0,
    total_blocked: raw.total_blocked ?? 0,
    logged: raw.logged_events ?? 0,
    rate_limited: raw.rate_limited ?? 0,
    policy_events: raw.policy_events ?? 0,
    policy_blocked: raw.policy_blocked ?? 0,
    detect_blocked: raw.detect_blocked ?? 0,
    ddos_blocked: raw.ddos_blocked ?? 0,
    policy_allowed: raw.policy_allowed ?? 0,
    policy_skipped: raw.policy_skipped ?? 0,
    unique_clients: raw.unique_clients ?? 0,
    unique_services: raw.unique_services ?? 0,
    tag_counts: (raw.tag_counts ?? []).map((tc) => ({ tag: tc.tag, count: tc.count ?? 0 })),
    timeline: (raw.events_by_hour ?? []).map((h) => ({
      hour: h.hour,
      total: h.count ?? 0,
      total_blocked: h.total_blocked ?? 0,
      logged: h.logged ?? 0,
      rate_limited: h.rate_limited ?? 0,
      policy_block: h.policy_block ?? 0,
      detect_block: h.detect_block ?? 0,
      ddos_blocked: h.ddos_blocked ?? 0,
      policy_allow: h.policy_allow ?? 0,
      policy_skip: h.policy_skip ?? 0,
    })),
    top_services: (raw.top_services ?? []).map((s) => ({
      service: s.service,
      total: s.count ?? 0,
      total_blocked: s.total_blocked ?? 0,
      logged: s.logged ?? 0,
      rate_limited: s.rate_limited ?? 0,
      policy_block: s.policy_block ?? 0,
      detect_block: s.detect_block ?? 0,
      ddos_blocked: s.ddos_blocked ?? 0,
      policy_allow: s.policy_allow ?? 0,
      policy_skip: s.policy_skip ?? 0,
      block_rate: s.count > 0 ? ((s.total_blocked ?? 0) / s.count) * 100 : 0,
    })),
    top_clients: (raw.top_clients ?? []).map((c) => ({
      client_ip: c.client,
      country: c.country,
      total: c.count ?? 0,
      total_blocked: c.total_blocked ?? 0,
      rate_limited: c.rate_limited ?? 0,
      policy_block: c.policy_block ?? 0,
      detect_block: c.detect_block ?? 0,
      ddos_blocked: c.ddos_blocked ?? 0,
      policy_allow: c.policy_allow ?? 0,
      policy_skip: c.policy_skip ?? 0,
    })),
    top_countries: (raw.top_countries ?? []).map((c) => ({
      country: c.country,
      count: c.count ?? 0,
      total_blocked: c.total_blocked ?? 0,
    })),
    recent_events: (raw.recent_events ?? []).map(mapEvent),
    service_breakdown: (raw.service_breakdown ?? []).map((s) => ({
      service: s.service,
      total: s.total ?? 0,
      total_blocked: s.total_blocked ?? 0,
      logged: s.logged ?? 0,
      rate_limited: s.rate_limited ?? 0,
      policy_block: s.policy_block ?? 0,
      detect_block: s.detect_block ?? 0,
      ddos_blocked: s.ddos_blocked ?? 0,
      policy_allow: s.policy_allow ?? 0,
      policy_skip: s.policy_skip ?? 0,
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
  // total=-1 signals the backend used early-exit pagination (more results exist
  // but the exact count is unknown). Show a large totalPages to enable "Next".
  const totalPages = total < 0
    ? page + 1 // always allow "Next" when unknown
    : Math.max(1, Math.ceil(total / perPage));

  return {
    events: (raw.events ?? []).map(mapEvent),
    total,
    page,
    per_page: perPage,
    total_pages: totalPages,
  };
}

/** Result from export-mode fetch, includes truncation metadata. */
export interface ExportResult {
  events: WAFEvent[];
  /** Number of events actually returned (may be less than total matching). */
  totalEmitted: number;
  /** True when the backend's 10K export cap was reached. */
  truncated: boolean;
}

/** Fetch all events matching the current filters (export mode, capped at 10K by backend). */
export async function fetchAllEvents(
  params: EventsParams = {},
): Promise<ExportResult> {
  const searchParams = new URLSearchParams();
  searchParams.set("export", "true");
  if (params.blocked !== null && params.blocked !== undefined)
    searchParams.set("blocked", String(params.blocked));
  applyFilterParams(searchParams, params);

  const qs = searchParams.toString();
  const raw = await fetchJSON<{
    total: number;
    events: RawEvent[];
    total_emitted?: number;
  }>(`${API_BASE}/events${qs ? `?${qs}` : ""}`);
  const events = (raw.events ?? []).map(mapEvent);
  const totalEmitted = raw.total_emitted ?? events.length;
  return {
    events,
    totalEmitted,
    truncated: totalEmitted >= 10_000,
  };
}

// Services
// Go API returns {"services":[{service, total, total_blocked, logged, ..., top_uris, top_rules}]} — unwrap and compute derived fields.
// Module-level cache for fetchServices — avoids redundant calls when multiple
// components mount on the same page (OverviewDashboard, EventsTable, PolicyEngine, etc.).
let _servicesCacheData: ServiceDetail[] | null = null;
let _servicesCacheTs = 0;
const SERVICES_CACHE_TTL = 30_000; // 30 seconds

/** Clear the services cache (exported for tests). */
export function clearServicesCache(): void {
  _servicesCacheData = null;
  _servicesCacheTs = 0;
}

export async function fetchServices(hours?: number): Promise<ServiceDetail[]> {
  // Return cached data if fresh and no custom hours filter.
  const now = Date.now();
  if (!hours && _servicesCacheData && now - _servicesCacheTs < SERVICES_CACHE_TTL) {
    return _servicesCacheData;
  }

  const qs = hours ? `?hours=${hours}` : "";
  const raw = await fetchJSON<{ services: { service: string; total: number; total_blocked: number; logged: number; rate_limited: number; policy_block: number; detect_block: number; policy_allow: number; policy_skip: number; top_uris?: { uri: string; count: number; total_blocked: number }[]; top_rules?: { rule_id: number; rule_msg: string; count: number }[] }[] }>(
    `${API_BASE}/services${qs}`
  );
  const result = (raw.services ?? []).map((s) => ({
    service: s.service,
    total_events: s.total,
    total_blocked: s.total_blocked,
    logged: s.logged,
    rate_limited: s.rate_limited ?? 0,
    policy_block: s.policy_block ?? 0,
    detect_block: s.detect_block ?? 0,
    policy_allow: s.policy_allow ?? 0,
    policy_skip: s.policy_skip ?? 0,
    block_rate: s.total > 0 ? (s.total_blocked / s.total) * 100 : 0,
    top_uris: (s.top_uris ?? []).map((u) => ({ uri: u.uri, count: u.count, total_blocked: u.total_blocked })),
    top_rules: (s.top_rules ?? []).map((r) => ({ rule_id: String(r.rule_id), rule_msg: r.rule_msg, count: r.count })),
  }));

  // Cache the default (no-hours) result.
  if (!hours) {
    _servicesCacheData = result;
    _servicesCacheTs = now;
  }
  return result;
}

export async function fetchServiceDetail(service: string): Promise<ServiceDetail> {
  return fetchJSON<ServiceDetail>(
    `${API_BASE}/services/${encodeURIComponent(service)}`
  );
}

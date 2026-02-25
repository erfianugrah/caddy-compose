const API_BASE = "/api";

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

export interface EventsParams {
  page?: number;
  per_page?: number;
  service?: string;
  blocked?: boolean | null;
  method?: string;
  event_type?: EventType | null;
  search?: string;
  client?: string;  // Filter by client IP (exact match)
  hours?: number;
  start?: string; // ISO 8601
  end?: string;   // ISO 8601
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

// ─── IP Lookup / Analytics ──────────────────────────────────────────

export interface IPLookupData {
  ip: string;
  first_seen: string;
  last_seen: string;
  total_events: number;
  blocked_count: number;
  services: { service: string; total: number; blocked: number; logged: number; rate_limited: number; ipsum_blocked: number; honeypot: number; scanner: number; policy: number }[];
  timeline: TimelinePoint[];
  recent_events: WAFEvent[];
}

export interface TopBlockedIP {
  client_ip: string;
  country?: string;
  total: number;
  blocked: number;
  block_rate: number;
  first_seen: string;
  last_seen: string;
}

export interface CountryCount {
  country: string;
  count: number;
  blocked: number;
}

export interface TopTargetedURI {
  uri: string;
  total: number;
  blocked: number;
  services: string[];
}

// ─── CRS Catalog / Autocomplete ─────────────────────────────────────

export interface CRSRule {
  id: string;
  description: string;
  category: string;
  tags: string[];
  severity?: string;
  paranoia_level?: number;
}

export interface CRSCategory {
  id: string;
  name: string;
  description: string;
  rule_range: string;
  tag: string; // CRS tag for ctl:ruleRemoveByTag
}

export interface CRSCatalogResponse {
  categories: CRSCategory[];
  rules: CRSRule[];
  total: number;
}

export interface ModSecOperator {
  name: string;
  label: string;
  description: string;
  has_arg: boolean;
}

export interface CRSAutocompleteResponse {
  variables: string[];
  operators: ModSecOperator[];
  actions: string[];
}

// ─── Exclusions / Policy ────────────────────────────────────────────

export type ExclusionType =
  // Advanced (ModSecurity directive types)
  | "SecRuleRemoveById"
  | "SecRuleRemoveByTag"
  | "SecRuleUpdateTargetById"
  | "SecRuleUpdateTargetByTag"
  | "ctl:ruleRemoveById"
  | "ctl:ruleRemoveByTag"
  | "ctl:ruleRemoveTargetById"
  | "ctl:ruleRemoveTargetByTag"
  // Quick Actions
  | "allow"
  | "block"
  | "skip_rule"
  // Honeypot
  | "honeypot"
  // Raw editor
  | "raw";

// Condition fields and operators for the dynamic rule builder
export type ConditionField = "ip" | "path" | "host" | "method" | "user_agent" | "header" | "query" | "country" | "cookie" | "body" | "args" | "uri_path" | "referer" | "response_header" | "response_status" | "http_version";
export type ConditionOperator = "eq" | "neq" | "contains" | "begins_with" | "ends_with" | "regex" | "ip_match" | "not_ip_match" | "in";
export type GroupOperator = "and" | "or";

export interface Condition {
  field: ConditionField;
  operator: ConditionOperator;
  value: string;
}

export interface Exclusion {
  id: string;
  name: string;
  description: string;
  type: ExclusionType;
  conditions: Condition[];
  group_operator: GroupOperator;
  rule_id?: string;
  rule_tag?: string;
  variable?: string;
  raw_rule?: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface ExclusionCreateData {
  name: string;
  description?: string;
  type: ExclusionType;
  conditions?: Condition[];
  group_operator?: GroupOperator;
  rule_id?: string;
  rule_tag?: string;
  variable?: string;
  raw_rule?: string;
  enabled: boolean;
}

export interface ExclusionUpdateData extends Partial<ExclusionCreateData> {}

// ─── Exclusion type mapping (frontend ModSecurity names ↔ Go internal names) ──

const typeToGo: Record<ExclusionType, string> = {
  // Advanced types (frontend ModSecurity names → Go internal names)
  "SecRuleRemoveById": "remove_by_id",
  "SecRuleRemoveByTag": "remove_by_tag",
  "SecRuleUpdateTargetById": "update_target_by_id",
  "SecRuleUpdateTargetByTag": "update_target_by_tag",
  "ctl:ruleRemoveById": "runtime_remove_by_id",
  "ctl:ruleRemoveByTag": "runtime_remove_by_tag",
  "ctl:ruleRemoveTargetById": "runtime_remove_target_by_id",
  "ctl:ruleRemoveTargetByTag": "runtime_remove_target_by_tag",
  // Quick Actions + Honeypot + Raw (same names in Go)
  "allow": "allow",
  "block": "block",
  "skip_rule": "skip_rule",
  "honeypot": "honeypot",
  "raw": "raw",
};

const typeFromGo: Record<string, ExclusionType> = Object.fromEntries(
  Object.entries(typeToGo).map(([fe, go]) => [go, fe as ExclusionType])
) as Record<string, ExclusionType>;

// Raw exclusion shape from Go API (uses internal type names)
interface RawExclusion {
  id: string;
  name: string;
  description: string;
  type: string;
  conditions?: Condition[];
  group_operator?: string;
  rule_id?: string;
  rule_tag?: string;
  variable?: string;
  raw_rule?: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

function mapExclusionFromGo(raw: RawExclusion): Exclusion {
  return {
    id: raw.id,
    name: raw.name,
    description: raw.description,
    type: typeFromGo[raw.type] ?? ("SecRuleRemoveById" as ExclusionType),
    conditions: raw.conditions ?? [],
    group_operator: (raw.group_operator as GroupOperator) || "and",
    rule_id: raw.rule_id || undefined,
    rule_tag: raw.rule_tag || undefined,
    variable: raw.variable || undefined,
    raw_rule: raw.raw_rule || undefined,
    enabled: raw.enabled,
    created_at: raw.created_at,
    updated_at: raw.updated_at,
  };
}

function mapExclusionToGo(data: ExclusionCreateData | ExclusionUpdateData): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  if (data.name !== undefined) result.name = data.name;
  if (data.description !== undefined) result.description = data.description;
  if (data.type !== undefined) result.type = typeToGo[data.type] ?? data.type;
  if (data.conditions !== undefined) result.conditions = data.conditions;
  if (data.group_operator !== undefined) result.group_operator = data.group_operator;
  if (data.rule_id !== undefined) result.rule_id = data.rule_id;
  if (data.rule_tag !== undefined) result.rule_tag = data.rule_tag;
  if (data.variable !== undefined) result.variable = data.variable;
  if (data.raw_rule !== undefined) result.raw_rule = data.raw_rule;
  if (data.enabled !== undefined) result.enabled = data.enabled;
  return result;
}

export interface GeneratedConfig {
  pre_crs: string;
  post_crs: string;
}

export interface DeployResult {
  status: "deployed" | "partial";
  message: string;
  pre_crs_file: string;
  post_crs_file: string;
  waf_settings_file: string;
  reloaded: boolean;
  timestamp: string;
}

// ─── Settings / Config ──────────────────────────────────────────────

export type WAFMode = "enabled" | "detection_only" | "disabled";

export interface WAFServiceSettings {
  mode: WAFMode;
  paranoia_level: number;
  inbound_threshold: number;
  outbound_threshold: number;
  disabled_groups?: string[];
}

export interface WAFConfig {
  defaults: WAFServiceSettings;
  services: Record<string, WAFServiceSettings>;
}

// Sensitivity presets for the UI
export type WAFPreset = "strict" | "moderate" | "tuning" | "custom";

export function presetToSettings(preset: WAFPreset): Partial<WAFServiceSettings> {
  switch (preset) {
    case "strict": return { paranoia_level: 1, inbound_threshold: 5, outbound_threshold: 4 };
    case "moderate": return { paranoia_level: 1, inbound_threshold: 15, outbound_threshold: 15 };
    case "tuning": return { paranoia_level: 1, inbound_threshold: 10000, outbound_threshold: 10000 };
    case "custom": return {};
  }
}

export function settingsToPreset(s: WAFServiceSettings): WAFPreset {
  if (s.paranoia_level === 1 && s.inbound_threshold === 5 && s.outbound_threshold === 4) return "strict";
  if (s.paranoia_level === 1 && s.inbound_threshold === 15 && s.outbound_threshold === 15) return "moderate";
  if (s.inbound_threshold >= 10000 && s.outbound_threshold >= 10000) return "tuning";
  return "custom";
}

// ─── Helpers ────────────────────────────────────────────────────────

async function fetchJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API error: ${res.status} ${res.statusText}${text ? ` — ${text}` : ""}`);
  }
  // Handle 204 No Content (e.g., DELETE responses)
  if (res.status === 204) return undefined as T;
  return res.json();
}

async function postJSON<T>(url: string, body: unknown): Promise<T> {
  return fetchJSON<T>(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function putJSON<T>(url: string, body: unknown): Promise<T> {
  return fetchJSON<T>(url, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function deleteJSON<T>(url: string): Promise<T> {
  return fetchJSON<T>(url, { method: "DELETE" });
}

// ─── API Functions ──────────────────────────────────────────────────

// Summary
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

export interface TimeRangeParams {
  hours?: number;
  start?: string; // ISO 8601
  end?: string;   // ISO 8601
}

export async function fetchSummary(params?: TimeRangeParams): Promise<SummaryData> {
  const searchParams = new URLSearchParams();
  if (params?.start && params?.end) {
    searchParams.set("start", params.start);
    searchParams.set("end", params.end);
  } else if (params?.hours) {
    searchParams.set("hours", String(params.hours));
  }
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

// Events
// Go API uses offset/limit pagination and different field names (is_blocked, response_status).
// Transform to match our frontend types.
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

function mapEvent(raw: RawEvent): WAFEvent {
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

export async function fetchEvents(params: EventsParams = {}): Promise<EventsResponse> {
  const searchParams = new URLSearchParams();
  const page = params.page ?? 1;
  const perPage = params.per_page ?? 25;
  // Convert page/per_page to offset/limit for the Go API
  const offset = (page - 1) * perPage;
  searchParams.set("limit", String(perPage));
  searchParams.set("offset", String(offset));
  if (params.service) searchParams.set("service", params.service);
  if (params.blocked !== null && params.blocked !== undefined)
    searchParams.set("blocked", String(params.blocked));
  if (params.method) searchParams.set("method", params.method);
  if (params.event_type) searchParams.set("event_type", params.event_type);
  if (params.client) searchParams.set("client", params.client);
  if (params.start && params.end) {
    searchParams.set("start", params.start);
    searchParams.set("end", params.end);
  } else if (params.hours) {
    searchParams.set("hours", String(params.hours));
  }

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
  if (params.service) searchParams.set("service", params.service);
  if (params.blocked !== null && params.blocked !== undefined)
    searchParams.set("blocked", String(params.blocked));
  if (params.method) searchParams.set("method", params.method);
  if (params.event_type) searchParams.set("event_type", params.event_type);
  if (params.client) searchParams.set("client", params.client);
  if (params.start && params.end) {
    searchParams.set("start", params.start);
    searchParams.set("end", params.end);
  } else if (params.hours) {
    searchParams.set("hours", String(params.hours));
  }

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

// IP Lookup
// Go API returns {ip, total, blocked, first_seen, last_seen, services:[ServiceDetail], events:[RawEvent]}
interface RawIPLookup {
  ip: string;
  total: number;
  blocked: number;
  first_seen: string | null;
  last_seen: string | null;
  services: { service: string; total: number; blocked: number; logged: number; rate_limited: number; ipsum_blocked: number; honeypot: number; scanner: number; policy: number }[];
  events: RawEvent[];
}

export async function lookupIP(ip: string): Promise<IPLookupData> {
  const raw = await fetchJSON<RawIPLookup>(
    `${API_BASE}/lookup/${encodeURIComponent(ip)}`
  );
  return {
    ip: raw.ip,
    first_seen: raw.first_seen ?? "",
    last_seen: raw.last_seen ?? "",
    total_events: raw.total ?? 0,
    blocked_count: raw.blocked ?? 0,
    services: (raw.services ?? []).map((s) => ({
      service: s.service,
      total: s.total,
      blocked: s.blocked,
      logged: s.logged ?? 0,
      rate_limited: s.rate_limited ?? 0,
      ipsum_blocked: s.ipsum_blocked ?? 0,
      honeypot: s.honeypot ?? 0,
      scanner: s.scanner ?? 0,
      policy: s.policy ?? 0,
    })),
    timeline: [],
    recent_events: (raw.events ?? []).slice(0, 20).map(mapEvent),
  };
}

// Analytics
// These endpoints don't exist yet in the Go API — derive from summary/services data.
// Return empty arrays gracefully so the UI shows "no data" instead of crashing.
export async function fetchTopBlockedIPs(hours?: number): Promise<TopBlockedIP[]> {
  try {
    const qs = hours ? `?hours=${hours}` : "";
    return await fetchJSON<TopBlockedIP[]>(`${API_BASE}/analytics/top-ips${qs}`);
  } catch {
    // Endpoint not implemented yet — return empty
    return [];
  }
}

export async function fetchTopTargetedURIs(hours?: number): Promise<TopTargetedURI[]> {
  try {
    const qs = hours ? `?hours=${hours}` : "";
    return await fetchJSON<TopTargetedURI[]>(`${API_BASE}/analytics/top-uris${qs}`);
  } catch {
    // Endpoint not implemented yet — return empty
    return [];
  }
}

export async function fetchTopCountries(hours?: number): Promise<CountryCount[]> {
  try {
    const qs = hours ? `?hours=${hours}` : "";
    return await fetchJSON<CountryCount[]>(`${API_BASE}/analytics/top-countries${qs}`);
  } catch {
    return [];
  }
}

// CRS Catalog
// These return the Go shapes directly — no field name mapping needed.

export async function fetchCRSRules(): Promise<CRSCatalogResponse> {
  return fetchJSON<CRSCatalogResponse>(`${API_BASE}/crs/rules`);
}

export async function fetchCRSAutocomplete(): Promise<CRSAutocompleteResponse> {
  return fetchJSON<CRSAutocompleteResponse>(`${API_BASE}/crs/autocomplete`);
}

// Exclusions
// Go API uses internal type names (remove_by_id, etc.) and "condition" instead of "uri".
// All CRUD functions transform between frontend and Go shapes.

export async function getExclusions(): Promise<Exclusion[]> {
  const raw = await fetchJSON<RawExclusion[]>(`${API_BASE}/exclusions`);
  return (raw ?? []).map(mapExclusionFromGo);
}

export async function createExclusion(data: ExclusionCreateData): Promise<Exclusion> {
  const payload = mapExclusionToGo(data);
  const raw = await postJSON<RawExclusion>(`${API_BASE}/exclusions`, payload);
  return mapExclusionFromGo(raw);
}

export async function updateExclusion(
  id: string,
  data: ExclusionUpdateData
): Promise<Exclusion> {
  const payload = mapExclusionToGo(data);
  const raw = await putJSON<RawExclusion>(`${API_BASE}/exclusions/${encodeURIComponent(id)}`, payload);
  return mapExclusionFromGo(raw);
}

export async function deleteExclusion(id: string): Promise<void> {
  await deleteJSON<void>(`${API_BASE}/exclusions/${encodeURIComponent(id)}`);
}

export async function generateConfig(): Promise<GeneratedConfig> {
  const raw = await postJSON<{ pre_crs_conf?: string; post_crs_conf?: string; pre_crs?: string; post_crs?: string }>(
    `${API_BASE}/config/generate`,
    {}
  );
  return {
    pre_crs: raw.pre_crs_conf ?? raw.pre_crs ?? "",
    post_crs: raw.post_crs_conf ?? raw.post_crs ?? "",
  };
}

export async function deployConfig(): Promise<DeployResult> {
  return postJSON<DeployResult>(`${API_BASE}/config/deploy`, {});
}

export async function exportExclusions(): Promise<Exclusion[]> {
  const raw = await fetchJSON<{ exclusions: RawExclusion[] }>(`${API_BASE}/exclusions/export`);
  return (raw.exclusions ?? []).map(mapExclusionFromGo);
}

export async function importExclusions(data: Exclusion[]): Promise<{ imported: number }> {
  // Transform exclusions to Go shape for import
  const goExclusions = data.map((e) => mapExclusionToGo({
    name: e.name,
    description: e.description,
    type: e.type,
    conditions: e.conditions,
    group_operator: e.group_operator,
    rule_id: e.rule_id,
    rule_tag: e.rule_tag,
    variable: e.variable,
    raw_rule: e.raw_rule,
    enabled: e.enabled,
  }));
  return postJSON<{ imported: number }>(`${API_BASE}/exclusions/import`, {
    version: 1,
    exclusions: goExclusions,
  });
}

// Config / Settings
// New format: Go API returns WAFConfig directly with defaults + per-service settings.
// No field name mapping needed — frontend types match Go JSON tags.

export async function getConfig(): Promise<WAFConfig> {
  const raw = await fetchJSON<WAFConfig>(`${API_BASE}/config`);
  return {
    defaults: raw.defaults ?? { mode: "enabled", paranoia_level: 1, inbound_threshold: 5, outbound_threshold: 4 },
    services: raw.services ?? {},
  };
}

export async function updateConfig(data: WAFConfig): Promise<WAFConfig> {
  return putJSON<WAFConfig>(`${API_BASE}/config`, data);
}

// ─── Rate Limits ────────────────────────────────────────────────────

export interface RateLimitZone {
  name: string;
  events: number;
  window: string;
  enabled: boolean;
}

export interface RateLimitConfig {
  zones: RateLimitZone[];
}

export interface RateLimitDeployResult {
  status: "deployed" | "partial";
  message: string;
  files: string[];
  reloaded: boolean;
  timestamp: string;
}

export async function getRateLimits(): Promise<RateLimitConfig> {
  const raw = await fetchJSON<RateLimitConfig>(`${API_BASE}/rate-limits`);
  return {
    zones: (raw.zones ?? []).map((z) => ({
      name: z.name,
      events: z.events,
      window: z.window,
      enabled: z.enabled,
    })),
  };
}

export async function updateRateLimits(config: RateLimitConfig): Promise<RateLimitConfig> {
  return putJSON<RateLimitConfig>(`${API_BASE}/rate-limits`, config);
}

export async function deployRateLimits(): Promise<RateLimitDeployResult> {
  return postJSON<RateLimitDeployResult>(`${API_BASE}/rate-limits/deploy`, {});
}

// ─── Rate Limit Analytics (429 events) ──────────────────────────────

export interface RLTimelinePoint {
  hour: string;
  count: number;
  blocked: number;
}

export interface RLClientCount {
  client_ip: string;
  count: number;
  first_seen: string;
  last_seen: string;
}

export interface RLServiceCount {
  service: string;
  count: number;
}

export interface RLURICount {
  uri: string;
  count: number;
  services: string[];
}

export interface RateLimitEvent {
  timestamp: string;
  client_ip: string;
  service: string;
  method: string;
  uri: string;
  user_agent: string;
}

export interface RLSummaryData {
  total_429s: number;
  unique_clients: number;
  unique_services: number;
  events_by_hour: RLTimelinePoint[];
  top_clients: RLClientCount[];
  top_services: RLServiceCount[];
  top_uris: RLURICount[];
  recent_events: RateLimitEvent[];
}

export interface RLEventsData {
  total: number;
  events: RateLimitEvent[];
}

export async function getRLSummary(hours?: number): Promise<RLSummaryData> {
  const qs = hours ? `?hours=${hours}` : "";
  return fetchJSON<RLSummaryData>(`${API_BASE}/rate-limits/summary${qs}`);
}

export async function getRLEvents(params?: {
  service?: string;
  client?: string;
  method?: string;
  limit?: number;
  offset?: number;
  hours?: number;
}): Promise<RLEventsData> {
  const q = new URLSearchParams();
  if (params?.service) q.set("service", params.service);
  if (params?.client) q.set("client", params.client);
  if (params?.method) q.set("method", params.method);
  if (params?.limit) q.set("limit", String(params.limit));
  if (params?.offset) q.set("offset", String(params.offset));
  if (params?.hours) q.set("hours", String(params.hours));
  const qs = q.toString();
  return fetchJSON<RLEventsData>(`${API_BASE}/rate-limits/events${qs ? `?${qs}` : ""}`);
}

// ─── Blocklist (IPsum) ──────────────────────────────────────────────

export interface BlocklistStats {
  blocked_ips: number;
  last_updated: string;
  source: string;
  min_score: number;
  file_path: string;
}

export interface BlocklistCheckResult {
  ip: string;
  blocked: boolean;
  source: string;
}

export async function getBlocklistStats(): Promise<BlocklistStats> {
  return fetchJSON<BlocklistStats>(`${API_BASE}/blocklist/stats`);
}

export async function checkBlocklistIP(ip: string): Promise<BlocklistCheckResult> {
  return fetchJSON<BlocklistCheckResult>(`${API_BASE}/blocklist/check/${encodeURIComponent(ip)}`);
}

export interface BlocklistRefreshResult {
  status: string;
  message: string;
  blocked_ips: number;
  min_score: number;
  last_updated: string;
  reloaded: boolean;
}

export async function refreshBlocklist(): Promise<BlocklistRefreshResult> {
  const res = await fetch(`${API_BASE}/blocklist/refresh`, { method: "POST" });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ message: res.statusText }));
    throw new Error(body.message || body.error || `HTTP ${res.status}`);
  }
  return res.json();
}

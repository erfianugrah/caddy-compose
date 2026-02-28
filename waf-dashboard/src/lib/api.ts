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

export type FilterOp = "eq" | "neq" | "contains" | "in" | "regex";

export interface EventsParams {
  id?: string;        // Lookup a single event by ID (fast path)
  page?: number;
  per_page?: number;
  service?: string;
  service_op?: FilterOp;
  blocked?: boolean | null;
  method?: string;
  method_op?: FilterOp;
  event_type?: EventType | null;
  event_type_op?: FilterOp;
  search?: string;
  client?: string;     // Filter by client IP
  client_op?: FilterOp;
  rule_name?: string;  // Filter by policy exclusion name (matched_rules msg)
  rule_name_op?: FilterOp;
  uri?: string;        // Filter by request URI/path
  uri_op?: FilterOp;
  status_code?: string; // Filter by response status code
  status_code_op?: FilterOp;
  country?: string;    // Filter by country code (ISO 3166-1 alpha-2)
  country_op?: FilterOp;
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
  events_total: number;
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
export type ConditionField = "ip" | "path" | "host" | "method" | "user_agent" | "header" | "query" | "country" | "cookie" | "body" | "body_json" | "body_form" | "args" | "uri_path" | "referer" | "response_header" | "response_status" | "http_version";
export type ConditionOperator = "eq" | "neq" | "contains" | "begins_with" | "ends_with" | "regex" | "ip_match" | "not_ip_match" | "in" | "exists";
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

  // CRS v4 extended settings (all optional — zero/absent = CRS default)
  blocking_paranoia_level?: number;
  detection_paranoia_level?: number;
  early_blocking?: boolean;
  sampling_percentage?: number;
  reporting_level?: number;
  enforce_bodyproc_urlencoded?: boolean;

  // Request policy
  allowed_methods?: string;
  allowed_request_content_type?: string;
  allowed_http_versions?: string;
  restricted_extensions?: string;
  restricted_headers?: string;

  // Argument limits
  max_num_args?: number;
  arg_name_length?: number;
  arg_length?: number;
  total_arg_length?: number;

  // File upload limits
  max_file_size?: number;
  combined_file_sizes?: number;

  // CRS built-in exclusion profiles
  crs_exclusions?: string[];
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
  // 204 No Content — used by DELETE endpoints. Callers expecting void
  // discard the return value; callers expecting data never get 204.
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

export interface SummaryParams extends TimeRangeParams {
  service?: string;     // Filter to events for a specific service
  service_op?: FilterOp;
  client?: string;      // Filter by client IP
  client_op?: FilterOp;
  method?: string;      // Filter by HTTP method
  method_op?: FilterOp;
  event_type?: string;  // Filter by event type
  event_type_op?: FilterOp;
  rule_name?: string;   // Filter to events matching a specific policy exclusion name
  rule_name_op?: FilterOp;
  uri?: string;         // Filter by request URI/path
  uri_op?: FilterOp;
  status_code?: string; // Filter by response status code
  status_code_op?: FilterOp;
  country?: string;     // Filter by country code (ISO 3166-1 alpha-2)
  country_op?: FilterOp;
}

/** Apply shared filter and time-range params to URLSearchParams. */
function applyFilterParams(sp: URLSearchParams, params?: SummaryParams): void {
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
    ["event_type", params.event_type, params.event_type_op],
    ["rule_name", params.rule_name, params.rule_name_op],
    ["uri", params.uri, params.uri_op],
    ["status_code", params.status_code, params.status_code_op],
    ["country", params.country, params.country_op],
  ];
  for (const [field, value, op] of filters) {
    if (value) sp.set(field, value);
    if (op && op !== "eq") sp.set(`${field}_op`, op);
  }
}

export async function fetchSummary(params?: SummaryParams): Promise<SummaryData> {
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

// IP Lookup
// Go API returns {ip, total, blocked, first_seen, last_seen, services:[ServiceDetail], events:[RawEvent]}
interface RawIPLookup {
  ip: string;
  total: number;
  blocked: number;
  events_total: number;
  first_seen: string | null;
  last_seen: string | null;
  services: { service: string; total: number; blocked: number; logged: number; rate_limited: number; ipsum_blocked: number; honeypot: number; scanner: number; policy: number }[];
  events: RawEvent[];
}

export async function lookupIP(ip: string, limit = 50, offset = 0): Promise<IPLookupData> {
  const qs = `?limit=${limit}&offset=${offset}`;
  const raw = await fetchJSON<RawIPLookup>(
    `${API_BASE}/lookup/${encodeURIComponent(ip)}${qs}`
  );
  return {
    ip: raw.ip,
    first_seen: raw.first_seen ?? "",
    last_seen: raw.last_seen ?? "",
    total_events: raw.total ?? 0,
    blocked_count: raw.blocked ?? 0,
    events_total: raw.events_total ?? raw.total ?? 0,
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
    recent_events: (raw.events ?? []).map(mapEvent),
  };
}

// Analytics

export async function fetchTopBlockedIPs(hours?: number): Promise<TopBlockedIP[]> {
  const qs = hours ? `?hours=${hours}` : "";
  return fetchJSON<TopBlockedIP[]>(`${API_BASE}/analytics/top-ips${qs}`);
}

export async function fetchTopTargetedURIs(hours?: number): Promise<TopTargetedURI[]> {
  const qs = hours ? `?hours=${hours}` : "";
  return fetchJSON<TopTargetedURI[]>(`${API_BASE}/analytics/top-uris${qs}`);
}

export async function fetchTopCountries(hours?: number): Promise<CountryCount[]> {
  const qs = hours ? `?hours=${hours}` : "";
  return fetchJSON<CountryCount[]>(`${API_BASE}/analytics/top-countries${qs}`);
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

// Exclusion hit stats — per-rule trigger counts with sparkline data.

export interface ExclusionHitData {
  total: number;
  sparkline: number[];
}

export interface ExclusionHitsResponse {
  hits: Record<string, ExclusionHitData>;
}

export async function fetchExclusionHits(hours = 24): Promise<ExclusionHitsResponse> {
  return fetchJSON<ExclusionHitsResponse>(`${API_BASE}/exclusions/hits?hours=${hours}`);
}

export async function reorderExclusions(ids: string[]): Promise<Exclusion[]> {
  const raw = await putJSON<RawExclusion[]>(`${API_BASE}/exclusions/reorder`, { ids });
  return raw.map(mapExclusionFromGo);
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

// ─── Rate Limit Rules (Policy Engine) ───────────────────────────────

export type RLRuleAction = "deny" | "log_only";
export type RLRuleKey = "client_ip" | string; // "client_ip", "header:X-API-Key", etc.

export interface RateLimitRule {
  id: string;
  name: string;
  description: string;
  service: string;
  conditions: Condition[];
  group_operator: GroupOperator;
  key: RLRuleKey;
  events: number;
  window: string;
  action: RLRuleAction;
  priority: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface RateLimitRuleCreateData {
  name: string;
  description?: string;
  service: string;
  conditions?: Condition[];
  group_operator?: GroupOperator;
  key: RLRuleKey;
  events: number;
  window: string;
  action?: RLRuleAction;
  priority?: number;
  enabled: boolean;
}

export interface RateLimitRuleUpdateData extends Partial<RateLimitRuleCreateData> {}

export interface RateLimitGlobalConfig {
  jitter: number;
  sweep_interval: string;
  distributed: boolean;
  read_interval: string;
  write_interval: string;
  purge_age: string;
}

export interface RateLimitRuleExport {
  version: number;
  exported_at: string;
  rules: RateLimitRule[];
  global: RateLimitGlobalConfig;
}

export interface RateLimitDeployResult {
  status: string;
  message: string;
  files: string[];
  reloaded: boolean;
  timestamp: string;
}

export interface RLRuleHitStats {
  total: number;
  sparkline: number[];
}

export interface RLRuleHitsResponse {
  [ruleId: string]: RLRuleHitStats;
}

// ─── Rate Limit Rule CRUD ───────────────────────────────────────────

export async function getRLRules(): Promise<RateLimitRule[]> {
  const raw = await fetchJSON<RateLimitRule[]>(`${API_BASE}/rate-rules`);
  return (raw ?? []).map(mapRLRule);
}

export async function getRLRule(id: string): Promise<RateLimitRule> {
  const raw = await fetchJSON<RateLimitRule>(`${API_BASE}/rate-rules/${encodeURIComponent(id)}`);
  return mapRLRule(raw);
}

export async function createRLRule(data: RateLimitRuleCreateData): Promise<RateLimitRule> {
  const raw = await postJSON<RateLimitRule>(`${API_BASE}/rate-rules`, data);
  return mapRLRule(raw);
}

export async function updateRLRule(id: string, data: RateLimitRuleUpdateData): Promise<RateLimitRule> {
  const raw = await putJSON<RateLimitRule>(`${API_BASE}/rate-rules/${encodeURIComponent(id)}`, data);
  return mapRLRule(raw);
}

export async function deleteRLRule(id: string): Promise<void> {
  await deleteJSON<void>(`${API_BASE}/rate-rules/${encodeURIComponent(id)}`);
}

export async function deployRLRules(): Promise<RateLimitDeployResult> {
  return postJSON<RateLimitDeployResult>(`${API_BASE}/rate-rules/deploy`, {});
}

// ─── Rate Limit Global Config ───────────────────────────────────────

export async function getRLGlobal(): Promise<RateLimitGlobalConfig> {
  return fetchJSON<RateLimitGlobalConfig>(`${API_BASE}/rate-rules/global`);
}

export async function updateRLGlobal(config: RateLimitGlobalConfig): Promise<RateLimitGlobalConfig> {
  return putJSON<RateLimitGlobalConfig>(`${API_BASE}/rate-rules/global`, config);
}

// ─── Rate Limit Export / Import / Hits ──────────────────────────────

export async function exportRLRules(): Promise<RateLimitRuleExport> {
  return fetchJSON<RateLimitRuleExport>(`${API_BASE}/rate-rules/export`);
}

export async function importRLRules(data: RateLimitRuleExport): Promise<{ status: string; imported: number }> {
  return postJSON<{ status: string; imported: number }>(`${API_BASE}/rate-rules/import`, data);
}

export async function getRLRuleHits(hours = 24): Promise<RLRuleHitsResponse> {
  return fetchJSON<RLRuleHitsResponse>(`${API_BASE}/rate-rules/hits?hours=${hours}`);
}

export async function reorderRLRules(ids: string[]): Promise<RateLimitRule[]> {
  const raw = await putJSON<RateLimitRule[]>(`${API_BASE}/rate-rules/reorder`, { ids });
  return raw.map(mapRLRule);
}

// ─── Rate Limit Rule Mapper ─────────────────────────────────────────

function mapRLRule(raw: RateLimitRule): RateLimitRule {
  return {
    id: raw.id ?? "",
    name: raw.name ?? "",
    description: raw.description ?? "",
    service: raw.service ?? "",
    conditions: raw.conditions ?? [],
    group_operator: (raw.group_operator as GroupOperator) || "and",
    key: raw.key ?? "client_ip",
    events: raw.events ?? 0,
    window: raw.window ?? "1m",
    action: (raw.action as RLRuleAction) || "deny",
    priority: raw.priority ?? 0,
    enabled: raw.enabled ?? false,
    created_at: raw.created_at ?? "",
    updated_at: raw.updated_at ?? "",
  };
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

// ─── Rate Limit Advisor ─────────────────────────────────────────────

export type ClientClassification = "normal" | "elevated" | "suspicious" | "abusive";

export interface RateAdvisorClient {
  client_ip: string;
  country?: string;
  requests: number;
  requests_per_sec: number;
  error_rate: number;
  path_diversity: number;
  burstiness: number;
  classification: ClientClassification;
  anomaly_score: number;
  top_paths: { path: string; count: number }[];
}

export interface AdvisorRecommendation {
  threshold: number;
  confidence: "low" | "medium" | "high";
  method: "mad" | "p99" | "iqr";
  affected_clients: number;
  affected_requests: number;
  median: number;
  mad: number;
  separation: number;
}

export interface ImpactPoint {
  threshold: number;
  clients_affected: number;
  requests_affected: number;
  client_pct: number;
  request_pct: number;
}

export interface HistogramBin {
  min: number;
  max: number;
  count: number;
}

export interface NormalizedPercentiles {
  p50: number;
  p75: number;
  p90: number;
  p95: number;
  p99: number;
}

export interface TimeOfDayBaseline {
  hour: number;
  median_rps: number;
  p95_rps: number;
  clients: number;
  requests: number;
}

export interface RateAdvisorResponse {
  window: string;
  window_seconds: number;
  service?: string;
  path?: string;
  method?: string;
  total_requests: number;
  unique_clients: number;
  clients: RateAdvisorClient[];
  percentiles: {
    p50: number;
    p75: number;
    p90: number;
    p95: number;
    p99: number;
  };
  normalized_percentiles: NormalizedPercentiles;
  recommendation?: AdvisorRecommendation;
  impact_curve: ImpactPoint[];
  histogram: HistogramBin[];
  time_of_day_baselines?: TimeOfDayBaseline[];
}

export async function getRateAdvisor(params?: {
  window?: string;
  service?: string;
  path?: string;
  method?: string;
  limit?: number;
}): Promise<RateAdvisorResponse> {
  const q = new URLSearchParams();
  if (params?.window) q.set("window", params.window);
  if (params?.service) q.set("service", params.service);
  if (params?.path) q.set("path", params.path);
  if (params?.method) q.set("method", params.method);
  if (params?.limit) q.set("limit", String(params.limit));
  const qs = q.toString();
  return fetchJSON<RateAdvisorResponse>(`${API_BASE}/rate-rules/advisor${qs ? `?${qs}` : ""}`);
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

// ─── CSP (Content Security Policy) ─────────────────────────────────

export interface CSPPolicy {
  default_src?: string[];
  script_src?: string[];
  style_src?: string[];
  img_src?: string[];
  font_src?: string[];
  connect_src?: string[];
  media_src?: string[];
  frame_src?: string[];
  worker_src?: string[];
  object_src?: string[];
  child_src?: string[];
  manifest_src?: string[];
  base_uri?: string[];
  form_action?: string[];
  frame_ancestors?: string[];
  upgrade_insecure_requests?: boolean;
  raw_directives?: string;
}

export interface CSPServiceConfig {
  mode: "set" | "default" | "none";
  report_only: boolean;
  inherit: boolean;
  policy: CSPPolicy;
}

export interface CSPConfig {
  enabled?: boolean;
  global_defaults: CSPPolicy;
  services: Record<string, CSPServiceConfig>;
}

export interface CSPDeployResponse {
  status: string;
  message: string;
  files: string[];
  reloaded: boolean;
  timestamp: string;
}

export interface CSPPreviewEntry {
  mode: string;
  report_only: boolean;
  header: string;
}

export interface CSPPreviewResponse {
  services: Record<string, CSPPreviewEntry>;
}

export async function getCSPConfig(): Promise<CSPConfig> {
  return fetchJSON<CSPConfig>(`${API_BASE}/csp`);
}

export async function updateCSPConfig(cfg: CSPConfig): Promise<CSPConfig> {
  return putJSON<CSPConfig>(`${API_BASE}/csp`, cfg);
}

export async function deployCSP(): Promise<CSPDeployResponse> {
  return postJSON<CSPDeployResponse>(`${API_BASE}/csp/deploy`, {});
}

export async function previewCSP(): Promise<CSPPreviewResponse> {
  return fetchJSON<CSPPreviewResponse>(`${API_BASE}/csp/preview`);
}

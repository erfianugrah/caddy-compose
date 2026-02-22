const API_BASE = "/api";

// ─── Summary / Overview ─────────────────────────────────────────────

export interface SummaryData {
  total_events: number;
  blocked: number;
  logged: number;
  rate_limited: number;
  unique_clients: number;
  unique_services: number;
  timeline: TimelinePoint[];
  top_services: ServiceStat[];
  top_clients: ClientStat[];
  recent_events: WAFEvent[];
  service_breakdown: ServiceBreakdown[];
}

export interface TimelinePoint {
  hour: string;
  total: number;
  blocked: number;
  logged: number;
  rate_limited: number;
}

export interface ServiceStat {
  service: string;
  total: number;
  blocked: number;
  logged: number;
  block_rate: number;
}

export interface ClientStat {
  client_ip: string;
  total: number;
  blocked: number;
}

export interface ServiceBreakdown {
  service: string;
  total: number;
  blocked: number;
  logged: number;
}

// ─── Events ─────────────────────────────────────────────────────────

export type EventType = "blocked" | "logged" | "rate_limited";

export interface WAFEvent {
  id: string;
  timestamp: string;
  service: string;
  method: string;
  uri: string;
  client_ip: string;
  status: number;
  blocked: boolean;
  event_type: EventType;
  rule_id: number;
  rule_msg: string;
  severity: number;
  request_headers?: Record<string, string>;
  matched_data?: string;
  rule_tags?: string[];
  user_agent?: string;
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
  services: { service: string; total: number; blocked: number }[];
  timeline: TimelinePoint[];
  recent_events: WAFEvent[];
}

export interface TopBlockedIP {
  client_ip: string;
  total: number;
  blocked: number;
  block_rate: number;
  first_seen: string;
  last_seen: string;
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
  // Quick Actions
  | "allow"
  | "block"
  | "skip_rule"
  // Raw editor
  | "raw";

// Condition fields and operators for the dynamic rule builder
export type ConditionField = "ip" | "path" | "host" | "method" | "user_agent" | "header" | "query";
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
  // Quick Actions + Raw (same names in Go)
  "allow": "allow",
  "block": "block",
  "skip_rule": "skip_rule",
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
  reloaded: boolean;
  timestamp: string;
}

// ─── Settings / Config ──────────────────────────────────────────────

export type WAFEngineMode = "on" | "detection_only" | "off";

export interface WAFConfig {
  engine_mode: WAFEngineMode;
  paranoia_level: number;
  inbound_anomaly_threshold: number;
  outbound_anomaly_threshold: number;
  service_profiles: ServiceProfile[];
}

export type ServiceProfileMode = "strict" | "tuning" | "off";

export interface ServiceProfile {
  service: string;
  profile: ServiceProfileMode;
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
  unique_clients: number;
  unique_services: number;
  events_by_hour: { hour: string; count: number; blocked: number; logged: number; rate_limited: number }[];
  top_services: { service: string; count: number; blocked: number; logged: number; rate_limited: number }[];
  top_clients: { client: string; count: number; blocked: number }[];
  top_uris: { uri: string; count: number }[];
  service_breakdown: { service: string; total: number; blocked: number; logged: number; rate_limited: number }[];
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
    unique_clients: raw.unique_clients ?? 0,
    unique_services: raw.unique_services ?? 0,
    timeline: (raw.events_by_hour ?? []).map((h) => ({
      hour: h.hour,
      total: h.count ?? 0,
      blocked: h.blocked ?? 0,
      logged: h.logged ?? 0,
      rate_limited: h.rate_limited ?? 0,
    })),
    top_services: (raw.top_services ?? []).map((s) => ({
      service: s.service,
      total: s.count ?? 0,
      blocked: s.blocked ?? 0,
      logged: s.logged ?? 0,
      block_rate: s.count > 0 ? (s.blocked / s.count) * 100 : 0,
    })),
    top_clients: (raw.top_clients ?? []).map((c) => ({
      client_ip: c.client,
      total: c.count ?? 0,
      blocked: c.blocked ?? 0,
    })),
    recent_events: (raw.recent_events ?? []).map(mapEvent),
    service_breakdown: (raw.service_breakdown ?? []).map((s) => ({
      service: s.service,
      total: s.total ?? 0,
      blocked: s.blocked ?? 0,
      logged: s.logged ?? 0,
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
  is_blocked: boolean;
  response_status: number;
  event_type?: string;
  user_agent?: string;
  rule_id?: number;
  rule_msg?: string;
  severity?: number;
  matched_data?: string;
  rule_tags?: string[];
}

function mapEvent(raw: RawEvent): WAFEvent {
  // Derive event_type from the API field, falling back to is_blocked.
  let eventType: EventType = raw.is_blocked ? "blocked" : "logged";
  if (raw.event_type === "rate_limited" || raw.event_type === "blocked" || raw.event_type === "logged") {
    eventType = raw.event_type as EventType;
  }

  return {
    id: raw.id,
    timestamp: raw.timestamp,
    service: raw.service,
    method: raw.method,
    uri: raw.uri,
    client_ip: raw.client_ip,
    status: raw.response_status ?? 0,
    blocked: raw.is_blocked ?? false,
    event_type: eventType,
    rule_id: raw.rule_id ?? 0,
    rule_msg: raw.rule_msg ?? "",
    severity: raw.severity ?? 0,
    matched_data: raw.matched_data,
    rule_tags: raw.rule_tags,
    user_agent: raw.user_agent,
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

// Services
// Go API returns {"services":[{service, total, blocked, logged}]} — unwrap and compute derived fields.
export async function fetchServices(hours?: number): Promise<ServiceDetail[]> {
  const qs = hours ? `?hours=${hours}` : "";
  const raw = await fetchJSON<{ services: { service: string; total: number; blocked: number; logged: number }[] }>(
    `${API_BASE}/services${qs}`
  );
  return (raw.services ?? []).map((s) => ({
    service: s.service,
    total_events: s.total,
    blocked: s.blocked,
    logged: s.logged,
    block_rate: s.total > 0 ? (s.blocked / s.total) * 100 : 0,
    top_uris: [],
    top_rules: [],
  }));
}

export async function fetchServiceDetail(service: string): Promise<ServiceDetail> {
  return fetchJSON<ServiceDetail>(
    `${API_BASE}/services/${encodeURIComponent(service)}`
  );
}

// IP Lookup
// Go API returns {ip, total, blocked, first_seen, last_seen, services:[{service,total,blocked,logged}], events:[RawEvent]}
interface RawIPLookup {
  ip: string;
  total: number;
  blocked: number;
  first_seen: string | null;
  last_seen: string | null;
  services: { service: string; total: number; blocked: number; logged: number }[];
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
// Go API uses different field names and shapes — transform both directions.

interface RawWAFConfig {
  paranoia_level: number;
  inbound_threshold: number;
  outbound_threshold: number;
  rule_engine: string; // "On" | "Off" | "DetectionOnly"
  services: Record<string, { profile: string }>;
}

// Map Go's rule_engine string to frontend WAFEngineMode
function mapRuleEngineToMode(engine: string): WAFEngineMode {
  switch (engine) {
    case "On": return "on";
    case "DetectionOnly": return "detection_only";
    case "Off": return "off";
    default: return "on";
  }
}

// Map frontend WAFEngineMode to Go's rule_engine string
function mapModeToRuleEngine(mode: WAFEngineMode): string {
  switch (mode) {
    case "on": return "On";
    case "detection_only": return "DetectionOnly";
    case "off": return "Off";
    default: return "On";
  }
}

// Transform Go's services map to frontend's service_profiles array
function mapServicesToProfiles(services: Record<string, { profile: string }> | null | undefined): ServiceProfile[] {
  if (!services) return [];
  return Object.entries(services).map(([service, cfg]) => ({
    service,
    profile: (cfg.profile || "strict") as ServiceProfileMode,
  }));
}

// Transform frontend's service_profiles array to Go's services map
function mapProfilesToServices(profiles: ServiceProfile[] | null | undefined): Record<string, { profile: string }> {
  const services: Record<string, { profile: string }> = {};
  if (!profiles) return services;
  for (const p of profiles) {
    services[p.service] = { profile: p.profile };
  }
  return services;
}

export async function getConfig(): Promise<WAFConfig> {
  const raw = await fetchJSON<RawWAFConfig>(`${API_BASE}/config`);
  return {
    engine_mode: mapRuleEngineToMode(raw.rule_engine),
    paranoia_level: raw.paranoia_level ?? 1,
    inbound_anomaly_threshold: raw.inbound_threshold ?? 5,
    outbound_anomaly_threshold: raw.outbound_threshold ?? 4,
    service_profiles: mapServicesToProfiles(raw.services),
  };
}

export async function updateConfig(data: Partial<WAFConfig>): Promise<WAFConfig> {
  // We need to send a full WAFConfig to Go — fetch current first if partial
  const current = await fetchJSON<RawWAFConfig>(`${API_BASE}/config`);
  const payload: RawWAFConfig = {
    paranoia_level: data.paranoia_level ?? current.paranoia_level,
    inbound_threshold: data.inbound_anomaly_threshold ?? current.inbound_threshold,
    outbound_threshold: data.outbound_anomaly_threshold ?? current.outbound_threshold,
    rule_engine: data.engine_mode ? mapModeToRuleEngine(data.engine_mode) : current.rule_engine,
    services: data.service_profiles !== undefined
      ? mapProfilesToServices(data.service_profiles)
      : current.services,
  };
  const raw = await putJSON<RawWAFConfig>(`${API_BASE}/config`, payload);
  return {
    engine_mode: mapRuleEngineToMode(raw.rule_engine),
    paranoia_level: raw.paranoia_level ?? 1,
    inbound_anomaly_threshold: raw.inbound_threshold ?? 5,
    outbound_anomaly_threshold: raw.outbound_threshold ?? 4,
    service_profiles: mapServicesToProfiles(raw.services),
  };
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

import { API_BASE, fetchJSON, postJSON, putJSON, deleteJSON } from "./shared";
import type { Condition, GroupOperator, Exclusion, DeployResult } from "./exclusions";

// ─── Rate Limit Types ───────────────────────────────────────────────
// Rate limit rules are now managed via the unified /api/rules endpoint
// with type="rate_limit". The CRUD functions below are compatibility
// wrappers that translate between the legacy RateLimitRule interface
// and the unified RuleExclusion model.

export type RLRuleAction = "deny" | "log_only";
export type RLRuleKey =
  | "client_ip"
  | "path"
  | "static"
  | "client_ip+path"
  | "client_ip+method"
  | `header:${string}`
  | `cookie:${string}`
  | `body_json:${string}`
  | `body_form:${string}`;

export interface RateLimitGlobalConfig {
  jitter: number;
  sweep_interval: string;
  distributed: boolean;
  read_interval: string;
  write_interval: string;
  purge_age: string;
}

// ─── Legacy RateLimitRule Type (compatibility) ──────────────────────
// RateLimitsPanel.tsx still uses this shape. These wrappers translate
// to/from the unified /api/rules endpoint.

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
  tags: string[];
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
  tags?: string[];
  enabled: boolean;
}

export type RateLimitRuleUpdateData = Partial<RateLimitRuleCreateData>;

function exclusionToRL(e: Exclusion): RateLimitRule {
  return {
    id: e.id,
    name: e.name,
    description: e.description,
    service: e.service ?? "*",
    conditions: e.conditions,
    group_operator: e.group_operator,
    key: (e.rate_limit_key ?? "client_ip") as RLRuleKey,
    events: e.rate_limit_events ?? 0,
    window: e.rate_limit_window ?? "1m",
    action: (e.rate_limit_action ?? "deny") as RLRuleAction,
    priority: e.priority ?? 0,
    tags: e.tags ?? [],
    enabled: e.enabled,
    created_at: e.created_at,
    updated_at: e.updated_at,
  };
}

function rlToUnifiedPayload(data: RateLimitRuleCreateData | RateLimitRuleUpdateData): Record<string, unknown> {
  const result: Record<string, unknown> = { type: "rate_limit" };
  if (data.name !== undefined) result.name = data.name;
  if (data.description !== undefined) result.description = data.description;
  if (data.service !== undefined) result.service = data.service;
  if (data.conditions !== undefined) result.conditions = data.conditions;
  if (data.group_operator !== undefined) result.group_operator = data.group_operator;
  if (data.key !== undefined) result.rate_limit_key = data.key;
  if (data.events !== undefined) result.rate_limit_events = data.events;
  if (data.window !== undefined) result.rate_limit_window = data.window;
  if (data.action !== undefined) result.rate_limit_action = data.action;
  if (data.priority !== undefined) result.priority = data.priority;
  if (data.tags !== undefined) result.tags = data.tags;
  if (data.enabled !== undefined) result.enabled = data.enabled;
  return result;
}

/** List rate limit rules (filters unified rules by type=rate_limit). */
export async function getRLRules(): Promise<RateLimitRule[]> {
  const all = await fetchJSON<Exclusion[]>(`${API_BASE}/rules`);
  return (all ?? []).filter(e => e.type === "rate_limit").map(exclusionToRL);
}

export async function createRLRule(data: RateLimitRuleCreateData): Promise<RateLimitRule> {
  const raw = await postJSON<Exclusion>(`${API_BASE}/rules`, rlToUnifiedPayload(data));
  return exclusionToRL(raw);
}

export async function updateRLRule(id: string, data: RateLimitRuleUpdateData): Promise<RateLimitRule> {
  const raw = await putJSON<Exclusion>(`${API_BASE}/rules/${encodeURIComponent(id)}`, rlToUnifiedPayload(data));
  return exclusionToRL(raw);
}

export async function deleteRLRule(id: string): Promise<void> {
  await deleteJSON<void>(`${API_BASE}/rules/${encodeURIComponent(id)}`);
}

export async function deployRLRules(): Promise<DeployResult> {
  return postJSON<DeployResult>(`${API_BASE}/deploy`, {});
}

export async function getRLGlobal(): Promise<RateLimitGlobalConfig> {
  const cfg = await fetchJSON<{ rate_limit_global?: RateLimitGlobalConfig }>(`${API_BASE}/config`);
  return cfg.rate_limit_global ?? { jitter: 0, sweep_interval: "", distributed: false, read_interval: "", write_interval: "", purge_age: "" };
}

export async function updateRLGlobal(config: RateLimitGlobalConfig): Promise<RateLimitGlobalConfig> {
  // Read current WAF config, update the rate_limit_global field, PUT back.
  const current = await fetchJSON<Record<string, unknown>>(`${API_BASE}/config`);
  current.rate_limit_global = config;
  await putJSON(`${API_BASE}/config`, current);
  return config;
}

export async function exportRLRules(): Promise<{ version: number; rules: RateLimitRule[] }> {
  const data = await fetchJSON<{ exclusions: Exclusion[] }>(`${API_BASE}/rules/export`);
  const rlRules = (data.exclusions ?? []).filter(e => e.type === "rate_limit").map(exclusionToRL);
  return { version: 1, rules: rlRules };
}

export async function importRLRules(data: { rules: RateLimitRuleCreateData[] }): Promise<{ status: string; imported: number }> {
  // Convert RL rules to unified exclusions and import via /api/rules/import
  const exclusions = data.rules.map(r => rlToUnifiedPayload(r));
  return postJSON<{ status: string; imported: number }>(`${API_BASE}/rules/import`, {
    version: 1,
    exclusions,
  });
}

export async function reorderRLRules(rlIds: string[]): Promise<RateLimitRule[]> {
  // The backend Reorder requires ALL rule IDs. Fetch all rules, replace
  // the RL subset with the new order, and send the full list.
  const all = await fetchJSON<Exclusion[]>(`${API_BASE}/rules`);
  const rlIdSet = new Set((all ?? []).filter(e => e.type === "rate_limit").map(e => e.id));
  const nonRL = (all ?? []).filter(e => !rlIdSet.has(e.id)).map(e => e.id);
  const fullOrder = [...nonRL, ...rlIds];
  const raw = await putJSON<Exclusion[]>(`${API_BASE}/rules/reorder`, { ids: fullOrder });
  return (raw ?? []).filter(e => e.type === "rate_limit").map(exclusionToRL);
}

// ─── Rate Limit Analytics Hits ──────────────────────────────────────

export interface RLRuleHitStats {
  total: number;
  sparkline: number[];
}

export interface RLRuleHitsResponse {
  [ruleId: string]: RLRuleHitStats;
}

export async function getRLRuleHits(hours = 24): Promise<RLRuleHitsResponse> {
  return fetchJSON<RLRuleHitsResponse>(`${API_BASE}/rate-rules/hits?hours=${hours}`);
}

// ─── Rate Limit Analytics (429 events) ──────────────────────────────

export interface RLTimelinePoint {
  hour: string;
  count: number;
  total_blocked: number;
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

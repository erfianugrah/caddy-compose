import { API_BASE, fetchJSON, postJSON, putJSON, deleteJSON } from "./shared";
import type { Condition, GroupOperator } from "./exclusions";

// ─── Rate Limit Rules (Policy Engine) ───────────────────────────────

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
    tags: raw.tags ?? [],
    enabled: raw.enabled ?? false,
    created_at: raw.created_at ?? "",
    updated_at: raw.updated_at ?? "",
  };
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

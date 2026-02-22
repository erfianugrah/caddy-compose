const API_BASE = "/api";

// ─── Summary / Overview ─────────────────────────────────────────────

export interface SummaryData {
  total_events: number;
  blocked: number;
  logged: number;
  unique_clients: number;
  unique_services: number;
  timeline: TimelinePoint[];
  top_services: ServiceStat[];
  top_clients: ClientStat[];
  recent_blocks: WAFEvent[];
  service_breakdown: ServiceBreakdown[];
}

export interface TimelinePoint {
  hour: string;
  total: number;
  blocked: number;
  logged: number;
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

export interface WAFEvent {
  id: string;
  timestamp: string;
  service: string;
  method: string;
  uri: string;
  client_ip: string;
  status: number;
  blocked: boolean;
  rule_id: string;
  rule_msg: string;
  severity: string;
  request_headers?: Record<string, string>;
  matched_data?: string;
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
  search?: string;
  hours?: number;
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

// ─── Exclusions / Policy ────────────────────────────────────────────

export type ExclusionType =
  | "SecRuleRemoveById"
  | "SecRuleRemoveByTag"
  | "SecRuleUpdateTargetById"
  | "SecRuleUpdateTargetByTag"
  | "ctl:ruleRemoveById"
  | "ctl:ruleRemoveByTag"
  | "ctl:ruleRemoveTargetById";

export interface Exclusion {
  id: string;
  name: string;
  description: string;
  type: ExclusionType;
  rule_id?: string;
  rule_tag?: string;
  variable?: string;
  uri?: string;
  service?: string;
  enabled: boolean;
  priority: number;
  raw_rule?: string;
  created_at: string;
  updated_at: string;
}

export interface ExclusionCreateData {
  name: string;
  description: string;
  type: ExclusionType;
  rule_id?: string;
  rule_tag?: string;
  variable?: string;
  uri?: string;
  service?: string;
  enabled: boolean;
  raw_rule?: string;
}

export interface ExclusionUpdateData extends Partial<ExclusionCreateData> {
  priority?: number;
}

export interface GeneratedConfig {
  pre_crs: string;
  post_crs: string;
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
export async function fetchSummary(hours?: number): Promise<SummaryData> {
  const qs = hours ? `?hours=${hours}` : "";
  return fetchJSON<SummaryData>(`${API_BASE}/summary${qs}`);
}

// Events
export async function fetchEvents(params: EventsParams = {}): Promise<EventsResponse> {
  const searchParams = new URLSearchParams();
  if (params.page) searchParams.set("page", String(params.page));
  if (params.per_page) searchParams.set("per_page", String(params.per_page));
  if (params.service) searchParams.set("service", params.service);
  if (params.blocked !== null && params.blocked !== undefined)
    searchParams.set("blocked", String(params.blocked));
  if (params.method) searchParams.set("method", params.method);
  if (params.search) searchParams.set("search", params.search);
  if (params.hours) searchParams.set("hours", String(params.hours));

  const qs = searchParams.toString();
  return fetchJSON<EventsResponse>(`${API_BASE}/events${qs ? `?${qs}` : ""}`);
}

// Services
export async function fetchServices(hours?: number): Promise<ServiceDetail[]> {
  const qs = hours ? `?hours=${hours}` : "";
  return fetchJSON<ServiceDetail[]>(`${API_BASE}/services${qs}`);
}

export async function fetchServiceDetail(service: string): Promise<ServiceDetail> {
  return fetchJSON<ServiceDetail>(
    `${API_BASE}/services/${encodeURIComponent(service)}`
  );
}

// IP Lookup
export async function lookupIP(ip: string): Promise<IPLookupData> {
  return fetchJSON<IPLookupData>(
    `${API_BASE}/lookup/${encodeURIComponent(ip)}`
  );
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

// Exclusions
export async function getExclusions(): Promise<Exclusion[]> {
  return fetchJSON<Exclusion[]>(`${API_BASE}/exclusions`);
}

export async function createExclusion(data: ExclusionCreateData): Promise<Exclusion> {
  return postJSON<Exclusion>(`${API_BASE}/exclusions`, data);
}

export async function updateExclusion(
  id: string,
  data: ExclusionUpdateData
): Promise<Exclusion> {
  return putJSON<Exclusion>(`${API_BASE}/exclusions/${encodeURIComponent(id)}`, data);
}

export async function deleteExclusion(id: string): Promise<void> {
  await deleteJSON<void>(`${API_BASE}/exclusions/${encodeURIComponent(id)}`);
}

export async function generateConfig(): Promise<GeneratedConfig> {
  return postJSON<GeneratedConfig>(`${API_BASE}/config/generate`, {});
}

export async function exportExclusions(): Promise<Exclusion[]> {
  return fetchJSON<Exclusion[]>(`${API_BASE}/exclusions/export`);
}

export async function importExclusions(data: Exclusion[]): Promise<{ imported: number }> {
  return postJSON<{ imported: number }>(`${API_BASE}/exclusions/import`, data);
}

// Config / Settings
export async function getConfig(): Promise<WAFConfig> {
  return fetchJSON<WAFConfig>(`${API_BASE}/config`);
}

export async function updateConfig(data: Partial<WAFConfig>): Promise<WAFConfig> {
  return putJSON<WAFConfig>(`${API_BASE}/config`, data);
}

import { API_BASE, fetchJSON } from "./shared";

// ─── Types ──────────────────────────────────────────────────────────

export interface ChallengeStats {
  issued: number;
  passed: number;
  failed: number;
  bypassed: number;
  pass_rate: number;
  fail_rate: number;
  bypass_rate: number;
  avg_solve_ms: number;
  avg_difficulty: number;
  score_buckets: ScoreBucket[];
  timeline: ChallengeHour[];
  top_clients: ChallengeClient[];
  top_services: ChallengeService[];
  top_ja4s: ChallengeJA4[];
  fail_reasons?: Record<string, number>;
  algorithm_breakdown?: AlgorithmStats[];
  solve_time_estimates: SolveTimeEstimate[];
}

export interface AlgorithmStats {
  algorithm: string;
  count: number;
  passed: number;
  failed: number;
  avg_solve_ms: number;
  avg_difficulty: number;
}

export interface SolveTimeEstimate {
  difficulty: number;
  algorithm: string;
  cores: number;
  expected_ms: number;
  label: string;
}

export interface ScoreBucket {
  label: string;
  min: number;
  max: number;
  count: number;
}

export interface ChallengeHour {
  hour: string;
  issued: number;
  passed: number;
  failed: number;
  bypassed: number;
}

export interface ChallengeClient {
  client: string;
  country?: string;
  issued: number;
  passed: number;
  failed: number;
  bypassed: number;
  avg_bot_score: number;
  max_bot_score: number;
  avg_solve_ms: number;
  unique_tokens: number;
}

export interface ChallengeService {
  service: string;
  issued: number;
  passed: number;
  failed: number;
  bypassed: number;
  fail_rate: number;
}

export interface ChallengeJA4 {
  ja4: string;
  total: number;
  passed: number;
  failed: number;
  clients: number;
}

// ─── Challenge Reputation ────────────────────────────────────────────

export interface ChallengeReputationResponse {
  ja4s: JA4Reputation[];
  clients: IPChallengeHistory[];
  alerts: ReputationAlert[];
  total_ja4s: number;
  total_clients: number;
  total_alerts: number;
}

export interface JA4Reputation {
  ja4: string;
  total_events: number;
  passed: number;
  failed: number;
  pass_rate: number;
  fail_rate: number;
  avg_bot_score: number;
  unique_ips: number;
  first_seen: string;
  last_seen: string;
  verdict: "trusted" | "suspicious" | "hostile";
}

export interface IPChallengeHistory {
  ip: string;
  country?: string;
  issued: number;
  passed: number;
  failed: number;
  bypassed: number;
  unique_tokens: number;
  unique_ja4s: number;
  avg_bot_score: number;
  max_bot_score: number;
  avg_solve_ms: number;
  first_seen: string;
  last_seen: string;
  flags?: string[];
}

export interface ReputationAlert {
  type: string;
  target: string;
  detail: string;
  count: number;
  severity: "high" | "medium" | "low";
}

// ─── Endpoint Discovery ─────────────────────────────────────────────

export interface DiscoveredEndpoint {
  service: string;
  method: string;
  path: string;
  requests: number;
  unique_ips: number;
  unique_ja4s: number;
  unique_uas: number;
  non_browser_pct: number;
  has_challenge: boolean;
  has_rate_limit: boolean;
  top_ja4?: string;
  status_codes?: Record<number, number>;
}

export interface EndpointDiscoveryResponse {
  endpoints: DiscoveredEndpoint[];
  total_requests: number;
  total_paths: number;
  uncovered_pct: number;
}

// ─── API Functions ──────────────────────────────────────────────────

export async function fetchChallengeStats(
  hours = 24,
  service?: string,
  client?: string,
): Promise<ChallengeStats> {
  const params = new URLSearchParams({ hours: String(hours) });
  if (service) params.set("service", service);
  if (client) params.set("client", client);
  return fetchJSON<ChallengeStats>(`${API_BASE}/challenge/stats?${params}`);
}

export async function fetchChallengeReputation(
  hours = 24,
  service?: string,
): Promise<ChallengeReputationResponse> {
  const params = new URLSearchParams({ hours: String(hours) });
  if (service) params.set("service", service);
  return fetchJSON<ChallengeReputationResponse>(`${API_BASE}/challenge/reputation?${params}`);
}

export async function fetchEndpointDiscovery(
  hours = 24,
  service?: string,
): Promise<EndpointDiscoveryResponse> {
  const params = new URLSearchParams({ hours: String(hours) });
  if (service) params.set("service", service);
  return fetchJSON<EndpointDiscoveryResponse>(`${API_BASE}/discovery/endpoints?${params}`);
}

// ─── OpenAPI Schema Management ──────────────────────────────────────

export interface OpenAPISchemaInfo {
  service: string;
  routes: number;
}

export async function fetchOpenAPISchemas(): Promise<OpenAPISchemaInfo[]> {
  const resp = await fetchJSON<{ schemas: OpenAPISchemaInfo[] }>(`${API_BASE}/discovery/schemas`);
  return resp.schemas || [];
}

export async function uploadOpenAPISchema(service: string, spec: string): Promise<{ service: string; routes: number; message: string }> {
  const res = await fetch(`${API_BASE}/discovery/schemas/${encodeURIComponent(service)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: spec,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || err.details || res.statusText);
  }
  return res.json();
}

export async function deleteOpenAPISchema(service: string): Promise<void> {
  const res = await fetch(`${API_BASE}/discovery/schemas/${encodeURIComponent(service)}`, {
    method: "DELETE",
  });
  if (!res.ok) throw new Error(res.statusText);
}

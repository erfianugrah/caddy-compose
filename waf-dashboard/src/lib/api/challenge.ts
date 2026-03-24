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

export async function fetchEndpointDiscovery(
  hours = 24,
  service?: string,
): Promise<EndpointDiscoveryResponse> {
  const params = new URLSearchParams({ hours: String(hours) });
  if (service) params.set("service", service);
  return fetchJSON<EndpointDiscoveryResponse>(`${API_BASE}/discovery/endpoints?${params}`);
}

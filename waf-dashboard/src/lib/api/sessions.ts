import { API_BASE, fetchJSON, putJSON } from "./shared";

// ─── Types ──────────────────────────────────────────────────────────

export interface SessionStats {
  active_sessions: number;
  suspicious_sessions: number;
  total_navigations: number;
  top_suspicious: SessionSummary[];
}

export interface SessionSummary {
  jti: string;
  ip: string;
  service: string;
  score: number;
  page_count: number;
  duration_ms: number;
  flags: string[];
  first_seen: string;
  last_seen: string;
}

export interface SessionScoringConfig {
  denylist_enabled: boolean;
  denylist_threshold: number;
  weight_single_page: number;
  weight_short_session: number;
  weight_uniform_dwell: number;
  weight_no_scroll: number;
  weight_no_interaction: number;
  weight_low_visible: number;
  organic_bonus: number;
  alert_ip_threshold: number;
  auto_escalate_enabled: boolean;
  auto_escalate_threshold: number;
  auto_escalate_ttl: string;
}

// ─── API ────────────────────────────────────────────────────────────

export async function fetchSessionStats(): Promise<SessionStats> {
  return fetchJSON<SessionStats>(`${API_BASE}/sessions/stats`);
}

export async function fetchSessionConfig(): Promise<SessionScoringConfig> {
  return fetchJSON<SessionScoringConfig>(`${API_BASE}/sessions/config`);
}

export async function updateSessionConfig(cfg: SessionScoringConfig): Promise<SessionScoringConfig> {
  return putJSON<SessionScoringConfig>(`${API_BASE}/sessions/config`, cfg);
}

// ─── Session List ───────────────────────────────────────────────────

export interface SessionListResponse {
  sessions: SessionDetail[];
  total: number;
  offset: number;
  limit: number;
}

export interface SessionDetail {
  jti: string;
  ip: string;
  ja4?: string;
  service: string;
  first_seen: string;
  last_seen: string;
  score: number;
  flags: string[];
  page_count: number;
  duration_ms: number;
  navigations: SessionNavigation[];
}

export interface SessionNavigation {
  ts: string;
  path: string;
  dwell_ms?: number;
  vis?: number;
  scr?: number;
  clk?: number;
  key?: boolean;
  type?: string;
}

export interface SessionAlert {
  type: string;
  ip?: string;
  service?: string;
  count: number;
  threshold: number;
  message: string;
  timestamp: string;
}

export async function fetchSessionList(params?: {
  offset?: number;
  limit?: number;
  ip?: string;
  service?: string;
  min_score?: number;
}): Promise<SessionListResponse> {
  const q = new URLSearchParams();
  if (params?.offset) q.set("offset", String(params.offset));
  if (params?.limit) q.set("limit", String(params.limit));
  if (params?.ip) q.set("ip", params.ip);
  if (params?.service) q.set("service", params.service);
  if (params?.min_score) q.set("min_score", String(params.min_score));
  const qs = q.toString();
  return fetchJSON<SessionListResponse>(`${API_BASE}/sessions/list${qs ? "?" + qs : ""}`);
}

export async function fetchSessionDetail(jti: string): Promise<SessionDetail> {
  return fetchJSON<SessionDetail>(`${API_BASE}/sessions/${encodeURIComponent(jti)}`);
}

export async function fetchSessionAlerts(): Promise<SessionAlert[]> {
  return fetchJSON<SessionAlert[]>(`${API_BASE}/sessions/alerts`);
}

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

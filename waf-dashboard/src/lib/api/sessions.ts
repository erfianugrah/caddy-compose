import { API_BASE, fetchJSON } from "./shared";

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

// ─── API ────────────────────────────────────────────────────────────

export async function fetchSessionStats(): Promise<SessionStats> {
  return fetchJSON<SessionStats>(`${API_BASE}/sessions/stats`);
}

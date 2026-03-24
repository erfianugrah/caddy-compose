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
  score_buckets: ScoreBucket[];
  timeline: ChallengeHour[];
  top_clients: ChallengeClient[];
  top_services: ChallengeService[];
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
}

export interface ChallengeService {
  service: string;
  issued: number;
  passed: number;
  failed: number;
  bypassed: number;
}

// ─── API Functions ──────────────────────────────────────────────────

export async function fetchChallengeStats(hours = 24): Promise<ChallengeStats> {
  return fetchJSON<ChallengeStats>(`${API_BASE}/challenge/stats?hours=${hours}`);
}

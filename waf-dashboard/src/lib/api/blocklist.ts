import { API_BASE, fetchJSON } from "./shared";

// ─── Blocklist (IPsum) ──────────────────────────────────────────────

export interface BlocklistStats {
  blocked_ips: number;
  last_updated: string;
  source: string;
  min_score: number;
  file_path: string;
}

export interface BlocklistCheckResult {
  ip: string;
  blocked: boolean;
  source: string;
}

export interface BlocklistRefreshResult {
  status: string;
  message: string;
  blocked_ips: number;
  min_score: number;
  last_updated: string;
  reloaded: boolean;
}

// ─── API Functions ──────────────────────────────────────────────────

export async function getBlocklistStats(): Promise<BlocklistStats> {
  return fetchJSON<BlocklistStats>(`${API_BASE}/blocklist/stats`);
}

export async function checkBlocklistIP(ip: string): Promise<BlocklistCheckResult> {
  return fetchJSON<BlocklistCheckResult>(`${API_BASE}/blocklist/check/${encodeURIComponent(ip)}`);
}

export async function refreshBlocklist(): Promise<BlocklistRefreshResult> {
  const res = await fetch(`${API_BASE}/blocklist/refresh`, { method: "POST" });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ message: res.statusText }));
    throw new Error(body.message || body.error || `HTTP ${res.status}`);
  }
  return res.json();
}

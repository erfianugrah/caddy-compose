import { API_BASE, fetchJSON, postJSON, putJSON, deleteJSON } from "./shared";

// ─── Types ──────────────────────────────────────────────────────────

export interface DosStatus {
  mode: "normal" | "spike";
  eps: number;
  peak_eps: number;
  jail_count: number;
  kernel_drop: boolean;
  strategy: string;
}

export interface JailEntry {
  ip: string;
  expires_at: string;
  infractions: number;
  reason: string;
  jailed_at: string;
  ttl: string;
}

export interface DosConfig {
  enabled: boolean;
  threshold: number;
  base_penalty: string;
  max_penalty: string;
  eps_trigger: number;
  eps_cooldown: number;
  cooldown_delay: string;
  max_buckets: number;
  max_reports: number;
  whitelist: string[];
  kernel_drop: boolean;
  strategy: string;
}

// ─── API Functions ──────────────────────────────────────────────────

export async function fetchDosStatus(): Promise<DosStatus> {
  return fetchJSON<DosStatus>(`${API_BASE}/dos/status`);
}

export async function fetchJail(): Promise<JailEntry[]> {
  return fetchJSON<JailEntry[]>(`${API_BASE}/dos/jail`);
}

export async function addJail(ip: string, ttl: string, reason: string): Promise<void> {
  await postJSON(`${API_BASE}/dos/jail`, { ip, ttl, reason });
}

export async function removeJail(ip: string): Promise<void> {
  await deleteJSON(`${API_BASE}/dos/jail/${encodeURIComponent(ip)}`);
}

export async function getDosConfig(): Promise<DosConfig> {
  return fetchJSON<DosConfig>(`${API_BASE}/dos/config`);
}

export async function updateDosConfig(config: DosConfig): Promise<DosConfig> {
  return putJSON<DosConfig>(`${API_BASE}/dos/config`, config);
}

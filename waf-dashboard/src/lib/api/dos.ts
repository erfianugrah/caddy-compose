import { API_BASE, fetchJSON, postJSON, putJSON, deleteJSON } from "./shared";

// ─── Types ──────────────────────────────────────────────────────────

export interface DosStatus {
  mode: "normal" | "spike";
  eps: number;
  peak_eps: number;
  jail_count: number;
  kernel_drop: boolean;
  strategy: string;
  eps_history: number[];
  ddos_events: number;
  updated_at: string;
  // Three-layer detection stats (v0.17.0+)
  rate_jail_count: number;
  behav_jail_count: number;
}

export interface JailEntry {
  ip: string;
  expires_at: string;
  infractions: number;
  reason: string;
  jailed_at: string;
  ttl: string;
  // Enriched fields (v0.17.0+)
  anomaly_score: number;
  host_count: number;
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
  // Three-layer detection config (v0.17.0+)
  global_rate_threshold: number;
  min_host_exculpation: number;
  profile_ttl: string;
}

// ─── IP Profiles (v0.17.0+) ─────────────────────────────────────────

export interface IPProfile {
  ip: string;
  is_jailed: boolean;
  infractions: number;
  jail_reason?: string;
  anomaly_score: number;
  recent_events: number;
  blocked_reqs: number;
  jailed_reqs: number;
  hosts?: string[];
  top_paths?: string[];
  ttl?: string;
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

export async function fetchProfiles(): Promise<IPProfile[]> {
  return fetchJSON<IPProfile[]>(`${API_BASE}/dos/profiles`);
}

// ─── Spike Reports ──────────────────────────────────────────────────

export interface SpikeReport {
  id: string;
  start_time: string;
  end_time: string;
  duration: string;
  total_events: number;
  peak_eps: number;
  jailed_ips: number;
  top_ips?: { key: string; count: number }[];
  top_paths?: { key: string; count: number }[];
}

export async function fetchSpikeReports(): Promise<SpikeReport[]> {
  return fetchJSON<SpikeReport[]>(`${API_BASE}/dos/reports`);
}

export async function fetchSpikeReport(id: string): Promise<SpikeReport> {
  return fetchJSON<SpikeReport>(`${API_BASE}/dos/reports/${encodeURIComponent(id)}`);
}

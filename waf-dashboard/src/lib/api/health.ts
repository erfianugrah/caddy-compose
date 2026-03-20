import { API_BASE, fetchJSON } from "./shared";

// ─── Health / Uptime ────────────────────────────────────────────────

export interface HealthData {
  status: string;
  version: string;
  crs_version: string;
  uptime: string;
}

export async function fetchHealth(init?: RequestInit): Promise<HealthData> {
  return fetchJSON<HealthData>(`${API_BASE}/health`, init);
}

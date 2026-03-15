import { API_BASE, fetchJSON, putJSON } from "./shared";

// ─── CORS Config API ────────────────────────────────────────────────

export interface CORSSettings {
  allowed_origins?: string[];
  allowed_methods?: string[];
  allowed_headers?: string[];
  exposed_headers?: string[];
  max_age?: number;
  allow_credentials?: boolean;
}

export interface CORSConfig {
  enabled?: boolean;
  global: CORSSettings;
  per_service?: Record<string, CORSSettings>;
}

export async function getCORS(): Promise<CORSConfig> {
  return fetchJSON<CORSConfig>(`${API_BASE}/cors`);
}

export async function updateCORS(config: CORSConfig): Promise<CORSConfig> {
  return putJSON<CORSConfig>(`${API_BASE}/cors`, config);
}

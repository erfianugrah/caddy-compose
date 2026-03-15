import { API_BASE, fetchJSON, putJSON } from "./shared";

// ─── Cache Control Config API ───────────────────────────────────────

export interface CacheRule {
  pattern: string;
  value: string;
  mode?: "set" | "default";
}

export interface CacheConfig {
  enabled?: boolean;
  global_rules?: CacheRule[];
  per_service?: Record<string, CacheRule[]>;
}

export async function getCache(): Promise<CacheConfig> {
  return fetchJSON<CacheConfig>(`${API_BASE}/cache`);
}

export async function updateCache(config: CacheConfig): Promise<CacheConfig> {
  return putJSON<CacheConfig>(`${API_BASE}/cache`, config);
}

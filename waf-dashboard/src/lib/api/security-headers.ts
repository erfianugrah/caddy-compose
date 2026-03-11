import { API_BASE, fetchJSON, postJSON, putJSON } from "./shared";

// ─── Security Headers ───────────────────────────────────────────────

export interface SecurityServiceConfig {
  profile?: string;
  headers?: Record<string, string>;
  remove?: string[];
}

export interface SecurityHeaderConfig {
  enabled?: boolean;
  profile: string;
  headers?: Record<string, string>;
  remove?: string[];
  services?: Record<string, SecurityServiceConfig>;
}

export interface SecurityProfile {
  name: string;
  description: string;
  headers: Record<string, string>;
  remove: string[];
}

export interface SecurityHeaderDeployResponse {
  status: string;
  message: string;
  reloaded: boolean;
  timestamp: string;
}

export interface ResolvedSecurityHeaders {
  headers: Record<string, string>;
  remove: string[];
}

export interface SecurityHeaderPreviewResponse {
  global: ResolvedSecurityHeaders;
  services: Record<string, ResolvedSecurityHeaders>;
}

// ─── API Functions ──────────────────────────────────────────────────

export async function getSecurityHeaders(): Promise<SecurityHeaderConfig> {
  return fetchJSON<SecurityHeaderConfig>(`${API_BASE}/security-headers`);
}

export async function updateSecurityHeaders(
  cfg: SecurityHeaderConfig,
): Promise<SecurityHeaderConfig> {
  return putJSON<SecurityHeaderConfig>(`${API_BASE}/security-headers`, cfg);
}

export async function listSecurityProfiles(): Promise<SecurityProfile[]> {
  return fetchJSON<SecurityProfile[]>(
    `${API_BASE}/security-headers/profiles`,
  );
}

export async function deploySecurityHeaders(): Promise<SecurityHeaderDeployResponse> {
  return postJSON<SecurityHeaderDeployResponse>(
    `${API_BASE}/security-headers/deploy`,
    {},
  );
}

export async function previewSecurityHeaders(): Promise<SecurityHeaderPreviewResponse> {
  return fetchJSON<SecurityHeaderPreviewResponse>(
    `${API_BASE}/security-headers/preview`,
  );
}

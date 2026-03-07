import { API_BASE, fetchJSON, postJSON, putJSON } from "./shared";

// ─── CSP (Content Security Policy) ─────────────────────────────────

export interface CSPPolicy {
  default_src?: string[];
  script_src?: string[];
  style_src?: string[];
  img_src?: string[];
  font_src?: string[];
  connect_src?: string[];
  media_src?: string[];
  frame_src?: string[];
  worker_src?: string[];
  object_src?: string[];
  child_src?: string[];
  manifest_src?: string[];
  base_uri?: string[];
  form_action?: string[];
  frame_ancestors?: string[];
  upgrade_insecure_requests?: boolean;
  raw_directives?: string;
}

export interface CSPServiceConfig {
  mode: "set" | "default" | "none";
  report_only: boolean;
  inherit: boolean;
  policy: CSPPolicy;
}

export interface CSPConfig {
  enabled?: boolean;
  global_defaults: CSPPolicy;
  services: Record<string, CSPServiceConfig>;
}

export interface CSPDeployResponse {
  status: string;
  message: string;
  files: string[];
  reloaded: boolean;
  timestamp: string;
}

export interface CSPPreviewEntry {
  mode: string;
  report_only: boolean;
  header: string;
}

export interface CSPPreviewResponse {
  services: Record<string, CSPPreviewEntry>;
}

// ─── API Functions ──────────────────────────────────────────────────

export async function getCSPConfig(): Promise<CSPConfig> {
  return fetchJSON<CSPConfig>(`${API_BASE}/csp`);
}

export async function updateCSPConfig(cfg: CSPConfig): Promise<CSPConfig> {
  return putJSON<CSPConfig>(`${API_BASE}/csp`, cfg);
}

export async function deployCSP(): Promise<CSPDeployResponse> {
  return postJSON<CSPDeployResponse>(`${API_BASE}/csp/deploy`, {});
}

export async function previewCSP(): Promise<CSPPreviewResponse> {
  return fetchJSON<CSPPreviewResponse>(`${API_BASE}/csp/preview`);
}

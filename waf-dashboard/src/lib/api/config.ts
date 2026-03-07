import { API_BASE, fetchJSON, putJSON } from "./shared";

// ─── Settings / Config ──────────────────────────────────────────────

export type WAFMode = "enabled" | "detection_only" | "disabled";

export interface WAFServiceSettings {
  mode: WAFMode;
  paranoia_level: number;
  inbound_threshold: number;
  outbound_threshold: number;
  disabled_groups?: string[];

  // CRS v4 extended settings (all optional — zero/absent = CRS default)
  blocking_paranoia_level?: number;
  detection_paranoia_level?: number;
  early_blocking?: boolean;
  sampling_percentage?: number;
  reporting_level?: number;
  enforce_bodyproc_urlencoded?: boolean;

  // Request policy
  allowed_methods?: string;
  allowed_request_content_type?: string;
  allowed_http_versions?: string;
  restricted_extensions?: string;
  restricted_headers?: string;

  // Argument limits
  max_num_args?: number;
  arg_name_length?: number;
  arg_length?: number;
  total_arg_length?: number;

  // File upload limits
  max_file_size?: number;
  combined_file_sizes?: number;

  // CRS built-in exclusion profiles
  crs_exclusions?: string[];
}

export interface WAFConfig {
  defaults: WAFServiceSettings;
  services: Record<string, WAFServiceSettings>;
}

// Sensitivity presets for the UI
export type WAFPreset = "strict" | "moderate" | "tuning" | "custom";

export function presetToSettings(preset: WAFPreset): Partial<WAFServiceSettings> {
  switch (preset) {
    case "strict": return { paranoia_level: 1, inbound_threshold: 5, outbound_threshold: 4 };
    case "moderate": return { paranoia_level: 1, inbound_threshold: 15, outbound_threshold: 15 };
    case "tuning": return { paranoia_level: 1, inbound_threshold: 10000, outbound_threshold: 10000 };
    case "custom": return {};
  }
}

export function settingsToPreset(s: WAFServiceSettings): WAFPreset {
  if (s.paranoia_level === 1 && s.inbound_threshold === 5 && s.outbound_threshold === 4) return "strict";
  if (s.paranoia_level === 1 && s.inbound_threshold === 15 && s.outbound_threshold === 15) return "moderate";
  if (s.inbound_threshold >= 10000 && s.outbound_threshold >= 10000) return "tuning";
  return "custom";
}

// ─── API Functions ──────────────────────────────────────────────────

export async function getConfig(): Promise<WAFConfig> {
  const raw = await fetchJSON<WAFConfig>(`${API_BASE}/config`);
  return {
    defaults: raw.defaults ?? { mode: "enabled", paranoia_level: 1, inbound_threshold: 5, outbound_threshold: 4 },
    services: raw.services ?? {},
  };
}

export async function updateConfig(data: WAFConfig): Promise<WAFConfig> {
  return putJSON<WAFConfig>(`${API_BASE}/config`, data);
}

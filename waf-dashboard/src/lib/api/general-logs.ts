import { API_BASE, fetchJSON } from "./shared";
import type { FilterOp } from "./shared";

// ─── General Log Viewer ─────────────────────────────────────────────

export interface SecurityHeaderInfo {
  has_csp: boolean;
  csp?: string;
  has_hsts: boolean;
  hsts?: string;
  has_x_content_type_options: boolean;
  x_content_type_options?: string;
  has_x_frame_options: boolean;
  x_frame_options?: string;
  has_referrer_policy: boolean;
  referrer_policy?: string;
  has_cors_origin: boolean;
  cors_origin?: string;
  has_permissions_policy: boolean;
  permissions_policy?: string;
}

export interface TLSInfo {
  version: string;       // e.g. "TLS 1.3"
  cipher_suite: string;  // e.g. "TLS_AES_128_GCM_SHA256"
  proto: string;         // ALPN: "h2", "http/1.1"
  ech: boolean;          // Encrypted Client Hello
  resumed: boolean;      // TLS session resumed
  server_name: string;   // SNI
}

export interface GeneralLogEvent {
  timestamp: string;
  client_ip: string;
  country?: string;
  service: string;
  method: string;
  uri: string;
  protocol: string;
  status: number;
  size: number;
  bytes_read: number;
  duration: number;
  user_agent: string;
  logger?: string;
  level?: string;
  request_id?: string;
  tls?: TLSInfo | null;
  security_headers: SecurityHeaderInfo;
}

export interface GeneralLogsResponse {
  total: number;
  events: GeneralLogEvent[];
}

export interface GeneralServiceCount {
  service: string;
  count: number;
  error_count: number;
  error_rate: number;
  avg_duration: number;
}

export interface GeneralURICount {
  uri: string;
  count: number;
  error_count: number;
  avg_duration: number;
}

export interface GeneralClientCount {
  client_ip: string;
  country?: string;
  count: number;
  error_count: number;
}

export interface HeaderCompliance {
  service: string;
  total: number;
  csp_rate: number;
  hsts_rate: number;
  x_content_type_options_rate: number;
  x_frame_options_rate: number;
  referrer_policy_rate: number;
  cors_origin_rate: number;
  permissions_policy_rate: number;
}

export interface GeneralLogsSummary {
  total_requests: number;
  error_count: number;
  client_error_count: number;
  avg_duration: number;
  p50_duration: number;
  p95_duration: number;
  p99_duration: number;
  status_distribution: Record<string, number>;
  top_services: GeneralServiceCount[];
  top_uris: GeneralURICount[];
  top_clients: GeneralClientCount[];
  header_compliance: HeaderCompliance[];
  recent_errors: GeneralLogEvent[];
}

export interface GeneralLogsParams {
  hours?: number;
  start?: string;
  end?: string;
  service?: string;
  service_op?: FilterOp;
  method?: string;
  method_op?: FilterOp;
  client?: string;
  client_op?: FilterOp;
  uri?: string;
  uri_op?: FilterOp;
  status?: string;
  status_op?: FilterOp;
  level?: string;
  level_op?: FilterOp;
  country?: string;
  country_op?: FilterOp;
  user_agent?: string;
  user_agent_op?: FilterOp;
  missing_header?: string;
  page?: number;
  per_page?: number;
}

// ─── Helpers ────────────────────────────────────────────────────────

function applyGeneralLogParams(sp: URLSearchParams, params?: GeneralLogsParams): void {
  if (!params) return;
  if (params.start && params.end) {
    sp.set("start", params.start);
    sp.set("end", params.end);
  } else if (params.hours) {
    sp.set("hours", String(params.hours));
  }
  const filters: [string, string | undefined, FilterOp | undefined][] = [
    ["service", params.service, params.service_op],
    ["method", params.method, params.method_op],
    ["client", params.client, params.client_op],
    ["uri", params.uri, params.uri_op],
    ["status", params.status, params.status_op],
    ["level", params.level, params.level_op],
    ["country", params.country, params.country_op],
    ["user_agent", params.user_agent, params.user_agent_op],
  ];
  for (const [field, value, op] of filters) {
    if (value) sp.set(field, value);
    if (op && op !== "eq") sp.set(`${field}_op`, op);
  }
  if (params.missing_header) sp.set("missing_header", params.missing_header);
}

// ─── API Functions ──────────────────────────────────────────────────

export async function fetchGeneralLogs(params?: GeneralLogsParams): Promise<GeneralLogsResponse> {
  const sp = new URLSearchParams();
  applyGeneralLogParams(sp, params);
  if (params?.page && params.per_page) {
    const limit = params.per_page;
    const offset = (params.page - 1) * limit;
    sp.set("limit", String(limit));
    sp.set("offset", String(offset));
  }
  const qs = sp.toString() ? `?${sp}` : "";
  return fetchJSON<GeneralLogsResponse>(`${API_BASE}/logs${qs}`);
}

export async function fetchGeneralLogsSummary(params?: GeneralLogsParams): Promise<GeneralLogsSummary> {
  const sp = new URLSearchParams();
  applyGeneralLogParams(sp, params);
  const qs = sp.toString() ? `?${sp}` : "";
  return fetchJSON<GeneralLogsSummary>(`${API_BASE}/logs/summary${qs}`);
}

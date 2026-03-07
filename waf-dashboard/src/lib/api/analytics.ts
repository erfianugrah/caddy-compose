import { API_BASE, fetchJSON } from "./shared";
import type { WAFEvent, TimelinePoint, CountryCount } from "./waf-events";
import { mapEvent } from "./waf-events";

// ─── IP Lookup / Analytics ──────────────────────────────────────────

export interface GeoIPInfo {
  country?: string;
  city?: string;
  region?: string;
  timezone?: string;
  asn?: string;
  org?: string;
  network?: string;
  source?: string;  // "cf_header" | "mmdb" | "api"
}

export interface IPLookupData {
  ip: string;
  geoip?: GeoIPInfo;
  first_seen: string;
  last_seen: string;
  total_events: number;
  blocked_count: number;
  events_total: number;
  services: { service: string; total: number; blocked: number; logged: number; rate_limited: number; ipsum_blocked: number; honeypot: number; scanner: number; policy: number }[];
  timeline: TimelinePoint[];
  recent_events: WAFEvent[];
}

export interface TopBlockedIP {
  client_ip: string;
  country?: string;
  total: number;
  blocked: number;
  block_rate: number;
  first_seen: string;
  last_seen: string;
}

export interface TopTargetedURI {
  uri: string;
  total: number;
  blocked: number;
  services: string[];
}

// ─── Raw types ──────────────────────────────────────────────────────

// Go API returns {ip, geoip?, total, blocked, first_seen, last_seen, services:[ServiceDetail], events:[RawEvent]}
interface RawIPLookup {
  ip: string;
  geoip?: GeoIPInfo;
  total: number;
  blocked: number;
  events_total: number;
  first_seen: string | null;
  last_seen: string | null;
  services: { service: string; total: number; blocked: number; logged: number; rate_limited: number; ipsum_blocked: number; honeypot: number; scanner: number; policy: number }[];
  events: {
    id: string;
    timestamp: string;
    service: string;
    method: string;
    uri: string;
    client_ip: string;
    country?: string;
    is_blocked: boolean;
    response_status: number;
    event_type?: string;
    user_agent?: string;
    rule_id?: number;
    rule_msg?: string;
    severity?: number;
    anomaly_score?: number;
    outbound_anomaly_score?: number;
    blocked_by?: string;
    matched_data?: string;
    rule_tags?: string[];
    matched_rules?: { id: number; msg: string; severity: number; matched_data?: string; file?: string; tags?: string[] }[];
    request_headers?: Record<string, string[]>;
    request_body?: string;
    request_args?: Record<string, string>;
  }[];
}

// ─── API Functions ──────────────────────────────────────────────────

export async function lookupIP(ip: string, limit = 50, offset = 0): Promise<IPLookupData> {
  const qs = `?limit=${limit}&offset=${offset}`;
  const raw = await fetchJSON<RawIPLookup>(
    `${API_BASE}/lookup/${encodeURIComponent(ip)}${qs}`
  );
  return {
    ip: raw.ip,
    geoip: raw.geoip,
    first_seen: raw.first_seen ?? "",
    last_seen: raw.last_seen ?? "",
    total_events: raw.total ?? 0,
    blocked_count: raw.blocked ?? 0,
    events_total: raw.events_total ?? raw.total ?? 0,
    services: (raw.services ?? []).map((s) => ({
      service: s.service,
      total: s.total,
      blocked: s.blocked,
      logged: s.logged ?? 0,
      rate_limited: s.rate_limited ?? 0,
      ipsum_blocked: s.ipsum_blocked ?? 0,
      honeypot: s.honeypot ?? 0,
      scanner: s.scanner ?? 0,
      policy: s.policy ?? 0,
    })),
    timeline: [],
    recent_events: (raw.events ?? []).map(mapEvent),
  };
}

export async function fetchTopBlockedIPs(hours?: number): Promise<TopBlockedIP[]> {
  const qs = hours ? `?hours=${hours}` : "";
  return fetchJSON<TopBlockedIP[]>(`${API_BASE}/analytics/top-ips${qs}`);
}

export async function fetchTopTargetedURIs(hours?: number): Promise<TopTargetedURI[]> {
  const qs = hours ? `?hours=${hours}` : "";
  return fetchJSON<TopTargetedURI[]>(`${API_BASE}/analytics/top-uris${qs}`);
}

export async function fetchTopCountries(hours?: number): Promise<CountryCount[]> {
  const qs = hours ? `?hours=${hours}` : "";
  return fetchJSON<CountryCount[]>(`${API_BASE}/analytics/top-countries${qs}`);
}

import type { FilterOp } from "@/lib/api";
import type { FilterField, LogFilterField, OpMeta, FieldMeta, FilterConfig } from "./types";

// ─── Operator metadata ──────────────────────────────────────────────

export const OP_META: Record<FilterOp, OpMeta> = {
  eq:       { label: "equals",          chip: "=" },
  neq:      { label: "not equals",      chip: "≠" },
  contains: { label: "contains",        chip: "~" },
  in:       { label: "is in",           chip: "in" },
  regex:    { label: "matches regex",   chip: "re" },
};

// ─── Shared option lists ────────────────────────────────────────────

export const EVENT_TYPE_OPTIONS: { value: string; label: string }[] = [
  { value: "detect_block", label: "CRS Blocked" },
  { value: "logged", label: "Logged" },
  { value: "rate_limited", label: "Rate Limited" },
  { value: "policy_skip", label: "Policy Skip" },
  { value: "policy_allow", label: "Policy Allow" },
  { value: "policy_block", label: "Policy Block" },
];

export const METHOD_OPTIONS: { value: string; label: string }[] = [
  { value: "GET", label: "GET" },
  { value: "POST", label: "POST" },
  { value: "PUT", label: "PUT" },
  { value: "DELETE", label: "DELETE" },
  { value: "PATCH", label: "PATCH" },
  { value: "HEAD", label: "HEAD" },
  { value: "OPTIONS", label: "OPTIONS" },
];

export const LEVEL_OPTIONS: { value: string; label: string }[] = [
  { value: "info", label: "Info" },
  { value: "error", label: "Error" },
];

export const STATUS_BUCKET_OPTIONS: { value: string; label: string }[] = [
  { value: "2xx", label: "2xx Success" },
  { value: "3xx", label: "3xx Redirect" },
  { value: "4xx", label: "4xx Client Error" },
  { value: "5xx", label: "5xx Server Error" },
];

export const MISSING_HEADER_OPTIONS: { value: string; label: string }[] = [
  { value: "csp", label: "Missing CSP" },
  { value: "hsts", label: "Missing HSTS" },
  { value: "xcto", label: "Missing X-Content-Type-Options" },
  { value: "xfo", label: "Missing X-Frame-Options" },
  { value: "referrer-policy", label: "Missing Referrer-Policy" },
  { value: "permissions-policy", label: "Missing Permissions-Policy" },
];

// ─── WAF Events filter config ───────────────────────────────────────

/** Operators available per WAF field. Order matters — first is default. */
export const FIELD_OPERATORS: Record<FilterField, FilterOp[]> = {
  service:     ["eq", "neq", "contains", "in", "regex"],
  client:      ["eq", "neq", "in"],
  event_type:  ["eq", "in"],
  blocked_by:  ["eq", "neq", "in"],
  method:      ["eq", "in"],
  rule_name:   ["eq", "contains", "regex"],
  uri:         ["eq", "neq", "contains", "regex"],
  status_code: ["eq", "neq", "in", "regex"],
  country:     ["eq", "neq", "in"],
  event_id:    ["eq"],
  request_id:  ["eq"],
  tag:         ["eq", "neq", "contains", "in", "regex"],
};

export const BLOCKED_BY_OPTIONS: { value: string; label: string }[] = [
  { value: "anomaly_inbound", label: "Anomaly (Inbound)" },
  { value: "anomaly_outbound", label: "Anomaly (Outbound)" },
  { value: "direct", label: "Direct (Policy Rule)" },
];

export const FILTER_FIELDS: Record<FilterField, FieldMeta> = {
  service: { label: "Service", placeholder: "Search services...", dynamic: true, dynamicKey: "services" },
  client: { label: "Client IP", placeholder: "e.g. 192.168.1.100" },
  event_type: { label: "Event Type", placeholder: "Select type", options: EVENT_TYPE_OPTIONS },
  blocked_by: { label: "Blocked By", placeholder: "Select source", options: BLOCKED_BY_OPTIONS },
  method: { label: "Method", placeholder: "Select method", options: METHOD_OPTIONS },
  rule_name: { label: "Policy Rule", placeholder: "Search rules...", dynamic: true, dynamicKey: "ruleNames" },
  uri: { label: "Path", placeholder: "e.g. /api/v1/users" },
  status_code: { label: "Status Code", placeholder: "e.g. 403 or 4\\d\\d" },
  country: { label: "Country", placeholder: "e.g. US, DE, CN" },
  event_id: { label: "Event ID", placeholder: "e.g. abc123..." },
  request_id: { label: "Request ID", placeholder: "Caddy request UUID" },
  tag: { label: "Tag", placeholder: "e.g. scanner, blocklist" },
};

export const FIELD_ORDER: FilterField[] = ["service", "client", "event_type", "blocked_by", "tag", "method", "rule_name", "uri", "status_code", "country"];

export const WAF_FILTER_CONFIG: FilterConfig<FilterField> = {
  fields: FILTER_FIELDS,
  operators: FIELD_OPERATORS,
  fieldOrder: FIELD_ORDER,
};

// ─── General Logs filter config ─────────────────────────────────────

export const LOG_FIELD_OPERATORS: Record<LogFilterField, FilterOp[]> = {
  service:        ["eq", "neq", "contains", "in", "regex"],
  method:         ["eq", "in"],
  status:         ["eq", "neq", "in"],
  client:         ["eq", "neq", "in"],
  uri:            ["eq", "neq", "contains", "regex"],
  level:          ["eq"],
  country:        ["eq", "neq", "in"],
  user_agent:     ["eq", "contains", "regex"],
  missing_header: ["eq"],
};

export const LOG_FILTER_FIELDS: Record<LogFilterField, FieldMeta> = {
  service:        { label: "Service", placeholder: "Search services...", dynamic: true, dynamicKey: "services" },
  method:         { label: "Method", placeholder: "Select method", options: METHOD_OPTIONS },
  status:         { label: "Status", placeholder: "e.g. 403", options: STATUS_BUCKET_OPTIONS },
  client:         { label: "Client IP", placeholder: "e.g. 192.168.1.100" },
  uri:            { label: "URI", placeholder: "e.g. /api/v1/users" },
  level:          { label: "Level", placeholder: "Select level", options: LEVEL_OPTIONS },
  country:        { label: "Country", placeholder: "e.g. US, DE, CN" },
  user_agent:     { label: "User Agent", placeholder: "e.g. Mozilla, curl" },
  missing_header: { label: "Missing Header", placeholder: "Select header", options: MISSING_HEADER_OPTIONS },
};

export const LOG_FIELD_ORDER: LogFilterField[] = ["service", "method", "status", "client", "uri", "level", "country", "user_agent", "missing_header"];

export const LOG_FILTER_CONFIG: FilterConfig<LogFilterField> = {
  fields: LOG_FILTER_FIELDS,
  operators: LOG_FIELD_OPERATORS,
  fieldOrder: LOG_FIELD_ORDER,
};

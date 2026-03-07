import type { FilterOp } from "@/lib/api";
import type { FilterField, OpMeta, FieldMeta } from "./types";

// ─── Operator metadata ──────────────────────────────────────────────

export const OP_META: Record<FilterOp, OpMeta> = {
  eq:       { label: "equals",          chip: "=" },
  neq:      { label: "not equals",      chip: "≠" },
  contains: { label: "contains",        chip: "~" },
  in:       { label: "is in",           chip: "in" },
  regex:    { label: "matches regex",   chip: "re" },
};

/** Operators available per field. Order matters — first is default. */
export const FIELD_OPERATORS: Record<FilterField, FilterOp[]> = {
  service:     ["eq", "neq", "contains", "in", "regex"],
  client:      ["eq", "neq", "in"],
  event_type:  ["eq", "in"],
  method:      ["eq", "in"],
  rule_name:   ["eq", "contains", "regex"],
  uri:         ["eq", "neq", "contains", "regex"],
  status_code: ["eq", "neq", "in", "regex"],
  country:     ["eq", "neq", "in"],
  event_id:    ["eq"],
};

// ─── Field metadata ─────────────────────────────────────────────────

export const EVENT_TYPE_OPTIONS: { value: string; label: string }[] = [
  { value: "blocked", label: "CRS Blocked" },
  { value: "logged", label: "Logged" },
  { value: "rate_limited", label: "Rate Limited" },
  { value: "ipsum_blocked", label: "IPsum Blocked" },
  { value: "honeypot", label: "Honeypot" },
  { value: "scanner", label: "Scanner" },
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

export const FILTER_FIELDS: Record<FilterField, FieldMeta> = {
  service: { label: "Service", placeholder: "Search services...", dynamic: true },
  client: { label: "Client IP", placeholder: "e.g. 192.168.1.100" },
  event_type: { label: "Event Type", placeholder: "Select type", options: EVENT_TYPE_OPTIONS },
  method: { label: "Method", placeholder: "Select method", options: METHOD_OPTIONS },
  rule_name: { label: "Policy Rule", placeholder: "Search rules...", dynamic: true },
  uri: { label: "Path", placeholder: "e.g. /api/v1/users" },
  status_code: { label: "Status Code", placeholder: "e.g. 403 or 4\\d\\d" },
  country: { label: "Country", placeholder: "e.g. US, DE, CN" },
  event_id: { label: "Event ID", placeholder: "e.g. abc123..." },
};

export const FIELD_ORDER: FilterField[] = ["service", "client", "event_type", "method", "rule_name", "uri", "status_code", "country"];

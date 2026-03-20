import type { ConditionField } from "@/lib/api";
import type { FieldDef } from "../policy/constants";
import { CONDITION_FIELDS } from "../policy/constants";

// ─── RL-specific condition fields (subset of WAF fields) ────────────

export const RL_CONDITION_FIELDS: ConditionField[] = [
  "ip", "path", "host", "method", "user_agent",
  "header", "query", "country", "cookie", "body", "body_json", "body_form",
  "uri_path", "referer", "http_version",
];

export const RL_FIELD_DEFS: FieldDef[] = CONDITION_FIELDS.filter(
  (f) => RL_CONDITION_FIELDS.includes(f.value)
);

// ─── Rate Limit Key Options ─────────────────────────────────────────

export const RL_KEY_OPTIONS: { value: string; label: string; description: string }[] = [
  { value: "client_ip", label: "Client IP", description: "Rate limit per client IP address" },
  { value: "path", label: "Path", description: "Rate limit per request path" },
  { value: "static", label: "Static (Global)", description: "Single shared counter for all matching requests" },
  { value: "client_ip+path", label: "Client IP + Path", description: "Rate limit per IP and path combination" },
  { value: "client_ip+method", label: "Client IP + Method", description: "Rate limit per IP and HTTP method" },
  { value: "challenge_cookie", label: "Challenge Cookie", description: "Rate limit per solved challenge token — prevents cookie abuse after PoW" },
  { value: "header:", label: "Header Value", description: "Rate limit per request header value (e.g., header:X-API-Key)" },
  { value: "cookie:", label: "Cookie Value", description: "Rate limit per cookie value (e.g., cookie:session_id)" },
  { value: "body_json:", label: "Body JSON Field", description: "Rate limit per JSON body field value (e.g., body_json:.user.api_key)" },
  { value: "body_form:", label: "Body Form Field", description: "Rate limit per form field value (e.g., body_form:action)" },
];

// ─── Window Options ─────────────────────────────────────────────────

export const WINDOW_OPTIONS = [
  { value: "10s", label: "10 seconds" },
  { value: "30s", label: "30 seconds" },
  { value: "1m", label: "1 minute" },
  { value: "2m", label: "2 minutes" },
  { value: "5m", label: "5 minutes" },
  { value: "10m", label: "10 minutes" },
  { value: "30m", label: "30 minutes" },
  { value: "1h", label: "1 hour" },
];

export const WINDOW_VALUES = new Set(WINDOW_OPTIONS.map((o) => o.value));

// ─── Page Size ──────────────────────────────────────────────────────

export const RL_RULES_PAGE_SIZE = 15;

import type { ExclusionType, ConditionField, ConditionOperator } from "@/lib/api";

// ─── Quick Action Types ─────────────────────────────────────────────

export type QuickActionType = "allow" | "block" | "challenge" | "skip" | "detect";

export const QUICK_ACTIONS: { value: QuickActionType; label: string; description: string; iconName: "ShieldCheck" | "ShieldBan" | "ShieldQuestion" | "ShieldMinus" | "ShieldAlert" }[] = [
  { value: "allow", label: "Allow", description: "Full bypass — terminates evaluation immediately", iconName: "ShieldCheck" },
  { value: "block", label: "Block", description: "Deny requests by IP, path, or user agent", iconName: "ShieldBan" },
  { value: "challenge", label: "Challenge", description: "Proof-of-work verification for browser clients", iconName: "ShieldQuestion" },
  { value: "skip", label: "Skip", description: "Selective bypass — skip specific rules or phases", iconName: "ShieldMinus" },
  { value: "detect", label: "Detect", description: "Trigger a detection — runs matching CRS rules at configured severity", iconName: "ShieldAlert" },
];

// ─── All Exclusion Types ────────────────────────────────────────────

export const ALL_EXCLUSION_TYPES: { value: ExclusionType; label: string; description: string; group: "quick" | "advanced" }[] = [
  { value: "allow", label: "Allow", description: "Full bypass — terminates evaluation", group: "quick" },
  { value: "block", label: "Block", description: "Deny matching requests", group: "quick" },
  { value: "challenge", label: "Challenge", description: "Proof-of-work verification for browser clients", group: "advanced" },
  { value: "skip", label: "Skip", description: "Selective bypass — skip rules or phases", group: "quick" },
  { value: "detect", label: "Detect", description: "Trigger detection with severity level", group: "quick" },
  { value: "response_header", label: "Response Header", description: "Set, add, or remove response headers", group: "advanced" },
];

// ─── CRS Rule Tags ──────────────────────────────────────────────────

export const RULE_TAGS = [
  "attack-sqli", "attack-xss", "attack-rce", "attack-lfi", "attack-rfi",
  "attack-protocol", "attack-injection-php", "attack-injection-generic",
  "attack-reputation-ip", "attack-disclosure", "attack-fixation",
  "paranoia-level/1", "paranoia-level/2", "paranoia-level/3", "paranoia-level/4",
];

// ─── Condition Builder Field/Operator Definitions ───────────────────

export interface FieldDef {
  value: ConditionField;
  label: string;
  operators: { value: ConditionOperator; label: string }[];
  placeholder: string;
  /** Persistent hint text shown below the value input for syntax guidance. */
  hint?: string;
}

export const CONDITION_FIELDS: FieldDef[] = [
  {
    value: "ip", label: "IP Address",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "in", label: "is in" },
      { value: "not_in", label: "is not in" },
      { value: "ip_match", label: "is in (CIDR)" },
      { value: "not_ip_match", label: "is not in (CIDR)" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., 195.240.81.42 or 10.0.0.0/8",
  },
  {
    value: "path", label: "Path / URI",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "not_contains", label: "does not contain" },
      { value: "begins_with", label: "begins with" },
      { value: "not_begins_with", label: "does not begin with" },
      { value: "ends_with", label: "ends with" },
      { value: "not_ends_with", label: "does not end with" },
      { value: "regex", label: "matches regex" },
      { value: "not_regex", label: "does not match regex" },
      { value: "phrase_match", label: "phrase match" },
      { value: "not_phrase_match", label: "no phrase match" },
      { value: "in", label: "is in" },
      { value: "not_in", label: "is not in" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., /api/v3/, /socket.io/",
  },
  {
    value: "host", label: "Host / Service",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "not_contains", label: "does not contain" },
      { value: "begins_with", label: "begins with" },
      { value: "not_begins_with", label: "does not begin with" },
      { value: "ends_with", label: "ends with" },
      { value: "not_ends_with", label: "does not end with" },
      { value: "regex", label: "matches regex" },
      { value: "not_regex", label: "does not match regex" },
      { value: "phrase_match", label: "phrase match" },
      { value: "not_phrase_match", label: "no phrase match" },
      { value: "in", label: "is in" },
      { value: "not_in", label: "is not in" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., radarr.erfi.io",
  },
  {
    value: "method", label: "HTTP Method",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "in", label: "is in" },
      { value: "not_in", label: "is not in" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., POST or GET|POST|PUT",
  },
  {
    value: "user_agent", label: "User Agent",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "not_contains", label: "does not contain" },
      { value: "begins_with", label: "begins with" },
      { value: "not_begins_with", label: "does not begin with" },
      { value: "ends_with", label: "ends with" },
      { value: "not_ends_with", label: "does not end with" },
      { value: "regex", label: "matches regex" },
      { value: "not_regex", label: "does not match regex" },
      { value: "phrase_match", label: "phrase match" },
      { value: "not_phrase_match", label: "no phrase match" },
      { value: "in", label: "is in" },
      { value: "not_in", label: "is not in" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., BadBot.*, curl/.*",
  },
  {
    value: "header", label: "Request Header",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "not_contains", label: "does not contain" },
      { value: "begins_with", label: "begins with" },
      { value: "not_begins_with", label: "does not begin with" },
      { value: "ends_with", label: "ends with" },
      { value: "not_ends_with", label: "does not end with" },
      { value: "regex", label: "matches regex" },
      { value: "not_regex", label: "does not match regex" },
      { value: "phrase_match", label: "phrase match" },
      { value: "not_phrase_match", label: "no phrase match" },
      { value: "in", label: "is in" },
      { value: "not_in", label: "is not in" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., X-Custom-Header:value",
    hint: "Syntax: HeaderName:value — name before colon is the header, value after is the match target.",
  },
  {
    value: "query", label: "Query String",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "not_contains", label: "does not contain" },
      { value: "begins_with", label: "begins with" },
      { value: "not_begins_with", label: "does not begin with" },
      { value: "ends_with", label: "ends with" },
      { value: "not_ends_with", label: "does not end with" },
      { value: "regex", label: "matches regex" },
      { value: "not_regex", label: "does not match regex" },
      { value: "phrase_match", label: "phrase match" },
      { value: "not_phrase_match", label: "no phrase match" },
      { value: "in", label: "is in" },
      { value: "not_in", label: "is not in" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., debug=true",
  },
  {
    value: "country", label: "Country (GeoIP)",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "in", label: "is in" },
      { value: "not_in", label: "is not in" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., CN or CN RU KP (ISO 3166-1 alpha-2)",
  },
  {
    value: "cookie", label: "Cookie",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "not_contains", label: "does not contain" },
      { value: "begins_with", label: "begins with" },
      { value: "not_begins_with", label: "does not begin with" },
      { value: "ends_with", label: "ends with" },
      { value: "not_ends_with", label: "does not end with" },
      { value: "regex", label: "matches regex" },
      { value: "not_regex", label: "does not match regex" },
      { value: "phrase_match", label: "phrase match" },
      { value: "not_phrase_match", label: "no phrase match" },
      { value: "in", label: "is in" },
      { value: "not_in", label: "is not in" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., session_id:abc123",
    hint: "Syntax: cookie_name:value — name before colon is the cookie, value after is the match target.",
  },
  {
    value: "body", label: "Request Body",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "not_contains", label: "does not contain" },
      { value: "begins_with", label: "begins with" },
      { value: "not_begins_with", label: "does not begin with" },
      { value: "ends_with", label: "ends with" },
      { value: "not_ends_with", label: "does not end with" },
      { value: "regex", label: "matches regex" },
      { value: "not_regex", label: "does not match regex" },
      { value: "phrase_match", label: "phrase match" },
      { value: "not_phrase_match", label: "no phrase match" },
      { value: "in", label: "is in" },
      { value: "not_in", label: "is not in" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., <script> or password=.*",
  },
  {
    value: "body_json", label: "Body JSON Field",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "not_contains", label: "does not contain" },
      { value: "begins_with", label: "begins with" },
      { value: "not_begins_with", label: "does not begin with" },
      { value: "ends_with", label: "ends with" },
      { value: "not_ends_with", label: "does not end with" },
      { value: "regex", label: "matches regex" },
      { value: "not_regex", label: "does not match regex" },
      { value: "phrase_match", label: "phrase match" },
      { value: "not_phrase_match", label: "no phrase match" },
      { value: "in", label: "is in" },
      { value: "not_in", label: "is not in" },
      { value: "exists", label: "exists" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., .user.role:admin",
    hint: "Syntax: .dot.path:value — dot-path navigates JSON, colon separates match value. Use .path for exists.",
  },
  {
    value: "body_form", label: "Body Form Field",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "not_contains", label: "does not contain" },
      { value: "begins_with", label: "begins with" },
      { value: "not_begins_with", label: "does not begin with" },
      { value: "ends_with", label: "ends with" },
      { value: "not_ends_with", label: "does not end with" },
      { value: "regex", label: "matches regex" },
      { value: "not_regex", label: "does not match regex" },
      { value: "phrase_match", label: "phrase match" },
      { value: "not_phrase_match", label: "no phrase match" },
      { value: "in", label: "is in" },
      { value: "not_in", label: "is not in" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., action:delete",
    hint: "Syntax: field_name:value — name before colon is the form field, value after is the match target.",
  },
  {
    value: "args", label: "Parameter (Args)",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "not_contains", label: "does not contain" },
      { value: "begins_with", label: "begins with" },
      { value: "not_begins_with", label: "does not begin with" },
      { value: "ends_with", label: "ends with" },
      { value: "not_ends_with", label: "does not end with" },
      { value: "regex", label: "matches regex" },
      { value: "not_regex", label: "does not match regex" },
      { value: "phrase_match", label: "phrase match" },
      { value: "not_phrase_match", label: "no phrase match" },
      { value: "in", label: "is in" },
      { value: "not_in", label: "is not in" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., action:delete",
    hint: "Syntax: param_name:value — name before colon is the parameter, value after is the match target.",
  },
  {
    value: "uri_path", label: "URI Path (no query)",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "not_contains", label: "does not contain" },
      { value: "begins_with", label: "begins with" },
      { value: "not_begins_with", label: "does not begin with" },
      { value: "ends_with", label: "ends with" },
      { value: "not_ends_with", label: "does not end with" },
      { value: "regex", label: "matches regex" },
      { value: "not_regex", label: "does not match regex" },
      { value: "phrase_match", label: "phrase match" },
      { value: "not_phrase_match", label: "no phrase match" },
      { value: "in", label: "is in" },
      { value: "not_in", label: "is not in" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., /api/v1/upload",
  },
  {
    value: "referer", label: "Referer",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "not_contains", label: "does not contain" },
      { value: "begins_with", label: "begins with" },
      { value: "not_begins_with", label: "does not begin with" },
      { value: "ends_with", label: "ends with" },
      { value: "not_ends_with", label: "does not end with" },
      { value: "regex", label: "matches regex" },
      { value: "not_regex", label: "does not match regex" },
      { value: "phrase_match", label: "phrase match" },
      { value: "not_phrase_match", label: "no phrase match" },
      { value: "in", label: "is in" },
      { value: "not_in", label: "is not in" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., https://example.com/page",
  },
  {
    value: "response_header", label: "Response Header",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "not_contains", label: "does not contain" },
      { value: "begins_with", label: "begins with" },
      { value: "not_begins_with", label: "does not begin with" },
      { value: "ends_with", label: "ends with" },
      { value: "not_ends_with", label: "does not end with" },
      { value: "regex", label: "matches regex" },
      { value: "not_regex", label: "does not match regex" },
      { value: "phrase_match", label: "phrase match" },
      { value: "not_phrase_match", label: "no phrase match" },
      { value: "in", label: "is in" },
      { value: "not_in", label: "is not in" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., Content-Type:application/json",
  },
  {
    value: "response_status", label: "Response Status",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "gt", label: "greater than" },
      { value: "ge", label: "greater or equal" },
      { value: "lt", label: "less than" },
      { value: "le", label: "less or equal" },
      { value: "in", label: "is in" },
      { value: "not_in", label: "is not in" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., 403 or 401 403 500",
  },
  {
    value: "http_version", label: "HTTP Version",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "in", label: "is in" },
      { value: "not_in", label: "is not in" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., HTTP/1.0 or HTTP/2.0",
  },
  {
    value: "ja4", label: "JA4 TLS Fingerprint",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "begins_with", label: "begins with" },
      { value: "regex", label: "matches regex" },
      { value: "in", label: "is in" },
      { value: "not_in", label: "is not in" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., t13d1516h2_8daaf6152771_e5627efa2ab1",
    hint: "TLS client fingerprint computed from the ClientHello. Identifies browser/client implementation. Empty for non-TLS connections.",
  },
  // ─── Aggregate Fields ────────────────────────────────────────────
  {
    value: "all_args", label: "All Args (names+values)",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "not_contains", label: "does not contain" },
      { value: "begins_with", label: "begins with" },
      { value: "not_begins_with", label: "does not begin with" },
      { value: "ends_with", label: "ends with" },
      { value: "not_ends_with", label: "does not end with" },
      { value: "regex", label: "matches regex" },
      { value: "not_regex", label: "does not match regex" },
      { value: "phrase_match", label: "phrase match" },
      { value: "not_phrase_match", label: "no phrase match" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "Matches across all query/form parameter names and values",
    hint: "Aggregate: searches all ARGS names and values in a single check.",
  },
  {
    value: "all_args_names", label: "All Arg Names",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "not_contains", label: "does not contain" },
      { value: "begins_with", label: "begins with" },
      { value: "not_begins_with", label: "does not begin with" },
      { value: "ends_with", label: "ends with" },
      { value: "not_ends_with", label: "does not end with" },
      { value: "regex", label: "matches regex" },
      { value: "not_regex", label: "does not match regex" },
      { value: "phrase_match", label: "phrase match" },
      { value: "not_phrase_match", label: "no phrase match" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "Matches across all query/form parameter names",
    hint: "Aggregate: searches all ARGS_NAMES.",
  },
  {
    value: "all_args_values", label: "All Arg Values",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "not_contains", label: "does not contain" },
      { value: "begins_with", label: "begins with" },
      { value: "not_begins_with", label: "does not begin with" },
      { value: "ends_with", label: "ends with" },
      { value: "not_ends_with", label: "does not end with" },
      { value: "regex", label: "matches regex" },
      { value: "not_regex", label: "does not match regex" },
      { value: "phrase_match", label: "phrase match" },
      { value: "not_phrase_match", label: "no phrase match" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "Matches across all query/form parameter values",
    hint: "Aggregate: searches all ARGS values.",
  },
  {
    value: "all_headers", label: "All Headers (names+values)",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "not_contains", label: "does not contain" },
      { value: "begins_with", label: "begins with" },
      { value: "not_begins_with", label: "does not begin with" },
      { value: "ends_with", label: "ends with" },
      { value: "not_ends_with", label: "does not end with" },
      { value: "regex", label: "matches regex" },
      { value: "not_regex", label: "does not match regex" },
      { value: "phrase_match", label: "phrase match" },
      { value: "not_phrase_match", label: "no phrase match" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "Matches across all request header names and values",
    hint: "Aggregate: searches all REQUEST_HEADERS names and values.",
  },
  {
    value: "all_headers_names", label: "All Header Names",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "not_contains", label: "does not contain" },
      { value: "begins_with", label: "begins with" },
      { value: "not_begins_with", label: "does not begin with" },
      { value: "ends_with", label: "ends with" },
      { value: "not_ends_with", label: "does not end with" },
      { value: "regex", label: "matches regex" },
      { value: "not_regex", label: "does not match regex" },
      { value: "phrase_match", label: "phrase match" },
      { value: "not_phrase_match", label: "no phrase match" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "Matches across all request header names",
    hint: "Aggregate: searches all REQUEST_HEADERS names.",
  },
  {
    value: "all_cookies", label: "All Cookies (names+values)",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "not_contains", label: "does not contain" },
      { value: "begins_with", label: "begins with" },
      { value: "not_begins_with", label: "does not begin with" },
      { value: "ends_with", label: "ends with" },
      { value: "not_ends_with", label: "does not end with" },
      { value: "regex", label: "matches regex" },
      { value: "not_regex", label: "does not match regex" },
      { value: "phrase_match", label: "phrase match" },
      { value: "not_phrase_match", label: "no phrase match" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "Matches across all cookie names and values",
    hint: "Aggregate: searches all REQUEST_COOKIES names and values.",
  },
  {
    value: "all_cookies_names", label: "All Cookie Names",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "not_contains", label: "does not contain" },
      { value: "begins_with", label: "begins with" },
      { value: "not_begins_with", label: "does not begin with" },
      { value: "ends_with", label: "ends with" },
      { value: "not_ends_with", label: "does not end with" },
      { value: "regex", label: "matches regex" },
      { value: "not_regex", label: "does not match regex" },
      { value: "phrase_match", label: "phrase match" },
      { value: "not_phrase_match", label: "no phrase match" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "Matches across all cookie names",
    hint: "Aggregate: searches all REQUEST_COOKIES names.",
  },
  {
    value: "request_combined", label: "Request Combined",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "not_contains", label: "does not contain" },
      { value: "begins_with", label: "begins with" },
      { value: "not_begins_with", label: "does not begin with" },
      { value: "ends_with", label: "ends with" },
      { value: "not_ends_with", label: "does not end with" },
      { value: "regex", label: "matches regex" },
      { value: "not_regex", label: "does not match regex" },
      { value: "phrase_match", label: "phrase match" },
      { value: "not_phrase_match", label: "no phrase match" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "Matches across args, headers, cookies, body, path, and user agent",
    hint: "Aggregate: extracts values from ALL CRS variable sources for broad detection.",
  },
  // ─── Count Fields (numeric comparison on element count) ─────────
  {
    value: "count:all_args", label: "Count: All Args",
    operators: [
      { value: "gt", label: "greater than" },
      { value: "ge", label: "greater or equal" },
      { value: "lt", label: "less than" },
      { value: "le", label: "less or equal" },
    ],
    placeholder: "e.g., 255",
    hint: "Number of arguments (query + form parameters). Numeric comparison only.",
  },
  {
    value: "count:all_args_names", label: "Count: Arg Names",
    operators: [
      { value: "gt", label: "greater than" },
      { value: "ge", label: "greater or equal" },
      { value: "lt", label: "less than" },
      { value: "le", label: "less or equal" },
    ],
    placeholder: "e.g., 50",
    hint: "Number of distinct argument names.",
  },
  {
    value: "count:all_args_values", label: "Count: Arg Values",
    operators: [
      { value: "gt", label: "greater than" },
      { value: "ge", label: "greater or equal" },
      { value: "lt", label: "less than" },
      { value: "le", label: "less or equal" },
    ],
    placeholder: "e.g., 255",
    hint: "Number of argument values.",
  },
  {
    value: "count:all_headers", label: "Count: All Headers",
    operators: [
      { value: "gt", label: "greater than" },
      { value: "ge", label: "greater or equal" },
      { value: "lt", label: "less than" },
      { value: "le", label: "less or equal" },
    ],
    placeholder: "e.g., 50",
    hint: "Number of request headers (names + values).",
  },
  {
    value: "count:all_headers_names", label: "Count: Header Names",
    operators: [
      { value: "gt", label: "greater than" },
      { value: "ge", label: "greater or equal" },
      { value: "lt", label: "less than" },
      { value: "le", label: "less or equal" },
    ],
    placeholder: "e.g., 30",
    hint: "Number of distinct request header names.",
  },
  {
    value: "count:all_cookies", label: "Count: All Cookies",
    operators: [
      { value: "gt", label: "greater than" },
      { value: "ge", label: "greater or equal" },
      { value: "lt", label: "less than" },
      { value: "le", label: "less or equal" },
    ],
    placeholder: "e.g., 20",
    hint: "Number of cookies (names + values).",
  },
  {
    value: "count:all_cookies_names", label: "Count: Cookie Names",
    operators: [
      { value: "gt", label: "greater than" },
      { value: "ge", label: "greater or equal" },
      { value: "lt", label: "less than" },
      { value: "le", label: "less or equal" },
    ],
    placeholder: "e.g., 10",
    hint: "Number of distinct cookie names.",
  },
];

// ─── Helpers ────────────────────────────────────────────────────────

export function getFieldDef(field: ConditionField): FieldDef {
  return CONDITION_FIELDS.find((f) => f.value === field) ?? CONDITION_FIELDS[0];
}

// ─── Advanced Form Types ────────────────────────────────────────────

export interface AdvancedFormState {
  name: string;
  description: string;
  type: ExclusionType;
  phase: import("@/lib/api").RulePhase | undefined;
  severity: string;
  detect_paranoia_level: number;
  skip_targets: import("@/lib/api").SkipTargets;
  conditions: import("@/lib/api").Condition[];
  group_operator: import("@/lib/api").GroupOperator;
  tags: string[];
  enabled: boolean;
  // challenge fields
  challenge_difficulty: number;
  challenge_algorithm: string;
  challenge_ttl: string;
  challenge_bind_ip: boolean;
  // response header fields
  header_set: Record<string, string>;
  header_add: Record<string, string>;
  header_remove: string[];
  header_default: Record<string, string>;
}

export const emptyAdvancedForm: AdvancedFormState = {
  name: "",
  description: "",
  type: "allow",
  phase: undefined,
  severity: "",
  detect_paranoia_level: 0,
  skip_targets: {},
  conditions: [],
  group_operator: "and",
  tags: [],
  enabled: true,
  // challenge defaults
  challenge_difficulty: 4,
  challenge_algorithm: "fast",
  challenge_ttl: "1h",
  challenge_bind_ip: true,
  // response header defaults
  header_set: {},
  header_add: {},
  header_remove: [],
  header_default: {},
};

// ─── Phase-Filtered Field Sets ──────────────────────────────────────

const RESPONSE_PHASE_FIELD_IDS = new Set(["response_header", "response_status", "response_content_type"]);

/** Inbound-only fields (excludes response-phase fields). */
export const INBOUND_FIELD_DEFS = CONDITION_FIELDS.filter(f => !RESPONSE_PHASE_FIELD_IDS.has(f.value));

/** All fields including response-phase (for outbound rules). */
export const OUTBOUND_FIELD_DEFS = CONDITION_FIELDS;

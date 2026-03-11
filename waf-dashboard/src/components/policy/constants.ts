import type { ExclusionType, ConditionField, ConditionOperator } from "@/lib/api";

// ─── Quick Action Types ─────────────────────────────────────────────

export type QuickActionType = "allow" | "block" | "skip_rule" | "anomaly";

export const QUICK_ACTIONS: { value: QuickActionType; label: string; description: string; iconName: "ShieldCheck" | "ShieldBan" | "SkipForward" | "ShieldAlert" }[] = [
  { value: "allow", label: "Allow", description: "Whitelist IP, path, or service — bypass WAF checks", iconName: "ShieldCheck" },
  { value: "block", label: "Block", description: "Deny requests by IP, path, or user agent", iconName: "ShieldBan" },
  { value: "skip_rule", label: "Skip / Bypass", description: "Skip specific CRS rules for a path or service", iconName: "SkipForward" },
  { value: "anomaly", label: "Anomaly Score", description: "Add anomaly score points — heuristic bot/threat signals", iconName: "ShieldAlert" },
];

// ─── All Exclusion Types ────────────────────────────────────────────

export const ALL_EXCLUSION_TYPES: { value: ExclusionType; label: string; description: string; group: "quick" | "advanced" | "runtime" }[] = [
  // Quick action types (mainly created from Quick Actions tab, but editable here)
  { value: "allow", label: "Allow", description: "Whitelist — bypass WAF checks", group: "quick" },
  { value: "block", label: "Block", description: "Deny matching requests", group: "quick" },
  { value: "skip_rule", label: "Skip / Bypass", description: "Skip specific CRS rules", group: "quick" },
  { value: "anomaly", label: "Anomaly Score", description: "Add anomaly score points for heuristic signals", group: "quick" },
  // Global exclusions — applied at deploy time to all requests unconditionally
  { value: "SecRuleRemoveById", label: "Disable rule globally", description: "Completely removes a rule by ID — it never runs for any request", group: "advanced" },
  { value: "SecRuleRemoveByTag", label: "Disable rule category globally", description: "Removes all rules in a category (e.g., all SQLi rules) — they never run", group: "advanced" },
  { value: "SecRuleUpdateTargetById", label: "Ignore a field in a rule", description: "Tells a specific rule to stop inspecting a field (e.g., skip checking ARGS:token)", group: "advanced" },
  { value: "SecRuleUpdateTargetByTag", label: "Ignore a field in a category", description: "Tells all rules in a category to stop inspecting a field", group: "advanced" },
  // Conditional exclusions — only applied when a request matches your conditions
  { value: "ctl:ruleRemoveById", label: "Disable rule for matching requests", description: "Skips a rule only when conditions match (e.g., disable SQLi check on /api/webhook)", group: "runtime" },
  { value: "ctl:ruleRemoveByTag", label: "Disable category for matching requests", description: "Skips all rules in a category only when conditions match", group: "runtime" },
  { value: "ctl:ruleRemoveTargetById", label: "Ignore a field for matching requests", description: "Tells a rule to skip a specific field only when conditions match", group: "runtime" },
  { value: "ctl:ruleRemoveTargetByTag", label: "Ignore a field in category for matching requests", description: "Tells all rules in a category to skip a field only when conditions match", group: "runtime" },
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
      { value: "begins_with", label: "begins with" },
      { value: "ends_with", label: "ends with" },
      { value: "regex", label: "matches regex" },
      { value: "in", label: "is in (substring match)" },
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
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., POST or GET|POST|PUT",
  },
  {
    value: "user_agent", label: "User Agent",
    operators: [
      { value: "eq", label: "equals" },
      { value: "contains", label: "contains" },
      { value: "regex", label: "matches regex" },
      { value: "in", label: "is in (substring match)" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., BadBot.*, curl/.*",
  },
  {
    value: "header", label: "Request Header",
    operators: [
      { value: "eq", label: "equals" },
      { value: "contains", label: "contains" },
      { value: "regex", label: "matches regex" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., X-Custom-Header:value",
    hint: "Syntax: HeaderName:value — name before colon is the header, value after is the match target.",
  },
  {
    value: "query", label: "Query String",
    operators: [
      { value: "contains", label: "contains" },
      { value: "regex", label: "matches regex" },
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
      { value: "regex", label: "matches regex" },
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
      { value: "contains", label: "contains" },
      { value: "begins_with", label: "begins with" },
      { value: "ends_with", label: "ends with" },
      { value: "regex", label: "matches regex" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., <script> or password=.*",
  },
  {
    value: "body_json", label: "Body JSON Field",
    operators: [
      { value: "eq", label: "equals" },
      { value: "contains", label: "contains" },
      { value: "regex", label: "matches regex" },
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
      { value: "contains", label: "contains" },
      { value: "regex", label: "matches regex" },
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
      { value: "regex", label: "matches regex" },
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
      { value: "begins_with", label: "begins with" },
      { value: "ends_with", label: "ends with" },
      { value: "regex", label: "matches regex" },
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
      { value: "regex", label: "matches regex" },
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., https://example.com/page",
  },
  {
    value: "response_header", label: "Response Header",
    operators: [
      { value: "eq", label: "equals" },
      { value: "contains", label: "contains" },
      { value: "regex", label: "matches regex" },
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
      { value: "in", label: "is in" },
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
      { value: "in_list", label: "is in list" },
      { value: "not_in_list", label: "is not in list" },
    ],
    placeholder: "e.g., HTTP/1.0 or HTTP/2.0",
  },
];

// ─── Helpers ────────────────────────────────────────────────────────

export function getFieldDef(field: ConditionField): FieldDef {
  return CONDITION_FIELDS.find((f) => f.value === field) ?? CONDITION_FIELDS[0];
}

export function isById(type: ExclusionType): boolean {
  return type.includes("ById");
}

export function isByTag(type: ExclusionType): boolean {
  return type.includes("ByTag");
}

export function isTargetType(type: ExclusionType): boolean {
  return type.includes("Target") || type.includes("UpdateTarget");
}

export function isRuntimeType(type: ExclusionType): boolean {
  return type.startsWith("ctl:");
}

// ─── Advanced Form Types ────────────────────────────────────────────

export interface AdvancedFormState {
  name: string;
  description: string;
  type: ExclusionType;
  rule_id: string;
  rule_tag: string;
  variable: string;
  anomaly_score: number;
  anomaly_paranoia_level: number;
  conditions: import("@/lib/api").Condition[];
  group_operator: import("@/lib/api").GroupOperator;
  tags: string[];
  enabled: boolean;
}

export const emptyAdvancedForm: AdvancedFormState = {
  name: "",
  description: "",
  type: "SecRuleRemoveById",
  rule_id: "",
  rule_tag: "",
  variable: "",
  anomaly_score: 3,
  anomaly_paranoia_level: 1,
  conditions: [],
  group_operator: "and",
  tags: [],
  enabled: true,
};

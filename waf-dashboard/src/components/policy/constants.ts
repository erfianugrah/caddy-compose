import type { ExclusionType, ConditionField, ConditionOperator } from "@/lib/api";

// ─── Quick Action Types ─────────────────────────────────────────────

export type QuickActionType = "allow" | "block" | "skip_rule";

export const QUICK_ACTIONS: { value: QuickActionType; label: string; description: string; iconName: "ShieldCheck" | "ShieldBan" | "SkipForward" }[] = [
  { value: "allow", label: "Allow", description: "Whitelist IP, path, or service — bypass WAF checks", iconName: "ShieldCheck" },
  { value: "block", label: "Block", description: "Deny requests by IP, path, or user agent", iconName: "ShieldBan" },
  { value: "skip_rule", label: "Skip / Bypass", description: "Skip specific CRS rules for a path or service", iconName: "SkipForward" },
];

// ─── All Exclusion Types ────────────────────────────────────────────

export const ALL_EXCLUSION_TYPES: { value: ExclusionType; label: string; description: string; group: "quick" | "advanced" | "runtime" }[] = [
  // Quick action types (mainly created from Quick Actions tab, but editable here)
  { value: "allow", label: "Allow", description: "Whitelist — bypass WAF checks", group: "quick" },
  { value: "block", label: "Block", description: "Deny matching requests", group: "quick" },
  { value: "skip_rule", label: "Skip / Bypass", description: "Skip specific CRS rules", group: "quick" },
  // Configure-time advanced types
  { value: "SecRuleRemoveById", label: "Remove entire rule", description: "SecRuleRemoveById — removes a rule globally", group: "advanced" },
  { value: "SecRuleRemoveByTag", label: "Remove rule category", description: "SecRuleRemoveByTag — removes all rules in a tag category", group: "advanced" },
  { value: "SecRuleUpdateTargetById", label: "Exclude variable from rule", description: "SecRuleUpdateTargetById — excludes a specific variable from a rule", group: "advanced" },
  { value: "SecRuleUpdateTargetByTag", label: "Exclude variable from category", description: "SecRuleUpdateTargetByTag — excludes a variable from all rules in a tag", group: "advanced" },
  // Runtime ctl: types
  { value: "ctl:ruleRemoveById", label: "Remove rule for URI", description: "Runtime ctl:ruleRemoveById — removes a rule only for matching requests", group: "runtime" },
  { value: "ctl:ruleRemoveByTag", label: "Remove category for URI", description: "Runtime ctl:ruleRemoveByTag — removes a tag category for matching requests", group: "runtime" },
  { value: "ctl:ruleRemoveTargetById", label: "Exclude variable for URI", description: "Runtime ctl:ruleRemoveTargetById — excludes a variable for matching requests", group: "runtime" },
  { value: "ctl:ruleRemoveTargetByTag", label: "Exclude variable from category for URI", description: "Runtime ctl:ruleRemoveTargetByTag — surgical variable exclusion from a tag category for matching requests", group: "runtime" },
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
}

export const CONDITION_FIELDS: FieldDef[] = [
  {
    value: "ip", label: "IP Address",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "ip_match", label: "is in (CIDR)" },
      { value: "not_ip_match", label: "is not in (CIDR)" },
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
    ],
    placeholder: "e.g., /api/v3/, /socket.io/",
  },
  {
    value: "host", label: "Host / Service",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
    ],
    placeholder: "e.g., radarr.erfi.io",
  },
  {
    value: "method", label: "HTTP Method",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "in", label: "is in" },
    ],
    placeholder: "e.g., POST or GET|POST|PUT",
  },
  {
    value: "user_agent", label: "User Agent",
    operators: [
      { value: "eq", label: "equals" },
      { value: "contains", label: "contains" },
      { value: "regex", label: "matches regex" },
    ],
    placeholder: "e.g., BadBot.*, curl/.*",
  },
  {
    value: "header", label: "Request Header",
    operators: [
      { value: "eq", label: "equals" },
      { value: "contains", label: "contains" },
      { value: "regex", label: "matches regex" },
    ],
    placeholder: "e.g., X-Custom-Header:value",
  },
  {
    value: "query", label: "Query String",
    operators: [
      { value: "contains", label: "contains" },
      { value: "regex", label: "matches regex" },
    ],
    placeholder: "e.g., debug=true",
  },
  {
    value: "country", label: "Country (GeoIP)",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "in", label: "is in" },
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
    ],
    placeholder: "e.g., session_id:abc123 or cookie_name:value",
  },
  {
    value: "body", label: "Request Body",
    operators: [
      { value: "contains", label: "contains" },
      { value: "regex", label: "matches regex" },
    ],
    placeholder: "e.g., <script> or password=.*",
  },
  {
    value: "args", label: "Parameter (Args)",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "regex", label: "matches regex" },
    ],
    placeholder: "e.g., action:delete or param_name:value",
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
    ],
    placeholder: "e.g., https://example.com/page",
  },
  {
    value: "response_header", label: "Response Header",
    operators: [
      { value: "eq", label: "equals" },
      { value: "contains", label: "contains" },
      { value: "regex", label: "matches regex" },
    ],
    placeholder: "e.g., Content-Type:application/json",
  },
  {
    value: "response_status", label: "Response Status",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "in", label: "is in" },
    ],
    placeholder: "e.g., 403 or 401 403 500",
  },
  {
    value: "http_version", label: "HTTP Version",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
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
  conditions: import("@/lib/api").Condition[];
  group_operator: import("@/lib/api").GroupOperator;
  enabled: boolean;
}

export const emptyAdvancedForm: AdvancedFormState = {
  name: "",
  description: "",
  type: "SecRuleRemoveById",
  rule_id: "",
  rule_tag: "",
  variable: "",
  conditions: [],
  group_operator: "and",
  enabled: true,
};

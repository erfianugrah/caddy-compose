// ─── Default Rules API ──────────────────────────────────────────────
// CRUD for baked-in CRS default rules and user overrides.

import { API_BASE, fetchJSON, putJSON, deleteJSON } from "./shared";

// ─── Types ──────────────────────────────────────────────────────────

export type RuleSeverity = "CRITICAL" | "ERROR" | "WARNING" | "NOTICE";

export interface PolicyCondition {
  field: string;
  operator: string;
  value?: string;
  name?: string;
  negate?: boolean;
  transforms?: string[];
  list_items?: string[];
}

export interface DefaultRule {
  id: string;
  name: string;
  description?: string;
  type: string;
  service?: string;
  conditions: PolicyCondition[];
  group_op: string;
  severity?: RuleSeverity;
  paranoia_level?: number;
  tags?: string[];
  enabled: boolean;
  priority: number;
  is_default: boolean;
  has_override: boolean;
  override_fields?: string[];
}

export interface DefaultRuleOverride {
  enabled?: boolean;
  severity?: RuleSeverity;
  paranoia_level?: number;
}

// ─── CRS Category Helpers ───────────────────────────────────────────

export interface RuleCategory {
  prefix: string;
  name: string;
  shortName: string;
}

export const CRS_CATEGORIES: RuleCategory[] = [
  { prefix: "913", name: "Scanner Detection", shortName: "Scanner" },
  { prefix: "920", name: "Protocol Enforcement", shortName: "Protocol" },
  { prefix: "921", name: "Protocol Attack", shortName: "HTTP Attack" },
  { prefix: "922", name: "Multipart Attack", shortName: "Multipart" },
  { prefix: "930", name: "Local File Inclusion", shortName: "LFI" },
  { prefix: "931", name: "Remote File Inclusion", shortName: "RFI" },
  { prefix: "932", name: "Remote Code Execution", shortName: "RCE" },
  { prefix: "933", name: "PHP Injection", shortName: "PHP" },
  { prefix: "934", name: "Generic Attack", shortName: "Generic" },
  { prefix: "941", name: "Cross-Site Scripting", shortName: "XSS" },
  { prefix: "942", name: "SQL Injection", shortName: "SQLi" },
  { prefix: "943", name: "Session Fixation", shortName: "Session" },
  { prefix: "944", name: "Java Injection", shortName: "Java" },
  { prefix: "9100", name: "Custom Rules", shortName: "Custom" },
];

export function getCategoryForRule(ruleId: string): RuleCategory | undefined {
  // Custom rules (9100xxx) must match before 91x CRS ranges.
  if (ruleId.startsWith("9100")) {
    return CRS_CATEGORIES.find((c) => c.prefix === "9100");
  }
  return CRS_CATEGORIES.find((c) => ruleId.startsWith(c.prefix));
}

export function getCategoryName(ruleId: string): string {
  return getCategoryForRule(ruleId)?.name ?? "Other";
}

// ─── API Functions ──────────────────────────────────────────────────

export async function listDefaultRules(): Promise<DefaultRule[]> {
  return fetchJSON<DefaultRule[]>(`${API_BASE}/default-rules`);
}

export async function getDefaultRule(id: string): Promise<DefaultRule> {
  return fetchJSON<DefaultRule>(`${API_BASE}/default-rules/${id}`);
}

export async function overrideDefaultRule(
  id: string,
  override: DefaultRuleOverride,
): Promise<DefaultRule> {
  return putJSON<DefaultRule>(`${API_BASE}/default-rules/${id}`, override);
}

export async function resetDefaultRule(id: string): Promise<DefaultRule> {
  return deleteJSON<DefaultRule>(`${API_BASE}/default-rules/${id}/override`);
}

// ─── Default Rules API ──────────────────────────────────────────────
// CRUD for baked-in CRS default rules and user overrides.

import { API_BASE, fetchJSON, postJSON, putJSON, deleteJSON } from "./shared";

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

export type DetectAction = "score" | "log_only";

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
  action?: string;  // "score" (default / empty) or "log_only"
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
  action?: DetectAction;
}

// ─── CRS Category Helpers ───────────────────────────────────────────
//
// Categories are loaded from the API (/api/crs/rules) at runtime.
// The initial seed below is a compile-time fallback that matches the
// converter-generated crs-metadata.json. When refreshCRSCategories()
// is called, it replaces this with live data from the backend.

export interface RuleCategory {
  prefix: string;
  name: string;
  shortName: string;
  phase: "inbound" | "outbound";
}

// shortNameMap derives concise display names from category IDs.
// Used when converting API categories (which have id/name but no shortName).
const shortNameMap: Record<string, string> = {
  "scanner-detection": "Scanner",
  "protocol-enforcement": "Protocol",
  "protocol-attack": "HTTP Attack",
  "multipart-attack": "Multipart",
  "lfi": "LFI",
  "rfi": "RFI",
  "rce": "RCE",
  "php": "PHP",
  "generic-attack": "Generic",
  "xss": "XSS",
  "sqli": "SQLi",
  "session-fixation": "Session",
  "java": "Java",
  "bot-detection": "Bot",
  "data-leakage": "Leakage",
  "data-leakage-sql": "SQL Leak",
  "data-leakage-java": "Java Leak",
  "data-leakage-php": "PHP Leak",
  "data-leakage-iis": "IIS Leak",
  "web-shells": "Web Shell",
  "data-leakages-ruby": "Ruby Leak",
};

/** Returns the current CRS categories (API data if loaded, fallback otherwise). */
export function getCRSCategories(): RuleCategory[] {
  return _crsCategories;
}

// Compile-time fallback — replaced by API data via refreshCRSCategories().
// Not exported directly; use getCRSCategories() to read current state.
let _crsCategories: RuleCategory[] = [
  { prefix: "913", name: "Scanner Detection", shortName: "Scanner", phase: "inbound" },
  { prefix: "920", name: "Protocol Enforcement", shortName: "Protocol", phase: "inbound" },
  { prefix: "921", name: "Protocol Attack", shortName: "HTTP Attack", phase: "inbound" },
  { prefix: "922", name: "Multipart Attack", shortName: "Multipart", phase: "inbound" },
  { prefix: "930", name: "Local File Inclusion", shortName: "LFI", phase: "inbound" },
  { prefix: "931", name: "Remote File Inclusion", shortName: "RFI", phase: "inbound" },
  { prefix: "932", name: "Remote Code Execution", shortName: "RCE", phase: "inbound" },
  { prefix: "933", name: "PHP Injection", shortName: "PHP", phase: "inbound" },
  { prefix: "934", name: "Generic Attack", shortName: "Generic", phase: "inbound" },
  { prefix: "941", name: "Cross-Site Scripting", shortName: "XSS", phase: "inbound" },
  { prefix: "942", name: "SQL Injection", shortName: "SQLi", phase: "inbound" },
  { prefix: "943", name: "Session Fixation", shortName: "Session", phase: "inbound" },
  { prefix: "944", name: "Java Injection", shortName: "Java", phase: "inbound" },
  { prefix: "9100", name: "Custom Rules", shortName: "Custom", phase: "inbound" },
  { prefix: "950", name: "Data Leakages", shortName: "Leakage", phase: "outbound" },
  { prefix: "951", name: "SQL Data Leakages", shortName: "SQL Leak", phase: "outbound" },
  { prefix: "952", name: "Java Data Leakages", shortName: "Java Leak", phase: "outbound" },
  { prefix: "953", name: "PHP Data Leakages", shortName: "PHP Leak", phase: "outbound" },
  { prefix: "954", name: "IIS Data Leakages", shortName: "IIS Leak", phase: "outbound" },
  { prefix: "955", name: "Web Shell Detection", shortName: "Web Shell", phase: "outbound" },
  { prefix: "956", name: "Ruby Data Leakages", shortName: "Ruby Leak", phase: "outbound" },
];

/** Fetch categories from /api/crs/rules and update the internal cache.
 *  Called by useCRSCategories() hook on first mount. */
export async function refreshCRSCategories(): Promise<void> {
  try {
    const resp = await fetchJSON<{
      categories: Array<{ id: string; name: string; prefix: string; rule_range: string; phase: string; }>;
    }>(`${API_BASE}/crs/rules`);
    if (resp.categories && resp.categories.length > 0) {
      _crsCategories = resp.categories.map((c) => {
        // Use prefix directly from API (from crs-metadata.json).
        // Fallback to deriving from rule_range for older API versions.
        const prefix = c.prefix || c.rule_range?.replace(/000-.*$/, "") || "";
        const shortName = shortNameMap[c.id] ?? c.name.split(" ")[0];
        const phase: "inbound" | "outbound" = c.phase === "outbound" ? "outbound" : "inbound";
        return { prefix, name: c.name, shortName, phase };
      });
    }
  } catch {
    // Silently keep fallback — API may not be reachable during SSG build.
  }
}

export function getCategoryForRule(ruleId: string): RuleCategory | undefined {
  // Custom rules (9100xxx) must match before 91x CRS ranges.
  if (ruleId.startsWith("9100")) {
    return _crsCategories.find((c) => c.prefix === "9100");
  }
  return _crsCategories.find((c) => ruleId.startsWith(c.prefix));
}

export function getCategoryName(ruleId: string): string {
  return getCategoryForRule(ruleId)?.name ?? "Other";
}

export function getCategoryShortName(ruleId: string): string {
  return getCategoryForRule(ruleId)?.shortName ?? "Other";
}

// ─── API Functions ──────────────────────────────────────────────────

export async function listDefaultRules(): Promise<DefaultRule[]> {
  return fetchJSON<DefaultRule[]>(`${API_BASE}/default-rules`);
}

export async function getDefaultRule(id: string): Promise<DefaultRule> {
  return fetchJSON<DefaultRule>(`${API_BASE}/default-rules/${encodeURIComponent(id)}`);
}

export async function overrideDefaultRule(
  id: string,
  override: DefaultRuleOverride,
): Promise<DefaultRule> {
  return putJSON<DefaultRule>(`${API_BASE}/default-rules/${encodeURIComponent(id)}`, override);
}

export async function resetDefaultRule(id: string): Promise<DefaultRule> {
  return deleteJSON<DefaultRule>(`${API_BASE}/default-rules/${encodeURIComponent(id)}/override`);
}

// ─── Bulk Actions ───────────────────────────────────────────────────

export interface BulkOverrideResult {
  changed: number;
}

export interface BulkResetResult {
  removed: number;
}

/** Apply an override to multiple rules at once. */
export async function bulkOverrideDefaultRules(
  ids: string[],
  override: DefaultRuleOverride,
): Promise<BulkOverrideResult> {
  return postJSON<BulkOverrideResult>(`${API_BASE}/default-rules/bulk`, { ids, action: "override", override });
}

/** Reset overrides for multiple rules at once. */
export async function bulkResetDefaultRules(
  ids: string[],
): Promise<BulkResetResult> {
  return postJSON<BulkResetResult>(`${API_BASE}/default-rules/bulk`, { ids, action: "reset" });
}

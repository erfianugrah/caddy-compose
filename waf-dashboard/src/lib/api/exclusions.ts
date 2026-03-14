import { API_BASE, fetchJSON, postJSON, putJSON, deleteJSON } from "./shared";

// ─── CRS Catalog / Autocomplete ─────────────────────────────────────

export interface CRSRule {
  id: string;
  description: string;
  category: string;
  tags: string[];
  severity?: string;
  paranoia_level?: number;
}

export interface CRSCategory {
  id: string;
  name: string;
  description: string;
  rule_range: string;
  tag: string; // CRS tag for ctl:ruleRemoveByTag
}

export interface CRSCatalogResponse {
  categories: CRSCategory[];
  rules: CRSRule[];
  total: number;
}

// ─── Exclusions / Policy ────────────────────────────────────────────

export type ExclusionType = "allow" | "block" | "skip" | "detect";

// Condition fields and operators for the dynamic rule builder
export type ConditionField =
  | "ip" | "path" | "host" | "method" | "user_agent" | "header" | "query"
  | "country" | "cookie" | "body" | "body_json" | "body_form" | "args"
  | "uri_path" | "referer" | "response_header" | "response_status" | "http_version"
  // Aggregate fields (combine multiple sources for broad matching)
  | "all_args" | "all_args_names" | "all_args_values"
  | "all_headers" | "all_headers_names"
  | "all_cookies" | "all_cookies_names"
  | "request_combined"
  // Count pseudo-fields (numeric comparison on aggregate field element count)
  | "count:all_args" | "count:all_args_names" | "count:all_args_values"
  | "count:all_headers" | "count:all_headers_names"
  | "count:all_cookies" | "count:all_cookies_names";
export type ConditionOperator =
  | "eq" | "neq" | "contains" | "not_contains"
  | "begins_with" | "not_begins_with" | "ends_with" | "not_ends_with"
  | "regex" | "not_regex" | "phrase_match" | "not_phrase_match"
  | "ip_match" | "not_ip_match"
  | "in" | "not_in" | "exists" | "in_list" | "not_in_list"
  | "gt" | "ge" | "lt" | "le";
export type GroupOperator = "and" | "or";

export interface Condition {
  field: ConditionField;
  operator: ConditionOperator;
  value: string;
  transforms?: string[];
  /** Inline pattern list for phrase_match operator. */
  list_items?: string[];
}

/** All transform names supported by the policy engine plugin (v0.8.1+). */
export const VALID_TRANSFORMS = [
  // Phase 1 — covers ~90% of CRS usage
  "lowercase",
  "urlDecode",
  "urlDecodeUni",
  "htmlEntityDecode",
  "normalizePath",
  "normalizePathWin",
  "removeNulls",
  "compressWhitespace",
  "removeWhitespace",
  // Phase 2 — extended transforms
  "base64Decode",
  "hexDecode",
  "jsDecode",
  "cssDecode",
  "utf8toUnicode",
  "removeComments",
  "trim",
  "length",
] as const;

export type TransformName = (typeof VALID_TRANSFORMS)[number];

export interface SkipTargets {
  rules?: string[];
  phases?: string[];
  all_remaining?: boolean;
}

export interface Exclusion {
  id: string;
  name: string;
  description: string;
  type: ExclusionType;
  conditions: Condition[];
  group_operator: GroupOperator;
  skip_targets?: SkipTargets;
  severity?: string;
  detect_paranoia_level?: number;
  tags?: string[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface ExclusionCreateData {
  name: string;
  description?: string;
  type: ExclusionType;
  conditions?: Condition[];
  group_operator?: GroupOperator;
  skip_targets?: SkipTargets;
  severity?: string;
  detect_paranoia_level?: number;
  tags?: string[];
  enabled: boolean;
}

export interface ExclusionUpdateData extends Partial<ExclusionCreateData> {}

export interface DeployResult {
  status: "deployed" | "partial";
  message: string;
  reloaded: boolean;
  timestamp: string;
}

export interface ExclusionHitData {
  total: number;
  sparkline: number[];
}

export interface ExclusionHitsResponse {
  hits: Record<string, ExclusionHitData>;
}

// ─── Exclusion type mapping (frontend ModSecurity names ↔ Go internal names) ──

const typeToGo: Record<ExclusionType, string> = {
  allow: "allow",
  block: "block",
  skip: "skip",
  detect: "detect",
};

const typeFromGo: Record<string, ExclusionType> = Object.fromEntries(
  Object.entries(typeToGo).map(([fe, go]) => [go, fe as ExclusionType])
) as Record<string, ExclusionType>;

// Raw exclusion shape from Go API (uses internal type names)
interface RawExclusion {
  id: string;
  name: string;
  description: string;
  type: string;
  conditions?: Condition[];
  group_operator?: string;
  skip_targets?: SkipTargets;
  severity?: string;
  detect_paranoia_level?: number;
  tags?: string[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

function mapExclusionFromGo(raw: RawExclusion): Exclusion {
  return {
    id: raw.id,
    name: raw.name,
    description: raw.description,
    type: typeFromGo[raw.type] ?? ("allow" as ExclusionType),
    conditions: raw.conditions ?? [],
    group_operator: (raw.group_operator as GroupOperator) || "and",
    skip_targets: raw.skip_targets ?? undefined,
    severity: raw.severity || undefined,
    detect_paranoia_level: raw.detect_paranoia_level ?? undefined,
    tags: raw.tags,
    enabled: raw.enabled,
    created_at: raw.created_at,
    updated_at: raw.updated_at,
  };
}

function mapExclusionToGo(data: ExclusionCreateData | ExclusionUpdateData): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  if (data.name !== undefined) result.name = data.name;
  if (data.description !== undefined) result.description = data.description;
  if (data.type !== undefined) result.type = typeToGo[data.type] ?? data.type;
  if (data.conditions !== undefined) result.conditions = data.conditions;
  if (data.group_operator !== undefined) result.group_operator = data.group_operator;
  if (data.skip_targets !== undefined) result.skip_targets = data.skip_targets;
  if (data.severity !== undefined) result.severity = data.severity;
  if (data.detect_paranoia_level !== undefined) result.detect_paranoia_level = data.detect_paranoia_level;
  if (data.tags !== undefined) result.tags = data.tags;
  if (data.enabled !== undefined) result.enabled = data.enabled;
  return result;
}

// ─── API Functions ──────────────────────────────────────────────────

export async function fetchCRSRules(): Promise<CRSCatalogResponse> {
  return fetchJSON<CRSCatalogResponse>(`${API_BASE}/crs/rules`);
}

export async function getExclusions(): Promise<Exclusion[]> {
  const raw = await fetchJSON<RawExclusion[]>(`${API_BASE}/exclusions`);
  return (raw ?? []).map(mapExclusionFromGo);
}

export async function createExclusion(data: ExclusionCreateData): Promise<Exclusion> {
  const payload = mapExclusionToGo(data);
  const raw = await postJSON<RawExclusion>(`${API_BASE}/exclusions`, payload);
  return mapExclusionFromGo(raw);
}

export async function updateExclusion(
  id: string,
  data: ExclusionUpdateData
): Promise<Exclusion> {
  const payload = mapExclusionToGo(data);
  const raw = await putJSON<RawExclusion>(`${API_BASE}/exclusions/${encodeURIComponent(id)}`, payload);
  return mapExclusionFromGo(raw);
}

export async function deleteExclusion(id: string): Promise<void> {
  await deleteJSON<void>(`${API_BASE}/exclusions/${encodeURIComponent(id)}`);
}

export async function deployConfig(): Promise<DeployResult> {
  return postJSON<DeployResult>(`${API_BASE}/config/deploy`, {});
}

export async function exportExclusions(): Promise<Exclusion[]> {
  const raw = await fetchJSON<{ exclusions: RawExclusion[] }>(`${API_BASE}/exclusions/export`);
  return (raw.exclusions ?? []).map(mapExclusionFromGo);
}

export async function importExclusions(data: Exclusion[]): Promise<{ imported: number }> {
  // Transform exclusions to Go shape for import
  const goExclusions = data.map((e) => mapExclusionToGo({
    name: e.name,
    description: e.description,
    type: e.type,
    conditions: e.conditions,
    group_operator: e.group_operator,
    skip_targets: e.skip_targets,
    severity: e.severity,
    detect_paranoia_level: e.detect_paranoia_level,
    tags: e.tags,
    enabled: e.enabled,
  }));
  return postJSON<{ imported: number }>(`${API_BASE}/exclusions/import`, {
    version: 1,
    exclusions: goExclusions,
  });
}

export async function fetchExclusionHits(hours = 24): Promise<ExclusionHitsResponse> {
  return fetchJSON<ExclusionHitsResponse>(`${API_BASE}/exclusions/hits?hours=${hours}`);
}

export async function reorderExclusions(ids: string[]): Promise<Exclusion[]> {
  const raw = await putJSON<RawExclusion[]>(`${API_BASE}/exclusions/reorder`, { ids });
  return raw.map(mapExclusionFromGo);
}

// ─── Bulk Actions ───────────────────────────────────────────────────

export type BulkExclusionAction = "enable" | "disable" | "delete";

/** Apply a bulk action to multiple exclusions. */
export async function bulkUpdateExclusions(
  ids: string[],
  action: BulkExclusionAction,
): Promise<{ changed: number }> {
  return postJSON<{ changed: number }>(`${API_BASE}/exclusions/bulk`, { ids, action });
}

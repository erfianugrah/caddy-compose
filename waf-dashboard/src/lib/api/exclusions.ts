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

export interface ModSecOperator {
  name: string;
  label: string;
  description: string;
  has_arg: boolean;
}

export interface CRSAutocompleteResponse {
  variables: string[];
  operators: ModSecOperator[];
  actions: string[];
}

// ─── Exclusions / Policy ────────────────────────────────────────────

export type ExclusionType =
  // Advanced (ModSecurity directive types)
  | "SecRuleRemoveById"
  | "SecRuleRemoveByTag"
  | "SecRuleUpdateTargetById"
  | "SecRuleUpdateTargetByTag"
  | "ctl:ruleRemoveById"
  | "ctl:ruleRemoveByTag"
  | "ctl:ruleRemoveTargetById"
  | "ctl:ruleRemoveTargetByTag"
  // Quick Actions
  | "allow"
  | "block"
  | "skip_rule"
  | "anomaly"
  // Honeypot
  | "honeypot"
  // Raw editor
  | "raw";

// Condition fields and operators for the dynamic rule builder
export type ConditionField = "ip" | "path" | "host" | "method" | "user_agent" | "header" | "query" | "country" | "cookie" | "body" | "body_json" | "body_form" | "args" | "uri_path" | "referer" | "response_header" | "response_status" | "http_version";
export type ConditionOperator = "eq" | "neq" | "contains" | "begins_with" | "ends_with" | "regex" | "ip_match" | "not_ip_match" | "in" | "exists" | "in_list" | "not_in_list";
export type GroupOperator = "and" | "or";

export interface Condition {
  field: ConditionField;
  operator: ConditionOperator;
  value: string;
}

export interface Exclusion {
  id: string;
  name: string;
  description: string;
  type: ExclusionType;
  conditions: Condition[];
  group_operator: GroupOperator;
  rule_id?: string;
  rule_tag?: string;
  variable?: string;
  raw_rule?: string;
  anomaly_score?: number;
  anomaly_paranoia_level?: number;
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
  rule_id?: string;
  rule_tag?: string;
  variable?: string;
  raw_rule?: string;
  anomaly_score?: number;
  anomaly_paranoia_level?: number;
  tags?: string[];
  enabled: boolean;
}

export interface ExclusionUpdateData extends Partial<ExclusionCreateData> {}

export interface GeneratedConfig {
  pre_crs: string;
  post_crs: string;
}

export interface DeployResult {
  status: "deployed" | "partial";
  message: string;
  pre_crs_file: string;
  post_crs_file: string;
  waf_settings_file: string;
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
  // Advanced types (frontend ModSecurity names → Go internal names)
  "SecRuleRemoveById": "remove_by_id",
  "SecRuleRemoveByTag": "remove_by_tag",
  "SecRuleUpdateTargetById": "update_target_by_id",
  "SecRuleUpdateTargetByTag": "update_target_by_tag",
  "ctl:ruleRemoveById": "runtime_remove_by_id",
  "ctl:ruleRemoveByTag": "runtime_remove_by_tag",
  "ctl:ruleRemoveTargetById": "runtime_remove_target_by_id",
  "ctl:ruleRemoveTargetByTag": "runtime_remove_target_by_tag",
  // Quick Actions + Honeypot + Raw (same names in Go)
  "allow": "allow",
  "block": "block",
  "skip_rule": "skip_rule",
  "anomaly": "anomaly",
  "honeypot": "honeypot",
  "raw": "raw",
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
  rule_id?: string;
  rule_tag?: string;
  variable?: string;
  raw_rule?: string;
  anomaly_score?: number;
  anomaly_paranoia_level?: number;
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
    type: typeFromGo[raw.type] ?? ("SecRuleRemoveById" as ExclusionType),
    conditions: raw.conditions ?? [],
    group_operator: (raw.group_operator as GroupOperator) || "and",
    rule_id: raw.rule_id || undefined,
    rule_tag: raw.rule_tag || undefined,
    variable: raw.variable || undefined,
    raw_rule: raw.raw_rule || undefined,
    anomaly_score: raw.anomaly_score ?? undefined,
    anomaly_paranoia_level: raw.anomaly_paranoia_level ?? undefined,
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
  if (data.rule_id !== undefined) result.rule_id = data.rule_id;
  if (data.rule_tag !== undefined) result.rule_tag = data.rule_tag;
  if (data.variable !== undefined) result.variable = data.variable;
  if (data.raw_rule !== undefined) result.raw_rule = data.raw_rule;
  if (data.anomaly_score !== undefined) result.anomaly_score = data.anomaly_score;
  if (data.anomaly_paranoia_level !== undefined) result.anomaly_paranoia_level = data.anomaly_paranoia_level;
  if (data.tags !== undefined) result.tags = data.tags;
  if (data.enabled !== undefined) result.enabled = data.enabled;
  return result;
}

// ─── API Functions ──────────────────────────────────────────────────

export async function fetchCRSRules(): Promise<CRSCatalogResponse> {
  return fetchJSON<CRSCatalogResponse>(`${API_BASE}/crs/rules`);
}

export async function fetchCRSAutocomplete(): Promise<CRSAutocompleteResponse> {
  return fetchJSON<CRSAutocompleteResponse>(`${API_BASE}/crs/autocomplete`);
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

export async function generateConfig(): Promise<GeneratedConfig> {
  const raw = await postJSON<{ pre_crs_conf?: string; post_crs_conf?: string; pre_crs?: string; post_crs?: string }>(
    `${API_BASE}/config/generate`,
    {}
  );
  return {
    pre_crs: raw.pre_crs_conf ?? raw.pre_crs ?? "",
    post_crs: raw.post_crs_conf ?? raw.post_crs ?? "",
  };
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
    rule_id: e.rule_id,
    rule_tag: e.rule_tag,
    variable: e.variable,
    raw_rule: e.raw_rule,
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

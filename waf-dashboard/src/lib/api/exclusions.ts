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
  prefix: string;
  phase: string;
}

export interface CRSCatalogResponse {
  categories: CRSCategory[];
  rules: CRSRule[];
  total: number;
}

// ─── Exclusions / Policy ────────────────────────────────────────────

export type ExclusionType = "allow" | "block" | "challenge" | "skip" | "detect" | "rate_limit" | "response_header";

// Condition fields and operators for the dynamic rule builder
export type ConditionField =
  | "ip" | "path" | "host" | "method" | "user_agent" | "header" | "query"
  | "country" | "cookie" | "body" | "body_json" | "body_form" | "args"
  | "uri_path" | "referer" | "response_header" | "response_status" | "response_content_type" | "http_version" | "ja4" | "challenge_history"
  // Aggregate fields (combine multiple sources for broad matching)
  | "all_args" | "all_args_names" | "all_args_values"
  | "query_args_values" | "query_args_names"
  | "post_args_values" | "post_args_names"
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

export type RulePhase = "inbound" | "outbound";

/** Server-assigned fields present on stored exclusions. */
type ExclusionServerFields = "id" | "created_at" | "updated_at" | "expires_at";

export interface Exclusion {
  id: string;
  name: string;
  description: string;
  type: ExclusionType;
  phase?: RulePhase;
  conditions: Condition[];
  group_operator: GroupOperator;
  service?: string;
  priority?: number;
  // skip fields
  skip_targets?: SkipTargets;
  // detect fields
  severity?: string;
  detect_paranoia_level?: number;
  // rate_limit fields
  rate_limit_key?: string;
  rate_limit_events?: number;
  rate_limit_window?: string;
  rate_limit_action?: string;
  // challenge fields
  challenge_difficulty?: number;
  challenge_min_difficulty?: number;
  challenge_max_difficulty?: number;
  challenge_algorithm?: "fast" | "slow";
  challenge_ttl?: string;
  challenge_bind_ip?: boolean;
  challenge_bind_ja4?: boolean;
  // response_header fields
  header_set?: Record<string, string>;
  header_add?: Record<string, string>;
  header_remove?: string[];
  header_default?: Record<string, string>;
  tags?: string[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
  expires_at?: string;
}

/**
 * Data for creating a new exclusion — same as Exclusion without server-assigned
 * fields, with most fields optional for partial payloads.
 * Derived from Exclusion to stay in sync automatically — adding a field to
 * Exclusion automatically makes it available here.
 */
export interface ExclusionCreateData extends Omit<Partial<Exclusion>, ExclusionServerFields> {
  /** Required fields for creation. */
  name: string;
  type: ExclusionType;
  enabled: boolean;
}

export type ExclusionUpdateData = Partial<ExclusionCreateData>;

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
  challenge: "challenge",
  skip: "skip",
  detect: "detect",
  rate_limit: "rate_limit",
  response_header: "response_header",
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
  phase?: string;
  conditions?: Condition[];
  group_operator?: string;
  service?: string;
  priority?: number;
  skip_targets?: SkipTargets;
  severity?: string;
  detect_paranoia_level?: number;
  rate_limit_key?: string;
  rate_limit_events?: number;
  rate_limit_window?: string;
  rate_limit_action?: string;
  challenge_difficulty?: number;
  challenge_min_difficulty?: number;
  challenge_max_difficulty?: number;
  challenge_algorithm?: string;
  challenge_ttl?: string;
  challenge_bind_ip?: boolean;
  challenge_bind_ja4?: boolean;
  header_set?: Record<string, string>;
  header_add?: Record<string, string>;
  header_remove?: string[];
  header_default?: Record<string, string>;
  tags?: string[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
  expires_at?: string;
}

/**
 * Map a raw Go API response to a typed Exclusion.
 *
 * Normalizes `type` via `typeFromGo`, coerces `phase` and `group_operator` to
 * their union types, and converts falsy optional fields to `undefined`.
 */
function mapExclusionFromGo(raw: RawExclusion): Exclusion {
  return {
    // ─── required / server-assigned ──────────────────────────────
    id: raw.id,
    name: raw.name,
    description: raw.description,
    type: typeFromGo[raw.type] ?? ("allow" as ExclusionType),
    phase: (raw.phase as RulePhase) || undefined,
    conditions: raw.conditions ?? [],
    group_operator: (raw.group_operator as GroupOperator) || "and",
    enabled: raw.enabled,
    created_at: raw.created_at,
    updated_at: raw.updated_at,
    // ─── common optional ─────────────────────────────────────────
    service: raw.service || undefined,
    priority: raw.priority ?? undefined,
    tags: raw.tags,
    // ─── skip ────────────────────────────────────────────────────
    skip_targets: raw.skip_targets ?? undefined,
    // ─── detect ──────────────────────────────────────────────────
    severity: raw.severity || undefined,
    detect_paranoia_level: raw.detect_paranoia_level ?? undefined,
    // ─── rate_limit ──────────────────────────────────────────────
    rate_limit_key: raw.rate_limit_key || undefined,
    rate_limit_events: raw.rate_limit_events ?? undefined,
    rate_limit_window: raw.rate_limit_window || undefined,
    rate_limit_action: raw.rate_limit_action || undefined,
    // ─── challenge ───────────────────────────────────────────────
    challenge_difficulty: raw.challenge_difficulty ?? undefined,
    challenge_min_difficulty: raw.challenge_min_difficulty ?? undefined,
    challenge_max_difficulty: raw.challenge_max_difficulty ?? undefined,
    challenge_algorithm: (raw.challenge_algorithm as "fast" | "slow") || undefined,
    challenge_ttl: raw.challenge_ttl || undefined,
    challenge_bind_ip: raw.challenge_bind_ip ?? undefined,
    challenge_bind_ja4: raw.challenge_bind_ja4 ?? undefined,
    // ─── response_header ─────────────────────────────────────────
    header_set: raw.header_set || undefined,
    header_add: raw.header_add || undefined,
    header_remove: raw.header_remove || undefined,
    header_default: raw.header_default || undefined,
    // ─── expiration ──────────────────────────────────────────────
    expires_at: raw.expires_at || undefined,
  };
}

/**
 * Convert frontend exclusion data to the Go API shape.
 *
 * All field names are 1:1 with the Go JSON tags (no renaming needed) except
 * `type` which is mapped through `typeToGo`. Only defined (non-undefined)
 * fields are included so partial updates work correctly.
 */
function mapExclusionToGo(data: ExclusionCreateData | ExclusionUpdateData): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  const src = data as Record<string, unknown>;
  for (const key of Object.keys(src)) {
    if (src[key] === undefined) continue;
    result[key] = key === "type" ? (typeToGo[src[key] as ExclusionType] ?? src[key]) : src[key];
  }
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
  return postJSON<DeployResult>(`${API_BASE}/deploy`, {});
}

export async function exportExclusions(): Promise<Exclusion[]> {
  const raw = await fetchJSON<{ exclusions: RawExclusion[] }>(`${API_BASE}/exclusions/export`);
  return (raw.exclusions ?? []).map(mapExclusionFromGo);
}

export async function importExclusions(data: Exclusion[]): Promise<{ imported: number }> {
  // Transform exclusions to Go shape for import — pass all fields through
  const goExclusions = data.map((e) => {
    const { id, created_at, updated_at, ...rest } = e;
    return mapExclusionToGo(rest);
  });
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

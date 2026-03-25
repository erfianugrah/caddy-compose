import type { FilterOp } from "@/lib/api";

// ─── Types ──────────────────────────────────────────────────────────

/** WAF-specific filter fields (preserved for backward compatibility). */
export type FilterField = "service" | "client" | "event_type" | "blocked_by" | "method" | "rule_name" | "uri" | "status_code" | "country" | "event_id" | "request_id" | "tag" | "ja4";

/** General logs filter fields. */
export type LogFilterField = "service" | "method" | "status" | "client" | "uri" | "level" | "country" | "user_agent" | "missing_header";

export interface DashboardFilter<F extends string = FilterField> {
  field: F;
  operator: FilterOp;
  value: string;
}

export interface OpMeta {
  label: string;
  /** Short display label for chips */
  chip: string;
}

export interface FieldMeta {
  label: string;
  placeholder: string;
  /** If present, show a selection list instead of free text */
  options?: { value: string; label: string }[];
  /** If true, the field supports dynamic options (e.g. services from API) + free text */
  dynamic?: boolean;
  /** Dynamic options key — maps to a prop on DashboardFilterBar (e.g. "services", "ruleNames") */
  dynamicKey?: string;
}

/** Generic filter configuration — decouples DashboardFilterBar from specific field sets. */
export interface FilterConfig<F extends string = string> {
  fields: Record<F, FieldMeta>;
  operators: Record<F, FilterOp[]>;
  fieldOrder: F[];
}

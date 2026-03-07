import type { FilterOp } from "@/lib/api";

// ─── Types ──────────────────────────────────────────────────────────

export type FilterField = "service" | "client" | "event_type" | "method" | "rule_name" | "uri" | "status_code" | "country" | "event_id";

export interface DashboardFilter {
  field: FilterField;
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
}

import type { Exclusion, ExclusionType } from "@/lib/api";
import { CONDITION_FIELDS } from "./constants";

// ─── Exclusion Display Helpers ──────────────────────────────────────

export function conditionsSummary(excl: Exclusion): string {
  // For response_header rules, show header actions instead of conditions
  if (excl.type === "response_header") {
    const parts: string[] = [];
    if (excl.header_set && Object.keys(excl.header_set).length > 0) {
      parts.push(`Set: ${Object.keys(excl.header_set).join(", ")}`);
    }
    if (excl.header_add && Object.keys(excl.header_add).length > 0) {
      parts.push(`Add: ${Object.keys(excl.header_add).join(", ")}`);
    }
    if (excl.header_remove && excl.header_remove.length > 0) {
      parts.push(`Remove: ${excl.header_remove.join(", ")}`);
    }
    if (excl.header_default && Object.keys(excl.header_default).length > 0) {
      parts.push(`Default: ${Object.keys(excl.header_default).join(", ")}`);
    }
    if (parts.length > 0) {
      const joined = parts.join(" | ");
      return joined.length > 100 ? joined.slice(0, 100) + "..." : joined;
    }
  }

  // Build composite summary: rule scope + variable + conditions
  const segments: string[] = [];

  if (excl.conditions && excl.conditions.length > 0) {
    const parts = excl.conditions.map((c) => {
      const fieldLabel = CONDITION_FIELDS.find((f) => f.value === c.field)?.label ?? c.field;
      const opLabel = CONDITION_FIELDS.find((f) => f.value === c.field)
        ?.operators.find((o) => o.value === c.operator)?.label ?? c.operator;
      const val = c.value.length > 30 ? c.value.slice(0, 30) + "..." : c.value;
      return `${fieldLabel} ${opLabel} ${val}`;
    });
    const joiner = excl.group_operator === "or" ? " OR " : " AND ";
    segments.push(parts.join(joiner));
  }

  if (segments.length === 0) return "-";
  const joined = segments.join(" · ");
  return joined.length > 100 ? joined.slice(0, 100) + "..." : joined;
}

export function exclusionTypeLabel(type: ExclusionType): string {
  switch (type) {
    case "allow": return "Allow";
    case "block": return "Block";
    case "skip": return "Skip";
    case "detect": return "Detect";
    case "response_header": return "Response Header";
    default: return type;
  }
}

export function exclusionTypeBadgeVariant(type: ExclusionType): "default" | "outline" | "secondary" | "destructive" {
  switch (type) {
    case "allow": return "outline";
    case "block": return "destructive";
    case "skip": return "default";
    case "detect": return "secondary";
    case "response_header": return "default";
    default: return "outline";
  }
}

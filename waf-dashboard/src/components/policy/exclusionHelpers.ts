import type { Exclusion, ExclusionType } from "@/lib/api";
import { CONDITION_FIELDS } from "./constants";

// ─── Exclusion Display Helpers ──────────────────────────────────────

export function conditionsSummary(excl: Exclusion): string {
  // Build composite summary: rule scope + variable + conditions
  const segments: string[] = [];

  if (excl.rule_id) segments.push(`Rule ${excl.rule_id}`);
  if (excl.rule_tag) segments.push(`Tag: ${excl.rule_tag}`);
  if (excl.variable) segments.push(`Var: ${excl.variable}`);

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
    case "detect": return "Detect";
    default: return type;
  }
}

export function exclusionTypeBadgeVariant(type: ExclusionType): "default" | "outline" | "secondary" | "destructive" {
  switch (type) {
    case "allow": return "outline";
    case "block": return "destructive";
    case "detect": return "secondary";
    default: return "outline";
  }
}

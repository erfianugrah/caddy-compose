import type { Exclusion, ExclusionType } from "@/lib/api";
import { CONDITION_FIELDS } from "./constants";

// ─── Exclusion Display Helpers ──────────────────────────────────────

export function conditionsSummary(excl: Exclusion): string {
  // For honeypot rules, show path count
  if (excl.type === "honeypot" && excl.conditions && excl.conditions.length > 0) {
    const paths = excl.conditions.flatMap((c) => c.value.split(/\s+/).filter(Boolean));
    const preview = paths.slice(0, 3).join(", ");
    return paths.length > 3 ? `${preview} (+${paths.length - 3} more)` : preview;
  }
  // For raw rules, show raw_rule snippet
  if (excl.type === "raw" && excl.raw_rule) {
    return excl.raw_rule.length > 50 ? excl.raw_rule.slice(0, 50) + "..." : excl.raw_rule;
  }

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
    case "skip_rule": return "Skip";
    case "honeypot": return "Honeypot";
    case "raw": return "Raw";
    // Configure-time
    case "SecRuleRemoveById": return "Remove Rule";
    case "SecRuleRemoveByTag": return "Remove Tag";
    case "SecRuleUpdateTargetById": return "Excl. Var (Rule)";
    case "SecRuleUpdateTargetByTag": return "Excl. Var (Tag)";
    // Runtime
    case "ctl:ruleRemoveById": return "RT Remove Rule";
    case "ctl:ruleRemoveByTag": return "RT Remove Tag";
    case "ctl:ruleRemoveTargetById": return "RT Excl. Var (Rule)";
    case "ctl:ruleRemoveTargetByTag": return "RT Excl. Var (Tag)";
    default: return type;
  }
}

export function exclusionTypeBadgeVariant(type: ExclusionType): "default" | "outline" | "secondary" | "destructive" {
  switch (type) {
    case "allow": return "default";
    case "block": return "destructive";
    case "honeypot": return "destructive";
    case "skip_rule": return "secondary";
    // Configure-time types
    case "SecRuleRemoveById":
    case "SecRuleRemoveByTag":
    case "SecRuleUpdateTargetById":
    case "SecRuleUpdateTargetByTag":
      return "outline";
    // Runtime types
    case "ctl:ruleRemoveById":
    case "ctl:ruleRemoveByTag":
    case "ctl:ruleRemoveTargetById":
    case "ctl:ruleRemoveTargetByTag":
      return "secondary";
    default: return "outline";
  }
}

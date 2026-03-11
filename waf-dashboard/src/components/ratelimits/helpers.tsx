import { Badge } from "@/components/ui/badge";
import { RL_KEY_OPTIONS, RL_FIELD_DEFS } from "./constants";
import type { RateLimitRule, RLRuleAction } from "@/lib/api";
import { T } from "@/lib/typography";

// ─── Action Badge ───────────────────────────────────────────────────

export function ActionBadge({ action }: { action: RLRuleAction }) {
  if (action === "log_only") {
    return (
      <Badge variant="outline" className={`${T.badgeMono} bg-lv-peach/10 text-lv-peach border-lv-peach/30`}>
        Monitor
      </Badge>
    );
  }
  return (
      <Badge variant="outline" className={`${T.badgeMono} bg-lv-red/10 text-lv-red border-lv-red/30`}>
      Deny
    </Badge>
  );
}

// ─── Key Display ────────────────────────────────────────────────────

export function keyLabel(key: string): string {
  const found = RL_KEY_OPTIONS.find((k) => k.value === key);
  if (found) return found.label;
  if (key.startsWith("header:")) return `Header: ${key.slice(7)}`;
  if (key.startsWith("cookie:")) return `Cookie: ${key.slice(7)}`;
  if (key.startsWith("body_json:")) return `Body JSON: ${key.slice(10)}`;
  if (key.startsWith("body_form:")) return `Body Form: ${key.slice(10)}`;
  return key;
}

// ─── Conditions Summary ─────────────────────────────────────────────

export function rlConditionsSummary(rule: RateLimitRule): string {
  const parts: string[] = [];
  if (rule.service) parts.push(`Service: ${rule.service}`);
  if (rule.conditions && rule.conditions.length > 0) {
    const condParts = rule.conditions.map((c) => {
      const fieldDef = RL_FIELD_DEFS.find((f) => f.value === c.field);
      const fieldLabel = fieldDef?.label ?? c.field;
      const opLabel = fieldDef?.operators.find((o) => o.value === c.operator)?.label ?? c.operator;
      const val = c.value.length > 30 ? c.value.slice(0, 30) + "..." : c.value;
      return `${fieldLabel} ${opLabel} ${val}`;
    });
    const joiner = rule.group_operator === "or" ? " OR " : " AND ";
    parts.push(condParts.join(joiner));
  }
  if (parts.length === 0) return "All requests";
  const joined = parts.join(" · ");
  return joined.length > 100 ? joined.slice(0, 100) + "..." : joined;
}

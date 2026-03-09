import { describe, it, expect } from "vitest";
import { conditionsSummary, exclusionTypeLabel, exclusionTypeBadgeVariant } from "./exclusionHelpers";
import type { Exclusion, ExclusionType } from "@/lib/api";

// ─── Helper to build minimal exclusion objects ──────────────────────

function makeExclusion(overrides: Partial<Exclusion>): Exclusion {
  return {
    id: "test-id",
    name: "Test",
    description: "",
    type: "allow",
    enabled: true,
    conditions: [],
    group_operator: "and",
    ...overrides,
  } as Exclusion;
}

// ─── conditionsSummary ──────────────────────────────────────────────

describe("conditionsSummary", () => {
  it("returns '-' for an exclusion with no conditions, rules, or variables", () => {
    const excl = makeExclusion({});
    expect(conditionsSummary(excl)).toBe("-");
  });

  it("shows rule_id", () => {
    const excl = makeExclusion({ rule_id: "942100" });
    expect(conditionsSummary(excl)).toContain("Rule 942100");
  });

  it("shows rule_tag", () => {
    const excl = makeExclusion({ rule_tag: "attack-sqli" });
    expect(conditionsSummary(excl)).toContain("Tag: attack-sqli");
  });

  it("shows variable", () => {
    const excl = makeExclusion({ variable: "ARGS:foo" });
    expect(conditionsSummary(excl)).toContain("Var: ARGS:foo");
  });

  it("shows conditions with field labels and operator labels", () => {
    const excl = makeExclusion({
      conditions: [
        { field: "ip", operator: "eq", value: "10.0.0.1" },
      ],
    });
    const summary = conditionsSummary(excl);
    expect(summary).toContain("IP Address");
    expect(summary).toContain("equals");
    expect(summary).toContain("10.0.0.1");
  });

  it("joins multiple conditions with AND", () => {
    const excl = makeExclusion({
      group_operator: "and",
      conditions: [
        { field: "ip", operator: "eq", value: "10.0.0.1" },
        { field: "path", operator: "eq", value: "/test" },
      ],
    });
    const summary = conditionsSummary(excl);
    expect(summary).toContain(" AND ");
  });

  it("joins multiple conditions with OR", () => {
    const excl = makeExclusion({
      group_operator: "or",
      conditions: [
        { field: "ip", operator: "eq", value: "10.0.0.1" },
        { field: "ip", operator: "eq", value: "10.0.0.2" },
      ],
    });
    const summary = conditionsSummary(excl);
    expect(summary).toContain(" OR ");
  });

  it("combines rule_id and conditions with separator", () => {
    const excl = makeExclusion({
      rule_id: "942100",
      conditions: [
        { field: "path", operator: "eq", value: "/api/test" },
      ],
    });
    const summary = conditionsSummary(excl);
    expect(summary).toContain("Rule 942100");
    expect(summary).toContain("·");
    expect(summary).toContain("/api/test");
  });

  it("truncates long condition values at 30 chars", () => {
    const longValue = "a".repeat(50);
    const excl = makeExclusion({
      conditions: [
        { field: "path", operator: "eq", value: longValue },
      ],
    });
    const summary = conditionsSummary(excl);
    expect(summary).toContain("...");
    expect(summary).not.toContain(longValue);
  });

  it("truncates entire summary at 100 chars", () => {
    const excl = makeExclusion({
      rule_id: "942100 942200 942300",
      rule_tag: "attack-sqli",
      variable: "ARGS:very_long_variable_name",
      conditions: [
        { field: "path", operator: "eq", value: "/very/long/path/to/something" },
        { field: "host", operator: "eq", value: "very-long-hostname.example.com" },
      ],
    });
    const summary = conditionsSummary(excl);
    expect(summary.length).toBeLessThanOrEqual(103); // 100 + "..."
  });

  // Anomaly rules
  it("shows anomaly score and paranoia level for anomaly type", () => {
    const excl = makeExclusion({
      type: "anomaly",
      anomaly_score: 5,
      anomaly_paranoia_level: 2,
      conditions: [
        { field: "user_agent", operator: "contains", value: "curl" },
      ],
    });
    const summary = conditionsSummary(excl);
    expect(summary).toContain("+5 PL2");
    expect(summary).toContain("curl");
  });

  it("defaults anomaly paranoia level to 1 when not set", () => {
    const excl = makeExclusion({
      type: "anomaly",
      anomaly_score: 3,
      conditions: [
        { field: "method", operator: "eq", value: "GET" },
      ],
    });
    const summary = conditionsSummary(excl);
    expect(summary).toContain("+3 PL1");
  });

  // Honeypot rules (now use generic condition display)
  it("shows path condition for honeypot rules", () => {
    const excl = makeExclusion({
      type: "honeypot",
      conditions: [
        { field: "path", operator: "in", value: "/wp-login.php /wp-admin/ /xmlrpc.php /.env /.git/" },
      ],
    });
    const summary = conditionsSummary(excl);
    expect(summary).toContain("/wp-login.php");
  });

  it("shows all honeypot paths if 3 or fewer", () => {
    const excl = makeExclusion({
      type: "honeypot",
      conditions: [
        { field: "path", operator: "in", value: "/wp-login.php /wp-admin/" },
      ],
    });
    const summary = conditionsSummary(excl);
    expect(summary).toContain("/wp-login.php");
    expect(summary).toContain("/wp-admin/");
    expect(summary).not.toContain("more");
  });

  // Raw rules
  it("shows raw_rule snippet for raw type", () => {
    const excl = makeExclusion({
      type: "raw",
      raw_rule: 'SecRule REQUEST_URI "@streq /api/upload" "id:10001,phase:1,pass"',
    });
    const summary = conditionsSummary(excl);
    expect(summary).toContain("SecRule REQUEST_URI");
  });

  it("truncates long raw_rule at 50 chars", () => {
    const longRule = "SecRule " + "X".repeat(100);
    const excl = makeExclusion({
      type: "raw",
      raw_rule: longRule,
    });
    const summary = conditionsSummary(excl);
    expect(summary.length).toBeLessThanOrEqual(53); // 50 + "..."
    expect(summary).toContain("...");
  });
});

// ─── exclusionTypeLabel ─────────────────────────────────────────────

describe("exclusionTypeLabel", () => {
  const expectedLabels: Record<string, string> = {
    allow: "Allow",
    block: "Block",
    skip_rule: "Skip",
    anomaly: "Anomaly",
    honeypot: "honeypot",
    raw: "Raw",
    SecRuleRemoveById: "Remove Rule",
    SecRuleRemoveByTag: "Remove Tag",
    SecRuleUpdateTargetById: "Excl. Var (Rule)",
    SecRuleUpdateTargetByTag: "Excl. Var (Tag)",
    "ctl:ruleRemoveById": "RT Remove Rule",
    "ctl:ruleRemoveByTag": "RT Remove Tag",
    "ctl:ruleRemoveTargetById": "RT Excl. Var (Rule)",
    "ctl:ruleRemoveTargetByTag": "RT Excl. Var (Tag)",
  };

  for (const [type, label] of Object.entries(expectedLabels)) {
    it(`returns "${label}" for type "${type}"`, () => {
      expect(exclusionTypeLabel(type as ExclusionType)).toBe(label);
    });
  }

  it("returns the raw type string for unknown types", () => {
    expect(exclusionTypeLabel("unknown_type" as ExclusionType)).toBe("unknown_type");
  });
});

// ─── exclusionTypeBadgeVariant ──────────────────────────────────────

describe("exclusionTypeBadgeVariant", () => {
  it("returns 'default' for allow", () => {
    expect(exclusionTypeBadgeVariant("allow")).toBe("default");
  });

  it("returns 'destructive' for block", () => {
    expect(exclusionTypeBadgeVariant("block")).toBe("destructive");
  });

  it("returns 'outline' for honeypot (no special case)", () => {
    expect(exclusionTypeBadgeVariant("honeypot")).toBe("outline");
  });

  it("returns 'secondary' for skip_rule and anomaly", () => {
    expect(exclusionTypeBadgeVariant("skip_rule")).toBe("secondary");
    expect(exclusionTypeBadgeVariant("anomaly")).toBe("secondary");
  });

  it("returns 'outline' for configure-time types", () => {
    expect(exclusionTypeBadgeVariant("SecRuleRemoveById")).toBe("outline");
    expect(exclusionTypeBadgeVariant("SecRuleRemoveByTag")).toBe("outline");
    expect(exclusionTypeBadgeVariant("SecRuleUpdateTargetById")).toBe("outline");
    expect(exclusionTypeBadgeVariant("SecRuleUpdateTargetByTag")).toBe("outline");
  });

  it("returns 'secondary' for runtime types", () => {
    expect(exclusionTypeBadgeVariant("ctl:ruleRemoveById")).toBe("secondary");
    expect(exclusionTypeBadgeVariant("ctl:ruleRemoveByTag")).toBe("secondary");
    expect(exclusionTypeBadgeVariant("ctl:ruleRemoveTargetById")).toBe("secondary");
    expect(exclusionTypeBadgeVariant("ctl:ruleRemoveTargetByTag")).toBe("secondary");
  });

  it("returns 'outline' for unknown types", () => {
    expect(exclusionTypeBadgeVariant("unknown" as ExclusionType)).toBe("outline");
  });
});

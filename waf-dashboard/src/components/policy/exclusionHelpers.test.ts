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
      conditions: [
        { field: "path", operator: "eq", value: "/very/long/path/to/something/that/is/quite/lengthy" },
        { field: "host", operator: "eq", value: "very-long-hostname.example.com" },
        { field: "user_agent", operator: "contains", value: "some-long-user-agent-string" },
      ],
    });
    const summary = conditionsSummary(excl);
    expect(summary.length).toBeLessThanOrEqual(103); // 100 + "..."
  });

  // Detect rules
  it("shows conditions for detect type", () => {
    const excl = makeExclusion({
      type: "detect",
      severity: "WARNING",
      detect_paranoia_level: 2,
      conditions: [
        { field: "user_agent", operator: "contains", value: "curl" },
      ],
    });
    const summary = conditionsSummary(excl);
    expect(summary).toContain("curl");
  });

  // Block rules with path conditions
  it("shows path condition for block rules", () => {
    const excl = makeExclusion({
      type: "block",
      conditions: [
        { field: "path", operator: "in", value: "/wp-login.php /wp-admin/ /xmlrpc.php /.env /.git/" },
      ],
    });
    const summary = conditionsSummary(excl);
    expect(summary).toContain("/wp-login.php");
  });
});

// ─── exclusionTypeLabel ─────────────────────────────────────────────

describe("exclusionTypeLabel", () => {
  it('returns "Allow" for allow', () => {
    expect(exclusionTypeLabel("allow")).toBe("Allow");
  });

  it('returns "Block" for block', () => {
    expect(exclusionTypeLabel("block")).toBe("Block");
  });

  it('returns "Skip" for skip', () => {
    expect(exclusionTypeLabel("skip")).toBe("Skip");
  });

  it('returns "Detect" for detect', () => {
    expect(exclusionTypeLabel("detect")).toBe("Detect");
  });

  it("returns the raw type string for unknown types", () => {
    expect(exclusionTypeLabel("unknown_type" as ExclusionType)).toBe("unknown_type");
  });
});

// ─── exclusionTypeBadgeVariant ──────────────────────────────────────

describe("exclusionTypeBadgeVariant", () => {
  it("returns 'outline' for allow", () => {
    expect(exclusionTypeBadgeVariant("allow")).toBe("outline");
  });

  it("returns 'destructive' for block", () => {
    expect(exclusionTypeBadgeVariant("block")).toBe("destructive");
  });

  it("returns 'default' for skip", () => {
    expect(exclusionTypeBadgeVariant("skip")).toBe("default");
  });

  it("returns 'secondary' for detect", () => {
    expect(exclusionTypeBadgeVariant("detect")).toBe("secondary");
  });

  it("returns 'outline' for unknown types", () => {
    expect(exclusionTypeBadgeVariant("unknown" as ExclusionType)).toBe("outline");
  });
});

import { describe, it, expect, vi } from "vitest";
import {
  listDefaultRules,
  getDefaultRule,
  overrideDefaultRule,
  resetDefaultRule,
  bulkOverrideDefaultRules,
  bulkResetDefaultRules,
  getCategoryForRule,
  getCategoryName,
  type DefaultRule,
} from "@/lib/api";
import { mockFetchResponse, setupMockFetch } from "./__test-helpers";

setupMockFetch();

// ─── Default Rules API Tests ────────────────────────────────────────

const mockRule: DefaultRule = {
  id: "942100",
  name: "SQL Injection Attack Detected via libinjection",
  description: "Detects SQLi via libinjection tokenization",
  type: "detect",
  conditions: [
    {
      field: "request_combined",
      operator: "detect_sqli",
      transforms: ["urlDecodeUni", "removeNulls"],
    },
  ],
  group_op: "and",
  severity: "CRITICAL",
  paranoia_level: 1,
  tags: ["attack-sqli"],
  enabled: true,
  priority: 400,
  is_default: true,
  has_override: false,
};

describe("listDefaultRules", () => {
  it("returns array of rules", async () => {
    vi.stubGlobal("fetch", mockFetchResponse([mockRule]));
    const result = await listDefaultRules();
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("942100");
    expect(result[0].is_default).toBe(true);
  });

  it("returns empty array when no rules", async () => {
    vi.stubGlobal("fetch", mockFetchResponse([]));
    const result = await listDefaultRules();
    expect(result).toHaveLength(0);
  });
});

describe("getDefaultRule", () => {
  it("returns a single rule by ID", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockRule));
    const result = await getDefaultRule("942100");
    expect(result.id).toBe("942100");
    expect(result.severity).toBe("CRITICAL");
  });

  it("throws on 404", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: "Not Found",
        text: () => Promise.resolve('{"error":"rule not found"}'),
      }),
    );
    await expect(getDefaultRule("nonexistent")).rejects.toThrow("404");
  });
});

describe("overrideDefaultRule", () => {
  const overriddenRule: DefaultRule = {
    ...mockRule,
    enabled: false,
    has_override: true,
    override_fields: ["enabled"],
  };

  it("sends PUT with override body", async () => {
    const fn = mockFetchResponse(overriddenRule);
    vi.stubGlobal("fetch", fn);
    const result = await overrideDefaultRule("942100", { enabled: false });
    expect(result.enabled).toBe(false);
    expect(result.has_override).toBe(true);
    expect(fn).toHaveBeenCalledWith(
      expect.stringContaining("/default-rules/942100"),
      expect.objectContaining({ method: "PUT" }),
    );
  });

  it("can override severity", async () => {
    const updated = { ...mockRule, severity: "WARNING" as const, has_override: true };
    vi.stubGlobal("fetch", mockFetchResponse(updated));
    const result = await overrideDefaultRule("942100", { severity: "WARNING" });
    expect(result.severity).toBe("WARNING");
  });

  it("can override paranoia_level", async () => {
    const updated = { ...mockRule, paranoia_level: 3, has_override: true };
    vi.stubGlobal("fetch", mockFetchResponse(updated));
    const result = await overrideDefaultRule("942100", { paranoia_level: 3 });
    expect(result.paranoia_level).toBe(3);
  });
});

describe("resetDefaultRule", () => {
  it("sends DELETE to override endpoint", async () => {
    const fn = mockFetchResponse(mockRule);
    vi.stubGlobal("fetch", fn);
    const result = await resetDefaultRule("942100");
    expect(result.has_override).toBe(false);
    expect(fn).toHaveBeenCalledWith(
      expect.stringContaining("/default-rules/942100/override"),
      expect.objectContaining({ method: "DELETE" }),
    );
  });
});

describe("bulkOverrideDefaultRules", () => {
  it("sends POST with ids and override", async () => {
    const fn = mockFetchResponse({ changed: 3 });
    vi.stubGlobal("fetch", fn);
    const result = await bulkOverrideDefaultRules(
      ["942100", "942110", "942120"],
      { enabled: false },
    );
    expect(result.changed).toBe(3);
    expect(fn).toHaveBeenCalledWith(
      expect.stringContaining("/default-rules/bulk"),
      expect.objectContaining({
        method: "POST",
        body: expect.stringContaining('"action":"override"'),
      }),
    );
  });

  it("throws on error response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        text: () => Promise.resolve("invalid action"),
      }),
    );
    await expect(
      bulkOverrideDefaultRules(["942100"], { enabled: false }),
    ).rejects.toThrow("invalid action");
  });
});

describe("bulkResetDefaultRules", () => {
  it("sends POST with ids and reset action", async () => {
    const fn = mockFetchResponse({ removed: 2 });
    vi.stubGlobal("fetch", fn);
    const result = await bulkResetDefaultRules(["942100", "942110"]);
    expect(result.removed).toBe(2);
    expect(fn).toHaveBeenCalledWith(
      expect.stringContaining("/default-rules/bulk"),
      expect.objectContaining({
        method: "POST",
        body: expect.stringContaining('"action":"reset"'),
      }),
    );
  });
});

// ─── Category Helper Tests ──────────────────────────────────────────

describe("getCategoryForRule", () => {
  it("maps standard CRS rule IDs", () => {
    expect(getCategoryForRule("942100")?.shortName).toBe("SQLi");
    expect(getCategoryForRule("941100")?.shortName).toBe("XSS");
    expect(getCategoryForRule("932100")?.shortName).toBe("RCE");
    expect(getCategoryForRule("930110")?.shortName).toBe("LFI");
    expect(getCategoryForRule("913100")?.shortName).toBe("Scanner");
  });

  it("maps 9100xxx to Custom Rules before 91x CRS ranges", () => {
    expect(getCategoryForRule("9100003")?.shortName).toBe("Custom");
    expect(getCategoryForRule("9100030")?.shortName).toBe("Custom");
  });

  it("does not map 9100xxx as Scanner (913)", () => {
    const cat = getCategoryForRule("9100003");
    expect(cat?.prefix).toBe("9100");
    expect(cat?.prefix).not.toBe("913");
  });

  it("returns undefined for unmapped IDs", () => {
    expect(getCategoryForRule("999999")).toBeUndefined();
  });
});

describe("getCategoryName", () => {
  it("returns full category name", () => {
    expect(getCategoryName("942100")).toBe("SQL Injection");
    expect(getCategoryName("941100")).toBe("Cross-Site Scripting");
  });

  it("returns 'Other' for unmapped IDs", () => {
    expect(getCategoryName("999999")).toBe("Other");
  });
});

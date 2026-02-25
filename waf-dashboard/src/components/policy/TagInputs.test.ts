import { describe, it, expect } from "vitest";
import { parseRuleIds, joinRuleIds, HTTP_METHODS } from "./TagInputs";

// ─── parseRuleIds ───────────────────────────────────────────────────

describe("parseRuleIds", () => {
  it("parses space-separated IDs", () => {
    expect(parseRuleIds("942100 942200 920420")).toEqual(["942100", "942200", "920420"]);
  });

  it("parses comma-separated IDs", () => {
    expect(parseRuleIds("942100,942200,920420")).toEqual(["942100", "942200", "920420"]);
  });

  it("parses mixed separators", () => {
    expect(parseRuleIds("942100, 942200 920420")).toEqual(["942100", "942200", "920420"]);
  });

  it("handles empty string", () => {
    expect(parseRuleIds("")).toEqual([]);
  });

  it("handles whitespace-only string", () => {
    expect(parseRuleIds("   ")).toEqual([]);
  });

  it("handles single ID", () => {
    expect(parseRuleIds("942100")).toEqual(["942100"]);
  });

  it("filters out empty segments from multiple spaces", () => {
    expect(parseRuleIds("942100   942200")).toEqual(["942100", "942200"]);
  });

  it("handles tab separators", () => {
    expect(parseRuleIds("942100\t942200")).toEqual(["942100", "942200"]);
  });

  it("preserves range syntax", () => {
    expect(parseRuleIds("942000-942999 920420")).toEqual(["942000-942999", "920420"]);
  });
});

// ─── joinRuleIds ────────────────────────────────────────────────────

describe("joinRuleIds", () => {
  it("joins array with spaces", () => {
    expect(joinRuleIds(["942100", "942200", "920420"])).toBe("942100 942200 920420");
  });

  it("handles single ID", () => {
    expect(joinRuleIds(["942100"])).toBe("942100");
  });

  it("handles empty array", () => {
    expect(joinRuleIds([])).toBe("");
  });
});

// ─── parseRuleIds / joinRuleIds roundtrip ───────────────────────────

describe("parseRuleIds / joinRuleIds roundtrip", () => {
  it("roundtrips cleanly for space-separated input", () => {
    const input = "942100 942200 920420";
    expect(joinRuleIds(parseRuleIds(input))).toBe(input);
  });

  it("normalizes comma-separated to space-separated", () => {
    const input = "942100,942200,920420";
    expect(joinRuleIds(parseRuleIds(input))).toBe("942100 942200 920420");
  });

  it("normalizes mixed separators", () => {
    const input = "942100, 942200  920420";
    expect(joinRuleIds(parseRuleIds(input))).toBe("942100 942200 920420");
  });
});

// ─── HTTP_METHODS ───────────────────────────────────────────────────

describe("HTTP_METHODS", () => {
  it("contains all standard HTTP methods", () => {
    expect(HTTP_METHODS).toContain("GET");
    expect(HTTP_METHODS).toContain("POST");
    expect(HTTP_METHODS).toContain("PUT");
    expect(HTTP_METHODS).toContain("PATCH");
    expect(HTTP_METHODS).toContain("DELETE");
    expect(HTTP_METHODS).toContain("HEAD");
    expect(HTTP_METHODS).toContain("OPTIONS");
  });

  it("has exactly 7 methods", () => {
    expect(HTTP_METHODS).toHaveLength(7);
  });

  it("has no duplicates", () => {
    expect(new Set(HTTP_METHODS).size).toBe(HTTP_METHODS.length);
  });

  it("is all uppercase", () => {
    for (const method of HTTP_METHODS) {
      expect(method).toBe(method.toUpperCase());
    }
  });
});

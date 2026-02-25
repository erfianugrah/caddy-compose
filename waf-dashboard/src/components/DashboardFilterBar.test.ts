import { describe, it, expect } from "vitest";
import {
  parseFiltersFromURL,
  filtersToSummaryParams,
  filtersToEventsParams,
  filterDisplayValue,
  operatorChip,
  FILTER_FIELDS,
  type DashboardFilter,
  type FilterField,
} from "./DashboardFilterBar";

// ─── parseFiltersFromURL ────────────────────────────────────────────

describe("parseFiltersFromURL", () => {
  it("returns empty array for empty search string", () => {
    expect(parseFiltersFromURL("")).toEqual([]);
  });

  it("returns empty array for no recognized params", () => {
    expect(parseFiltersFromURL("?foo=bar&baz=qux")).toEqual([]);
  });

  it("parses service param with default eq operator", () => {
    const result = parseFiltersFromURL("?service=cdn.erfi.io");
    expect(result).toEqual([{ field: "service", operator: "eq", value: "cdn.erfi.io" }]);
  });

  it("parses client param", () => {
    const result = parseFiltersFromURL("?client=1.2.3.4");
    expect(result).toEqual([{ field: "client", operator: "eq", value: "1.2.3.4" }]);
  });

  it("parses ip param as client (alias)", () => {
    const result = parseFiltersFromURL("?ip=10.0.0.1");
    expect(result).toEqual([{ field: "client", operator: "eq", value: "10.0.0.1" }]);
  });

  it("prefers client over ip if both present", () => {
    const result = parseFiltersFromURL("?client=1.1.1.1&ip=2.2.2.2");
    expect(result).toEqual([{ field: "client", operator: "eq", value: "1.1.1.1" }]);
  });

  it("parses event_type param", () => {
    const result = parseFiltersFromURL("?event_type=blocked");
    expect(result).toEqual([{ field: "event_type", operator: "eq", value: "blocked" }]);
  });

  it("parses type param as event_type (alias)", () => {
    const result = parseFiltersFromURL("?type=honeypot");
    expect(result).toEqual([{ field: "event_type", operator: "eq", value: "honeypot" }]);
  });

  it("prefers event_type over type if both present", () => {
    const result = parseFiltersFromURL("?event_type=blocked&type=logged");
    expect(result).toEqual([{ field: "event_type", operator: "eq", value: "blocked" }]);
  });

  it("parses method param", () => {
    const result = parseFiltersFromURL("?method=POST");
    expect(result).toEqual([{ field: "method", operator: "eq", value: "POST" }]);
  });

  it("parses rule_name param", () => {
    const result = parseFiltersFromURL("?rule_name=Allow+Static+Assets");
    expect(result).toEqual([{ field: "rule_name", operator: "eq", value: "Allow Static Assets" }]);
  });

  it("parses multiple params at once", () => {
    const result = parseFiltersFromURL("?service=cdn.erfi.io&client=1.2.3.4&event_type=blocked");
    expect(result).toHaveLength(3);
    expect(result).toContainEqual({ field: "service", operator: "eq", value: "cdn.erfi.io" });
    expect(result).toContainEqual({ field: "client", operator: "eq", value: "1.2.3.4" });
    expect(result).toContainEqual({ field: "event_type", operator: "eq", value: "blocked" });
  });

  it("parses all five params together", () => {
    const result = parseFiltersFromURL(
      "?service=api.io&client=10.0.0.1&event_type=rate_limited&method=GET&rule_name=My+Rule"
    );
    expect(result).toHaveLength(5);
  });

  it("ignores empty param values", () => {
    const result = parseFiltersFromURL("?service=&client=1.2.3.4");
    expect(result).toEqual([{ field: "client", operator: "eq", value: "1.2.3.4" }]);
  });

  // ── Operator parsing ──

  it("parses _op param for service", () => {
    const result = parseFiltersFromURL("?service=erfi&service_op=contains");
    expect(result).toEqual([{ field: "service", operator: "contains", value: "erfi" }]);
  });

  it("parses _op=in for event_type", () => {
    const result = parseFiltersFromURL("?event_type=blocked,logged&event_type_op=in");
    expect(result).toEqual([{ field: "event_type", operator: "in", value: "blocked,logged" }]);
  });

  it("parses _op=regex for rule_name", () => {
    const result = parseFiltersFromURL("?rule_name=Allow.*&rule_name_op=regex");
    expect(result).toEqual([{ field: "rule_name", operator: "regex", value: "Allow.*" }]);
  });

  it("parses _op=neq for client", () => {
    const result = parseFiltersFromURL("?client=1.2.3.4&client_op=neq");
    expect(result).toEqual([{ field: "client", operator: "neq", value: "1.2.3.4" }]);
  });

  it("falls back to eq for invalid operator", () => {
    const result = parseFiltersFromURL("?service=cdn&service_op=invalid_op");
    expect(result).toEqual([{ field: "service", operator: "eq", value: "cdn" }]);
  });

  it("falls back to first valid op when _op is not in field's allowed set", () => {
    // client does not support "regex"
    const result = parseFiltersFromURL("?client=1.2.3.4&client_op=regex");
    expect(result).toEqual([{ field: "client", operator: "eq", value: "1.2.3.4" }]);
  });

  it("parses method with in operator", () => {
    const result = parseFiltersFromURL("?method=GET,POST&method_op=in");
    expect(result).toEqual([{ field: "method", operator: "in", value: "GET,POST" }]);
  });
});

// ─── filtersToSummaryParams ─────────────────────────────────────────

describe("filtersToSummaryParams", () => {
  it("returns empty object for no filters", () => {
    expect(filtersToSummaryParams([])).toEqual({});
  });

  it("maps service filter with default eq operator", () => {
    const filters: DashboardFilter[] = [{ field: "service", operator: "eq", value: "cdn.erfi.io" }];
    expect(filtersToSummaryParams(filters)).toEqual({ service: "cdn.erfi.io", service_op: "eq" });
  });

  it("maps client filter", () => {
    const filters: DashboardFilter[] = [{ field: "client", operator: "eq", value: "1.2.3.4" }];
    expect(filtersToSummaryParams(filters)).toEqual({ client: "1.2.3.4", client_op: "eq" });
  });

  it("maps event_type filter", () => {
    const filters: DashboardFilter[] = [{ field: "event_type", operator: "eq", value: "blocked" }];
    expect(filtersToSummaryParams(filters)).toEqual({ event_type: "blocked", event_type_op: "eq" });
  });

  it("maps method filter", () => {
    const filters: DashboardFilter[] = [{ field: "method", operator: "eq", value: "POST" }];
    expect(filtersToSummaryParams(filters)).toEqual({ method: "POST", method_op: "eq" });
  });

  it("maps rule_name filter", () => {
    const filters: DashboardFilter[] = [{ field: "rule_name", operator: "eq", value: "My Rule" }];
    expect(filtersToSummaryParams(filters)).toEqual({ rule_name: "My Rule", rule_name_op: "eq" });
  });

  it("maps multiple filters with operators", () => {
    const filters: DashboardFilter[] = [
      { field: "service", operator: "contains", value: "erfi" },
      { field: "client", operator: "neq", value: "1.2.3.4" },
      { field: "method", operator: "in", value: "GET,POST" },
    ];
    expect(filtersToSummaryParams(filters)).toEqual({
      service: "erfi", service_op: "contains",
      client: "1.2.3.4", client_op: "neq",
      method: "GET,POST", method_op: "in",
    });
  });

  it("last filter wins for duplicate fields", () => {
    const filters: DashboardFilter[] = [
      { field: "service", operator: "eq", value: "a.io" },
      { field: "service", operator: "contains", value: "b" },
    ];
    const result = filtersToSummaryParams(filters);
    expect(result.service).toBe("b");
    expect(result.service_op).toBe("contains");
  });
});

// ─── filtersToEventsParams ──────────────────────────────────────────

describe("filtersToEventsParams", () => {
  it("returns empty object for no filters", () => {
    expect(filtersToEventsParams([])).toEqual({});
  });

  it("maps all filter types with operators correctly", () => {
    const filters: DashboardFilter[] = [
      { field: "service", operator: "regex", value: "^cdn\\." },
      { field: "client", operator: "in", value: "1.2.3.4,5.6.7.8" },
      { field: "event_type", operator: "eq", value: "honeypot" },
      { field: "method", operator: "in", value: "GET,POST" },
      { field: "rule_name", operator: "contains", value: "Allow" },
    ];
    const result = filtersToEventsParams(filters);
    expect(result).toEqual({
      service: "^cdn\\.", service_op: "regex",
      client: "1.2.3.4,5.6.7.8", client_op: "in",
      event_type: "honeypot", event_type_op: "eq",
      method: "GET,POST", method_op: "in",
      rule_name: "Allow", rule_name_op: "contains",
    });
  });
});

// ─── filterDisplayValue ─────────────────────────────────────────────

describe("filterDisplayValue", () => {
  it("returns option label for event_type values", () => {
    expect(filterDisplayValue("event_type", "blocked")).toBe("Blocked");
    expect(filterDisplayValue("event_type", "rate_limited")).toBe("Rate Limited");
    expect(filterDisplayValue("event_type", "ipsum_blocked")).toBe("IPsum Blocked");
    expect(filterDisplayValue("event_type", "honeypot")).toBe("Honeypot");
    expect(filterDisplayValue("event_type", "scanner")).toBe("Scanner");
    expect(filterDisplayValue("event_type", "policy_skip")).toBe("Policy Skip");
    expect(filterDisplayValue("event_type", "policy_allow")).toBe("Policy Allow");
    expect(filterDisplayValue("event_type", "policy_block")).toBe("Policy Block");
  });

  it("returns option label for method values", () => {
    expect(filterDisplayValue("method", "GET")).toBe("GET");
    expect(filterDisplayValue("method", "POST")).toBe("POST");
    expect(filterDisplayValue("method", "DELETE")).toBe("DELETE");
  });

  it("returns raw value for free-text fields", () => {
    expect(filterDisplayValue("service", "cdn.erfi.io")).toBe("cdn.erfi.io");
    expect(filterDisplayValue("client", "1.2.3.4")).toBe("1.2.3.4");
    expect(filterDisplayValue("rule_name", "My Rule")).toBe("My Rule");
  });

  it("returns raw value for unknown event_type option", () => {
    expect(filterDisplayValue("event_type", "unknown_type")).toBe("unknown_type");
  });

  it("resolves comma-separated IN values to labels", () => {
    expect(filterDisplayValue("event_type", "blocked,logged")).toBe("Blocked, Logged");
    expect(filterDisplayValue("method", "GET,POST,DELETE")).toBe("GET, POST, DELETE");
  });

  it("keeps raw values for IN on free-text fields", () => {
    expect(filterDisplayValue("client", "1.2.3.4,5.6.7.8")).toBe("1.2.3.4,5.6.7.8");
  });
});

// ─── operatorChip ───────────────────────────────────────────────────

describe("operatorChip", () => {
  it("returns = for eq", () => {
    expect(operatorChip("eq")).toBe("=");
  });

  it("returns ≠ for neq", () => {
    expect(operatorChip("neq")).toBe("≠");
  });

  it("returns ~ for contains", () => {
    expect(operatorChip("contains")).toBe("~");
  });

  it("returns in for in", () => {
    expect(operatorChip("in")).toBe("in");
  });

  it("returns re for regex", () => {
    expect(operatorChip("regex")).toBe("re");
  });
});

// ─── FILTER_FIELDS metadata ─────────────────────────────────────────

describe("FILTER_FIELDS", () => {
  it("defines all five filter fields", () => {
    const fields = Object.keys(FILTER_FIELDS);
    expect(fields).toContain("service");
    expect(fields).toContain("client");
    expect(fields).toContain("event_type");
    expect(fields).toContain("method");
    expect(fields).toContain("rule_name");
  });

  it("event_type has 9 options", () => {
    expect(FILTER_FIELDS.event_type.options).toHaveLength(9);
  });

  it("method has 7 options", () => {
    expect(FILTER_FIELDS.method.options).toHaveLength(7);
  });

  it("service has no options (free text)", () => {
    expect(FILTER_FIELDS.service.options).toBeUndefined();
  });

  it("client has no options (free text)", () => {
    expect(FILTER_FIELDS.client.options).toBeUndefined();
  });

  it("rule_name has no options (free text)", () => {
    expect(FILTER_FIELDS.rule_name.options).toBeUndefined();
  });

  it("all fields have a label and placeholder", () => {
    const allFields: FilterField[] = ["service", "client", "event_type", "method", "rule_name"];
    for (const field of allFields) {
      expect(FILTER_FIELDS[field].label).toBeTruthy();
      expect(FILTER_FIELDS[field].placeholder).toBeTruthy();
    }
  });
});

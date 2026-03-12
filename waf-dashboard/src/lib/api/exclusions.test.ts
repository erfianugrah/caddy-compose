import { describe, it, expect, vi } from "vitest";
import {
  deployConfig,
  fetchCRSRules,
  type CRSCatalogResponse,
} from "@/lib/api";
import { mockFetchResponse, setupMockFetch } from "./__test-helpers";

setupMockFetch();

// ─── Exclusion type/field mapping ───────────────────────────────────

describe("getExclusions", () => {
  it("maps Go type names and conditions", async () => {
    const goExclusions = [
      {
        id: "exc-1",
        name: "Block bad IP",
        description: "Block known attacker",
        type: "block",
        conditions: [
          { field: "ip", operator: "ip_match", value: "10.0.0.1" },
          { field: "path", operator: "begins_with", value: "/api/" },
        ],
        group_operator: "and",
        enabled: true,
        created_at: "2026-02-22T10:00:00Z",
        updated_at: "2026-02-22T10:00:00Z",
      },
      {
        id: "exc-2",
        name: "Allow admin",
        description: "",
        type: "allow",
        conditions: [
          { field: "ip", operator: "eq", value: "10.0.0.2" },
        ],
        group_operator: "and",
        enabled: true,
        created_at: "2026-02-22T10:00:00Z",
        updated_at: "2026-02-22T10:00:00Z",
      },
    ];

    vi.stubGlobal("fetch", mockFetchResponse(goExclusions));

    const { getExclusions } = await import("@/lib/api");
    const result = await getExclusions();

    expect(result).toHaveLength(2);
    expect(result[0].type).toBe("block");
    expect(result[1].type).toBe("allow");

    // Conditions
    expect(result[0].conditions).toHaveLength(2);
    expect(result[0].conditions[0].field).toBe("ip");
    expect(result[0].conditions[0].operator).toBe("ip_match");
    expect(result[0].conditions[0].value).toBe("10.0.0.1");
    expect(result[0].group_operator).toBe("and");
  });
});

describe("createExclusion", () => {
  it("maps type names and conditions in the request payload", async () => {
    const goCreated = {
      id: "exc-new",
      name: "Allow admin IP",
      description: "",
      type: "allow",
      conditions: [
        { field: "ip", operator: "ip_match", value: "195.240.81.42" },
      ],
      group_operator: "and",
      enabled: true,
      created_at: "2026-02-22T10:00:00Z",
      updated_at: "2026-02-22T10:00:00Z",
    };

    vi.stubGlobal("fetch", mockFetchResponse(goCreated, 201));

    const { createExclusion } = await import("@/lib/api");
    const result = await createExclusion({
      name: "Allow admin IP",
      description: "",
      type: "allow",
      conditions: [
        { field: "ip", operator: "ip_match", value: "195.240.81.42" },
      ],
      group_operator: "and",
      enabled: true,
    });

    // Response is mapped back
    expect(result.type).toBe("allow");
    expect(result.conditions).toHaveLength(1);
    expect(result.conditions[0].field).toBe("ip");

    // Verify the POST payload
    const postCall = vi.mocked(fetch).mock.calls[0];
    const body = JSON.parse(postCall[1]?.body as string);
    expect(body.type).toBe("allow");
    expect(body.conditions).toHaveLength(1);
    expect(body.conditions[0].field).toBe("ip");
  });
});

// ─── Detect type with severity ──────────────────────────────────────

describe("createExclusion (detect type)", () => {
  it("sends severity and detect_paranoia_level in payload", async () => {
    const goCreated = {
      id: "exc-detect",
      name: "Detect missing referer",
      description: "Detect heuristic",
      type: "detect",
      conditions: [
        { field: "referer", operator: "eq", value: "" },
      ],
      group_operator: "and",
      severity: "WARNING",
      detect_paranoia_level: 2,
      enabled: true,
      created_at: "2026-03-08T10:00:00Z",
      updated_at: "2026-03-08T10:00:00Z",
    };

    vi.stubGlobal("fetch", mockFetchResponse(goCreated, 201));

    const { createExclusion } = await import("@/lib/api");
    const result = await createExclusion({
      name: "Detect missing referer",
      description: "Detect heuristic",
      type: "detect",
      conditions: [
        { field: "referer", operator: "eq", value: "" },
      ],
      group_operator: "and",
      severity: "WARNING",
      detect_paranoia_level: 2,
      enabled: true,
    });

    // Response is mapped back correctly
    expect(result.type).toBe("detect");
    expect(result.severity).toBe("WARNING");
    expect(result.detect_paranoia_level).toBe(2);

    // Verify the POST payload includes detect fields
    const postCall = vi.mocked(fetch).mock.calls[0];
    const body = JSON.parse(postCall[1]?.body as string);
    expect(body.type).toBe("detect");
    expect(body.severity).toBe("WARNING");
    expect(body.detect_paranoia_level).toBe(2);
  });
});

describe("getExclusions (detect type mapping)", () => {
  it("maps Go detect type and preserves severity fields", async () => {
    const goExclusions = [
      {
        id: "exc-detect-1",
        name: "Generic UA detect",
        description: "",
        type: "detect",
        conditions: [
          { field: "user_agent", operator: "contains", value: "python-requests" },
        ],
        group_operator: "and",
        severity: "NOTICE",
        detect_paranoia_level: 1,
        enabled: true,
        created_at: "2026-03-08T10:00:00Z",
        updated_at: "2026-03-08T10:00:00Z",
      },
    ];

    vi.stubGlobal("fetch", mockFetchResponse(goExclusions));

    const { getExclusions } = await import("@/lib/api");
    const result = await getExclusions();

    expect(result).toHaveLength(1);
    expect(result[0].type).toBe("detect");
    expect(result[0].severity).toBe("NOTICE");
    expect(result[0].detect_paranoia_level).toBe(1);
  });
});

// ─── Condition transforms ───────────────────────────────────────────

describe("getExclusions (conditions with transforms)", () => {
  it("preserves transforms on conditions from Go API", async () => {
    const goExclusions = [
      {
        id: "exc-tf-1",
        name: "Block encoded admin",
        description: "",
        type: "block",
        conditions: [
          { field: "path", operator: "contains", value: "/admin", transforms: ["urlDecode", "lowercase"] },
          { field: "user_agent", operator: "regex", value: "bot" },
        ],
        group_operator: "and",
        enabled: true,
        created_at: "2026-03-11T10:00:00Z",
        updated_at: "2026-03-11T10:00:00Z",
      },
    ];

    vi.stubGlobal("fetch", mockFetchResponse(goExclusions));

    const { getExclusions } = await import("@/lib/api");
    const result = await getExclusions();

    expect(result).toHaveLength(1);
    expect(result[0].conditions[0].transforms).toEqual(["urlDecode", "lowercase"]);
    expect(result[0].conditions[1].transforms).toBeUndefined();
  });
});

describe("createExclusion (conditions with transforms)", () => {
  it("sends transforms in condition payload", async () => {
    const goCreated = {
      id: "exc-tf-new",
      name: "Block with transforms",
      description: "",
      type: "block",
      conditions: [
        { field: "path", operator: "contains", value: "/admin", transforms: ["urlDecode", "lowercase"] },
      ],
      group_operator: "and",
      enabled: true,
      created_at: "2026-03-11T10:00:00Z",
      updated_at: "2026-03-11T10:00:00Z",
    };

    vi.stubGlobal("fetch", mockFetchResponse(goCreated, 201));

    const { createExclusion } = await import("@/lib/api");
    await createExclusion({
      name: "Block with transforms",
      type: "block",
      conditions: [
        { field: "path", operator: "contains", value: "/admin", transforms: ["urlDecode", "lowercase"] },
      ],
      enabled: true,
    });

    const postCall = vi.mocked(fetch).mock.calls[0];
    const body = JSON.parse(postCall[1]?.body as string);
    expect(body.conditions[0].transforms).toEqual(["urlDecode", "lowercase"]);
  });

  it("omits transforms when empty/undefined", async () => {
    const goCreated = {
      id: "exc-notf",
      name: "No transforms",
      description: "",
      type: "block",
      conditions: [
        { field: "path", operator: "eq", value: "/test" },
      ],
      group_operator: "and",
      enabled: true,
      created_at: "2026-03-11T10:00:00Z",
      updated_at: "2026-03-11T10:00:00Z",
    };

    vi.stubGlobal("fetch", mockFetchResponse(goCreated, 201));

    const { createExclusion } = await import("@/lib/api");
    await createExclusion({
      name: "No transforms",
      type: "block",
      conditions: [
        { field: "path", operator: "eq", value: "/test" },
      ],
      enabled: true,
    });

    const postCall = vi.mocked(fetch).mock.calls[0];
    const body = JSON.parse(postCall[1]?.body as string);
    expect(body.conditions[0].transforms).toBeUndefined();
  });
});

// ─── deployConfig ───────────────────────────────────────────────────

describe("deployConfig", () => {
  it("calls POST /api/config/deploy and returns DeployResult", async () => {
    const deployResponse = {
      status: "deployed",
      message: "Config files written and Caddy reloaded successfully",
      reloaded: true,
      timestamp: "2026-02-22T11:00:00Z",
    };
    vi.stubGlobal("fetch", mockFetchResponse(deployResponse));
    const { deployConfig } = await import("@/lib/api");
    const result = await deployConfig();
    expect(result.status).toBe("deployed");
    expect(result.reloaded).toBe(true);
  });

  it("handles partial deploy (reload failed)", async () => {
    const partialResponse = {
      status: "partial",
      message: "Config files written but Caddy reload failed",
      reloaded: false,
      timestamp: "2026-02-22T11:00:00Z",
    };
    vi.stubGlobal("fetch", mockFetchResponse(partialResponse));
    const { deployConfig } = await import("@/lib/api");
    const result = await deployConfig();
    expect(result.status).toBe("partial");
    expect(result.reloaded).toBe(false);
  });
});

// ─── fetchCRSRules ──────────────────────────────────────────────────

describe("fetchCRSRules", () => {
  it("returns CRS catalog with categories and rules", async () => {
    const mockCatalog = {
      categories: [
        { id: "sqli", name: "SQL Injection", description: "SQL injection detection", rule_range: "942000-942999" },
      ],
      rules: [
        { id: "942100", description: "SQL Injection Attack Detected via libinjection", category: "sqli", tags: ["OWASP_CRS"], severity: "CRITICAL", paranoia_level: 1 },
        { id: "942110", description: "SQL Injection Attack: Common Injection Testing Detected", category: "sqli", tags: ["OWASP_CRS"], severity: "CRITICAL", paranoia_level: 1 },
      ],
      total: 2,
    };
    vi.stubGlobal("fetch", mockFetchResponse(mockCatalog));

    const result: CRSCatalogResponse = await fetchCRSRules();
    expect(result.total).toBe(2);
    expect(result.categories).toHaveLength(1);
    expect(result.categories[0].id).toBe("sqli");
    expect(result.rules).toHaveLength(2);
    expect(result.rules[0].id).toBe("942100");
    expect(result.rules[0].severity).toBe("CRITICAL");
  });

  it("calls the correct API endpoint", async () => {
    const mockFetch = mockFetchResponse({ categories: [], rules: [], total: 0 });
    vi.stubGlobal("fetch", mockFetch);

    await fetchCRSRules();
    expect(mockFetch).toHaveBeenCalledWith("/api/crs/rules", undefined);
  });
});

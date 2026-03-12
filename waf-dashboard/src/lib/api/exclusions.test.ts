import { describe, it, expect, vi } from "vitest";
import {
  generateConfig,
  deployConfig,
  fetchCRSRules,
  fetchCRSAutocomplete,
  type GeneratedConfig,
  type CRSCatalogResponse,
  type CRSAutocompleteResponse,
} from "@/lib/api";
import { mockFetchResponse, setupMockFetch } from "./__test-helpers";

setupMockFetch();

// ─── Exclusion type/field mapping ───────────────────────────────────

describe("getExclusions", () => {
  it("maps Go internal type names to ModSecurity names and conditions", async () => {
    const goExclusions = [
      {
        id: "exc-1",
        name: "Remove 920420",
        description: "Remove content-type rule",
        type: "remove_by_id",
        rule_id: "920420",
        conditions: [],
        enabled: true,
        created_at: "2026-02-22T10:00:00Z",
        updated_at: "2026-02-22T10:00:00Z",
      },
      {
        id: "exc-2",
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
    ];

    vi.stubGlobal("fetch", mockFetchResponse(goExclusions));

    const { getExclusions } = await import("@/lib/api");
    const result = await getExclusions();

    expect(result).toHaveLength(2);

    // Type mapping
    expect(result[0].type).toBe("SecRuleRemoveById");
    expect(result[1].type).toBe("block");

    // Conditions
    expect(result[1].conditions).toHaveLength(2);
    expect(result[1].conditions[0].field).toBe("ip");
    expect(result[1].conditions[0].operator).toBe("ip_match");
    expect(result[1].conditions[0].value).toBe("10.0.0.1");
    expect(result[1].group_operator).toBe("and");

    // Empty conditions default
    expect(result[0].conditions).toEqual([]);
    expect(result[0].group_operator).toBe("and");
  });
});

describe("createExclusion", () => {
  it("maps ModSecurity type names to Go internal names with conditions", async () => {
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

describe("createExclusion (anomaly type)", () => {
  it("sends anomaly_score and anomaly_paranoia_level in payload", async () => {
    const goCreated = {
      id: "exc-anomaly",
      name: "HTTP/1.0 penalty",
      description: "+2 anomaly for HTTP/1.0",
      type: "anomaly",
      conditions: [
        { field: "http_version", operator: "eq", value: "HTTP/1.0" },
      ],
      group_operator: "and",
      anomaly_score: 2,
      anomaly_paranoia_level: 1,
      enabled: true,
      created_at: "2026-03-08T10:00:00Z",
      updated_at: "2026-03-08T10:00:00Z",
    };

    vi.stubGlobal("fetch", mockFetchResponse(goCreated, 201));

    const { createExclusion } = await import("@/lib/api");
    const result = await createExclusion({
      name: "HTTP/1.0 penalty",
      description: "+2 anomaly for HTTP/1.0",
      type: "anomaly",
      conditions: [
        { field: "http_version", operator: "eq", value: "HTTP/1.0" },
      ],
      group_operator: "and",
      anomaly_score: 2,
      anomaly_paranoia_level: 1,
      enabled: true,
    });

    // Response is mapped back correctly
    expect(result.type).toBe("anomaly");
    expect(result.anomaly_score).toBe(2);
    expect(result.anomaly_paranoia_level).toBe(1);

    // Verify the POST payload includes anomaly fields
    const postCall = vi.mocked(fetch).mock.calls[0];
    const body = JSON.parse(postCall[1]?.body as string);
    expect(body.type).toBe("anomaly");
    expect(body.anomaly_score).toBe(2);
    expect(body.anomaly_paranoia_level).toBe(1);
  });
});

describe("getExclusions (anomaly type mapping)", () => {
  it("maps Go anomaly type and preserves score fields", async () => {
    const goExclusions = [
      {
        id: "exc-anomaly-1",
        name: "Generic UA penalty",
        description: "",
        type: "anomaly",
        conditions: [
          { field: "user_agent", operator: "contains", value: "python-requests" },
        ],
        group_operator: "and",
        anomaly_score: 5,
        anomaly_paranoia_level: 1,
        enabled: true,
        created_at: "2026-03-08T10:00:00Z",
        updated_at: "2026-03-08T10:00:00Z",
      },
    ];

    vi.stubGlobal("fetch", mockFetchResponse(goExclusions));

    const { getExclusions } = await import("@/lib/api");
    const result = await getExclusions();

    expect(result).toHaveLength(1);
    expect(result[0].type).toBe("anomaly");
    expect(result[0].anomaly_score).toBe(5);
    expect(result[0].anomaly_paranoia_level).toBe(1);
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

// ─── generateConfig ─────────────────────────────────────────────────

describe("generateConfig", () => {
  it("maps pre_crs_conf/post_crs_conf to pre_crs/post_crs", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchResponse({
        pre_crs_conf: "# pre-CRS content",
        post_crs_conf: "# post-CRS content",
      })
    );

    const result: GeneratedConfig = await generateConfig();
    expect(result.pre_crs).toBe("# pre-CRS content");
    expect(result.post_crs).toBe("# post-CRS content");
  });

  it("falls back to pre_crs/post_crs field names", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchResponse({
        pre_crs: "# pre-CRS fallback",
        post_crs: "# post-CRS fallback",
      })
    );

    const result = await generateConfig();
    expect(result.pre_crs).toBe("# pre-CRS fallback");
    expect(result.post_crs).toBe("# post-CRS fallback");
  });

  it("handles missing fields", async () => {
    vi.stubGlobal("fetch", mockFetchResponse({}));

    const result = await generateConfig();
    expect(result.pre_crs).toBe("");
    expect(result.post_crs).toBe("");
  });
});

// ─── deployConfig ───────────────────────────────────────────────────

describe("deployConfig", () => {
  it("calls POST /api/config/deploy and returns DeployResult", async () => {
    const deployResponse = {
      status: "deployed",
      message: "Config files written and Caddy reloaded successfully",
      pre_crs_file: "/data/waf/custom-pre-crs.conf",
      post_crs_file: "/data/waf/custom-post-crs.conf",
      waf_settings_file: "/data/waf/custom-waf-settings.conf",
      reloaded: true,
      timestamp: "2026-02-22T11:00:00Z",
    };
    vi.stubGlobal("fetch", mockFetchResponse(deployResponse));
    const { deployConfig } = await import("@/lib/api");
    const result = await deployConfig();
    expect(result.status).toBe("deployed");
    expect(result.reloaded).toBe(true);
    expect(result.pre_crs_file).toContain("custom-pre-crs");
  });

  it("handles partial deploy (reload failed)", async () => {
    const partialResponse = {
      status: "partial",
      message: "Config files written but Caddy reload failed",
      pre_crs_file: "/data/waf/custom-pre-crs.conf",
      post_crs_file: "/data/waf/custom-post-crs.conf",
      waf_settings_file: "/data/waf/custom-waf-settings.conf",
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

// ─── fetchCRSAutocomplete ───────────────────────────────────────────

describe("fetchCRSAutocomplete", () => {
  it("returns autocomplete data with variables, operators, and actions", async () => {
    const mockAutocomplete = {
      variables: ["ARGS", "REQUEST_URI", "REQUEST_HEADERS"],
      operators: [
        { name: "@rx", label: "matches regex", description: "Regular expression match", has_arg: true },
        { name: "@streq", label: "equals", description: "Exact string match", has_arg: true },
        { name: "@detectSQLi", label: "detect SQL injection", description: "SQL injection detection", has_arg: false },
      ],
      actions: ["id:", "phase:", "pass", "deny", "log", "t:none"],
    };
    vi.stubGlobal("fetch", mockFetchResponse(mockAutocomplete));

    const result: CRSAutocompleteResponse = await fetchCRSAutocomplete();
    expect(result.variables).toContain("ARGS");
    expect(result.operators).toHaveLength(3);
    expect(result.operators[0].label).toBe("matches regex");
    expect(result.operators[2].has_arg).toBe(false);
    expect(result.actions).toContain("deny");
  });

  it("calls the correct API endpoint", async () => {
    const mockFetch = mockFetchResponse({ variables: [], operators: [], actions: [] });
    vi.stubGlobal("fetch", mockFetch);

    await fetchCRSAutocomplete();
    expect(mockFetch).toHaveBeenCalledWith("/api/crs/autocomplete", undefined);
  });
});

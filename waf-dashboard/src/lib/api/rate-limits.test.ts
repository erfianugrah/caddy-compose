import { describe, it, expect, vi } from "vitest";
import {
  getRLRules,
  createRLRule,
  updateRLRule,
  deleteRLRule,
  deployRLRules,
  getRLGlobal,
  updateRLGlobal,
  exportRLRules,
  importRLRules,
  getRLRuleHits,
  getRateAdvisor,
  type RateLimitRule,
  type RateLimitGlobalConfig,
  type RateLimitRuleExport,
  type RateLimitDeployResult,
  type RLRuleHitsResponse,
  type RateAdvisorResponse,
} from "@/lib/api";
import { mockFetchResponse, setupMockFetch } from "./__test-helpers";

setupMockFetch();

// ─── Rate Limit Rule API Tests ──────────────────────────────────────

const mockRLRule: RateLimitRule = {
  id: "rl-001",
  name: "API rate limit",
  description: "Protect API from abuse",
  service: "api.erfi.io",
  conditions: [
    { field: "path", operator: "begins_with", value: "/api/" },
  ],
  group_operator: "and",
  key: "client_ip",
  events: 100,
  window: "1m",
  action: "deny",
  priority: 10,
  enabled: true,
  created_at: "2026-02-25T10:00:00Z",
  updated_at: "2026-02-25T10:00:00Z",
};

describe("getRLRules", () => {
  it("returns list of rate limit rules with defaults applied", async () => {
    vi.stubGlobal("fetch", mockFetchResponse([mockRLRule]));

    const result = await getRLRules();
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("rl-001");
    expect(result[0].name).toBe("API rate limit");
    expect(result[0].service).toBe("api.erfi.io");
    expect(result[0].conditions).toHaveLength(1);
    expect(result[0].conditions[0].field).toBe("path");
    expect(result[0].key).toBe("client_ip");
    expect(result[0].events).toBe(100);
    expect(result[0].window).toBe("1m");
    expect(result[0].action).toBe("deny");
    expect(result[0].enabled).toBe(true);
  });

  it("calls the correct endpoint", async () => {
    const mockFetch = mockFetchResponse([]);
    vi.stubGlobal("fetch", mockFetch);

    await getRLRules();
    expect(mockFetch).toHaveBeenCalledWith("/api/rate-rules", undefined);
  });

  it("handles null response gracefully", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(null));

    const result = await getRLRules();
    expect(result).toEqual([]);
  });

  it("applies defaults for missing fields", async () => {
    vi.stubGlobal("fetch", mockFetchResponse([{
      id: "rl-002",
      name: "Sparse rule",
      service: "web.erfi.io",
      events: 50,
      window: "30s",
      enabled: true,
      created_at: "2026-02-25T10:00:00Z",
      updated_at: "2026-02-25T10:00:00Z",
    }]));

    const result = await getRLRules();
    expect(result[0].description).toBe("");
    expect(result[0].conditions).toEqual([]);
    expect(result[0].group_operator).toBe("and");
    expect(result[0].key).toBe("client_ip");
    expect(result[0].action).toBe("deny");
    expect(result[0].priority).toBe(0);
  });
});

describe("createRLRule", () => {
  it("sends POST and returns created rule", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockRLRule, 201));

    const result = await createRLRule({
      name: "API rate limit",
      service: "api.erfi.io",
      conditions: [{ field: "path", operator: "begins_with", value: "/api/" }],
      key: "client_ip",
      events: 100,
      window: "1m",
      action: "deny",
      enabled: true,
    });

    expect(result.id).toBe("rl-001");
    expect(result.name).toBe("API rate limit");

    // Verify POST payload
    const postCall = vi.mocked(fetch).mock.calls[0];
    expect(postCall[1]?.method).toBe("POST");
    const body = JSON.parse(postCall[1]?.body as string);
    expect(body.name).toBe("API rate limit");
    expect(body.service).toBe("api.erfi.io");
    expect(body.key).toBe("client_ip");
    expect(body.events).toBe(100);
  });
});

describe("updateRLRule", () => {
  it("sends PUT and returns updated rule", async () => {
    const updated = { ...mockRLRule, events: 200 };
    vi.stubGlobal("fetch", mockFetchResponse(updated));

    const result = await updateRLRule("rl-001", { events: 200 });

    expect(result.events).toBe(200);

    // Verify PUT call
    const putCall = vi.mocked(fetch).mock.calls[0];
    expect(putCall[0]).toBe("/api/rate-rules/rl-001");
    expect(putCall[1]?.method).toBe("PUT");
  });
});

describe("deleteRLRule", () => {
  it("sends DELETE request", async () => {
    vi.stubGlobal("fetch", mockFetchResponse({ status: "deleted" }));

    await deleteRLRule("rl-001");

    const deleteCall = vi.mocked(fetch).mock.calls[0];
    expect(deleteCall[0]).toBe("/api/rate-rules/rl-001");
    expect(deleteCall[1]?.method).toBe("DELETE");
  });
});

describe("deployRLRules", () => {
  it("calls POST and returns deploy result", async () => {
    const deployResponse: RateLimitDeployResult = {
      status: "deployed",
      message: "3 rate limit files written and Caddy reloaded",
      files: ["api.erfi.io_rate_limit.caddy", "web.erfi.io_rate_limit.caddy"],
      reloaded: true,
      timestamp: "2026-02-25T10:00:00Z",
    };
    vi.stubGlobal("fetch", mockFetchResponse(deployResponse));

    const result = await deployRLRules();
    expect(result.status).toBe("deployed");
    expect(result.reloaded).toBe(true);
    expect(result.files).toHaveLength(2);
  });

  it("handles partial deploy (reload failed)", async () => {
    vi.stubGlobal("fetch", mockFetchResponse({
      status: "partial",
      message: "Files written but Caddy reload failed",
      files: [],
      reloaded: false,
      timestamp: "2026-02-25T10:00:00Z",
    }));

    const result = await deployRLRules();
    expect(result.status).toBe("partial");
    expect(result.reloaded).toBe(false);
  });
});

describe("getRLGlobal / updateRLGlobal", () => {
  const mockGlobal: RateLimitGlobalConfig = {
    jitter: 0.1,
    sweep_interval: "1m",
    distributed: false,
    read_interval: "5s",
    write_interval: "5s",
    purge_age: "24h",
  };

  it("returns global config", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockGlobal));

    const result = await getRLGlobal();
    expect(result.jitter).toBe(0.1);
    expect(result.sweep_interval).toBe("1m");
    expect(result.distributed).toBe(false);
  });

  it("calls correct endpoint", async () => {
    const mockFetch = mockFetchResponse(mockGlobal);
    vi.stubGlobal("fetch", mockFetch);

    await getRLGlobal();
    expect(mockFetch).toHaveBeenCalledWith("/api/rate-rules/global", undefined);
  });

  it("updates global config", async () => {
    const updated = { ...mockGlobal, distributed: true, read_interval: "1s" };
    vi.stubGlobal("fetch", mockFetchResponse(updated));

    const result = await updateRLGlobal(updated);
    expect(result.distributed).toBe(true);
    expect(result.read_interval).toBe("1s");

    // Verify PUT
    const putCall = vi.mocked(fetch).mock.calls[0];
    expect(putCall[0]).toBe("/api/rate-rules/global");
    expect(putCall[1]?.method).toBe("PUT");
  });
});

describe("exportRLRules / importRLRules", () => {
  it("exports rules as JSON", async () => {
    const exportData: RateLimitRuleExport = {
      version: 1,
      exported_at: "2026-02-25T10:00:00Z",
      rules: [mockRLRule],
      global: {
        jitter: 0.1,
        sweep_interval: "1m",
        distributed: false,
        read_interval: "5s",
        write_interval: "5s",
        purge_age: "24h",
      },
    };
    vi.stubGlobal("fetch", mockFetchResponse(exportData));

    const result = await exportRLRules();
    expect(result.version).toBe(1);
    expect(result.rules).toHaveLength(1);
    expect(result.rules[0].id).toBe("rl-001");
    expect(result.global.jitter).toBe(0.1);
  });

  it("calls export endpoint", async () => {
    const mockFetch = mockFetchResponse({ version: 1, rules: [], global: {} });
    vi.stubGlobal("fetch", mockFetch);

    await exportRLRules();
    expect(mockFetch).toHaveBeenCalledWith("/api/rate-rules/export", undefined);
  });

  it("imports rules and returns count", async () => {
    vi.stubGlobal("fetch", mockFetchResponse({ status: "imported", imported: 5 }));

    const result = await importRLRules({
      version: 1,
      exported_at: "2026-02-25T10:00:00Z",
      rules: [],
      global: {
        jitter: 0.1,
        sweep_interval: "1m",
        distributed: false,
        read_interval: "5s",
        write_interval: "5s",
        purge_age: "24h",
      },
    });
    expect(result.imported).toBe(5);

    // Verify POST
    const postCall = vi.mocked(fetch).mock.calls[0];
    expect(postCall[0]).toBe("/api/rate-rules/import");
    expect(postCall[1]?.method).toBe("POST");
  });
});

describe("getRLRuleHits", () => {
  it("returns hit stats with sparkline", async () => {
    const hitsResponse: RLRuleHitsResponse = {
      "rl-001": { total: 42, sparkline: [1, 2, 3, 5, 8, 13, 10] },
      "rl-002": { total: 0, sparkline: [0, 0, 0, 0, 0, 0, 0] },
    };
    vi.stubGlobal("fetch", mockFetchResponse(hitsResponse));

    const result = await getRLRuleHits(24);
    expect(result["rl-001"].total).toBe(42);
    expect(result["rl-001"].sparkline).toHaveLength(7);
    expect(result["rl-002"].total).toBe(0);
  });

  it("passes hours parameter", async () => {
    const mockFetch = mockFetchResponse({});
    vi.stubGlobal("fetch", mockFetch);

    await getRLRuleHits(48);
    expect(mockFetch).toHaveBeenCalledWith("/api/rate-rules/hits?hours=48", undefined);
  });

  it("defaults to 24 hours", async () => {
    const mockFetch = mockFetchResponse({});
    vi.stubGlobal("fetch", mockFetch);

    await getRLRuleHits();
    expect(mockFetch).toHaveBeenCalledWith("/api/rate-rules/hits?hours=24", undefined);
  });
});

describe("RL API error handling", () => {
  it("throws on non-OK response for getRLRules", async () => {
    vi.stubGlobal("fetch", mockFetchResponse({ error: "server error" }, 500));
    await expect(getRLRules()).rejects.toThrow("API error: 500");
  });

  it("throws on non-OK response for createRLRule", async () => {
    vi.stubGlobal("fetch", mockFetchResponse({ error: "validation failed" }, 400));
    await expect(createRLRule({
      name: "Test",
      service: "test.erfi.io",
      key: "client_ip",
      events: 100,
      window: "1m",
      enabled: true,
    })).rejects.toThrow("API error: 400");
  });

  it("throws on non-OK response for deployRLRules", async () => {
    vi.stubGlobal("fetch", mockFetchResponse({ error: "deploy failed" }, 500));
    await expect(deployRLRules()).rejects.toThrow("API error: 500");
  });
});

// ─── Rate Advisor API Tests ───────────────────────────────────────

describe("getRateAdvisor", () => {
  const mockAdvisorResponse: RateAdvisorResponse = {
    window: "1m",
    window_seconds: 60,
    service: "test.erfi.io",
    total_requests: 1500,
    unique_clients: 25,
    clients: [
      {
        client_ip: "9.9.9.9",
        country: "US",
        requests: 500,
        requests_per_sec: 8.33,
        error_rate: 0.6,
        path_diversity: 0.01,
        burstiness: 15.0,
        classification: "abusive",
        anomaly_score: 92.5,
        top_paths: [{ path: "/admin/login", count: 498 }],
      },
      {
        client_ip: "1.1.1.1",
        country: "DE",
        requests: 10,
        requests_per_sec: 0.17,
        error_rate: 0.02,
        path_diversity: 0.8,
        burstiness: 1.1,
        classification: "normal",
        anomaly_score: 5.2,
        top_paths: [{ path: "/", count: 5 }, { path: "/about", count: 3 }],
      },
    ],
    percentiles: { p50: 8, p75: 15, p90: 30, p95: 45, p99: 200 },
    normalized_percentiles: { p50: 0.13, p75: 0.25, p90: 0.5, p95: 0.75, p99: 3.33 },
    recommendation: {
      threshold: 52,
      confidence: "high",
      method: "mad",
      affected_clients: 3,
      affected_requests: 800,
      median: 8.5,
      mad: 3.2,
      separation: 4.5,
    },
    impact_curve: [
      { threshold: 1, clients_affected: 25, requests_affected: 1500, client_pct: 1.0, request_pct: 1.0 },
      { threshold: 50, clients_affected: 3, requests_affected: 800, client_pct: 0.12, request_pct: 0.53 },
      { threshold: 500, clients_affected: 1, requests_affected: 500, client_pct: 0.04, request_pct: 0.33 },
    ],
    histogram: [
      { min: 1, max: 5, count: 10 },
      { min: 5, max: 15, count: 8 },
      { min: 15, max: 50, count: 4 },
      { min: 50, max: 200, count: 2 },
      { min: 200, max: 600, count: 1 },
    ],
    time_of_day_baselines: [
      { hour: 10, median_rps: 0.05, p95_rps: 0.25, clients: 15, requests: 400 },
      { hour: 14, median_rps: 0.08, p95_rps: 0.42, clients: 20, requests: 800 },
      { hour: 22, median_rps: 0.02, p95_rps: 0.10, clients: 8, requests: 300 },
    ],
  };

  it("fetches advisor data with all parameters", async () => {
    const mockFetch = mockFetchResponse(mockAdvisorResponse);
    vi.stubGlobal("fetch", mockFetch);

    const result = await getRateAdvisor({
      window: "1m",
      service: "test.erfi.io",
      path: "/api",
      method: "POST",
      limit: 50,
    });

    const calledUrl = mockFetch.mock.calls[0][0] as string;
    expect(calledUrl).toContain("/api/rate-rules/advisor");
    expect(calledUrl).toContain("window=1m");
    expect(calledUrl).toContain("service=test.erfi.io");
    expect(calledUrl).toContain("path=%2Fapi");
    expect(calledUrl).toContain("method=POST");
    expect(calledUrl).toContain("limit=50");

    expect(result.total_requests).toBe(1500);
    expect(result.unique_clients).toBe(25);
  });

  it("returns clients with anomaly metrics", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockAdvisorResponse));
    const result = await getRateAdvisor({ window: "1m" });

    expect(result.clients).toHaveLength(2);
    const abusive = result.clients[0];
    expect(abusive.classification).toBe("abusive");
    expect(abusive.anomaly_score).toBeGreaterThan(50);
    expect(abusive.error_rate).toBe(0.6);
    expect(abusive.path_diversity).toBe(0.01);
    expect(abusive.burstiness).toBe(15.0);

    const normal = result.clients[1];
    expect(normal.classification).toBe("normal");
    expect(normal.anomaly_score).toBeLessThan(20);
  });

  it("returns recommendation with confidence", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockAdvisorResponse));
    const result = await getRateAdvisor({ window: "1m" });

    expect(result.recommendation).toBeDefined();
    expect(result.recommendation!.threshold).toBe(52);
    expect(result.recommendation!.confidence).toBe("high");
    expect(result.recommendation!.method).toBe("mad");
    expect(result.recommendation!.affected_clients).toBe(3);
    expect(result.recommendation!.median).toBe(8.5);
    expect(result.recommendation!.mad).toBe(3.2);
    expect(result.recommendation!.separation).toBe(4.5);
  });

  it("returns impact curve", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockAdvisorResponse));
    const result = await getRateAdvisor({ window: "1m" });

    expect(result.impact_curve).toHaveLength(3);
    expect(result.impact_curve[0].threshold).toBe(1);
    expect(result.impact_curve[0].client_pct).toBe(1.0);
    expect(result.impact_curve[2].clients_affected).toBe(1);
  });

  it("returns histogram", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockAdvisorResponse));
    const result = await getRateAdvisor({ window: "1m" });

    expect(result.histogram).toHaveLength(5);
    expect(result.histogram[0].min).toBe(1);
    expect(result.histogram[0].count).toBe(10);
  });

  it("handles response without recommendation", async () => {
    const noRecResponse = { ...mockAdvisorResponse, recommendation: undefined };
    vi.stubGlobal("fetch", mockFetchResponse(noRecResponse));
    const result = await getRateAdvisor({ window: "1m" });
    expect(result.recommendation).toBeUndefined();
  });

  it("fetches with default params when none provided", async () => {
    const mockFetch = mockFetchResponse(mockAdvisorResponse);
    vi.stubGlobal("fetch", mockFetch);

    await getRateAdvisor();
    const calledUrl = mockFetch.mock.calls[0][0] as string;
    expect(calledUrl).toBe("/api/rate-rules/advisor");
  });

  it("returns normalized rates per second", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockAdvisorResponse));
    const result = await getRateAdvisor({ window: "1m" });

    expect(result.window_seconds).toBe(60);
    expect(result.normalized_percentiles).toBeDefined();
    expect(result.normalized_percentiles.p50).toBe(0.13);
    expect(result.normalized_percentiles.p95).toBe(0.75);
    expect(result.normalized_percentiles.p99).toBe(3.33);

    // Clients should have requests_per_sec
    expect(result.clients[0].requests_per_sec).toBe(8.33);
    expect(result.clients[1].requests_per_sec).toBe(0.17);
  });

  it("returns time-of-day baselines", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockAdvisorResponse));
    const result = await getRateAdvisor({ window: "1m" });

    expect(result.time_of_day_baselines).toBeDefined();
    expect(result.time_of_day_baselines).toHaveLength(3);
    expect(result.time_of_day_baselines![0].hour).toBe(10);
    expect(result.time_of_day_baselines![0].median_rps).toBe(0.05);
    expect(result.time_of_day_baselines![0].p95_rps).toBe(0.25);
    expect(result.time_of_day_baselines![0].clients).toBe(15);
    expect(result.time_of_day_baselines![0].requests).toBe(400);
    expect(result.time_of_day_baselines![2].hour).toBe(22);
  });

  it("handles response without time-of-day baselines", async () => {
    const noBaselinesResponse = { ...mockAdvisorResponse, time_of_day_baselines: undefined };
    vi.stubGlobal("fetch", mockFetchResponse(noBaselinesResponse));
    const result = await getRateAdvisor({ window: "1m" });
    expect(result.time_of_day_baselines).toBeUndefined();
  });
});

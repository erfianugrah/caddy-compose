import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  getRLRules,
  createRLRule,
  deleteRLRule,
  deployRLRules,
  getRLRuleHits,
  getRateAdvisor,
  getRLSummary,
  getRLEvents,
  type RateLimitRule,
  type RLRuleHitsResponse,
  type RateAdvisorResponse,
} from "@/lib/api";
import { mockFetchResponse, setupMockFetch } from "./__test-helpers";

setupMockFetch();

// ─── Unified API Exclusion format (what the server returns) ─────────

const mockUnifiedRL = {
  id: "rl-001",
  name: "API rate limit",
  description: "Protect API from abuse",
  type: "rate_limit",
  service: "api.erfi.io",
  conditions: [
    { field: "path", operator: "begins_with", value: "/api/" },
  ],
  group_operator: "and",
  rate_limit_key: "client_ip",
  rate_limit_events: 100,
  rate_limit_window: "1m",
  rate_limit_action: "deny",
  priority: 10,
  tags: ["api", "auth"],
  enabled: true,
  created_at: "2026-02-25T10:00:00Z",
  updated_at: "2026-02-25T10:00:00Z",
};

const mockNonRL = {
  id: "exc-001",
  name: "Allow health",
  description: "",
  type: "allow",
  conditions: [{ field: "path", operator: "eq", value: "/health" }],
  group_operator: "and",
  enabled: true,
  created_at: "2026-02-25T10:00:00Z",
  updated_at: "2026-02-25T10:00:00Z",
};

// ─── getRLRules (filters by type=rate_limit) ────────────────────────

describe("getRLRules", () => {
  it("maps unified rules to RateLimitRule format", async () => {
    // Server-side ?type=rate_limit filter means only RL rules are returned.
    vi.stubGlobal("fetch", mockFetchResponse([mockUnifiedRL]));
    const rules = await getRLRules();
    expect(rules).toHaveLength(1);
    expect(rules[0].id).toBe("rl-001");
    expect(rules[0].key).toBe("client_ip");
    expect(rules[0].events).toBe(100);
    expect(rules[0].window).toBe("1m");
    expect(rules[0].action).toBe("deny");
    expect(rules[0].service).toBe("api.erfi.io");
  });

  it("calls /api/rules?type=rate_limit endpoint", async () => {
    const mock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve([]),
    });
    vi.stubGlobal("fetch", mock);
    await getRLRules();
    const url = mock.mock.calls[0][0] as string;
    expect(url).toBe("/api/rules?type=rate_limit");
  });
});

// ─── createRLRule (translates to unified format) ────────────────────

describe("createRLRule", () => {
  it("sends type=rate_limit and translated fields", async () => {
    const mock = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: () => Promise.resolve(mockUnifiedRL),
    });
    vi.stubGlobal("fetch", mock);

    const result = await createRLRule({
      name: "API rate limit",
      service: "api.erfi.io",
      key: "client_ip",
      events: 100,
      window: "1m",
      action: "deny",
      enabled: true,
    });

    expect(result.id).toBe("rl-001");
    expect(result.key).toBe("client_ip");

    // Verify the payload sent to the server
    const callBody = JSON.parse(mock.mock.calls[0][1].body);
    expect(callBody.type).toBe("rate_limit");
    expect(callBody.rate_limit_key).toBe("client_ip");
    expect(callBody.rate_limit_events).toBe(100);
    expect(callBody.rate_limit_window).toBe("1m");
    expect(callBody.rate_limit_action).toBe("deny");
  });
});

// ─── deleteRLRule ───────────────────────────────────────────────────

describe("deleteRLRule", () => {
  it("calls DELETE on /api/rules/{id}", async () => {
    const mock = vi.fn().mockResolvedValue({
      ok: true,
      status: 204,
      json: () => Promise.resolve(null),
    });
    vi.stubGlobal("fetch", mock);
    await deleteRLRule("rl-001");
    expect(mock).toHaveBeenCalledWith(
      expect.stringContaining("/api/rules/rl-001"),
      expect.objectContaining({ method: "DELETE" }),
    );
  });
});

// ─── deployRLRules (uses unified /api/deploy) ───────────────────────

describe("deployRLRules", () => {
  it("calls POST /api/deploy", async () => {
    const mock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ status: "deployed", message: "ok", reloaded: false, timestamp: "2026-03-15T00:00:00Z" }),
    });
    vi.stubGlobal("fetch", mock);
    const result = await deployRLRules();
    expect(result.status).toBe("deployed");
    expect(mock).toHaveBeenCalledWith(
      expect.stringContaining("/api/deploy"),
      expect.anything(),
    );
  });
});

// ─── getRLRuleHits (analytics, unchanged endpoint) ──────────────────

describe("getRLRuleHits", () => {
  it("returns hit stats from /api/rate-rules/hits", async () => {
    const mockHits: RLRuleHitsResponse = {
      "rl-001": { total: 42, sparkline: [1, 2, 3] },
    };
    vi.stubGlobal("fetch", mockFetchResponse(mockHits));
    const result = await getRLRuleHits(24);
    expect(result["rl-001"].total).toBe(42);
  });
});

// ─── getRateAdvisor (analytics, unchanged endpoint) ─────────────────

describe("getRateAdvisor", () => {
  it("returns advisor response", async () => {
    const mockAdvisor: Partial<RateAdvisorResponse> = {
      window: "5m",
      total_requests: 1000,
      unique_clients: 50,
      clients: [],
      percentiles: { p50: 10, p75: 20, p90: 30, p95: 40, p99: 50 },
      normalized_percentiles: { p50: 0.1, p75: 0.2, p90: 0.3, p95: 0.4, p99: 0.5 },
      impact_curve: [],
      histogram: [],
    };
    vi.stubGlobal("fetch", mockFetchResponse(mockAdvisor));
    const result = await getRateAdvisor({ window: "5m" });
    expect(result.total_requests).toBe(1000);
  });
});

// ─── getRLSummary (analytics, unchanged endpoint) ───────────────────

describe("getRLSummary", () => {
  it("fetches rate limit summary", async () => {
    vi.stubGlobal("fetch", mockFetchResponse({
      total_429s: 10,
      unique_clients: 3,
      unique_services: 2,
      events_by_hour: [],
      top_clients: [],
      top_services: [],
      top_uris: [],
      recent_events: [],
    }));
    const result = await getRLSummary(1);
    expect(result.total_429s).toBe(10);
  });
});

// ─── getRLEvents (analytics, unchanged endpoint) ────────────────────

describe("getRLEvents", () => {
  it("fetches rate limit events", async () => {
    vi.stubGlobal("fetch", mockFetchResponse({ total: 5, events: [] }));
    const result = await getRLEvents({ hours: 1, limit: 10 });
    expect(result.total).toBe(5);
  });
});

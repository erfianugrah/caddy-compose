import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  fetchChallengeStats,
  fetchChallengeReputation,
  fetchEndpointDiscovery,
  type ChallengeStats,
  type ChallengeReputationResponse,
  type EndpointDiscoveryResponse,
} from "./challenge";

// ─── Mock setup ─────────────────────────────────────────────────────

function mockFetchResponse(body: unknown, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? "OK" : "Error",
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  });
}

beforeEach(() => {
  vi.stubGlobal("fetch", mockFetchResponse({}));
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ─── fetchChallengeStats ────────────────────────────────────────────

describe("fetchChallengeStats", () => {
  it("returns challenge stats with all expected fields", async () => {
    const goResponse: ChallengeStats = {
      issued: 100,
      passed: 60,
      failed: 25,
      bypassed: 15,
      pass_rate: 0.6,
      fail_rate: 0.25,
      bypass_rate: 0.2,
      avg_solve_ms: 1500.5,
      avg_difficulty: 4.2,
      score_buckets: [
        { label: "0-19 (clean)", min: 0, max: 19, count: 40 },
        { label: "20-39 (moderate)", min: 20, max: 39, count: 10 },
        { label: "40-59 (suspicious)", min: 40, max: 59, count: 5 },
        { label: "60-69 (borderline)", min: 60, max: 69, count: 3 },
        { label: "70-79 (rejected)", min: 70, max: 79, count: 8 },
        { label: "80-100 (automated)", min: 80, max: 100, count: 14 },
      ],
      timeline: [
        { hour: "2026-03-20T10:00:00Z", issued: 30, passed: 20, failed: 8, bypassed: 5 },
        { hour: "2026-03-20T11:00:00Z", issued: 70, passed: 40, failed: 17, bypassed: 10 },
      ],
      top_clients: [
        {
          client: "10.0.0.1",
          country: "US",
          issued: 20,
          passed: 15,
          failed: 3,
          bypassed: 2,
          avg_bot_score: 25.5,
          max_bot_score: 85,
          avg_solve_ms: 1200,
          unique_tokens: 3,
        },
      ],
      top_services: [
        { service: "app.example.com", issued: 50, passed: 35, failed: 10, bypassed: 5, fail_rate: 0.2 },
      ],
      top_ja4s: [
        { ja4: "t13d1517h2_8daaf615_b0da82dd", total: 30, passed: 20, failed: 10, clients: 5 },
      ],
      fail_reasons: { bot_score: 15, timing_hard: 5, ja4_mismatch: 3, bad_pow: 2 },
      avg_solve_ms_passed: 1200.0,
      avg_solve_ms_failed: 2500.0,
      algorithm_breakdown: [
        { algorithm: "fast", issued: 80, passed: 50, failed: 20, avg_solve_ms: 800.0, avg_difficulty: 4.0 },
        { algorithm: "slow", issued: 20, passed: 10, failed: 5, avg_solve_ms: 5000.0, avg_difficulty: 3.0 },
      ],
      solve_time_estimates: [
        { difficulty: 4, algorithm: "fast", cores: 8, expected_ms: 0.04 },
        { difficulty: 4, algorithm: "slow", cores: 8, expected_ms: 41000 },
      ],
    };

    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result = await fetchChallengeStats(24);

    expect(result.issued).toBe(100);
    expect(result.passed).toBe(60);
    expect(result.failed).toBe(25);
    expect(result.bypassed).toBe(15);
    expect(result.pass_rate).toBe(0.6);
    expect(result.fail_rate).toBe(0.25);
    expect(result.bypass_rate).toBe(0.2);
    expect(result.avg_solve_ms).toBe(1500.5);
    expect(result.avg_difficulty).toBe(4.2);
    expect(result.score_buckets).toHaveLength(6);
    expect(result.timeline).toHaveLength(2);
    expect(result.top_clients).toHaveLength(1);
    expect(result.top_services).toHaveLength(1);
    expect(result.top_ja4s).toHaveLength(1);
    expect(result.fail_reasons).toBeDefined();
    expect(result.fail_reasons?.bot_score).toBe(15);
    // Verify newer fields are present.
    expect(result.avg_solve_ms_passed).toBe(1200.0);
    expect(result.avg_solve_ms_failed).toBe(2500.0);
    expect(result.algorithm_breakdown).toHaveLength(2);
    expect(result.algorithm_breakdown?.[0].algorithm).toBe("fast");
    expect(result.solve_time_estimates).toHaveLength(2);
    expect(result.solve_time_estimates?.[0].expected_ms).toBe(0.04);
  });

  it("sends correct query params with hours, service, and client", async () => {
    const mockFetch = mockFetchResponse({
      issued: 0, passed: 0, failed: 0, bypassed: 0,
      pass_rate: 0, fail_rate: 0, bypass_rate: 0,
      avg_solve_ms: 0, avg_difficulty: 0,
      score_buckets: [], timeline: [],
      top_clients: [], top_services: [], top_ja4s: [],
    });
    vi.stubGlobal("fetch", mockFetch);

    await fetchChallengeStats(12, "app.example.com", "10.0.0.1");

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("hours=12");
    expect(url).toContain("service=app.example.com");
    expect(url).toContain("client=10.0.0.1");
  });

  it("omits optional params when not provided", async () => {
    const mockFetch = mockFetchResponse({
      issued: 0, passed: 0, failed: 0, bypassed: 0,
      pass_rate: 0, fail_rate: 0, bypass_rate: 0,
      avg_solve_ms: 0, avg_difficulty: 0,
      score_buckets: [], timeline: [],
      top_clients: [], top_services: [], top_ja4s: [],
    });
    vi.stubGlobal("fetch", mockFetch);

    await fetchChallengeStats();

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("hours=24");
    expect(url).not.toContain("service=");
    expect(url).not.toContain("client=");
  });

  it("handles empty stats response", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchResponse({
        issued: 0, passed: 0, failed: 0, bypassed: 0,
        pass_rate: 0, fail_rate: 0, bypass_rate: 0,
        avg_solve_ms: 0, avg_difficulty: 0,
        score_buckets: [], timeline: [],
        top_clients: [], top_services: [], top_ja4s: [],
      }),
    );

    const result = await fetchChallengeStats();
    expect(result.issued).toBe(0);
    expect(result.timeline).toEqual([]);
    expect(result.top_clients).toEqual([]);
  });

  it("correctly maps timeline entries with non-zero challenge data", async () => {
    const response = {
      issued: 50, passed: 30, failed: 15, bypassed: 5,
      pass_rate: 0.6, fail_rate: 0.3, bypass_rate: 0.143,
      avg_solve_ms: 2000, avg_difficulty: 5,
      score_buckets: [
        { label: "0-19 (clean)", min: 0, max: 19, count: 20 },
        { label: "20-39 (moderate)", min: 20, max: 39, count: 5 },
        { label: "40-59 (suspicious)", min: 40, max: 59, count: 3 },
        { label: "60-69 (borderline)", min: 60, max: 69, count: 2 },
        { label: "70-79 (rejected)", min: 70, max: 79, count: 10 },
        { label: "80-100 (automated)", min: 80, max: 100, count: 5 },
      ],
      timeline: [
        { hour: "2026-03-20T10:00:00Z", issued: 25, passed: 15, failed: 8, bypassed: 2 },
        { hour: "2026-03-20T11:00:00Z", issued: 25, passed: 15, failed: 7, bypassed: 3 },
      ],
      top_clients: [],
      top_services: [],
      top_ja4s: [],
    };
    vi.stubGlobal("fetch", mockFetchResponse(response));

    const result = await fetchChallengeStats(24);
    expect(result.timeline[0].issued).toBe(25);
    expect(result.timeline[0].passed).toBe(15);
    expect(result.timeline[0].failed).toBe(8);
    expect(result.timeline[0].bypassed).toBe(2);
  });
});

// ─── fetchChallengeReputation ───────────────────────────────────────

describe("fetchChallengeReputation", () => {
  it("returns reputation data with all expected fields", async () => {
    const goResponse: ChallengeReputationResponse = {
      ja4s: [
        {
          ja4: "t13d1517h2_8daaf615_b0da82dd",
          total_events: 50,
          passed: 40,
          failed: 10,
          pass_rate: 0.8,
          fail_rate: 0.2,
          avg_bot_score: 30.5,
          unique_ips: 5,
          first_seen: "2026-03-19T08:00:00Z",
          last_seen: "2026-03-20T12:00:00Z",
          verdict: "trusted",
        },
        {
          ja4: "t13d1312h1_deadbeef_cafebabe",
          total_events: 20,
          passed: 2,
          failed: 18,
          pass_rate: 0.1,
          fail_rate: 0.9,
          avg_bot_score: 78.2,
          unique_ips: 3,
          first_seen: "2026-03-20T06:00:00Z",
          last_seen: "2026-03-20T11:00:00Z",
          verdict: "hostile",
        },
      ],
      clients: [
        {
          ip: "10.0.0.1",
          country: "US",
          issued: 10,
          passed: 8,
          failed: 2,
          bypassed: 5,
          unique_tokens: 3,
          unique_ja4s: 1,
          avg_bot_score: 20,
          max_bot_score: 45,
          avg_solve_ms: 1500,
          first_seen: "2026-03-19T08:00:00Z",
          last_seen: "2026-03-20T12:00:00Z",
          flags: [],
        },
        {
          ip: "10.0.0.2",
          country: "DE",
          issued: 5,
          passed: 0,
          failed: 5,
          bypassed: 0,
          unique_tokens: 8,
          unique_ja4s: 4,
          avg_bot_score: 85,
          max_bot_score: 95,
          avg_solve_ms: 400,
          first_seen: "2026-03-20T10:00:00Z",
          last_seen: "2026-03-20T11:00:00Z",
          flags: ["repeat_failure", "cookie_harvesting", "ja4_rotation"],
        },
      ],
      alerts: [
        {
          type: "repeat_failure",
          target: "10.0.0.2",
          detail: "10.0.0.2 failed 5 challenges",
          count: 5,
          severity: "high",
        },
        {
          type: "ja4_rotation",
          target: "10.0.0.2",
          detail: "10.0.0.2 used 4 different TLS stacks",
          count: 4,
          severity: "medium",
        },
      ],
      total_ja4s: 2,
      total_clients: 2,
      total_alerts: 2,
    };

    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result = await fetchChallengeReputation(24);

    expect(result.ja4s).toHaveLength(2);
    expect(result.clients).toHaveLength(2);
    expect(result.alerts).toHaveLength(2);
    expect(result.total_ja4s).toBe(2);
    expect(result.total_clients).toBe(2);
    expect(result.total_alerts).toBe(2);

    // JA4 verdicts
    expect(result.ja4s[0].verdict).toBe("trusted");
    expect(result.ja4s[1].verdict).toBe("hostile");

    // Client flags
    expect(result.clients[1].flags).toContain("repeat_failure");
    expect(result.clients[1].flags).toContain("cookie_harvesting");
    expect(result.clients[1].flags).toContain("ja4_rotation");

    // Alert severity ordering (high before medium)
    expect(result.alerts[0].severity).toBe("high");
    expect(result.alerts[1].severity).toBe("medium");
  });

  it("sends correct query params with hours and service", async () => {
    const mockFetch = mockFetchResponse({
      ja4s: [], clients: [], alerts: [],
      total_ja4s: 0, total_clients: 0, total_alerts: 0,
    });
    vi.stubGlobal("fetch", mockFetch);

    await fetchChallengeReputation(12, "api.example.com");

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("hours=12");
    expect(url).toContain("service=api.example.com");
  });

  it("handles empty reputation response", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchResponse({
        ja4s: [], clients: [], alerts: [],
        total_ja4s: 0, total_clients: 0, total_alerts: 0,
      }),
    );

    const result = await fetchChallengeReputation();
    expect(result.ja4s).toEqual([]);
    expect(result.clients).toEqual([]);
    expect(result.total_alerts).toBe(0);
  });
});

// ─── fetchEndpointDiscovery ─────────────────────────────────────────

describe("fetchEndpointDiscovery", () => {
  it("returns discovery data with all expected fields", async () => {
    const goResponse: EndpointDiscoveryResponse = {
      endpoints: [
        {
          service: "app.example.com",
          method: "GET",
          path: "/api/users",
          requests: 150,
          unique_ips: 25,
          unique_ja4s: 8,
          unique_uas: 12,
          non_browser_pct: 0.35,
          has_challenge: true,
          has_rate_limit: false,
        },
        {
          service: "app.example.com",
          method: "POST",
          path: "/api/login",
          requests: 80,
          unique_ips: 40,
          unique_ja4s: 15,
          unique_uas: 20,
          non_browser_pct: 0.8,
          has_challenge: false,
          has_rate_limit: true,
        },
      ],
      total_requests: 230,
      total_paths: 2,
      uncovered_pct: 0.5,
    };

    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result = await fetchEndpointDiscovery(24);

    expect(result.endpoints).toHaveLength(2);
    expect(result.total_requests).toBe(230);
    expect(result.total_paths).toBe(2);
    expect(result.uncovered_pct).toBe(0.5);

    // Verify coverage fields
    expect(result.endpoints[0].has_challenge).toBe(true);
    expect(result.endpoints[0].has_rate_limit).toBe(false);
    expect(result.endpoints[1].has_challenge).toBe(false);
    expect(result.endpoints[1].has_rate_limit).toBe(true);
  });

  it("sends correct query params with service filter", async () => {
    const mockFetch = mockFetchResponse({
      endpoints: [], total_requests: 0, total_paths: 0, uncovered_pct: 0,
    });
    vi.stubGlobal("fetch", mockFetch);

    await fetchEndpointDiscovery(6, "api.example.com");

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("hours=6");
    expect(url).toContain("service=api.example.com");
  });
});

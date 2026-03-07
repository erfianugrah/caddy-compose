import { describe, it, expect, vi } from "vitest";
import {
  lookupIP,
  fetchTopBlockedIPs,
  fetchTopTargetedURIs,
  fetchTopCountries,
  type IPLookupData,
  type CountryCount,
} from "@/lib/api";
import { mockFetchResponse, setupMockFetch } from "./__test-helpers";

setupMockFetch();

// ─── lookupIP ───────────────────────────────────────────────────────

describe("lookupIP", () => {
  it("transforms Go API IP lookup response", async () => {
    const goResponse = {
      ip: "10.0.0.1",
      total: 50,
      blocked: 10,
      first_seen: "2026-02-22T07:00:00Z",
      last_seen: "2026-02-22T09:00:00Z",
      services: [
        { service: "radarr.erfi.io", total: 30, blocked: 5, logged: 25 },
        { service: "sonarr.erfi.io", total: 20, blocked: 5, logged: 15 },
      ],
      events: [
        {
          id: "E1",
          timestamp: "2026-02-22T09:00:00Z",
          service: "radarr.erfi.io",
          method: "GET",
          uri: "/api/v3/queue",
          client_ip: "10.0.0.1",
          is_blocked: false,
          response_status: 200,
        },
      ],
    };

    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result: IPLookupData = await lookupIP("10.0.0.1");

    expect(result.ip).toBe("10.0.0.1");
    expect(result.total_events).toBe(50); // total -> total_events
    expect(result.blocked_count).toBe(10); // blocked -> blocked_count
    expect(result.first_seen).toBe("2026-02-22T07:00:00Z");
    expect(result.last_seen).toBe("2026-02-22T09:00:00Z");
    expect(result.services).toHaveLength(2);
    expect(result.timeline).toEqual([]); // Not provided by Go API

    // Events mapped
    expect(result.recent_events).toHaveLength(1);
    expect(result.recent_events[0].blocked).toBe(false); // is_blocked -> blocked
    expect(result.recent_events[0].status).toBe(200); // response_status -> status
  });

  it("handles null first_seen/last_seen", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchResponse({
        ip: "1.2.3.4",
        total: 0,
        blocked: 0,
        first_seen: null,
        last_seen: null,
        services: null,
        events: null,
      })
    );

    const result = await lookupIP("1.2.3.4");
    expect(result.first_seen).toBe("");
    expect(result.last_seen).toBe("");
    expect(result.services).toEqual([]);
    expect(result.recent_events).toEqual([]);
  });

  it("passes limit and offset query params", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchResponse({
        ip: "10.0.0.1",
        total: 100,
        blocked: 0,
        events_total: 100,
        first_seen: "2026-02-22T07:00:00Z",
        last_seen: "2026-02-22T09:00:00Z",
        services: [],
        events: [],
      })
    );

    const result = await lookupIP("10.0.0.1", 20, 40);
    expect(result.events_total).toBe(100);

    const callUrl = (fetch as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    expect(callUrl).toContain("limit=20");
    expect(callUrl).toContain("offset=40");
  });
});

// ─── fetchTopBlockedIPs / fetchTopTargetedURIs ──────────────────────

describe("fetchTopBlockedIPs", () => {
  it("throws on API error", async () => {
    vi.stubGlobal("fetch", mockFetchResponse({ error: "not found" }, 404));

    await expect(fetchTopBlockedIPs()).rejects.toThrow("API error");
  });

  it("returns data when endpoint is available", async () => {
    const data = [
      {
        client_ip: "10.0.0.1",
        total: 100,
        blocked: 50,
        block_rate: 50.0,
        first_seen: "2026-02-22T07:00:00Z",
        last_seen: "2026-02-22T09:00:00Z",
      },
    ];
    vi.stubGlobal("fetch", mockFetchResponse(data));

    const result = await fetchTopBlockedIPs(24);
    expect(result).toHaveLength(1);
    expect(result[0].client_ip).toBe("10.0.0.1");
  });
});

describe("fetchTopTargetedURIs", () => {
  it("throws on API error", async () => {
    vi.stubGlobal("fetch", mockFetchResponse({ error: "not found" }, 404));

    await expect(fetchTopTargetedURIs()).rejects.toThrow("API error");
  });
});

// ─── fetchTopCountries ──────────────────────────────────────────────

describe("fetchTopCountries", () => {
  it("returns country data from API", async () => {
    const data: CountryCount[] = [
      { country: "US", count: 100, blocked: 30 },
      { country: "DE", count: 50, blocked: 10 },
    ];
    vi.stubGlobal("fetch", mockFetchResponse(data));

    const result = await fetchTopCountries(24);
    expect(result).toHaveLength(2);
    expect(result[0].country).toBe("US");
    expect(result[0].count).toBe(100);
  });

  it("calls correct endpoint with hours", async () => {
    const mockFetch = mockFetchResponse([]);
    vi.stubGlobal("fetch", mockFetch);

    await fetchTopCountries(168);
    expect(mockFetch).toHaveBeenCalledWith("/api/analytics/top-countries?hours=168", undefined);
  });

  it("throws on error", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("fail")));
    await expect(fetchTopCountries()).rejects.toThrow("fail");
  });
});

// ─── lookupIP breakdown fields ──────────────────────────────────────

describe("lookupIP service breakdown fields", () => {
  it("maps all breakdown fields in services array", async () => {
    const goResponse = {
      ip: "10.0.0.1",
      total: 10,
      blocked: 5,
      first_seen: "2026-02-22T10:00:00Z",
      last_seen: "2026-02-22T12:00:00Z",
      services: [{
        service: "web.io",
        total: 8,
        blocked: 4,
        logged: 4,
        rate_limited: 1,
        ipsum_blocked: 0,
        honeypot: 1,
        scanner: 1,
        policy: 2,
      }],
      events: [],
    };
    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result = await lookupIP("10.0.0.1");
    expect(result.services[0].honeypot).toBe(1);
    expect(result.services[0].scanner).toBe(1);
    expect(result.services[0].policy).toBe(2);
    expect(result.services[0].rate_limited).toBe(1);
  });
});

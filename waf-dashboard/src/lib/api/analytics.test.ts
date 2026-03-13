import { describe, it, expect, vi } from "vitest";
import {
  lookupIP,
  fetchTopBlockedIPs,
  fetchTopTargetedURIs,
  fetchTopCountries,
  type IPLookupData,
  type CountryCount,
  type IPIntelligence,
} from "@/lib/api";
import { mockFetchResponse, setupMockFetch } from "./__test-helpers";

setupMockFetch();

// ─── lookupIP ───────────────────────────────────────────────────────

describe("lookupIP", () => {
  it("transforms Go API IP lookup response", async () => {
    const goResponse = {
      ip: "10.0.0.1",
      total: 50,
      total_blocked: 10,
      first_seen: "2026-02-22T07:00:00Z",
      last_seen: "2026-02-22T09:00:00Z",
      services: [
        { service: "radarr.erfi.io", total: 30, total_blocked: 5, logged: 25 },
        { service: "sonarr.erfi.io", total: 20, total_blocked: 5, logged: 15 },
      ],
      events_by_hour: [
        { hour: "2026-02-22T07:00:00Z", count: 20, total_blocked: 5, logged: 15, rate_limited: 0, policy_block: 0, detect_block: 0, policy_allow: 0, policy_skip: 0 },
        { hour: "2026-02-22T08:00:00Z", count: 30, total_blocked: 5, logged: 25, rate_limited: 0, policy_block: 0, detect_block: 0, policy_allow: 0, policy_skip: 0 },
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
    expect(result.timeline).toHaveLength(2);
    expect(result.timeline[0]).toEqual({
      hour: "2026-02-22T07:00:00Z", total: 20, total_blocked: 5, logged: 15,
      rate_limited: 0, policy_block: 0, detect_block: 0, policy_allow: 0, policy_skip: 0,
    });

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
        total_blocked: 0,
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
        total_blocked: 0,
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
        total_blocked: 50,
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
      { country: "US", count: 100, total_blocked: 30 },
      { country: "DE", count: 50, total_blocked: 10 },
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

// ─── lookupIP intelligence passthrough ──────────────────────────────

describe("lookupIP intelligence", () => {
  it("passes through intelligence data from API", async () => {
    const goResponse = {
      ip: "1.1.1.1",
      geoip: {
        country: "AU",
        asn: "AS13335",
        org: "Cloudflare, Inc.",
        as_domain: "cloudflare.com",
        continent: "Oceania",
        source: "api",
      },
      intelligence: {
        routing: {
          is_announced: true,
          as_number: "13335",
          as_name: "CLOUDFLARENET - Cloudflare, Inc., US",
          route: "1.1.1.0/24",
          roa_count: 1,
          roa_validity: "valid",
          rir: "apnic",
          alloc_date: "2011-08-11",
        },
        network_type: {
          is_anycast: true,
          is_dc: false,
          org_type: "business",
        },
        reputation: {
          status: "known_good",
          sources: [
            {
              source: "greynoise",
              status: "benign",
              classification: "benign",
              name: "Cloudflare Public DNS",
              last_seen: "2026-03-07",
            },
            { source: "stopforumspam", status: "clean" },
          ],
          ipsum_listed: false,
        },
        shodan: {
          ports: [53, 80, 443],
          hostnames: ["one.one.one.one"],
          cpes: ["cpe:/a:cloudflare:cloudflare"],
          tags: [],
          vulns: [],
        },
      },
      total: 10,
      total_blocked: 2,
      first_seen: "2026-03-01T00:00:00Z",
      last_seen: "2026-03-07T12:00:00Z",
      services: [],
      events: [],
    };
    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result = await lookupIP("1.1.1.1");

    // GeoIP enriched fields
    expect(result.geoip?.as_domain).toBe("cloudflare.com");
    expect(result.geoip?.continent).toBe("Oceania");

    // Intelligence passthrough
    expect(result.intelligence).toBeDefined();
    const intel = result.intelligence!;

    // Routing
    expect(intel.routing?.is_announced).toBe(true);
    expect(intel.routing?.as_number).toBe("13335");
    expect(intel.routing?.roa_validity).toBe("valid");
    expect(intel.routing?.rir).toBe("apnic");

    // Network type
    expect(intel.network_type?.is_anycast).toBe(true);
    expect(intel.network_type?.org_type).toBe("business");

    // Reputation
    expect(intel.reputation?.status).toBe("known_good");
    expect(intel.reputation?.sources).toHaveLength(2);
    expect(intel.reputation?.sources?.[0].name).toBe("Cloudflare Public DNS");
    expect(intel.reputation?.ipsum_listed).toBe(false);

    // Shodan
    expect(intel.shodan?.ports).toEqual([53, 80, 443]);
    expect(intel.shodan?.hostnames).toEqual(["one.one.one.one"]);
  });

  it("handles missing intelligence field gracefully", async () => {
    const goResponse = {
      ip: "192.168.1.1",
      total: 0,
      total_blocked: 0,
      first_seen: null,
      last_seen: null,
      services: [],
      events: [],
    };
    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result = await lookupIP("192.168.1.1");
    expect(result.intelligence).toBeUndefined();
    expect(result.geoip).toBeUndefined();
  });

  it("handles intelligence with partial data", async () => {
    const goResponse = {
      ip: "10.0.0.1",
      intelligence: {
        routing: {
          is_announced: false,
        },
        reputation: {
          status: "clean",
          sources: [],
        },
      },
      total: 5,
      total_blocked: 0,
      first_seen: "2026-03-07T00:00:00Z",
      last_seen: "2026-03-07T00:00:00Z",
      services: [],
      events: [],
    };
    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result = await lookupIP("10.0.0.1");
    expect(result.intelligence?.routing?.is_announced).toBe(false);
    expect(result.intelligence?.shodan).toBeUndefined();
    expect(result.intelligence?.network_type).toBeUndefined();
  });
});

// ─── lookupIP breakdown fields ──────────────────────────────────────

describe("lookupIP service breakdown fields", () => {
  it("maps all breakdown fields in services array", async () => {
    const goResponse = {
      ip: "10.0.0.1",
      total: 10,
      total_blocked: 5,
      first_seen: "2026-02-22T10:00:00Z",
      last_seen: "2026-02-22T12:00:00Z",
      services: [{
        service: "web.io",
        total: 8,
        total_blocked: 4,
        logged: 4,
        rate_limited: 1,
        policy_block: 2,
        policy_allow: 0,
        policy_skip: 0,
      }],
      events: [],
    };
    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result = await lookupIP("10.0.0.1");
    expect(result.services[0].policy_block).toBe(2);
    expect(result.services[0].policy_allow).toBe(0);
    expect(result.services[0].policy_skip).toBe(0);
    expect(result.services[0].rate_limited).toBe(1);
  });
});

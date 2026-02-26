import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  fetchSummary,
  fetchEvents,
  fetchServices,
  lookupIP,
  fetchTopBlockedIPs,
  fetchTopTargetedURIs,
  fetchTopCountries,
  generateConfig,
  fetchCRSRules,
  fetchCRSAutocomplete,
  getBlocklistStats,
  checkBlocklistIP,
  refreshBlocklist,
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
  type SummaryData,
  type EventsResponse,
  type ServiceDetail,
  type IPLookupData,
  type GeneratedConfig,
  type CRSCatalogResponse,
  type CRSAutocompleteResponse,
  type CountryCount,
  type BlocklistStats,
  type BlocklistRefreshResult,
  type RateLimitRule,
  type RateLimitGlobalConfig,
  type RateLimitRuleExport,
  type RateLimitDeployResult,
  type RLRuleHitsResponse,
} from "./api";

// ─── Mock fetch ─────────────────────────────────────────────────────

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

// ─── fetchSummary ───────────────────────────────────────────────────

describe("fetchSummary", () => {
  it("transforms Go API response to frontend SummaryData shape", async () => {
    const goResponse = {
      total_events: 100,
      blocked_events: 30,
      logged_events: 70,
      unique_clients: 5,
      unique_services: 3,
      events_by_hour: [
        { hour: "2026-02-22T07:00:00Z", count: 40, blocked: 10, logged: 30 },
        { hour: "2026-02-22T08:00:00Z", count: 60, blocked: 20, logged: 40 },
      ],
      top_services: [
        { service: "radarr.erfi.io", count: 60, blocked: 15, logged: 45 },
        { service: "sonarr.erfi.io", count: 40, blocked: 15, logged: 25 },
      ],
      top_clients: [
        { client: "10.0.0.1", count: 50, blocked: 20 },
        { client: "10.0.0.2", count: 50, blocked: 10 },
      ],
      top_uris: [{ uri: "/.env", count: 20 }],
      service_breakdown: [
        { service: "radarr.erfi.io", total: 60, blocked: 15, logged: 45 },
        { service: "sonarr.erfi.io", total: 40, blocked: 15, logged: 25 },
      ],
      recent_events: [
        {
          id: "tx-001",
          timestamp: "2026-02-22T08:30:00Z",
          service: "radarr.erfi.io",
          method: "GET",
          uri: "/.env",
          client_ip: "10.0.0.1",
          is_blocked: true,
          response_status: 403,
        },
      ],
    };

    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result: SummaryData = await fetchSummary({ hours: 24 });

    expect(result.total_events).toBe(100);
    expect(result.blocked).toBe(30);
    expect(result.logged).toBe(70);
    expect(result.unique_clients).toBe(5);
    expect(result.unique_services).toBe(3);

    // Timeline mapped from events_by_hour (now includes blocked/logged)
    expect(result.timeline).toHaveLength(2);
    expect(result.timeline[0]).toEqual({
      hour: "2026-02-22T07:00:00Z",
      total: 40,
      blocked: 10,
      logged: 30,
      rate_limited: 0,
      ipsum_blocked: 0,
      honeypot: 0,
      scanner: 0,
      policy: 0,
    });

    // Top services mapped (now includes blocked/logged)
    expect(result.top_services).toHaveLength(2);
    expect(result.top_services[0].service).toBe("radarr.erfi.io");
    expect(result.top_services[0].total).toBe(60);
    expect(result.top_services[0].blocked).toBe(15);
    expect(result.top_services[0].logged).toBe(45);

    // Top clients mapped (client -> client_ip, now includes blocked)
    expect(result.top_clients).toHaveLength(2);
    expect(result.top_clients[0].client_ip).toBe("10.0.0.1");
    expect(result.top_clients[0].total).toBe(50);
    expect(result.top_clients[0].blocked).toBe(20);

    // Top clients now include rate_limited, ipsum_blocked, honeypot, scanner, policy
    expect(result.top_clients[0].rate_limited).toBe(0);
    expect(result.top_clients[0].ipsum_blocked).toBe(0);
    expect(result.top_clients[0].honeypot).toBe(0);
    expect(result.top_clients[0].scanner).toBe(0);
    expect(result.top_clients[0].policy).toBe(0);

    // Service breakdown from dedicated field
    expect(result.service_breakdown).toHaveLength(2);
    expect(result.service_breakdown[0]).toEqual({
      service: "radarr.erfi.io",
      total: 60,
      blocked: 15,
      logged: 45,
      rate_limited: 0,
      ipsum_blocked: 0,
      honeypot: 0,
      scanner: 0,
      policy: 0,
    });

    // recent_events mapped from Go events
    expect(result.recent_events).toHaveLength(1);
    expect(result.recent_events[0].blocked).toBe(true);
    expect(result.recent_events[0].status).toBe(403);
  });

  it("handles null/missing fields gracefully", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchResponse({
        total_events: 0,
        blocked_events: 0,
        logged_events: 0,
        unique_clients: 0,
        unique_services: 0,
        events_by_hour: null,
        top_services: null,
        top_clients: null,
        top_uris: null,
      })
    );

    const result = await fetchSummary();

    expect(result.total_events).toBe(0);
    expect(result.timeline).toEqual([]);
    expect(result.top_services).toEqual([]);
    expect(result.top_clients).toEqual([]);
    expect(result.service_breakdown).toEqual([]);
  });

  it("passes hours query parameter", async () => {
    const mockFetch = mockFetchResponse({
      total_events: 0,
      blocked_events: 0,
      logged_events: 0,
      unique_clients: 0,
      unique_services: 0,
      events_by_hour: [],
      top_services: [],
      top_clients: [],
      top_uris: [],
    });
    vi.stubGlobal("fetch", mockFetch);

    await fetchSummary({ hours: 24 });

    expect(mockFetch).toHaveBeenCalledWith("/api/summary?hours=24", undefined);
  });

  it("passes filter query parameters (service, client, method, event_type, rule_name)", async () => {
    const mockFetch = mockFetchResponse({
      total_events: 0,
      blocked_events: 0,
      logged_events: 0,
      unique_clients: 0,
      unique_services: 0,
      events_by_hour: [],
      top_services: [],
      top_clients: [],
      top_uris: [],
    });
    vi.stubGlobal("fetch", mockFetch);

    await fetchSummary({
      hours: 12,
      service: "cdn.erfi.io",
      client: "1.2.3.4",
      method: "GET",
      event_type: "blocked",
      rule_name: "My Rule",
    });

    const calledUrl = (mockFetch as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    const params = new URLSearchParams(calledUrl.split("?")[1]);
    expect(params.get("hours")).toBe("12");
    expect(params.get("service")).toBe("cdn.erfi.io");
    expect(params.get("client")).toBe("1.2.3.4");
    expect(params.get("method")).toBe("GET");
    expect(params.get("event_type")).toBe("blocked");
    expect(params.get("rule_name")).toBe("My Rule");
  });

  it("omits undefined filter params from URL", async () => {
    const mockFetch = mockFetchResponse({
      total_events: 0,
      blocked_events: 0,
      logged_events: 0,
      unique_clients: 0,
      unique_services: 0,
      events_by_hour: [],
      top_services: [],
      top_clients: [],
      top_uris: [],
    });
    vi.stubGlobal("fetch", mockFetch);

    await fetchSummary({ hours: 24, service: "cdn.erfi.io" });

    const calledUrl = (mockFetch as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    const params = new URLSearchParams(calledUrl.split("?")[1]);
    expect(params.get("hours")).toBe("24");
    expect(params.get("service")).toBe("cdn.erfi.io");
    expect(params.has("client")).toBe(false);
    expect(params.has("method")).toBe(false);
    expect(params.has("event_type")).toBe(false);
    expect(params.has("rule_name")).toBe(false);
  });

  it("sends _op params when operator is not eq", async () => {
    const mockFetch = mockFetchResponse({
      total_events: 0, blocked_events: 0, logged_events: 0,
      rate_limited: 0, ipsum_blocked: 0, policy_events: 0,
      honeypot_events: 0, scanner_events: 0,
      unique_clients: 0, unique_services: 0,
      events_by_hour: [], top_services: [], top_clients: [], top_uris: [],
    });
    vi.stubGlobal("fetch", mockFetch);

    await fetchSummary({
      hours: 24,
      service: "erfi",
      service_op: "contains",
      method: "GET,POST",
      method_op: "in",
    });

    const calledUrl = (mockFetch as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    const params = new URLSearchParams(calledUrl.split("?")[1]);
    expect(params.get("service")).toBe("erfi");
    expect(params.get("service_op")).toBe("contains");
    expect(params.get("method")).toBe("GET,POST");
    expect(params.get("method_op")).toBe("in");
  });

  it("omits _op params when operator is eq (default)", async () => {
    const mockFetch = mockFetchResponse({
      total_events: 0, blocked_events: 0, logged_events: 0,
      rate_limited: 0, ipsum_blocked: 0, policy_events: 0,
      honeypot_events: 0, scanner_events: 0,
      unique_clients: 0, unique_services: 0,
      events_by_hour: [], top_services: [], top_clients: [], top_uris: [],
    });
    vi.stubGlobal("fetch", mockFetch);

    await fetchSummary({ hours: 24, service: "cdn.erfi.io", service_op: "eq" });

    const calledUrl = (mockFetch as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    const params = new URLSearchParams(calledUrl.split("?")[1]);
    expect(params.get("service")).toBe("cdn.erfi.io");
    expect(params.has("service_op")).toBe(false);
  });
});

// ─── fetchEvents ────────────────────────────────────────────────────

describe("fetchEvents", () => {
  it("transforms Go API event fields to frontend WAFEvent shape", async () => {
    const goResponse = {
      total: 3,
      events: [
        {
          id: "AAA111",
          timestamp: "2026-02-22T07:19:01Z",
          service: "dockge-sg.erfi.io",
          method: "POST",
          uri: "/socket.io/?EIO=4",
          client_ip: "195.240.81.42",
          is_blocked: true,
          response_status: 403,
          user_agent: "Mozilla/5.0",
        },
        {
          id: "BBB222",
          timestamp: "2026-02-22T07:20:00Z",
          service: "radarr.erfi.io",
          method: "GET",
          uri: "/.env",
          client_ip: "10.0.0.1",
          is_blocked: false,
          response_status: 200,
          user_agent: "curl/7.68",
        },
      ],
    };

    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result: EventsResponse = await fetchEvents({ page: 1, per_page: 25 });

    // Pagination computed from total
    expect(result.total).toBe(3);
    expect(result.page).toBe(1);
    expect(result.per_page).toBe(25);
    expect(result.total_pages).toBe(1);

    // Event field mapping
    expect(result.events).toHaveLength(2);
    const evt = result.events[0];
    expect(evt.id).toBe("AAA111");
    expect(evt.blocked).toBe(true); // is_blocked -> blocked
    expect(evt.status).toBe(403); // response_status -> status
    expect(evt.rule_id).toBe(0); // No rule data in this event
    expect(evt.rule_msg).toBe("");
    expect(evt.severity).toBe(0);
    expect(evt.matched_data).toBeUndefined();
    expect(evt.rule_tags).toBeUndefined();
  });

  it("maps rule match data from Go API when present", async () => {
    const goResponse = {
      total: 1,
      events: [
        {
          id: "CCC333",
          timestamp: "2026-02-22T08:00:00Z",
          service: "app.erfi.io",
          method: "GET",
          uri: "/etc/passwd",
          client_ip: "10.0.0.5",
          is_blocked: true,
          response_status: 403,
          rule_id: 930120,
          rule_msg: "OS File Access Attempt",
          severity: 2,
          matched_data: "Matched Data: etc/passwd found within REQUEST_URI",
          rule_tags: ["attack-lfi", "OWASP_CRS"],
        },
      ],
    };

    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result = await fetchEvents({ page: 1, per_page: 25 });
    const evt = result.events[0];
    expect(evt.rule_id).toBe(930120);
    expect(evt.rule_msg).toBe("OS File Access Attempt");
    expect(evt.severity).toBe(2);
    expect(evt.matched_data).toBe("Matched Data: etc/passwd found within REQUEST_URI");
    expect(evt.rule_tags).toEqual(["attack-lfi", "OWASP_CRS"]);
  });

  it("converts page/per_page to offset/limit", async () => {
    const mockFetch = mockFetchResponse({ total: 0, events: [] });
    vi.stubGlobal("fetch", mockFetch);

    await fetchEvents({ page: 3, per_page: 10 });

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("limit=10");
    expect(url).toContain("offset=20"); // (3-1) * 10
  });

  it("passes service and blocked filters", async () => {
    const mockFetch = mockFetchResponse({ total: 0, events: [] });
    vi.stubGlobal("fetch", mockFetch);

    await fetchEvents({ service: "radarr.erfi.io", blocked: true });

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("service=radarr.erfi.io");
    expect(url).toContain("blocked=true");
  });

  it("computes total_pages correctly", async () => {
    vi.stubGlobal("fetch", mockFetchResponse({ total: 73, events: [] }));

    const result = await fetchEvents({ page: 1, per_page: 25 });
    expect(result.total_pages).toBe(3); // ceil(73/25) = 3
  });

  it("handles empty events array", async () => {
    vi.stubGlobal("fetch", mockFetchResponse({ total: 0, events: null }));

    const result = await fetchEvents();
    expect(result.events).toEqual([]);
    expect(result.total).toBe(0);
    expect(result.total_pages).toBe(1);
  });

  it("defaults page to 1 and per_page to 25", async () => {
    const mockFetch = mockFetchResponse({ total: 0, events: [] });
    vi.stubGlobal("fetch", mockFetch);

    const result = await fetchEvents();
    expect(result.page).toBe(1);
    expect(result.per_page).toBe(25);

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("limit=25");
    expect(url).toContain("offset=0");
  });
});

// ─── fetchServices ──────────────────────────────────────────────────

describe("fetchServices", () => {
  it("unwraps services wrapper and computes derived fields", async () => {
    const goResponse = {
      services: [
        { service: "radarr.erfi.io", total: 100, blocked: 25, logged: 75 },
        { service: "sonarr.erfi.io", total: 50, blocked: 0, logged: 50 },
      ],
    };

    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result: ServiceDetail[] = await fetchServices();

    expect(result).toHaveLength(2);

    // First service
    expect(result[0].service).toBe("radarr.erfi.io");
    expect(result[0].total_events).toBe(100); // total -> total_events
    expect(result[0].blocked).toBe(25);
    expect(result[0].logged).toBe(75);
    expect(result[0].block_rate).toBe(25); // (25/100)*100
    expect(result[0].top_uris).toEqual([]);
    expect(result[0].top_rules).toEqual([]);

    // Zero total should give 0 block_rate, not NaN
    expect(result[1].block_rate).toBe(0);
  });

  it("handles null services array", async () => {
    vi.stubGlobal("fetch", mockFetchResponse({ services: null }));

    const result = await fetchServices();
    expect(result).toEqual([]);
  });

  it("handles zero total without division by zero", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchResponse({
        services: [{ service: "test", total: 0, blocked: 0, logged: 0 }],
      })
    );

    const result = await fetchServices();
    expect(result[0].block_rate).toBe(0);
    expect(Number.isNaN(result[0].block_rate)).toBe(false);
  });

  it("passes hours parameter", async () => {
    const mockFetch = mockFetchResponse({ services: [] });
    vi.stubGlobal("fetch", mockFetch);

    await fetchServices(24);

    expect(mockFetch).toHaveBeenCalledWith(
      "/api/services?hours=24",
      undefined
    );
  });
});

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
      pre_crs_file: "/data/coraza/custom-pre-crs.conf",
      post_crs_file: "/data/coraza/custom-post-crs.conf",
      waf_settings_file: "/data/coraza/custom-waf-settings.conf",
      reloaded: true,
      timestamp: "2026-02-22T11:00:00Z",
    };
    vi.stubGlobal("fetch", mockFetchResponse(deployResponse));
    const { deployConfig } = await import("./api");
    const result = await deployConfig();
    expect(result.status).toBe("deployed");
    expect(result.reloaded).toBe(true);
    expect(result.pre_crs_file).toContain("custom-pre-crs");
  });

  it("handles partial deploy (reload failed)", async () => {
    const partialResponse = {
      status: "partial",
      message: "Config files written but Caddy reload failed",
      pre_crs_file: "/data/coraza/custom-pre-crs.conf",
      post_crs_file: "/data/coraza/custom-post-crs.conf",
      waf_settings_file: "/data/coraza/custom-waf-settings.conf",
      reloaded: false,
      timestamp: "2026-02-22T11:00:00Z",
    };
    vi.stubGlobal("fetch", mockFetchResponse(partialResponse));
    const { deployConfig } = await import("./api");
    const result = await deployConfig();
    expect(result.status).toBe("partial");
    expect(result.reloaded).toBe(false);
  });
});

// ─── getConfig / updateConfig ───────────────────────────────────────

describe("getConfig", () => {
  it("returns WAFConfig with defaults and per-service settings", async () => {
    const apiResponse = {
      defaults: {
        mode: "enabled",
        paranoia_level: 2,
        inbound_threshold: 10,
        outbound_threshold: 5,
      },
      services: {
        "radarr.erfi.io": { mode: "enabled", paranoia_level: 1, inbound_threshold: 5, outbound_threshold: 4 },
        "sonarr.erfi.io": { mode: "detection_only", paranoia_level: 1, inbound_threshold: 5, outbound_threshold: 4 },
      },
    };

    vi.stubGlobal("fetch", mockFetchResponse(apiResponse));

    const { getConfig } = await import("./api");
    const result = await getConfig();

    expect(result.defaults.mode).toBe("enabled");
    expect(result.defaults.paranoia_level).toBe(2);
    expect(result.defaults.inbound_threshold).toBe(10);
    expect(result.defaults.outbound_threshold).toBe(5);
    expect(Object.keys(result.services)).toHaveLength(2);
    expect(result.services["radarr.erfi.io"].mode).toBe("enabled");
    expect(result.services["sonarr.erfi.io"].mode).toBe("detection_only");
  });

  it("handles null/empty services gracefully", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchResponse({
        defaults: { mode: "enabled", paranoia_level: 1, inbound_threshold: 5, outbound_threshold: 4 },
        services: null,
      })
    );

    const { getConfig } = await import("./api");
    const result = await getConfig();
    expect(result.services).toEqual({});
  });

  it("uses fallback defaults when defaults are missing", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchResponse({ services: {} })
    );

    const { getConfig } = await import("./api");
    const result = await getConfig();
    expect(result.defaults.mode).toBe("enabled");
    expect(result.defaults.paranoia_level).toBe(1);
    expect(result.defaults.inbound_threshold).toBe(5);
    expect(result.defaults.outbound_threshold).toBe(4);
  });
});

describe("updateConfig", () => {
  it("sends WAFConfig directly and returns result", async () => {
    const updatedConfig = {
      defaults: {
        mode: "detection_only",
        paranoia_level: 3,
        inbound_threshold: 10,
        outbound_threshold: 8,
      },
      services: {
        "radarr.erfi.io": { mode: "enabled", paranoia_level: 1, inbound_threshold: 5, outbound_threshold: 4 },
      },
    };

    vi.stubGlobal("fetch", mockFetchResponse(updatedConfig));

    const { updateConfig } = await import("./api");
    const result = await updateConfig(updatedConfig as any);

    expect(result.defaults.mode).toBe("detection_only");
    expect(result.defaults.paranoia_level).toBe(3);
    expect(Object.keys(result.services)).toHaveLength(1);

    // Verify the PUT payload is sent directly (no field mapping)
    const putCall = vi.mocked(fetch).mock.calls[0];
    const putBody = JSON.parse(putCall[1]?.body as string);
    expect(putBody.defaults.mode).toBe("detection_only");
    expect(putBody.defaults.inbound_threshold).toBe(10);
    expect(putBody.services["radarr.erfi.io"].mode).toBe("enabled");
  });
});

// ─── CRS v4 Extended Settings ───────────────────────────────────────

describe("getConfig with CRS v4 extended settings", () => {
  it("returns CRS v4 extended fields when present", async () => {
    const apiResponse = {
      defaults: {
        mode: "enabled",
        paranoia_level: 3,
        inbound_threshold: 10,
        outbound_threshold: 8,
        blocking_paranoia_level: 1,
        detection_paranoia_level: 3,
        early_blocking: true,
        sampling_percentage: 50,
        reporting_level: 2,
        enforce_bodyproc_urlencoded: true,
        allowed_methods: "GET HEAD POST",
        allowed_http_versions: "HTTP/1.1 HTTP/2",
        max_num_args: 500,
        arg_name_length: 200,
        arg_length: 800,
        total_arg_length: 128000,
        max_file_size: 10485760,
        combined_file_sizes: 20971520,
        crs_exclusions: ["wordpress", "nextcloud"],
      },
      services: {},
    };

    vi.stubGlobal("fetch", mockFetchResponse(apiResponse));

    const { getConfig } = await import("./api");
    const result = await getConfig();

    expect(result.defaults.blocking_paranoia_level).toBe(1);
    expect(result.defaults.detection_paranoia_level).toBe(3);
    expect(result.defaults.early_blocking).toBe(true);
    expect(result.defaults.sampling_percentage).toBe(50);
    expect(result.defaults.reporting_level).toBe(2);
    expect(result.defaults.enforce_bodyproc_urlencoded).toBe(true);
    expect(result.defaults.allowed_methods).toBe("GET HEAD POST");
    expect(result.defaults.allowed_http_versions).toBe("HTTP/1.1 HTTP/2");
    expect(result.defaults.max_num_args).toBe(500);
    expect(result.defaults.arg_name_length).toBe(200);
    expect(result.defaults.arg_length).toBe(800);
    expect(result.defaults.total_arg_length).toBe(128000);
    expect(result.defaults.max_file_size).toBe(10485760);
    expect(result.defaults.combined_file_sizes).toBe(20971520);
    expect(result.defaults.crs_exclusions).toEqual(["wordpress", "nextcloud"]);
  });

  it("handles missing CRS v4 fields gracefully (all undefined)", async () => {
    const apiResponse = {
      defaults: {
        mode: "enabled",
        paranoia_level: 1,
        inbound_threshold: 5,
        outbound_threshold: 4,
      },
      services: {},
    };

    vi.stubGlobal("fetch", mockFetchResponse(apiResponse));

    const { getConfig } = await import("./api");
    const result = await getConfig();

    expect(result.defaults.blocking_paranoia_level).toBeUndefined();
    expect(result.defaults.crs_exclusions).toBeUndefined();
    expect(result.defaults.early_blocking).toBeUndefined();
    expect(result.defaults.max_num_args).toBeUndefined();
  });

  it("sends CRS v4 fields in updateConfig payload", async () => {
    const config = {
      defaults: {
        mode: "enabled" as const,
        paranoia_level: 2,
        inbound_threshold: 10,
        outbound_threshold: 8,
        blocking_paranoia_level: 1,
        crs_exclusions: ["wordpress"],
        max_num_args: 500,
      },
      services: {},
    };

    vi.stubGlobal("fetch", mockFetchResponse(config));

    const { updateConfig } = await import("./api");
    await updateConfig(config);

    const putCall = vi.mocked(fetch).mock.calls[0];
    const putBody = JSON.parse(putCall[1]?.body as string);
    expect(putBody.defaults.blocking_paranoia_level).toBe(1);
    expect(putBody.defaults.crs_exclusions).toEqual(["wordpress"]);
    expect(putBody.defaults.max_num_args).toBe(500);
  });
});

describe("presetToSettings and settingsToPreset", () => {
  it("presets only affect core trio", async () => {
    const { presetToSettings, settingsToPreset } = await import("./api");

    // Strict preset
    const strict = presetToSettings("strict");
    expect(strict.paranoia_level).toBe(1);
    expect(strict.inbound_threshold).toBe(5);
    expect(strict.outbound_threshold).toBe(4);
    // Extended fields are NOT set by presets
    expect((strict as any).blocking_paranoia_level).toBeUndefined();
    expect((strict as any).crs_exclusions).toBeUndefined();
  });

  it("settingsToPreset ignores extended fields", async () => {
    const { settingsToPreset } = await import("./api");

    // Even with extended fields, if core trio matches strict, it's strict
    const settings = {
      mode: "enabled" as const,
      paranoia_level: 1,
      inbound_threshold: 5,
      outbound_threshold: 4,
      blocking_paranoia_level: 1,
      crs_exclusions: ["wordpress"],
    };
    expect(settingsToPreset(settings)).toBe("strict");
  });
});

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

    const { getExclusions } = await import("./api");
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

    const { createExclusion } = await import("./api");
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

// ─── Error handling ─────────────────────────────────────────────────

describe("API error handling", () => {
  it("throws on non-OK response for fetchSummary", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchResponse({ error: "internal error" }, 500)
    );

    await expect(fetchSummary()).rejects.toThrow("API error: 500");
  });

  it("throws on non-OK response for fetchEvents", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchResponse({ error: "bad request" }, 400)
    );

    await expect(fetchEvents()).rejects.toThrow("API error: 400");
  });

  it("throws on non-OK response for fetchServices", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchResponse({ error: "unauthorized" }, 401)
    );

    await expect(fetchServices()).rejects.toThrow("API error: 401");
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

// ─── GeoIP / Country fields ─────────────────────────────────────────

describe("country field mapping", () => {
  it("maps country in summary top_clients", async () => {
    const goResponse = {
      total_events: 1,
      blocked_events: 0,
      logged_events: 1,
      unique_clients: 1,
      unique_services: 1,
      events_by_hour: [],
      top_services: [],
      top_clients: [
        { client: "1.2.3.4", country: "US", count: 5, blocked: 2, rate_limited: 0, ipsum_blocked: 0 },
      ],
      top_countries: [
        { country: "US", count: 5, blocked: 2 },
        { country: "DE", count: 3, blocked: 1 },
      ],
      top_uris: [],
      service_breakdown: [],
      recent_events: [],
    };
    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result = await fetchSummary();
    expect(result.top_clients[0].country).toBe("US");
    expect(result.top_countries).toHaveLength(2);
    expect(result.top_countries[0].country).toBe("US");
    expect(result.top_countries[0].count).toBe(5);
    expect(result.top_countries[0].blocked).toBe(2);
  });

  it("handles missing top_countries gracefully", async () => {
    vi.stubGlobal("fetch", mockFetchResponse({
      total_events: 0,
      blocked_events: 0,
      logged_events: 0,
      unique_clients: 0,
      unique_services: 0,
      events_by_hour: [],
      top_services: [],
      top_clients: [],
      top_uris: [],
      service_breakdown: [],
      recent_events: [],
    }));

    const result = await fetchSummary();
    expect(result.top_countries).toEqual([]);
  });

  it("maps country in event response", async () => {
    const goResponse = {
      total: 1,
      events: [{
        id: "tx-geo",
        timestamp: "2026-02-23T10:00:00Z",
        service: "test.erfi.io",
        method: "GET",
        uri: "/test",
        client_ip: "8.8.8.8",
        country: "US",
        is_blocked: false,
        response_status: 200,
      }],
    };
    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result = await fetchEvents();
    expect(result.events[0].country).toBe("US");
  });

  it("handles missing country in event gracefully", async () => {
    const goResponse = {
      total: 1,
      events: [{
        id: "tx-nocountry",
        timestamp: "2026-02-23T10:00:00Z",
        service: "test.erfi.io",
        method: "GET",
        uri: "/test",
        client_ip: "10.0.0.1",
        is_blocked: false,
        response_status: 200,
      }],
    };
    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result = await fetchEvents();
    expect(result.events[0].country).toBeUndefined();
  });
});

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

// ─── Event Type Mapping Tests ─────────────────────────────────────────

describe("event_type mapping in fetchEvents", () => {
  const eventTypes = [
    "blocked", "logged", "rate_limited", "ipsum_blocked",
    "policy_skip", "policy_allow", "policy_block", "honeypot", "scanner",
  ] as const;

  for (const eventType of eventTypes) {
    it(`maps event_type="${eventType}" correctly`, async () => {
      const goResponse = {
        total: 1,
        events: [{
          id: `tx-${eventType}`,
          timestamp: "2026-02-23T10:00:00Z",
          service: "test.erfi.io",
          method: "GET",
          uri: "/test",
          client_ip: "10.0.0.1",
          is_blocked: eventType !== "logged" && eventType !== "policy_skip" && eventType !== "policy_allow",
          response_status: 200,
          event_type: eventType,
        }],
      };
      vi.stubGlobal("fetch", mockFetchResponse(goResponse));

      const result = await fetchEvents();
      expect(result.events[0].event_type).toBe(eventType);
    });
  }

  it("falls back to 'blocked' when event_type is missing and is_blocked=true", async () => {
    const goResponse = {
      total: 1,
      events: [{
        id: "tx-fallback",
        timestamp: "2026-02-23T10:00:00Z",
        service: "test.erfi.io",
        method: "GET",
        uri: "/test",
        client_ip: "10.0.0.1",
        is_blocked: true,
        response_status: 403,
      }],
    };
    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result = await fetchEvents();
    expect(result.events[0].event_type).toBe("blocked");
  });

  it("falls back to 'logged' when event_type is missing and is_blocked=false", async () => {
    const goResponse = {
      total: 1,
      events: [{
        id: "tx-fallback",
        timestamp: "2026-02-23T10:00:00Z",
        service: "test.erfi.io",
        method: "GET",
        uri: "/test",
        client_ip: "10.0.0.1",
        is_blocked: false,
        response_status: 200,
      }],
    };
    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result = await fetchEvents();
    expect(result.events[0].event_type).toBe("logged");
  });

  it("ignores invalid event_type and falls back to is_blocked", async () => {
    const goResponse = {
      total: 1,
      events: [{
        id: "tx-invalid",
        timestamp: "2026-02-23T10:00:00Z",
        service: "test.erfi.io",
        method: "GET",
        uri: "/test",
        client_ip: "10.0.0.1",
        is_blocked: true,
        response_status: 403,
        event_type: "nonexistent_type",
      }],
    };
    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result = await fetchEvents();
    expect(result.events[0].event_type).toBe("blocked");
  });
});

// ─── Blocklist API Tests ────────────────────────────────────────────

describe("getBlocklistStats", () => {
  it("returns blocklist stats", async () => {
    const mockStats = {
      blocked_ips: 19823,
      last_updated: "2026-02-22T06:00:01Z",
      source: "IPsum",
      min_score: 3,
      file_path: "/data/coraza/ipsum_block.caddy",
    };
    vi.stubGlobal("fetch", mockFetchResponse(mockStats));

    const result = await getBlocklistStats();
    expect(result.blocked_ips).toBe(19823);
    expect(result.last_updated).toBe("2026-02-22T06:00:01Z");
    expect(result.source).toBe("IPsum");
    expect(result.min_score).toBe(3);
  });
});

describe("checkBlocklistIP", () => {
  it("returns check result for blocked IP", async () => {
    const mockResult = { ip: "1.2.3.4", blocked: true, source: "ipsum" };
    vi.stubGlobal("fetch", mockFetchResponse(mockResult));

    const result = await checkBlocklistIP("1.2.3.4");
    expect(result.ip).toBe("1.2.3.4");
    expect(result.blocked).toBe(true);
  });

  it("returns check result for clean IP", async () => {
    const mockResult = { ip: "8.8.8.8", blocked: false, source: "" };
    vi.stubGlobal("fetch", mockFetchResponse(mockResult));

    const result = await checkBlocklistIP("8.8.8.8");
    expect(result.blocked).toBe(false);
  });
});

// ─── fetchServices breakdown fields ─────────────────────────────────

describe("fetchServices breakdown fields", () => {
  it("maps honeypot/scanner/policy fields from Go API", async () => {
    const goResponse = {
      services: [{
        service: "web.erfi.io",
        total: 100,
        blocked: 40,
        logged: 60,
        rate_limited: 5,
        ipsum_blocked: 3,
        honeypot: 2,
        scanner: 1,
        policy: 4,
      }],
    };
    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result = await fetchServices(24);
    expect(result).toHaveLength(1);
    expect(result[0].honeypot).toBe(2);
    expect(result[0].scanner).toBe(1);
    expect(result[0].policy).toBe(4);
    expect(result[0].rate_limited).toBe(5);
    expect(result[0].ipsum_blocked).toBe(3);
  });

  it("defaults new fields to 0 when missing", async () => {
    const goResponse = {
      services: [{
        service: "old.erfi.io",
        total: 50,
        blocked: 10,
        logged: 40,
      }],
    };
    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result = await fetchServices(24);
    expect(result[0].honeypot).toBe(0);
    expect(result[0].scanner).toBe(0);
    expect(result[0].policy).toBe(0);
    expect(result[0].rate_limited).toBe(0);
    expect(result[0].ipsum_blocked).toBe(0);
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

// ─── Blocklist refresh tests ────────────────────────────────────────

describe("refreshBlocklist", () => {
  it("returns refresh result on success", async () => {
    const mockResponse: BlocklistRefreshResult = {
      status: "updated",
      message: "Downloaded 19823 IPs and updated blocklist",
      blocked_ips: 19823,
      min_score: 3,
      last_updated: "2026-02-23T12:00:00Z",
      reloaded: true,
    };
    vi.stubGlobal("fetch", mockFetchResponse(mockResponse));

    const result = await refreshBlocklist();
    expect(result.status).toBe("updated");
    expect(result.blocked_ips).toBe(19823);
    expect(result.min_score).toBe(3);
    expect(result.last_updated).toBe("2026-02-23T12:00:00Z");
    expect(result.reloaded).toBe(true);
  });

  it("throws on HTTP error", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
        json: () => Promise.resolve({ message: "download failed: connection refused" }),
      })
    );

    await expect(refreshBlocklist()).rejects.toThrow("download failed: connection refused");
  });

  it("handles partial status (Caddy reload failed)", async () => {
    const mockResponse: BlocklistRefreshResult = {
      status: "partial",
      message: "Downloaded 19823 IPs and updated blocklist (Caddy reload failed)",
      blocked_ips: 19823,
      min_score: 3,
      last_updated: "2026-02-23T12:00:00Z",
      reloaded: false,
    };
    vi.stubGlobal("fetch", mockFetchResponse(mockResponse));

    const result = await refreshBlocklist();
    expect(result.status).toBe("partial");
    expect(result.reloaded).toBe(false);
  });
});

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

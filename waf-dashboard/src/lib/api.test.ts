import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  fetchSummary,
  fetchEvents,
  fetchServices,
  lookupIP,
  fetchTopBlockedIPs,
  fetchTopTargetedURIs,
  generateConfig,
  fetchCRSRules,
  fetchCRSAutocomplete,
  type SummaryData,
  type EventsResponse,
  type ServiceDetail,
  type IPLookupData,
  type GeneratedConfig,
  type CRSCatalogResponse,
  type CRSAutocompleteResponse,
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
      recent_blocks: [
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

    const result: SummaryData = await fetchSummary(24);

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

    // Service breakdown from dedicated field
    expect(result.service_breakdown).toHaveLength(2);
    expect(result.service_breakdown[0]).toEqual({
      service: "radarr.erfi.io",
      total: 60,
      blocked: 15,
      logged: 45,
    });

    // recent_blocks mapped from Go events
    expect(result.recent_blocks).toHaveLength(1);
    expect(result.recent_blocks[0].blocked).toBe(true);
    expect(result.recent_blocks[0].status).toBe(403);
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

    await fetchSummary(24);

    expect(mockFetch).toHaveBeenCalledWith("/api/summary?hours=24", undefined);
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

  it("limits recent_events to 20", async () => {
    const events = Array.from({ length: 30 }, (_, i) => ({
      id: `E${i}`,
      timestamp: "2026-02-22T09:00:00Z",
      service: "test.erfi.io",
      method: "GET",
      uri: "/",
      client_ip: "10.0.0.1",
      is_blocked: false,
      response_status: 200,
    }));

    vi.stubGlobal(
      "fetch",
      mockFetchResponse({
        ip: "10.0.0.1",
        total: 30,
        blocked: 0,
        first_seen: "2026-02-22T07:00:00Z",
        last_seen: "2026-02-22T09:00:00Z",
        services: [],
        events,
      })
    );

    const result = await lookupIP("10.0.0.1");
    expect(result.recent_events).toHaveLength(20);
  });
});

// ─── fetchTopBlockedIPs / fetchTopTargetedURIs ──────────────────────

describe("fetchTopBlockedIPs", () => {
  it("returns empty array on API error (endpoint not implemented)", async () => {
    vi.stubGlobal("fetch", mockFetchResponse({ error: "not found" }, 404));

    const result = await fetchTopBlockedIPs();
    expect(result).toEqual([]);
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
  it("returns empty array on API error (endpoint not implemented)", async () => {
    vi.stubGlobal("fetch", mockFetchResponse({ error: "not found" }, 404));

    const result = await fetchTopTargetedURIs();
    expect(result).toEqual([]);
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
  it("transforms Go WAFConfig to frontend WAFConfig shape", async () => {
    const goResponse = {
      paranoia_level: 2,
      inbound_threshold: 10,
      outbound_threshold: 5,
      rule_engine: "On",
      services: {
        "radarr.erfi.io": { profile: "strict" },
        "sonarr.erfi.io": { profile: "tuning" },
      },
    };

    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const { getConfig } = await import("./api");
    const result = await getConfig();

    expect(result.engine_mode).toBe("on");
    expect(result.paranoia_level).toBe(2);
    expect(result.inbound_anomaly_threshold).toBe(10);
    expect(result.outbound_anomaly_threshold).toBe(5);
    expect(result.service_profiles).toHaveLength(2);
    expect(result.service_profiles).toEqual(
      expect.arrayContaining([
        { service: "radarr.erfi.io", profile: "strict" },
        { service: "sonarr.erfi.io", profile: "tuning" },
      ])
    );
  });

  it("maps DetectionOnly rule_engine to detection_only", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchResponse({
        paranoia_level: 1,
        inbound_threshold: 5,
        outbound_threshold: 4,
        rule_engine: "DetectionOnly",
        services: {},
      })
    );

    const { getConfig } = await import("./api");
    const result = await getConfig();
    expect(result.engine_mode).toBe("detection_only");
  });

  it("maps Off rule_engine to off", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchResponse({
        paranoia_level: 1,
        inbound_threshold: 5,
        outbound_threshold: 4,
        rule_engine: "Off",
        services: {},
      })
    );

    const { getConfig } = await import("./api");
    const result = await getConfig();
    expect(result.engine_mode).toBe("off");
  });

  it("handles null/empty services gracefully", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchResponse({
        paranoia_level: 1,
        inbound_threshold: 5,
        outbound_threshold: 4,
        rule_engine: "On",
        services: null,
      })
    );

    const { getConfig } = await import("./api");
    const result = await getConfig();
    expect(result.service_profiles).toEqual([]);
  });
});

describe("updateConfig", () => {
  it("transforms frontend WAFConfig to Go shape and back", async () => {
    // updateConfig first fetches current config (GET), then PUTs the transformed payload
    const goCurrentConfig = {
      paranoia_level: 1,
      inbound_threshold: 5,
      outbound_threshold: 4,
      rule_engine: "On",
      services: {},
    };
    const goUpdatedConfig = {
      paranoia_level: 3,
      inbound_threshold: 10,
      outbound_threshold: 8,
      rule_engine: "DetectionOnly",
      services: {
        "radarr.erfi.io": { profile: "tuning" },
      },
    };

    let callCount = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(() => {
        callCount++;
        // First call: GET /api/config (fetch current)
        // Second call: PUT /api/config (send update)
        const body = callCount <= 1 ? goCurrentConfig : goUpdatedConfig;
        return Promise.resolve({
          ok: true,
          status: 200,
          statusText: "OK",
          json: () => Promise.resolve(body),
          text: () => Promise.resolve(JSON.stringify(body)),
        });
      })
    );

    const { updateConfig } = await import("./api");
    const result = await updateConfig({
      engine_mode: "detection_only",
      paranoia_level: 3,
      inbound_anomaly_threshold: 10,
      outbound_anomaly_threshold: 8,
      service_profiles: [{ service: "radarr.erfi.io", profile: "tuning" }],
    });

    expect(result.engine_mode).toBe("detection_only");
    expect(result.paranoia_level).toBe(3);
    expect(result.inbound_anomaly_threshold).toBe(10);
    expect(result.outbound_anomaly_threshold).toBe(8);
    expect(result.service_profiles).toEqual([
      { service: "radarr.erfi.io", profile: "tuning" },
    ]);

    // Verify the PUT payload was in Go's format
    expect(callCount).toBe(2);
    const putCall = vi.mocked(fetch).mock.calls[1];
    const putBody = JSON.parse(putCall[1]?.body as string);
    expect(putBody.rule_engine).toBe("DetectionOnly");
    expect(putBody.inbound_threshold).toBe(10);
    expect(putBody.outbound_threshold).toBe(8);
    expect(putBody.services).toEqual({
      "radarr.erfi.io": { profile: "tuning" },
    });
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

import { describe, it, expect, vi } from "vitest";
import {
  fetchSummary,
  fetchEvents,
  fetchServices,
  type SummaryData,
  type EventsResponse,
  type ServiceDetail,
} from "@/lib/api";
import { mockFetchResponse, setupMockFetch } from "./__test-helpers";

setupMockFetch();

// ─── fetchSummary ───────────────────────────────────────────────────

describe("fetchSummary", () => {
  it("transforms Go API response to frontend SummaryData shape", async () => {
    const goResponse = {
      total_events: 100,
      total_blocked: 30,
      logged_events: 70,
      unique_clients: 5,
      unique_services: 3,
      events_by_hour: [
        { hour: "2026-02-22T07:00:00Z", count: 40, total_blocked: 10, logged: 30 },
        { hour: "2026-02-22T08:00:00Z", count: 60, total_blocked: 20, logged: 40 },
      ],
      top_services: [
        { service: "app.example.test", count: 60, total_blocked: 15, logged: 45 },
        { service: "api.example.test", count: 40, total_blocked: 15, logged: 25 },
      ],
      top_clients: [
        { client: "10.0.0.1", count: 50, total_blocked: 20 },
        { client: "10.0.0.2", count: 50, total_blocked: 10 },
      ],
      top_uris: [{ uri: "/.env", count: 20 }],
      service_breakdown: [
        { service: "app.example.test", total: 60, total_blocked: 15, logged: 45 },
        { service: "api.example.test", total: 40, total_blocked: 15, logged: 25 },
      ],
      recent_events: [
        {
          id: "tx-001",
          timestamp: "2026-02-22T08:30:00Z",
          service: "app.example.test",
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
    expect(result.total_blocked).toBe(30);
    expect(result.logged).toBe(70);
    expect(result.unique_clients).toBe(5);
    expect(result.unique_services).toBe(3);

    // Timeline mapped from events_by_hour (now includes blocked/logged)
    expect(result.timeline).toHaveLength(2);
    expect(result.timeline[0]).toEqual({
      hour: "2026-02-22T07:00:00Z",
      total: 40,
      total_blocked: 10,
      logged: 30,
      rate_limited: 0,
      policy_block: 0,
      detect_block: 0,
      ddos_blocked: 0,
      policy_allow: 0,
      policy_skip: 0,
      challenge_issued: 0,
      challenge_passed: 0,
      challenge_failed: 0,
    });

    // Top services mapped (now includes blocked/logged)
    expect(result.top_services).toHaveLength(2);
    expect(result.top_services[0].service).toBe("app.example.test");
    expect(result.top_services[0].total).toBe(60);
    expect(result.top_services[0].total_blocked).toBe(15);
    expect(result.top_services[0].logged).toBe(45);

    // Top clients mapped (client -> client_ip, now includes blocked)
    expect(result.top_clients).toHaveLength(2);
    expect(result.top_clients[0].client_ip).toBe("10.0.0.1");
    expect(result.top_clients[0].total).toBe(50);
    expect(result.top_clients[0].total_blocked).toBe(20);

    // Top clients now include rate_limited, policy breakdown
    expect(result.top_clients[0].rate_limited).toBe(0);
    expect(result.top_clients[0].policy_block).toBe(0);
    expect(result.top_clients[0].policy_allow).toBe(0);
    expect(result.top_clients[0].policy_skip).toBe(0);

    // Service breakdown from dedicated field
    expect(result.service_breakdown).toHaveLength(2);
    expect(result.service_breakdown[0]).toEqual({
      service: "app.example.test",
      total: 60,
      total_blocked: 15,
      logged: 45,
      rate_limited: 0,
      policy_block: 0,
      detect_block: 0,
      ddos_blocked: 0,
      policy_allow: 0,
      policy_skip: 0,
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
        total_blocked: 0,
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
      total_blocked: 0,
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
      total_blocked: 0,
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
      service: "cdn.example.test",
      client: "1.2.3.4",
      method: "GET",
      event_type: "detect_block",
      rule_name: "My Rule",
    });

    const calledUrl = (mockFetch as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    const params = new URLSearchParams(calledUrl.split("?")[1]);
    expect(params.get("hours")).toBe("12");
    expect(params.get("service")).toBe("cdn.example.test");
    expect(params.get("client")).toBe("1.2.3.4");
    expect(params.get("method")).toBe("GET");
    expect(params.get("event_type")).toBe("detect_block");
    expect(params.get("rule_name")).toBe("My Rule");
  });

  it("omits undefined filter params from URL", async () => {
    const mockFetch = mockFetchResponse({
      total_events: 0,
      total_blocked: 0,
      logged_events: 0,
      unique_clients: 0,
      unique_services: 0,
      events_by_hour: [],
      top_services: [],
      top_clients: [],
      top_uris: [],
    });
    vi.stubGlobal("fetch", mockFetch);

    await fetchSummary({ hours: 24, service: "cdn.example.test" });

    const calledUrl = (mockFetch as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    const params = new URLSearchParams(calledUrl.split("?")[1]);
    expect(params.get("hours")).toBe("24");
    expect(params.get("service")).toBe("cdn.example.test");
    expect(params.has("client")).toBe(false);
    expect(params.has("method")).toBe(false);
    expect(params.has("event_type")).toBe(false);
    expect(params.has("rule_name")).toBe(false);
  });

  it("sends _op params when operator is not eq", async () => {
    const mockFetch = mockFetchResponse({
      total_events: 0, total_blocked: 0, logged_events: 0,
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
      total_events: 0, total_blocked: 0, logged_events: 0,
      rate_limited: 0, ipsum_blocked: 0, policy_events: 0,
      honeypot_events: 0, scanner_events: 0,
      unique_clients: 0, unique_services: 0,
      events_by_hour: [], top_services: [], top_clients: [], top_uris: [],
    });
    vi.stubGlobal("fetch", mockFetch);

    await fetchSummary({ hours: 24, service: "cdn.example.test", service_op: "eq" });

    const calledUrl = (mockFetch as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    const params = new URLSearchParams(calledUrl.split("?")[1]);
    expect(params.get("service")).toBe("cdn.example.test");
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
          service: "dockge-svc.example.test",
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
          service: "app.example.test",
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
          service: "svc.example.test",
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

    await fetchEvents({ service: "app.example.test", blocked: true });

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("service=app.example.test");
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
        { service: "app.example.test", total: 100, total_blocked: 25, logged: 75 },
        { service: "api.example.test", total: 50, total_blocked: 0, logged: 50 },
      ],
    };

    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result: ServiceDetail[] = await fetchServices();

    expect(result).toHaveLength(2);

    // First service
    expect(result[0].service).toBe("app.example.test");
    expect(result[0].total_events).toBe(100); // total -> total_events
    expect(result[0].total_blocked).toBe(25);
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
        services: [{ service: "test", total: 0, total_blocked: 0, logged: 0 }],
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

// ─── GeoIP / Country fields ─────────────────────────────────────────

describe("country field mapping", () => {
  it("maps country in summary top_clients", async () => {
    const goResponse = {
      total_events: 1,
      total_blocked: 0,
      logged_events: 1,
      unique_clients: 1,
      unique_services: 1,
      events_by_hour: [],
      top_services: [],
      top_clients: [
        { client: "1.2.3.4", country: "US", count: 5, total_blocked: 2, rate_limited: 0, ipsum_blocked: 0 },
      ],
      top_countries: [
        { country: "US", count: 5, total_blocked: 2 },
        { country: "DE", count: 3, total_blocked: 1 },
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
    expect(result.top_countries[0].total_blocked).toBe(2);
  });

  it("handles missing top_countries gracefully", async () => {
    vi.stubGlobal("fetch", mockFetchResponse({
      total_events: 0,
      total_blocked: 0,
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
        service: "svc.example.test",
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
        service: "svc.example.test",
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

// ─── Event Type Mapping Tests ─────────────────────────────────────────

describe("event_type mapping in fetchEvents", () => {
  const eventTypes = [
    "detect_block", "logged", "rate_limited",
    "policy_skip", "policy_allow", "policy_block",
  ] as const;

  for (const eventType of eventTypes) {
    it(`maps event_type="${eventType}" correctly`, async () => {
      const goResponse = {
        total: 1,
        events: [{
          id: `tx-${eventType}`,
          timestamp: "2026-02-23T10:00:00Z",
          service: "svc.example.test",
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

  it("falls back to 'detect_block' when event_type is missing and is_blocked=true", async () => {
    const goResponse = {
      total: 1,
      events: [{
        id: "tx-fallback",
        timestamp: "2026-02-23T10:00:00Z",
        service: "svc.example.test",
        method: "GET",
        uri: "/test",
        client_ip: "10.0.0.1",
        is_blocked: true,
        response_status: 403,
      }],
    };
    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result = await fetchEvents();
    expect(result.events[0].event_type).toBe("detect_block");
  });

  it("falls back to 'logged' when event_type is missing and is_blocked=false", async () => {
    const goResponse = {
      total: 1,
      events: [{
        id: "tx-fallback",
        timestamp: "2026-02-23T10:00:00Z",
        service: "svc.example.test",
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
        service: "svc.example.test",
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
    expect(result.events[0].event_type).toBe("detect_block");
  });
});

// ─── fetchServices breakdown fields ─────────────────────────────────

describe("fetchServices breakdown fields", () => {
  it("maps policy breakdown/rate_limited fields from Go API", async () => {
    const goResponse = {
      services: [{
        service: "svc.example.test",
        total: 100,
        total_blocked: 40,
        logged: 60,
        rate_limited: 5,
        policy_block: 3,
        policy_allow: 1,
        policy_skip: 0,
      }],
    };
    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result = await fetchServices(24);
    expect(result).toHaveLength(1);
    expect(result[0].policy_block).toBe(3);
    expect(result[0].policy_allow).toBe(1);
    expect(result[0].policy_skip).toBe(0);
    expect(result[0].rate_limited).toBe(5);
  });

  it("defaults new fields to 0 when missing", async () => {
    const goResponse = {
      services: [{
        service: "svc.example.test",
        total: 50,
        total_blocked: 10,
        logged: 40,
      }],
    };
    vi.stubGlobal("fetch", mockFetchResponse(goResponse));

    const result = await fetchServices(24);
    expect(result[0].policy_block).toBe(0);
    expect(result[0].policy_allow).toBe(0);
    expect(result[0].policy_skip).toBe(0);
    expect(result[0].rate_limited).toBe(0);
  });
});

import { describe, it, expect, vi } from "vitest";
import {
  fetchGeneralLogs,
  fetchGeneralLogsSummary,
  type GeneralLogsResponse,
  type GeneralLogsSummary,
} from "@/lib/api";
import { mockFetchResponse, setupMockFetch } from "./__test-helpers";

setupMockFetch();

// ─── General Log Viewer ─────────────────────────────────────────────

const mockGeneralLogsResponse: GeneralLogsResponse = {
  total: 3,
  events: [
    {
      timestamp: "2026-03-01T12:00:00Z",
      client_ip: "10.0.0.1",
      country: "US",
      service: "app.example.com",
      method: "GET",
      uri: "/",
      protocol: "HTTP/2.0",
      status: 200,
      size: 5000,
      bytes_read: 0,
      duration: 0.05,
      user_agent: "Mozilla/5.0",
      logger: "http.log.access.app",
      level: "info",
      security_headers: {
        has_csp: true,
        csp: "default-src 'self'",
        has_hsts: true,
        hsts: "max-age=31536000",
        has_x_content_type_options: true,
        x_content_type_options: "nosniff",
        has_x_frame_options: true,
        x_frame_options: "DENY",
        has_referrer_policy: true,
        referrer_policy: "strict-origin",
        has_cors_origin: false,
        has_permissions_policy: false,
      },
    },
    {
      timestamp: "2026-03-01T12:01:00Z",
      client_ip: "10.0.0.2",
      service: "api.example.com",
      method: "POST",
      uri: "/v1/webhook",
      protocol: "HTTP/2.0",
      status: 500,
      size: 50,
      bytes_read: 2048,
      duration: 1.2,
      user_agent: "curl/8.0",
      level: "error",
      security_headers: {
        has_csp: false,
        has_hsts: false,
        has_x_content_type_options: false,
        has_x_frame_options: false,
        has_referrer_policy: false,
        has_cors_origin: false,
        has_permissions_policy: false,
      },
    },
    {
      timestamp: "2026-03-01T12:02:00Z",
      client_ip: "10.0.0.3",
      country: "DE",
      service: "app.example.com",
      method: "GET",
      uri: "/nonexistent",
      protocol: "HTTP/1.1",
      status: 404,
      size: 100,
      bytes_read: 0,
      duration: 0.005,
      user_agent: "Googlebot/2.1",
      level: "info",
      security_headers: {
        has_csp: false,
        has_hsts: true,
        hsts: "max-age=31536000",
        has_x_content_type_options: true,
        x_content_type_options: "nosniff",
        has_x_frame_options: false,
        has_referrer_policy: false,
        has_cors_origin: false,
        has_permissions_policy: false,
      },
    },
  ],
};

const mockGeneralLogsSummary: GeneralLogsSummary = {
  total_requests: 100,
  error_count: 5,
  client_error_count: 10,
  avg_duration: 0.15,
  p50_duration: 0.05,
  p95_duration: 0.5,
  p99_duration: 1.2,
  status_distribution: { "2xx": 75, "3xx": 5, "4xx": 10, "5xx": 5, other: 5 },
  top_services: [
    { service: "app.example.com", count: 60, error_count: 2, error_rate: 0.033, avg_duration: 0.1 },
    { service: "api.example.com", count: 40, error_count: 3, error_rate: 0.075, avg_duration: 0.2 },
  ],
  top_uris: [
    { uri: "/", count: 30, error_count: 0, avg_duration: 0.05 },
    { uri: "/api/v1/data", count: 25, error_count: 2, avg_duration: 0.15 },
  ],
  top_clients: [
    { client_ip: "10.0.0.1", country: "US", count: 50, error_count: 1 },
    { client_ip: "10.0.0.2", country: "DE", count: 30, error_count: 3 },
  ],
  header_compliance: [
    {
      service: "app.example.com",
      total: 60,
      csp_rate: 0.8,
      hsts_rate: 0.95,
      x_content_type_options_rate: 1.0,
      x_frame_options_rate: 0.9,
      referrer_policy_rate: 0.7,
      cors_origin_rate: 0.0,
      permissions_policy_rate: 0.0,
    },
  ],
  recent_errors: [mockGeneralLogsResponse.events[1]],
};

describe("fetchGeneralLogs", () => {
  it("fetches logs without params", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockGeneralLogsResponse));
    const result = await fetchGeneralLogs();

    expect(fetch).toHaveBeenCalledWith("/api/logs", undefined);
    expect(result.total).toBe(3);
    expect(result.events).toHaveLength(3);
  });

  it("passes filter params to query string", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockGeneralLogsResponse));
    await fetchGeneralLogs({
      hours: 24,
      service: "app.example.com",
      status: "5xx",
      method: "GET",
      level: "error",
      missing_header: "csp",
      page: 2,
      per_page: 25,
    });

    const url = (fetch as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    expect(url).toContain("hours=24");
    expect(url).toContain("service=app.example.com");
    expect(url).toContain("status=5xx");
    expect(url).toContain("method=GET");
    expect(url).toContain("level=error");
    expect(url).toContain("missing_header=csp");
    expect(url).toContain("limit=25");
    expect(url).toContain("offset=25"); // page 2 * 25 per page = offset 25
  });

  it("passes time range params (start/end)", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockGeneralLogsResponse));
    await fetchGeneralLogs({
      start: "2026-03-01T00:00:00Z",
      end: "2026-03-01T23:59:59Z",
    });

    const url = (fetch as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    expect(url).toContain("start=2026-03-01T00%3A00%3A00Z");
    expect(url).toContain("end=2026-03-01T23%3A59%3A59Z");
    expect(url).not.toContain("hours=");
  });

  it("passes filter operator params", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockGeneralLogsResponse));
    await fetchGeneralLogs({
      uri: "/api",
      uri_op: "contains",
      service: "app",
      service_op: "contains",
    });

    const url = (fetch as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    expect(url).toContain("uri=%2Fapi");
    expect(url).toContain("uri_op=contains");
    expect(url).toContain("service=app");
    expect(url).toContain("service_op=contains");
  });

  it("returns events with security header info", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockGeneralLogsResponse));
    const result = await fetchGeneralLogs();

    const first = result.events[0];
    expect(first.security_headers.has_csp).toBe(true);
    expect(first.security_headers.csp).toBe("default-src 'self'");
    expect(first.security_headers.has_hsts).toBe(true);
    expect(first.security_headers.has_cors_origin).toBe(false);

    const second = result.events[1];
    expect(second.security_headers.has_csp).toBe(false);
    expect(second.status).toBe(500);
  });

  it("throws on API error", async () => {
    vi.stubGlobal("fetch", mockFetchResponse({ error: "server error" }, 500));
    await expect(fetchGeneralLogs()).rejects.toThrow("API error: 500");
  });
});

describe("fetchGeneralLogsSummary", () => {
  it("fetches summary without params", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockGeneralLogsSummary));
    const result = await fetchGeneralLogsSummary();

    expect(fetch).toHaveBeenCalledWith("/api/logs/summary", undefined);
    expect(result.total_requests).toBe(100);
    expect(result.error_count).toBe(5);
    expect(result.client_error_count).toBe(10);
  });

  it("includes latency percentiles", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockGeneralLogsSummary));
    const result = await fetchGeneralLogsSummary();

    expect(result.p50_duration).toBe(0.05);
    expect(result.p95_duration).toBe(0.5);
    expect(result.p99_duration).toBe(1.2);
    expect(result.avg_duration).toBe(0.15);
  });

  it("includes status distribution", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockGeneralLogsSummary));
    const result = await fetchGeneralLogsSummary();

    expect(result.status_distribution["2xx"]).toBe(75);
    expect(result.status_distribution["5xx"]).toBe(5);
  });

  it("includes header compliance data", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockGeneralLogsSummary));
    const result = await fetchGeneralLogsSummary();

    expect(result.header_compliance).toHaveLength(1);
    expect(result.header_compliance[0].service).toBe("app.example.com");
    expect(result.header_compliance[0].csp_rate).toBe(0.8);
    expect(result.header_compliance[0].hsts_rate).toBe(0.95);
  });

  it("includes top services with error rates", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockGeneralLogsSummary));
    const result = await fetchGeneralLogsSummary();

    expect(result.top_services).toHaveLength(2);
    expect(result.top_services[0].error_rate).toBe(0.033);
    expect(result.top_services[1].avg_duration).toBe(0.2);
  });

  it("passes service filter to query string", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockGeneralLogsSummary));
    await fetchGeneralLogsSummary({ service: "api.example.com", hours: 1 });

    const url = (fetch as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    expect(url).toContain("service=api.example.com");
    expect(url).toContain("hours=1");
  });

  it("includes recent errors", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockGeneralLogsSummary));
    const result = await fetchGeneralLogsSummary();

    expect(result.recent_errors).toHaveLength(1);
    expect(result.recent_errors[0].status).toBe(500);
  });
});

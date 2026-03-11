import { describe, it, expect, vi } from "vitest";
import {
  fetchBackup,
  restoreBackup,
  type FullBackup,
  type RestoreResult,
} from "@/lib/api";
import { mockFetchResponse, setupMockFetch } from "./__test-helpers";

setupMockFetch();

// ─── Backup / Restore API Tests ─────────────────────────────────────

const mockBackup: FullBackup = {
  version: 1,
  exported_at: "2026-03-11T12:00:00Z",
  waf_config: {
    defaults: {
      mode: "enabled",
      paranoia_level: 2,
      inbound_threshold: 10,
      outbound_threshold: 10,
    },
    services: {},
  },
  csp_config: {
    enabled: true,
    global_defaults: { default_src: ["'self'"] },
    services: {},
  },
  exclusions: [
    { id: "exc-1", name: "Allow admin", type: "allow", enabled: true },
  ],
  rate_limits: {
    rules: [
      {
        id: "rl-1",
        name: "API limit",
        description: "",
        service: "api",
        conditions: [],
        group_operator: "and",
        key: "client_ip",
        events: 100,
        window: "1m",
        action: "deny",
        priority: 300,
        tags: [],
        enabled: true,
        created_at: "2026-03-01T00:00:00Z",
        updated_at: "2026-03-01T00:00:00Z",
      },
    ],
    global: {
      jitter: 0,
      sweep_interval: "30s",
      distributed: false,
      read_interval: "",
      write_interval: "",
      purge_age: "",
    },
  },
  lists: [],
};

describe("fetchBackup", () => {
  it("returns full backup envelope", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockBackup));
    const result = await fetchBackup();
    expect(result.version).toBe(1);
    expect(result.waf_config.defaults.mode).toBe("enabled");
    expect(result.exclusions).toHaveLength(1);
    expect(result.rate_limits.rules).toHaveLength(1);
  });

  it("includes CSP config in backup", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockBackup));
    const result = await fetchBackup();
    expect(result.csp_config.enabled).toBe(true);
    expect(result.csp_config.global_defaults.default_src).toEqual(["'self'"]);
  });

  it("calls correct endpoint", async () => {
    const mockFn = mockFetchResponse(mockBackup);
    vi.stubGlobal("fetch", mockFn);
    await fetchBackup();
    expect(mockFn).toHaveBeenCalledWith("/api/backup", undefined);
  });

  it("throws on server error", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
        text: () => Promise.resolve("backup generation failed"),
      })
    );
    await expect(fetchBackup()).rejects.toThrow("500");
  });
});

describe("restoreBackup", () => {
  const successResult: RestoreResult = {
    status: "restored",
    results: {
      waf_config: "restored",
      csp_config: "restored",
      exclusions: "restored 1 exclusions",
      rate_limits: "restored 1 rules",
      lists: "skipped: no lists in backup",
    },
  };

  it("returns restore result on success", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(successResult));
    const result = await restoreBackup(mockBackup);
    expect(result.status).toBe("restored");
    expect(result.results.waf_config).toBe("restored");
    expect(result.results.exclusions).toContain("restored");
  });

  it("returns partial result on partial failure", async () => {
    const partialResult: RestoreResult = {
      status: "partial",
      results: {
        waf_config: "restored",
        csp_config: "restored",
        exclusions: "failed: exclusion 0: name is required",
        rate_limits: "restored 1 rules",
        lists: "skipped: no lists in backup",
      },
    };
    vi.stubGlobal("fetch", mockFetchResponse(partialResult));
    const result = await restoreBackup(mockBackup);
    expect(result.status).toBe("partial");
    expect(result.results.exclusions).toContain("failed");
  });

  it("sends backup as JSON body", async () => {
    const mockFn = mockFetchResponse(successResult);
    vi.stubGlobal("fetch", mockFn);
    await restoreBackup(mockBackup);
    expect(mockFn).toHaveBeenCalledWith(
      "/api/backup/restore",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
      })
    );
  });

  it("throws on 400 (invalid backup)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        statusText: "Bad Request",
        text: () => Promise.resolve('{"error":"invalid backup: missing or zero version field"}'),
      })
    );
    await expect(restoreBackup(mockBackup)).rejects.toThrow("400");
  });

  it("handles all-skipped result", async () => {
    const skippedResult: RestoreResult = {
      status: "restored",
      results: {
        waf_config: "restored",
        csp_config: "restored",
        exclusions: "skipped: no exclusions in backup",
        rate_limits: "skipped: no rules in backup",
        lists: "skipped: no lists in backup",
      },
    };
    vi.stubGlobal("fetch", mockFetchResponse(skippedResult));
    const result = await restoreBackup(mockBackup);
    expect(result.status).toBe("restored");
    expect(result.results.exclusions).toContain("skipped");
    expect(result.results.rate_limits).toContain("skipped");
    expect(result.results.lists).toContain("skipped");
  });
});

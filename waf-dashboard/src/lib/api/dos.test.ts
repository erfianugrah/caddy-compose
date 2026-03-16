import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  fetchDosStatus,
  fetchJail,
  addJail,
  removeJail,
  getDosConfig,
  updateDosConfig,
} from "./dos";
import type { DosStatus, JailEntry, DosConfig } from "./dos";

// ─── Mock fetch ─────────────────────────────────────────────────────

const mockFetch = vi.fn();
beforeEach(() => {
  vi.stubGlobal("fetch", mockFetch);
});
afterEach(() => {
  vi.restoreAllMocks();
});

function mockResponse(data: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? "OK" : "Error",
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  };
}

// ─── Tests ──────────────────────────────────────────────────────────

describe("fetchDosStatus", () => {
  it("returns status from /api/dos/status", async () => {
    const status: DosStatus = {
      mode: "normal",
      eps: 2.5,
      peak_eps: 0,
      jail_count: 3,
      kernel_drop: false,
      strategy: "full",
    };
    mockFetch.mockResolvedValueOnce(mockResponse(status));

    const result = await fetchDosStatus();
    expect(result.mode).toBe("normal");
    expect(result.eps).toBe(2.5);
    expect(result.jail_count).toBe(3);
    expect(mockFetch).toHaveBeenCalledWith("/api/dos/status", undefined);
  });
});

describe("fetchJail", () => {
  it("returns jail entries from /api/dos/jail", async () => {
    const entries: JailEntry[] = [
      {
        ip: "192.0.2.1",
        expires_at: "2026-03-16T12:00:00Z",
        infractions: 3,
        reason: "auto:z-score",
        jailed_at: "2026-03-16T11:00:00Z",
        ttl: "59m30s",
      },
    ];
    mockFetch.mockResolvedValueOnce(mockResponse(entries));

    const result = await fetchJail();
    expect(result).toHaveLength(1);
    expect(result[0].ip).toBe("192.0.2.1");
    expect(result[0].reason).toBe("auto:z-score");
  });
});

describe("addJail", () => {
  it("posts to /api/dos/jail", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse({ status: "jailed" }));

    await addJail("198.51.100.1", "1h", "manual");

    expect(mockFetch).toHaveBeenCalledWith("/api/dos/jail", expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ ip: "198.51.100.1", ttl: "1h", reason: "manual" }),
    }));
  });
});

describe("removeJail", () => {
  it("deletes from /api/dos/jail/{ip}", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse({ status: "unjailed" }));

    await removeJail("198.51.100.1");

    expect(mockFetch).toHaveBeenCalledWith(
      "/api/dos/jail/198.51.100.1",
      expect.objectContaining({ method: "DELETE" }),
    );
  });

  it("encodes IPv6 addresses", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse({ status: "unjailed" }));

    await removeJail("2001:db8::1");

    expect(mockFetch).toHaveBeenCalledWith(
      "/api/dos/jail/2001%3Adb8%3A%3A1",
      expect.objectContaining({ method: "DELETE" }),
    );
  });
});

describe("getDosConfig", () => {
  it("returns config from /api/dos/config", async () => {
    const config: DosConfig = {
      enabled: true,
      threshold: 4.0,
      base_penalty: "60s",
      max_penalty: "24h",
      eps_trigger: 50,
      eps_cooldown: 10,
      cooldown_delay: "30s",
      max_buckets: 10000,
      max_reports: 100,
      whitelist: ["10.0.0.0/8"],
      kernel_drop: false,
      strategy: "auto",
    };
    mockFetch.mockResolvedValueOnce(mockResponse(config));

    const result = await getDosConfig();
    expect(result.threshold).toBe(4.0);
    expect(result.whitelist).toEqual(["10.0.0.0/8"]);
  });
});

describe("updateDosConfig", () => {
  it("puts config to /api/dos/config", async () => {
    const config: DosConfig = {
      enabled: true,
      threshold: 3.5,
      base_penalty: "90s",
      max_penalty: "12h",
      eps_trigger: 75,
      eps_cooldown: 15,
      cooldown_delay: "45s",
      max_buckets: 5000,
      max_reports: 50,
      whitelist: ["10.0.0.0/8"],
      kernel_drop: false,
      strategy: "full",
    };
    mockFetch.mockResolvedValueOnce(mockResponse(config));

    const result = await updateDosConfig(config);
    expect(result.threshold).toBe(3.5);
    expect(mockFetch).toHaveBeenCalledWith("/api/dos/config", expect.objectContaining({
      method: "PUT",
      body: JSON.stringify(config),
    }));
  });
});

describe("error handling", () => {
  it("throws on non-200 response", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse("not found", 404));
    await expect(fetchDosStatus()).rejects.toThrow("API error: 404");
  });
});

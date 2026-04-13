import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  fetchDosStatus,
  fetchJail,
  addJail,
  removeJail,
  getDosConfig,
  updateDosConfig,
  fetchProfiles,
} from "./dos";
import type { DosStatus, JailEntry, DosConfig, IPProfile } from "./dos";

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
  it("returns status from /api/dos/status with new fields", async () => {
    const status: DosStatus = {
      mode: "normal",
      eps: 2.5,
      peak_eps: 0,
      jail_count: 3,
      kernel_drop: false,
      strategy: "full",
      eps_history: [],
      ddos_events: 0,
      updated_at: "2026-03-16T12:00:00Z",
      rate_jail_count: 1,
      behav_jail_count: 2,
    };
    mockFetch.mockResolvedValueOnce(mockResponse(status));

    const result = await fetchDosStatus();
    expect(result.mode).toBe("normal");
    expect(result.eps).toBe(2.5);
    expect(result.jail_count).toBe(3);
    expect(result.rate_jail_count).toBe(1);
    expect(result.behav_jail_count).toBe(2);
    expect(mockFetch).toHaveBeenCalledWith("/api/dos/status", undefined);
  });
});

describe("fetchJail", () => {
  it("returns jail entries with new anomaly_score and host_count fields", async () => {
    const entries: JailEntry[] = [
      {
        ip: "192.0.2.1",
        expires_at: "2026-03-16T12:00:00Z",
        infractions: 3,
        reason: "auto:behavioral",
        jailed_at: "2026-03-16T11:00:00Z",
        ttl: "59m30s",
        anomaly_score: 0.87,
        host_count: 1,
      },
    ];
    mockFetch.mockResolvedValueOnce(mockResponse(entries));

    const result = await fetchJail();
    expect(result).toHaveLength(1);
    expect(result[0].ip).toBe("192.0.2.1");
    expect(result[0].reason).toBe("auto:behavioral");
    expect(result[0].anomaly_score).toBe(0.87);
    expect(result[0].host_count).toBe(1);
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
  it("returns config with new v0.17.0 fields", async () => {
    const config: DosConfig = {
      enabled: true,
      threshold: 0.65,
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
      global_rate_threshold: 50,
      min_host_exculpation: 2,
      profile_ttl: "10m",
    };
    mockFetch.mockResolvedValueOnce(mockResponse(config));

    const result = await getDosConfig();
    expect(result.threshold).toBe(0.65);
    expect(result.whitelist).toEqual(["10.0.0.0/8"]);
    expect(result.global_rate_threshold).toBe(50);
    expect(result.min_host_exculpation).toBe(2);
    expect(result.profile_ttl).toBe("10m");
  });
});

describe("updateDosConfig", () => {
  it("puts config with new fields to /api/dos/config", async () => {
    const config: DosConfig = {
      enabled: true,
      threshold: 0.65,
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
      global_rate_threshold: 100,
      min_host_exculpation: 3,
      profile_ttl: "5m",
    };
    mockFetch.mockResolvedValueOnce(mockResponse(config));

    const result = await updateDosConfig(config);
    expect(result.threshold).toBe(0.65);
    expect(result.global_rate_threshold).toBe(100);
    expect(mockFetch).toHaveBeenCalledWith("/api/dos/config", expect.objectContaining({
      method: "PUT",
      body: JSON.stringify(config),
    }));
  });
});

describe("fetchProfiles", () => {
  it("returns IP profiles from /api/dos/profiles", async () => {
    const profiles: IPProfile[] = [
      {
        ip: "89.0.95.223",
        is_jailed: false,
        infractions: 0,
        anomaly_score: 0.31,
        recent_events: 5,
        blocked_reqs: 3,
        jailed_reqs: 2,
        hosts: ["composer.erfi.io", "jellyfin.erfi.io", "waf.erfi.io"],
        top_paths: ["/api/v1/stacks", "/api/v1/sse/containers/abc/stats"],
      },
    ];
    mockFetch.mockResolvedValueOnce(mockResponse(profiles));

    const result = await fetchProfiles();
    expect(result).toHaveLength(1);
    expect(result[0].ip).toBe("89.0.95.223");
    expect(result[0].hosts).toHaveLength(3);
    expect(result[0].anomaly_score).toBe(0.31);
    expect(result[0].is_jailed).toBe(false);
    expect(mockFetch).toHaveBeenCalledWith("/api/dos/profiles", undefined);
  });

  it("returns empty array when no suspicious IPs", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse([]));
    const result = await fetchProfiles();
    expect(result).toHaveLength(0);
  });
});

describe("error handling", () => {
  it("throws on non-200 response", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse("not found", 404));
    await expect(fetchDosStatus()).rejects.toThrow("API error: 404");
  });
});

import { describe, it, expect, vi } from "vitest";
import {
  getBlocklistStats,
  checkBlocklistIP,
  refreshBlocklist,
  type BlocklistRefreshResult,
} from "@/lib/api";
import { mockFetchResponse, setupMockFetch } from "./__test-helpers";

setupMockFetch();

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

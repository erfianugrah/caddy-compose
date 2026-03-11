import { describe, it, expect, vi } from "vitest";
import {
  getSecurityHeaders,
  updateSecurityHeaders,
  listSecurityProfiles,
  deploySecurityHeaders,
  previewSecurityHeaders,
  type SecurityHeaderConfig,
  type SecurityProfile,
  type SecurityHeaderDeployResponse,
  type SecurityHeaderPreviewResponse,
} from "@/lib/api";
import { mockFetchResponse, setupMockFetch } from "./__test-helpers";

setupMockFetch();

// ─── getSecurityHeaders ─────────────────────────────────────────────

describe("getSecurityHeaders", () => {
  it("returns config with default profile", async () => {
    const mock: SecurityHeaderConfig = {
      enabled: true,
      profile: "default",
      headers: {
        "Strict-Transport-Security":
          "max-age=63072000; includeSubDomains; preload",
        "X-Content-Type-Options": "nosniff",
      },
      remove: ["Server", "X-Powered-By"],
    };
    vi.stubGlobal("fetch", mockFetchResponse(mock));

    const result = await getSecurityHeaders();
    expect(result.profile).toBe("default");
    expect(result.enabled).toBe(true);
    expect(result.headers?.["X-Content-Type-Options"]).toBe("nosniff");
    expect(result.remove).toContain("Server");
  });

  it("returns config with services", async () => {
    const mock: SecurityHeaderConfig = {
      profile: "default",
      services: {
        httpbun: {
          profile: "relaxed",
          headers: { "X-Frame-Options": "ALLOW-FROM https://example.com" },
        },
      },
    };
    vi.stubGlobal("fetch", mockFetchResponse(mock));

    const result = await getSecurityHeaders();
    expect(result.services?.httpbun?.profile).toBe("relaxed");
  });

  it("throws on HTTP error", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
        text: () => Promise.resolve("server error"),
      }),
    );
    await expect(getSecurityHeaders()).rejects.toThrow("API error: 500");
  });
});

// ─── updateSecurityHeaders ──────────────────────────────────────────

describe("updateSecurityHeaders", () => {
  it("sends PUT and returns updated config", async () => {
    const updated: SecurityHeaderConfig = {
      enabled: true,
      profile: "strict",
      headers: {
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
      },
      remove: ["Server"],
    };
    const mockFetch = mockFetchResponse(updated);
    vi.stubGlobal("fetch", mockFetch);

    const result = await updateSecurityHeaders(updated);
    expect(result.profile).toBe("strict");
    expect(result.headers?.["X-Frame-Options"]).toBe("DENY");

    // Verify PUT method
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining("/security-headers"),
      expect.objectContaining({ method: "PUT" }),
    );
  });

  it("handles disabled config", async () => {
    const cfg: SecurityHeaderConfig = {
      enabled: false,
      profile: "custom",
    };
    vi.stubGlobal("fetch", mockFetchResponse(cfg));

    const result = await updateSecurityHeaders(cfg);
    expect(result.enabled).toBe(false);
  });
});

// ─── listSecurityProfiles ───────────────────────────────────────────

describe("listSecurityProfiles", () => {
  it("returns list of profiles", async () => {
    const profiles: SecurityProfile[] = [
      {
        name: "strict",
        description: "Maximum security",
        headers: { "X-Frame-Options": "DENY" },
        remove: ["Server", "X-Powered-By"],
      },
      {
        name: "default",
        description: "Balanced security",
        headers: { "X-Frame-Options": "SAMEORIGIN" },
        remove: ["Server", "X-Powered-By"],
      },
      {
        name: "relaxed",
        description: "Relaxed security",
        headers: { "X-Frame-Options": "SAMEORIGIN" },
        remove: ["Server"],
      },
      {
        name: "api",
        description: "Minimal headers for APIs",
        headers: {},
        remove: ["Server"],
      },
    ];
    vi.stubGlobal("fetch", mockFetchResponse(profiles));

    const result = await listSecurityProfiles();
    expect(result).toHaveLength(4);
    expect(result[0].name).toBe("strict");
    expect(result[1].name).toBe("default");
  });
});

// ─── deploySecurityHeaders ──────────────────────────────────────────

describe("deploySecurityHeaders", () => {
  it("returns deploy result", async () => {
    const resp: SecurityHeaderDeployResponse = {
      status: "deployed",
      message: "Security headers config deployed and Caddy reloaded",
      reloaded: true,
      timestamp: "2026-03-11T10:00:00Z",
    };
    vi.stubGlobal("fetch", mockFetchResponse(resp));

    const result = await deploySecurityHeaders();
    expect(result.status).toBe("deployed");
    expect(result.reloaded).toBe(true);
  });

  it("handles deploy with reload failure", async () => {
    const resp: SecurityHeaderDeployResponse = {
      status: "partial",
      message: "Config written but Caddy reload failed",
      reloaded: false,
      timestamp: "2026-03-11T10:00:00Z",
    };
    vi.stubGlobal("fetch", mockFetchResponse(resp));

    const result = await deploySecurityHeaders();
    expect(result.status).toBe("partial");
    expect(result.reloaded).toBe(false);
  });

  it("throws on HTTP error", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
        text: () => Promise.resolve("deploy error"),
      }),
    );
    await expect(deploySecurityHeaders()).rejects.toThrow("API error: 500");
  });
});

// ─── previewSecurityHeaders ─────────────────────────────────────────

describe("previewSecurityHeaders", () => {
  it("returns global + per-service resolved headers", async () => {
    const resp: SecurityHeaderPreviewResponse = {
      global: {
        headers: {
          "Strict-Transport-Security":
            "max-age=63072000; includeSubDomains; preload",
          "X-Content-Type-Options": "nosniff",
          "X-Frame-Options": "SAMEORIGIN",
        },
        remove: ["Server", "X-Powered-By"],
      },
      services: {
        httpbun: {
          headers: {
            "Strict-Transport-Security":
              "max-age=63072000; includeSubDomains; preload",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
          },
          remove: ["Server", "X-Powered-By"],
        },
      },
    };
    vi.stubGlobal("fetch", mockFetchResponse(resp));

    const result = await previewSecurityHeaders();
    expect(result.global.headers["X-Frame-Options"]).toBe("SAMEORIGIN");
    expect(result.global.remove).toContain("Server");
    expect(result.services.httpbun.headers["X-Frame-Options"]).toBe("DENY");
  });

  it("returns empty services when none configured", async () => {
    const resp: SecurityHeaderPreviewResponse = {
      global: {
        headers: { "X-Content-Type-Options": "nosniff" },
        remove: [],
      },
      services: {},
    };
    vi.stubGlobal("fetch", mockFetchResponse(resp));

    const result = await previewSecurityHeaders();
    expect(Object.keys(result.services)).toHaveLength(0);
  });
});

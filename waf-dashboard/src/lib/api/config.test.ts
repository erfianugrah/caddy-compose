import { describe, it, expect, vi } from "vitest";
import { mockFetchResponse, setupMockFetch } from "./__test-helpers";

setupMockFetch();

// ─── getConfig / updateConfig ───────────────────────────────────────

describe("getConfig", () => {
  it("returns WAFConfig with defaults and per-service settings", async () => {
    const apiResponse = {
      defaults: {
        paranoia_level: 2,
        inbound_threshold: 10,
        outbound_threshold: 5,
      },
      services: {
        "app.example.test": { paranoia_level: 1, inbound_threshold: 5, outbound_threshold: 4 },
        "api.example.test": { paranoia_level: 1, inbound_threshold: 5, outbound_threshold: 4 },
      },
    };

    vi.stubGlobal("fetch", mockFetchResponse(apiResponse));

    const { getConfig } = await import("@/lib/api");
    const result = await getConfig();

    expect(result.defaults.paranoia_level).toBe(2);
    expect(result.defaults.inbound_threshold).toBe(10);
    expect(result.defaults.outbound_threshold).toBe(5);
    expect(Object.keys(result.services)).toHaveLength(2);
    expect(result.services["app.example.test"].paranoia_level).toBe(1);
    expect(result.services["api.example.test"].paranoia_level).toBe(1);
  });

  it("handles null/empty services gracefully", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchResponse({
        defaults: { paranoia_level: 1, inbound_threshold: 5, outbound_threshold: 4 },
        services: null,
      })
    );

    const { getConfig } = await import("@/lib/api");
    const result = await getConfig();
    expect(result.services).toEqual({});
  });

  it("uses fallback defaults when defaults are missing", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchResponse({ services: {} })
    );

    const { getConfig } = await import("@/lib/api");
    const result = await getConfig();
    expect(result.defaults.paranoia_level).toBe(1);
    expect(result.defaults.inbound_threshold).toBe(5);
    expect(result.defaults.outbound_threshold).toBe(4);
  });
});

describe("updateConfig", () => {
  it("sends WAFConfig directly and returns result", async () => {
    const updatedConfig = {
      defaults: {
        paranoia_level: 3,
        inbound_threshold: 10,
        outbound_threshold: 8,
      },
      services: {
        "app.example.test": { paranoia_level: 1, inbound_threshold: 5, outbound_threshold: 4 },
      },
    };

    vi.stubGlobal("fetch", mockFetchResponse(updatedConfig));

    const { updateConfig } = await import("@/lib/api");
    const result = await updateConfig(updatedConfig as any);

    expect(result.defaults.paranoia_level).toBe(3);
    expect(Object.keys(result.services)).toHaveLength(1);

    // Verify the PUT payload is sent directly (no field mapping)
    const putCall = vi.mocked(fetch).mock.calls[0];
    const putBody = JSON.parse(putCall[1]?.body as string);
    expect(putBody.defaults.inbound_threshold).toBe(10);
    expect(putBody.services["app.example.test"].paranoia_level).toBe(1);
  });
});

// ─── CRS v4 Extended Settings ───────────────────────────────────────

describe("getConfig with CRS v4 extended settings", () => {
  it("returns CRS v4 extended fields when present", async () => {
    const apiResponse = {
      defaults: {
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

    const { getConfig } = await import("@/lib/api");
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
        paranoia_level: 1,
        inbound_threshold: 5,
        outbound_threshold: 4,
      },
      services: {},
    };

    vi.stubGlobal("fetch", mockFetchResponse(apiResponse));

    const { getConfig } = await import("@/lib/api");
    const result = await getConfig();

    expect(result.defaults.blocking_paranoia_level).toBeUndefined();
    expect(result.defaults.crs_exclusions).toBeUndefined();
    expect(result.defaults.early_blocking).toBeUndefined();
    expect(result.defaults.max_num_args).toBeUndefined();
  });

  it("sends CRS v4 fields in updateConfig payload", async () => {
    const config = {
      defaults: {
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

    const { updateConfig } = await import("@/lib/api");
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
    const { presetToSettings, settingsToPreset } = await import("@/lib/api");

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
    const { settingsToPreset } = await import("@/lib/api");

    // Even with extended fields, if core trio matches strict, it's strict
    const settings = {
      paranoia_level: 1,
      inbound_threshold: 5,
      outbound_threshold: 4,
      blocking_paranoia_level: 1,
      crs_exclusions: ["wordpress"],
    };
    expect(settingsToPreset(settings)).toBe("strict");
  });
});

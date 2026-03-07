import { describe, it, expect, vi } from "vitest";
import {
  fetchSummary,
  fetchEvents,
  fetchServices,
} from "@/lib/api";
import { mockFetchResponse, setupMockFetch } from "./__test-helpers";

setupMockFetch();

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

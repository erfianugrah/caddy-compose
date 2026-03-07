import { vi, beforeEach, afterEach } from "vitest";

/**
 * Creates a mock fetch that resolves with the given body and status.
 */
export function mockFetchResponse(body: unknown, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? "OK" : "Error",
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  });
}

/**
 * Standard beforeEach/afterEach setup for API test files.
 * Call this at the top level of your test file.
 */
export function setupMockFetch() {
  beforeEach(() => {
    vi.stubGlobal("fetch", mockFetchResponse({}));
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });
}

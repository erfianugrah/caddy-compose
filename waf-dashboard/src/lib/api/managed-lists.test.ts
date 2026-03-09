import { describe, it, expect, vi } from "vitest";
import {
  fetchManagedLists,
  getManagedList,
  createManagedList,
  updateManagedList,
  deleteManagedList,
  refreshManagedList,
  exportManagedLists,
  importManagedLists,
  compatibleKinds,
  type ManagedList,
  type ManagedListExport,
} from "@/lib/api";
import { mockFetchResponse, setupMockFetch } from "./__test-helpers";

setupMockFetch();

// ─── Managed Lists API Tests ────────────────────────────────────────

const mockList: ManagedList = {
  id: "abc-123",
  name: "bad-ips",
  description: "Known bad IPs",
  kind: "ip",
  source: "manual",
  items: ["10.0.0.1", "10.0.0.2"],
  item_count: 2,
  created_at: "2026-03-01T00:00:00Z",
  updated_at: "2026-03-01T00:00:00Z",
};

describe("fetchManagedLists", () => {
  it("returns array of lists", async () => {
    vi.stubGlobal("fetch", mockFetchResponse([mockList]));
    const result = await fetchManagedLists();
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe("bad-ips");
    expect(result[0].kind).toBe("ip");
  });

  it("returns empty array when no lists", async () => {
    vi.stubGlobal("fetch", mockFetchResponse([]));
    const result = await fetchManagedLists();
    expect(result).toHaveLength(0);
  });
});

describe("getManagedList", () => {
  it("returns a single list by ID", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockList));
    const result = await getManagedList("abc-123");
    expect(result.id).toBe("abc-123");
    expect(result.items).toEqual(["10.0.0.1", "10.0.0.2"]);
  });

  it("throws on 404", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: "Not Found",
        text: () => Promise.resolve('{"error":"list not found"}'),
      })
    );
    await expect(getManagedList("nonexistent")).rejects.toThrow("404");
  });
});

describe("createManagedList", () => {
  it("creates and returns a new list", async () => {
    vi.stubGlobal("fetch", mockFetchResponse(mockList, 201));
    const result = await createManagedList({
      name: "bad-ips",
      kind: "ip",
      source: "manual",
      items: ["10.0.0.1", "10.0.0.2"],
    });
    expect(result.name).toBe("bad-ips");
    expect(result.item_count).toBe(2);
  });
});

describe("updateManagedList", () => {
  it("updates and returns the list", async () => {
    const updated = { ...mockList, description: "Updated desc" };
    vi.stubGlobal("fetch", mockFetchResponse(updated));
    const result = await updateManagedList("abc-123", { description: "Updated desc" });
    expect(result.description).toBe("Updated desc");
  });
});

describe("deleteManagedList", () => {
  it("calls delete endpoint", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        status: 204,
        statusText: "No Content",
        json: () => Promise.resolve(undefined),
        text: () => Promise.resolve(""),
      })
    );
    await expect(deleteManagedList("abc-123")).resolves.toBeUndefined();
  });
});

describe("refreshManagedList", () => {
  it("refreshes and returns updated list", async () => {
    const refreshed = { ...mockList, item_count: 5 };
    vi.stubGlobal("fetch", mockFetchResponse(refreshed));
    const result = await refreshManagedList("abc-123");
    expect(result.item_count).toBe(5);
  });
});

describe("exportManagedLists", () => {
  it("returns export envelope", async () => {
    const mockExport: ManagedListExport = {
      version: 1,
      exported_at: "2026-03-01T00:00:00Z",
      lists: [mockList],
    };
    vi.stubGlobal("fetch", mockFetchResponse(mockExport));
    const result = await exportManagedLists();
    expect(result.version).toBe(1);
    expect(result.lists).toHaveLength(1);
  });
});

describe("importManagedLists", () => {
  it("returns import count", async () => {
    vi.stubGlobal("fetch", mockFetchResponse({ imported: 3 }));
    const result = await importManagedLists({
      version: 1,
      exported_at: "2026-03-01T00:00:00Z",
      lists: [],
    });
    expect(result.imported).toBe(3);
  });
});

// ─── Field-Kind Compatibility ───────────────────────────────────────

describe("compatibleKinds", () => {
  it("ip field only accepts ip kind", () => {
    expect(compatibleKinds("ip")).toEqual(["ip"]);
  });

  it("country field only accepts string kind", () => {
    expect(compatibleKinds("country")).toEqual(["string"]);
  });

  it("host field accepts hostname and string", () => {
    expect(compatibleKinds("host")).toEqual(["hostname", "string"]);
  });

  it("other fields accept hostname, string, and asn", () => {
    expect(compatibleKinds("path")).toEqual(["hostname", "string", "asn"]);
    expect(compatibleKinds("user_agent")).toEqual(["hostname", "string", "asn"]);
    expect(compatibleKinds("method")).toEqual(["hostname", "string", "asn"]);
  });
});

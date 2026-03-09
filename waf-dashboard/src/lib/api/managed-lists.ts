import { API_BASE, fetchJSON, postJSON, putJSON, deleteJSON } from "./shared";

// ─── Managed Lists ──────────────────────────────────────────────────

export interface ManagedList {
  id: string;
  name: string;
  description?: string;
  kind: "ip" | "hostname" | "string" | "asn";
  source: "manual" | "url" | "ipsum";
  url?: string;
  items: string[];
  item_count: number;
  created_at: string;
  updated_at: string;
}

export interface ManagedListExport {
  version: number;
  exported_at: string;
  lists: ManagedList[];
}

export interface ManagedListCreate {
  name: string;
  description?: string;
  kind: ManagedList["kind"];
  source: ManagedList["source"];
  url?: string;
  items?: string[];
}

export interface ManagedListUpdate {
  name?: string;
  description?: string;
  items?: string[];
  url?: string;
}

// ─── Kind / Field Compatibility ─────────────────────────────────────

/** Maps condition fields to the list kinds they accept with in_list/not_in_list. */
const fieldKindCompatibility: Record<string, string[]> = {
  ip: ["ip"],
  country: ["string"],
  host: ["hostname", "string"],
};

const defaultCompatibleKinds = ["hostname", "string", "asn"];

/** Returns the list kinds compatible with a condition field. */
export function compatibleKinds(field: string): string[] {
  return fieldKindCompatibility[field] ?? defaultCompatibleKinds;
}

// ─── API Functions ──────────────────────────────────────────────────

export async function fetchManagedLists(): Promise<ManagedList[]> {
  return fetchJSON<ManagedList[]>(`${API_BASE}/lists`);
}

export async function getManagedList(id: string): Promise<ManagedList> {
  return fetchJSON<ManagedList>(`${API_BASE}/lists/${encodeURIComponent(id)}`);
}

export async function createManagedList(list: ManagedListCreate): Promise<ManagedList> {
  return postJSON<ManagedList>(`${API_BASE}/lists`, list);
}

export async function updateManagedList(id: string, updates: ManagedListUpdate): Promise<ManagedList> {
  return putJSON<ManagedList>(`${API_BASE}/lists/${encodeURIComponent(id)}`, updates);
}

export async function deleteManagedList(id: string): Promise<void> {
  return deleteJSON<void>(`${API_BASE}/lists/${encodeURIComponent(id)}`);
}

export async function refreshManagedList(id: string): Promise<ManagedList> {
  return postJSON<ManagedList>(`${API_BASE}/lists/${encodeURIComponent(id)}/refresh`, {});
}

export async function exportManagedLists(): Promise<ManagedListExport> {
  return fetchJSON<ManagedListExport>(`${API_BASE}/lists/export`);
}

export async function importManagedLists(data: ManagedListExport): Promise<{ imported: number }> {
  return postJSON<{ imported: number }>(`${API_BASE}/lists/import`, data);
}

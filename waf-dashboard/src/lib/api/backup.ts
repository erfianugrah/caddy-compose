import { API_BASE, fetchJSON, postJSON } from "./shared";
import type { WAFConfig } from "./config";
import type { CSPConfig } from "./csp";
import type { RateLimitRule, RateLimitGlobalConfig } from "./rate-limits";
import type { ManagedList } from "./managed-lists";

// ─── Backup / Restore ───────────────────────────────────────────────

// Exclusions in the backup use Go's internal type names (e.g. "remove_by_id")
// rather than the mapped frontend names. We keep them as opaque objects to
// avoid needing the type-mapping layer for round-trip fidelity.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type RawExclusion = Record<string, any>;

export interface RateLimitBackup {
  rules: RateLimitRule[];
  global: RateLimitGlobalConfig;
}

export interface FullBackup {
  version: number;
  exported_at: string;
  waf_config: WAFConfig;
  csp_config: CSPConfig;
  exclusions: RawExclusion[];
  rate_limits: RateLimitBackup;
  lists: ManagedList[];
}

export interface RestoreResult {
  status: "restored" | "partial";
  results: Record<string, string>;
}

// ─── API Functions ──────────────────────────────────────────────────

/** Download a unified backup of all configuration stores. */
export async function fetchBackup(): Promise<FullBackup> {
  return fetchJSON<FullBackup>(`${API_BASE}/backup`);
}

/**
 * Download backup as a file (triggers browser download).
 * Uses raw fetch to access the Content-Disposition header.
 */
export async function downloadBackup(): Promise<void> {
  const res = await fetch(`${API_BASE}/backup`);
  if (!res.ok) {
    const raw = await res.text().catch(() => "");
    throw new Error(`Backup failed: ${res.status} ${res.statusText}${raw ? ` — ${raw}` : ""}`);
  }
  const blob = await res.blob();
  const disposition = res.headers.get("Content-Disposition") ?? "";
  const match = disposition.match(/filename="?([^"]+)"?/);
  const filename = match?.[1] ?? `wafctl-backup-${new Date().toISOString().replace(/[:.]/g, "")}.json`;

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/** Restore all configuration stores from a unified backup. */
export async function restoreBackup(backup: FullBackup): Promise<RestoreResult> {
  return postJSON<RestoreResult>(`${API_BASE}/backup/restore`, backup);
}

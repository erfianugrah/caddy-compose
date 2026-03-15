import { API_BASE, fetchJSON, postJSON } from "./shared";
import type { Exclusion } from "./exclusions";

// ─── Rule Templates API ─────────────────────────────────────────────

export interface RuleTemplate {
  id: string;
  name: string;
  description: string;
  category: string; // "cache" | "security" | "cors" | "custom"
  rules: Exclusion[];
}

export interface ApplyTemplateResult {
  template: string;
  created: number;
  rules: Exclusion[];
}

/** List available rule templates. */
export async function listTemplates(): Promise<RuleTemplate[]> {
  return fetchJSON<RuleTemplate[]>(`${API_BASE}/rules/templates`);
}

/** Apply a template, creating all its rules. */
export async function applyTemplate(templateId: string): Promise<ApplyTemplateResult> {
  return postJSON<ApplyTemplateResult>(`${API_BASE}/rules/templates/${encodeURIComponent(templateId)}/apply`, {});
}

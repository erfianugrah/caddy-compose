import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// ─── Centralized Action-Type Color Map ───────────────────────────────
// Single source of truth for WAF event category colours used across all
// charts (timeline, donut, bar) and badges.  Chosen for maximum contrast
// on a dark background — every colour is perceptually distinct at a glance.
// Warm = hostile, cool = benign, neutral = informational.

export const ACTION_COLORS = {
  blocked:      "#ff006e", // neon pink   — WAF blocked (Coraza anomaly)
  rate_limited: "#f59e0b", // amber-500   — rate limited / blocklist
  policy_block: "#ef4444", // red-500     — policy engine blocks
  policy_allow: "#22c55e", // green-500   — policy engine allows (safe bypass)
  policy_skip:  "#a78bfa", // violet-400  — policy engine rule skips (tuning)
  logged:       "#38bdf8", // sky-400     — benign baseline (high volume, calm)
} as const;

// Human-readable labels for chart legends (keyed same as ACTION_COLORS)
export const ACTION_LABELS: Record<string, string> = {
  blocked:      "WAF Blocked",
  logged:       "Logged",
  rate_limited: "Rate Limited",
  policy_block: "Policy Block",
  policy_allow: "Policy Allow",
  policy_skip:  "Policy Skip",
};

// Tailwind badge classes per event type (border + text)
export const ACTION_BADGE_CLASSES: Record<string, string> = {
  blocked:       "border-pink-500/50 text-pink-400",
  rate_limited:  "border-amber-500/50 text-amber-400",
  policy_block:  "border-red-500/50 text-red-400",
  policy_allow:  "border-green-500/50 text-green-400",
  policy_skip:   "border-violet-400/50 text-violet-400",
  logged:        "border-sky-400/50 text-sky-400",
};

// Shared chart tooltip styling (dark theme)
export const CHART_TOOLTIP_STYLE = {
  contentStyle: {
    backgroundColor: "#0f1538",
    border: "1px solid #1e275c",
    borderRadius: "8px",
    fontSize: "12px",
    color: "#e0e6f0",
  },
  itemStyle: { color: "#e0e6f0" },
  labelStyle: { color: "#7a8baa" },
};

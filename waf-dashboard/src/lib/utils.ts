import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// ─── Centralized Action-Type Color Map ───────────────────────────────
// Single source of truth for WAF event category colours used across all
// charts (timeline, donut, bar) and badges.  Chosen for maximum contrast
// on a dark background: warm colours = threats, cool colours = benign/info.

export const ACTION_COLORS = {
  blocked:      "#ff006e", // neon pink  — WAF blocked
  logged:       "#00d4ff", // cyan       — benign baseline (high volume, calm)
  rate_limited: "#eab308", // yellow     — warning tier, distinct from orange
  ipsum:        "#a855f7", // purple     — IP reputation blocklist
  honeypot:     "#ff6b35", // orange     — trap hits, between yellow and red
  scanner:      "#ef4444", // red        — malicious scanner detections
  policy:       "#00ff41", // neon green — policy engine matches
} as const;

// Human-readable labels for chart legends (keyed same as ACTION_COLORS)
export const ACTION_LABELS: Record<string, string> = {
  blocked:      "WAF Blocked",
  logged:       "Logged",
  rate_limited: "Rate Limited",
  ipsum:        "IPsum",
  honeypot:     "Honeypot",
  scanner:      "Scanner",
  policy:       "Policy",
};

// Tailwind badge classes per event type (border + text)
export const ACTION_BADGE_CLASSES: Record<string, string> = {
  honeypot:      "border-orange-500/50 text-orange-400",
  scanner:       "border-red-500/50 text-red-400",
  ipsum_blocked: "border-purple-500/50 text-purple-400",
  rate_limited:  "border-yellow-500/50 text-yellow-400",
  policy_skip:   "border-emerald-500/50 text-emerald-400",
  policy_allow:  "border-emerald-500/50 text-emerald-400",
  policy_block:  "border-rose-500/50 text-rose-400",
  blocked:       "border-pink-500/50 text-pink-400",
  logged:        "border-cyan-500/50 text-cyan-400",
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

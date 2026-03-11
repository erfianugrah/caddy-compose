import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// ─── Centralized Action-Type Color Map ───────────────────────────────
// Lovelace palette — warm pastel-neon accents on dark charcoal.
// Warm = hostile, cool = benign, neutral = informational.

export const ACTION_COLORS = {
  blocked:      "#f37e96", // lv-red      — WAF blocked (Coraza anomaly)
  rate_limited: "#f1a171", // lv-peach    — rate limited / blocklist (warning)
  policy_block: "#ff4870", // lv-red-bright — policy engine blocks
  detect_block: "#f59e0b", // amber-500   — policy engine anomaly threshold blocks
  policy_allow: "#5adecd", // lv-green    — policy engine allows (safe bypass)
  policy_skip:  "#8796f4", // lv-blue     — policy engine rule skips (tuning)
  logged:       "#79e6f3", // lv-cyan     — benign baseline (high volume, calm)
} as const;

// Human-readable labels for chart legends (keyed same as ACTION_COLORS)
export const ACTION_LABELS: Record<string, string> = {
  blocked:      "WAF Blocked",
  logged:       "Logged",
  rate_limited: "Rate Limited",
  policy_block: "Policy Block",
  detect_block: "Detect Block",
  policy_allow: "Policy Allow",
  policy_skip:  "Policy Skip",
};

// Tailwind badge classes per event type — frosted-glass pattern
// bg-color/20 + text-color + border-color/30 for consistency
export const ACTION_BADGE_CLASSES: Record<string, string> = {
  blocked:       "bg-lv-red/20 border-lv-red/30 text-lv-red",
  rate_limited:  "bg-lv-peach/20 border-lv-peach/30 text-lv-peach",
  policy_block:  "bg-lv-red-bright/20 border-lv-red-bright/30 text-lv-red-bright",
  detect_block:  "bg-amber-500/20 border-amber-500/30 text-amber-400",
  policy_allow:  "bg-lv-green/20 border-lv-green/30 text-lv-green",
  policy_skip:   "bg-lv-blue/20 border-lv-blue/30 text-lv-blue",
  logged:        "bg-lv-cyan/20 border-lv-cyan/30 text-lv-cyan",
};

// Shared chart tooltip styling (Lovelace theme)
export const CHART_TOOLTIP_STYLE = {
  contentStyle: {
    backgroundColor: "#282a36",
    border: "1px solid #414457",
    borderRadius: "8px",
    fontSize: "12px",
    color: "#fcfcfc",
  },
  itemStyle: { color: "#fcfcfc" },
  labelStyle: { color: "#bdbdc1" },
};

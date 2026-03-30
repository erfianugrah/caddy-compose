import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// ─── Centralized Action-Type Color Map ───────────────────────────────
// Lovelace palette — warm pastel-neon accents on dark charcoal.
// Warm = hostile, cool = benign, neutral = informational.

export const ACTION_COLORS = {
  detect_block: "#f37e96", // lv-red      — CRS anomaly threshold exceeded
  rate_limited: "#f1a171", // lv-peach    — rate limited / blocklist (warning)
  policy_block: "#ff4870", // lv-red-bright — policy engine blocks
  policy_allow: "#5adecd", // lv-green    — policy engine allows (safe bypass)
  policy_skip:  "#8796f4", // lv-blue     — policy engine rule skips (tuning)
  ddos_blocked: "#c9a0dc", // lv-purple   — DDoS mitigator behavioral block
  ddos_jailed:         "#c9a0dc", // lv-purple   — DDoS mitigator auto-jail
  challenge_issued:    "#f0c674", // lv-yellow   — challenge interstitial served
  challenge_passed:    "#5adecd", // lv-green    — challenge solved successfully
  challenge_failed:    "#f37e96", // lv-red      — challenge failed (bot score too high)
  challenge_bypassed:  "#79e6f3", // lv-cyan     — valid cookie, challenge skipped
  logged:              "#79e6f3", // lv-cyan     — benign baseline (high volume, calm)
  total_blocked:       "#f37e96", // lv-red     — aggregate blocked (detect_block + policy_block + residual)
} as const;

// Human-readable labels for chart legends, filters, and badges.
// Single source of truth — every UI surface should derive from this map.
export const ACTION_LABELS: Record<string, string> = {
  detect_block:        "Detect Block",
  logged:              "Logged",
  rate_limited:        "Rate Limited",
  policy_block:        "Policy Block",
  policy_allow:        "Policy Allow",
  policy_skip:         "Policy Skip",
  challenge_issued:    "Challenge",
  challenge_passed:    "Challenge OK",
  challenge_failed:    "Challenge Fail",
  challenge_bypassed:  "Challenge Skip",
  ddos_blocked:        "DDoS Blocked",
  ddos_jailed:         "DDoS Jailed",
  total_blocked:       "Total Blocked",
};

// Tailwind badge classes per event type — frosted-glass pattern
// bg-color/20 + text-color + border-color/30 for consistency
export const ACTION_BADGE_CLASSES: Record<string, string> = {
  detect_block:        "bg-lv-red/20 border-lv-red/30 text-lv-red",
  rate_limited:        "bg-lv-peach/20 border-lv-peach/30 text-lv-peach",
  policy_block:        "bg-lv-red-bright/20 border-lv-red-bright/30 text-lv-red-bright",
  policy_allow:        "bg-lv-green/20 border-lv-green/30 text-lv-green",
  policy_skip:         "bg-lv-blue/20 border-lv-blue/30 text-lv-blue",
  challenge_issued:    "bg-lv-yellow/20 border-lv-yellow/30 text-lv-yellow",
  challenge_passed:    "bg-lv-green/20 border-lv-green/30 text-lv-green",
  challenge_failed:    "bg-lv-red/20 border-lv-red/30 text-lv-red",
  challenge_bypassed:  "bg-lv-cyan/20 border-lv-cyan/30 text-lv-cyan",
  ddos_blocked:        "bg-lv-purple/20 border-lv-purple/30 text-lv-purple",
  ddos_jailed:         "bg-lv-purple/20 border-lv-purple/30 text-lv-purple",
  logged:              "bg-lv-cyan/20 border-lv-cyan/30 text-lv-cyan",
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

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Info } from "lucide-react";

// ─── Stat Tooltip Helper ────────────────────────────────────────────

export function StatTip({ tip }: { tip: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Info className="ml-1 inline h-3 w-3 shrink-0 cursor-help text-muted-foreground/40 hover:text-muted-foreground" />
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs text-xs leading-relaxed">
        <p>{tip}</p>
      </TooltipContent>
    </Tooltip>
  );
}

// ─── Advisor Filter Constants ───────────────────────────────────────
// These differ from the RL rule WINDOW_OPTIONS in constants.ts — the
// advisor supports wider ranges (30 sec through 24 h) and uses shorter
// labels ("30 sec" vs "30 seconds").

export const ADVISOR_WINDOW_OPTIONS = [
  { value: "30s", label: "30 sec" },
  { value: "1m", label: "1 min" },
  { value: "2m", label: "2 min" },
  { value: "5m", label: "5 min" },
  { value: "10m", label: "10 min" },
  { value: "30m", label: "30 min" },
  { value: "1h", label: "1 hour" },
  { value: "6h", label: "6 hours" },
  { value: "24h", label: "24 hours" },
] as const;

const WINDOW_LABELS: Record<string, string> = Object.fromEntries(
  ADVISOR_WINDOW_OPTIONS.map((o) => [o.value, o.label])
);

/** Format a window value for display */
export function windowLabel(v: string): string {
  return WINDOW_LABELS[v] || v;
}

export const METHOD_OPTIONS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

export type AdvisorField = "service" | "method" | "path";

export const ADVISOR_FIELD_META: { field: AdvisorField; label: string; placeholder: string }[] = [
  { field: "service", label: "Service", placeholder: "Search services..." },
  { field: "method", label: "Method", placeholder: "Select method" },
  { field: "path", label: "Path", placeholder: "/api/..." },
];

import { Info } from "lucide-react";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

// ─── Tooltip Helper ─────────────────────────────────────────────────

export function FieldTip({ tip, rule }: { tip: string; rule?: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Info className="ml-1 inline h-3.5 w-3.5 shrink-0 cursor-help text-muted-foreground/50 hover:text-muted-foreground" />
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs text-xs leading-relaxed">
        <p>{tip}</p>
        {rule && <p className="mt-1 font-data text-xs text-muted-foreground">{rule}</p>}
      </TooltipContent>
    </Tooltip>
  );
}

// Dead settings removed: MODE_META, CRS_EXCLUSION_PROFILES
// Policy engine uses only paranoia_level + inbound_threshold

// ─── Constants ──────────────────────────────────────────────────────

export const PARANOIA_DESCRIPTIONS: Record<number, { label: string; desc: string }> = {
  1: {
    label: "Low (PL1)",
    desc: "Minimal false positives. Catches the most obvious attacks. Recommended starting point.",
  },
  2: {
    label: "Moderate (PL2)",
    desc: "More rules active, some false positives possible. Good for tuned sites.",
  },
  3: {
    label: "High (PL3)",
    desc: "Aggressive rules. Expect false positives. For security-sensitive applications.",
  },
  4: {
    label: "Ultra (PL4)",
    desc: "Maximum paranoia. Many false positives. Requires extensive tuning.",
  },
};

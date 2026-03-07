import { Info } from "lucide-react";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import type { WAFMode } from "@/lib/api";

// ─── Tooltip Helper ─────────────────────────────────────────────────

export function FieldTip({ tip, rule }: { tip: string; rule?: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Info className="ml-1 inline h-3.5 w-3.5 shrink-0 cursor-help text-muted-foreground/50 hover:text-muted-foreground" />
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs text-xs leading-relaxed">
        <p>{tip}</p>
        {rule && <p className="mt-1 font-mono text-xs text-muted-foreground">{rule}</p>}
      </TooltipContent>
    </Tooltip>
  );
}

// ─── CRS v4 Exclusion Profiles ──────────────────────────────────────

export const CRS_EXCLUSION_PROFILES: { value: string; label: string; desc: string }[] = [
  { value: "wordpress", label: "WordPress", desc: "Excludes common WP admin/editor false positives" },
  { value: "nextcloud", label: "Nextcloud", desc: "Excludes Nextcloud WebDAV and sync operations" },
  { value: "drupal", label: "Drupal", desc: "Excludes Drupal admin and module operations" },
  { value: "cpanel", label: "cPanel", desc: "Excludes cPanel/WHM control panel operations" },
  { value: "dokuwiki", label: "DokuWiki", desc: "Excludes DokuWiki editing operations" },
  { value: "phpbb", label: "phpBB", desc: "Excludes phpBB forum operations" },
  { value: "phpmyadmin", label: "phpMyAdmin", desc: "Excludes phpMyAdmin database operations" },
  { value: "xenforo", label: "XenForo", desc: "Excludes XenForo forum operations" },
];

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

export const MODE_META: Record<WAFMode, { label: string; desc: string; color: string; dot: string }> = {
  enabled: {
    label: "Enabled",
    desc: "WAF actively blocks malicious requests",
    color: "text-neon-green border-neon-green/30 bg-neon-green/5",
    dot: "bg-neon-green",
  },
  detection_only: {
    label: "Detection Only",
    desc: "WAF logs but does not block requests",
    color: "text-neon-amber border-neon-amber/30 bg-neon-amber/5",
    dot: "bg-neon-amber",
  },
  disabled: {
    label: "Disabled",
    desc: "WAF engine is completely disabled",
    color: "text-neon-pink border-neon-pink/30 bg-neon-pink/5",
    dot: "bg-neon-pink",
  },
};

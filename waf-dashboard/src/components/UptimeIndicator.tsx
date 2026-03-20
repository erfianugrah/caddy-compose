import { useState, useEffect, useCallback } from "react";
import { Clock, ArrowUpCircle } from "lucide-react";
import { fetchHealth, type HealthData } from "@/lib/api/health";
import { formatUptime } from "@/lib/format";
import { T } from "@/lib/typography";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

/**
 * Compact uptime + version indicator for the dashboard header.
 * Polls /api/health every 60s and on each manual refresh.
 */
export function UptimeIndicator({ refreshKey }: { refreshKey?: number }) {
  const [health, setHealth] = useState<HealthData | null>(null);

  const load = useCallback(() => {
    fetchHealth().then(setHealth).catch(() => {});
  }, []);

  // Initial load + poll every 60s
  useEffect(() => {
    load();
    const id = setInterval(load, 60_000);
    return () => clearInterval(id);
  }, [load]);

  // Re-fetch when parent triggers a refresh
  useEffect(() => {
    if (refreshKey) load();
  }, [refreshKey, load]);

  if (!health) return null;

  return (
    <TooltipProvider delayDuration={200}>
      <Tooltip>
        <TooltipTrigger asChild>
          <div className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-1.5">
            <ArrowUpCircle className="h-3.5 w-3.5 text-lv-green" />
            <div className="flex items-center gap-1.5">
              <span className={`${T.statLabelUpper} leading-none`}>Up</span>
              <span className="text-sm font-bold tabular-nums font-data text-lv-green leading-none">
                {formatUptime(health.uptime)}
              </span>
            </div>
            <span className="text-[10px] text-muted-foreground font-data leading-none">
              v{health.version}
            </span>
          </div>
        </TooltipTrigger>
        <TooltipContent side="bottom" className="text-xs">
          <div className="space-y-1">
            <div>Uptime: {health.uptime}</div>
            <div>Version: {health.version}</div>
            <div>CRS: {health.crs_version}</div>
          </div>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

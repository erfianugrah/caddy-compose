import { useState } from "react";
import { ChevronDown, ChevronRight, ShieldMinus, ExternalLink } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import type { WAFServiceSettings, ServiceDetail } from "@/lib/api";
import { SensitivitySettings } from "./SettingsFormSections";

// ─── Per-Service Card ───────────────────────────────────────────────

export function ServiceSettingsCard({
  hostname,
  settings,
  serviceDetail,
  onChange,
  onRemove,
}: {
  hostname: string;
  settings: WAFServiceSettings;
  categories?: unknown; // kept for call-site compat, unused
  serviceDetail?: ServiceDetail;
  onChange: (s: WAFServiceSettings) => void;
  onRemove: () => void;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <Card className="overflow-hidden">
      <div
        className="flex cursor-pointer items-center gap-3 px-4 py-3 hover:bg-lovelace-900/50"
        onClick={() => setExpanded(!expanded)}
      >
        {expanded ? (
          <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
        ) : (
          <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
        )}
        <div className="min-w-0 flex-1">
          <span className="text-sm font-medium truncate block">{hostname}</span>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {serviceDetail && (
            <>
              <span className="text-xs tabular-nums text-muted-foreground">
                {serviceDetail.total_events.toLocaleString()} events
              </span>
              <div className="flex items-center gap-1">
                <div className="h-1.5 w-10 overflow-hidden rounded-full bg-lovelace-800">
                  <div
                    className={`h-full rounded-full ${
                      serviceDetail.block_rate > 50
                        ? "bg-lv-red"
                        : serviceDetail.block_rate > 20
                          ? "bg-lv-peach"
                          : "bg-lv-green"
                    }`}
                    style={{ width: `${Math.min(serviceDetail.block_rate, 100)}%` }}
                  />
                </div>
                <span className="text-xs tabular-nums text-muted-foreground">
                  {serviceDetail.block_rate.toFixed(0)}%
                </span>
              </div>
            </>
          )}
          <Badge variant="outline" className="text-xs">
            PL{settings.paranoia_level}
          </Badge>
        </div>
      </div>

      {expanded && (
        <CardContent className="space-y-5 border-t border-border pt-4">
          <SensitivitySettings settings={settings} onChange={onChange} compact />

          <Separator />

          {/* Skip Rules shortcut — manage per-service CRS rule exceptions */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldMinus className="h-3.5 w-3.5 text-lv-cyan" />
                <span className="text-xs font-medium">Rule Exceptions</span>
              </div>
              <a
                href={`/policy`}
                className="inline-flex items-center gap-1 text-xs text-lv-cyan hover:underline"
              >
                Manage on Policy page
                <ExternalLink className="h-3 w-3" />
              </a>
            </div>
            <p className="text-xs text-muted-foreground">
              To disable specific CRS rules for {hostname}, create a <strong>Skip</strong> rule
              on the Policy page with a <code className="text-[10px] bg-muted/50 px-1 rounded">host equals {hostname}</code> condition
              and the rule IDs to skip.
            </p>
          </div>

          <div className="flex justify-end">
            <Button variant="ghost" size="sm" onClick={onRemove} className="text-lv-red text-xs">
              Remove Override
            </Button>
          </div>
        </CardContent>
      )}
    </Card>
  );
}

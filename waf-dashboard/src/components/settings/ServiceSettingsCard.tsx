import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import type { WAFServiceSettings, CRSCategory, ServiceDetail } from "@/lib/api";
import { T } from "@/lib/typography";
import { MODE_META } from "./constants";
import { ModeSelector, SensitivitySettings, RuleGroupToggles } from "./SettingsFormSections";
import {
  AdvancedParanoiaSettings,
  RequestPolicySettings,
  LimitsSettings,
  AdvancedCRSControls,
  CRSExclusionProfiles,
} from "./AdvancedSettings";

// ─── Per-Service Card ───────────────────────────────────────────────

export function ServiceSettingsCard({
  hostname,
  settings,
  categories,
  serviceDetail,
  onChange,
  onRemove,
}: {
  hostname: string;
  settings: WAFServiceSettings;
  categories: CRSCategory[];
  serviceDetail?: ServiceDetail;
  onChange: (s: WAFServiceSettings) => void;
  onRemove: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const modeMeta = MODE_META[settings.mode];

  return (
    <Card className="overflow-hidden">
      <div
        className="flex cursor-pointer items-center gap-3 px-4 py-3 hover:bg-navy-900/50"
        onClick={() => setExpanded(!expanded)}
      >
        {expanded ? (
          <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
        ) : (
          <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
        )}
        <div className={`h-2 w-2 rounded-full shrink-0 ${modeMeta.dot}`} />
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
                <div className="h-1.5 w-10 overflow-hidden rounded-full bg-navy-800">
                  <div
                    className={`h-full rounded-full ${
                      serviceDetail.block_rate > 50
                        ? "bg-neon-pink"
                        : serviceDetail.block_rate > 20
                          ? "bg-neon-amber"
                          : "bg-neon-green"
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
            {modeMeta.label}
          </Badge>
        </div>
      </div>

      {expanded && (
        <CardContent className="space-y-5 border-t border-border pt-4">
          {/* Mode */}
          <div className="space-y-2">
            <Label className={T.formLabel}>Mode</Label>
            <ModeSelector
              value={settings.mode}
              onChange={(mode) => onChange({ ...settings, mode })}
            />
          </div>

          {settings.mode !== "disabled" && (
            <>
              <Separator />
              <SensitivitySettings settings={settings} onChange={onChange} compact />
              <Separator />
              <RuleGroupToggles
                categories={categories}
                disabledGroups={settings.disabled_groups ?? []}
                onChange={(groups) => onChange({ ...settings, disabled_groups: groups })}
              />
              <Separator />
              <CRSExclusionProfiles
                exclusions={settings.crs_exclusions ?? []}
                onChange={(excl) => onChange({ ...settings, crs_exclusions: excl.length > 0 ? excl : undefined })}
              />
              <Separator />
              <AdvancedParanoiaSettings settings={settings} onChange={onChange} />
              <Separator />
              <RequestPolicySettings settings={settings} onChange={onChange} />
              <Separator />
              <LimitsSettings settings={settings} onChange={onChange} />
              <Separator />
              <AdvancedCRSControls settings={settings} onChange={onChange} />
            </>
          )}

          <div className="flex justify-end">
            <Button variant="ghost" size="sm" onClick={onRemove} className="text-neon-pink text-xs">
              Remove Override
            </Button>
          </div>
        </CardContent>
      )}
    </Card>
  );
}

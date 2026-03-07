import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Textarea } from "@/components/ui/textarea";
import { T } from "@/lib/typography";
import type { CSPPolicy } from "@/lib/api";
import { CSP_DIRECTIVES, type DirectiveKey } from "./constants";
import { CSPSourceInput } from "./CSPSourceInput";

export function DirectiveEditor({
  policy,
  onChange,
  compact,
}: {
  policy: CSPPolicy;
  onChange: (policy: CSPPolicy) => void;
  compact?: boolean;
}) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const getValues = (key: DirectiveKey): string[] => {
    return (policy[key] as string[] | undefined) ?? [];
  };

  const setValues = (key: DirectiveKey, values: string[]) => {
    onChange({ ...policy, [key]: values.length > 0 ? values : undefined });
  };

  // Show all directives that have values, plus allow expanding empty ones
  const activeDirectives = CSP_DIRECTIVES.filter((d) => (getValues(d.key).length > 0));
  const inactiveDirectives = CSP_DIRECTIVES.filter((d) => (getValues(d.key).length === 0));

  return (
    <div className="space-y-3">
      {/* Active directives (have values) */}
      {activeDirectives.map((d) => (
        <div key={d.key} className="space-y-1">
          <div className="flex items-center justify-between">
            <Tooltip>
              <TooltipTrigger asChild>
                <Label className={`${T.formLabel} cursor-help border-b border-dotted border-muted-foreground/40`}>{d.label}</Label>
              </TooltipTrigger>
              <TooltipContent side="top" className="max-w-sm text-xs">{d.tip}</TooltipContent>
            </Tooltip>
            {!compact && (
              <span className={T.muted}>{d.desc}</span>
            )}
          </div>
          <CSPSourceInput
            values={getValues(d.key)}
            onChange={(v) => setValues(d.key, v)}
            placeholder={`Add ${d.label} sources...`}
          />
        </div>
      ))}

      {/* Collapsed inactive directives */}
      {inactiveDirectives.length > 0 && (
        <div className="space-y-2">
          <button
            type="button"
            onClick={() => {
              if (expanded.has("_inactive")) {
                setExpanded((prev) => { const n = new Set(prev); n.delete("_inactive"); return n; });
              } else {
                setExpanded((prev) => new Set(prev).add("_inactive"));
              }
            }}
            className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
          >
            {expanded.has("_inactive") ? (
              <ChevronDown className="h-3 w-3" />
            ) : (
              <ChevronRight className="h-3 w-3" />
            )}
            {inactiveDirectives.length} more directive{inactiveDirectives.length !== 1 ? "s" : ""}
          </button>
          {expanded.has("_inactive") && (
            <div className="space-y-3 pl-4 border-l border-border">
              {inactiveDirectives.map((d) => (
                <div key={d.key} className="space-y-1">
                  <div className="flex items-center justify-between">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Label className={`${T.formLabel} cursor-help border-b border-dotted border-muted-foreground/40`}>{d.label}</Label>
                      </TooltipTrigger>
                      <TooltipContent side="top" className="max-w-sm text-xs">{d.tip}</TooltipContent>
                    </Tooltip>
                    {!compact && (
                      <span className={T.muted}>{d.desc}</span>
                    )}
                  </div>
                  <CSPSourceInput
                    values={getValues(d.key)}
                    onChange={(v) => setValues(d.key, v)}
                    placeholder={`Add ${d.label} sources...`}
                  />
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Boolean directives + raw escape hatch */}
      <Separator />
      <div className="flex items-center justify-between">
        <div>
          <Label className={T.formLabel}>upgrade-insecure-requests</Label>
          {!compact && (
            <p className={T.muted}>Upgrade HTTP to HTTPS for sub-resources</p>
          )}
        </div>
        <Switch
          checked={policy.upgrade_insecure_requests ?? false}
          onCheckedChange={(checked) => onChange({ ...policy, upgrade_insecure_requests: checked })}
        />
      </div>

      <div className="space-y-1">
        <Label className={T.formLabel}>Raw Directives</Label>
        {!compact && (
          <p className={T.muted}>Appended verbatim (for exotic directives not listed above)</p>
        )}
        <Textarea
          value={policy.raw_directives ?? ""}
          onChange={(e) => onChange({ ...policy, raw_directives: e.target.value || undefined })}
          placeholder="e.g. report-uri /csp-report"
          className="text-xs font-mono h-16"
        />
      </div>
    </div>
  );
}

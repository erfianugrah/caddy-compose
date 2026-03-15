import { useState, useEffect, useCallback, useMemo } from "react";
import { ChevronDown, ChevronRight, ShieldMinus, Plus, X, Loader2, Rocket, Search, Check } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import type { WAFServiceSettings, ServiceDetail, Exclusion, DefaultRule } from "@/lib/api";
import { getExclusions, createExclusion, deleteExclusion, deployConfig, listDefaultRules, getCategoryShortName } from "@/lib/api";
import { SensitivitySettings } from "./SettingsFormSections";
import { CategoryToggles } from "./CategoryToggles";

// ─── Helpers ────────────────────────────────────────────────────────

function findSkipRulesForHost(exclusions: Exclusion[], hostname: string): Exclusion[] {
  return exclusions.filter((e) => {
    if (e.type !== "skip" || !e.enabled) return false;
    return e.conditions.some(
      (c) => c.field === "host" && c.operator === "eq" && c.value === hostname,
    );
  });
}

function collectSkippedRuleIds(skipRules: Exclusion[]): string[] {
  const ids: string[] = [];
  for (const rule of skipRules) {
    if (rule.skip_targets?.rules) {
      for (const id of rule.skip_targets.rules) {
        if (!ids.includes(id)) ids.push(id);
      }
    }
  }
  return ids.sort();
}

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
  serviceDetail?: ServiceDetail;
  onChange: (s: WAFServiceSettings) => void;
  onRemove: () => void;
}) {
  const [expanded, setExpanded] = useState(false);

  // Skip rules state
  const [skipRules, setSkipRules] = useState<Exclusion[]>([]);
  const [skippedIds, setSkippedIds] = useState<string[]>([]);
  const [loadingSkips, setLoadingSkips] = useState(false);
  const [saving, setSaving] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [dirty, setDirty] = useState(false);

  // CRS rules for the picker
  const [crsRules, setCrsRules] = useState<DefaultRule[]>([]);
  const [pickerOpen, setPickerOpen] = useState(false);
  const [pickerSearch, setPickerSearch] = useState("");

  const loadData = useCallback(async () => {
    setLoadingSkips(true);
    try {
      const [all, rules] = await Promise.all([getExclusions(), listDefaultRules()]);
      const hostSkips = findSkipRulesForHost(all, hostname);
      setSkipRules(hostSkips);
      setSkippedIds(collectSkippedRuleIds(hostSkips));
      setCrsRules(rules);
    } catch {
      // silent
    } finally {
      setLoadingSkips(false);
    }
  }, [hostname]);

  useEffect(() => {
    if (expanded) loadData();
  }, [expanded, loadData]);

  // Filtered CRS rules for picker
  const filteredCrsRules = useMemo(() => {
    if (!pickerSearch.trim()) return crsRules.slice(0, 50);
    const q = pickerSearch.toLowerCase();
    return crsRules
      .filter((r) =>
        r.id.includes(q) ||
        (r.description ?? "").toLowerCase().includes(q) ||
        (r.name ?? "").toLowerCase().includes(q) ||
        getCategoryShortName(r.id).toLowerCase().includes(q)
      )
      .slice(0, 50);
  }, [crsRules, pickerSearch]);

  const skippedSet = useMemo(() => new Set(skippedIds), [skippedIds]);

  const saveSkipRule = async (newIds: string[]) => {
    setSaving(true);
    try {
      // Delete existing skip rules for this host
      for (const rule of skipRules) {
        await deleteExclusion(rule.id);
      }
      // Create consolidated skip rule if any IDs remain
      if (newIds.length > 0) {
        await createExclusion({
          name: `Skip CRS rules for ${hostname}`,
          type: "skip",
          enabled: true,
          conditions: [{ field: "host", operator: "eq", value: hostname }],
          group_operator: "and",
          skip_targets: { rules: newIds, phases: ["detect"] },
        });
      }
      setDirty(true);
      await loadData();
    } catch (err) {
      console.error("Failed to update skip rules:", err);
    } finally {
      setSaving(false);
    }
  };

  const addRuleId = (id: string) => {
    if (skippedSet.has(id)) return;
    saveSkipRule([...skippedIds, id]);
  };

  const removeRuleId = (id: string) => {
    saveSkipRule(skippedIds.filter((x) => x !== id));
  };

  const handleDeploy = async () => {
    setDeploying(true);
    try {
      await deployConfig();
      setDirty(false);
    } catch (err) {
      console.error("Deploy failed:", err);
    } finally {
      setDeploying(false);
    }
  };

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
          {(settings.disabled_categories?.length ?? 0) > 0 && (
            <Badge variant="outline" className="text-xs text-lv-peach border-lv-peach/30">
              {settings.disabled_categories!.length} cat off
            </Badge>
          )}
          {skippedIds.length > 0 && (
            <Badge variant="outline" className="text-xs text-lv-cyan border-lv-cyan/30">
              {skippedIds.length} skipped
            </Badge>
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

          {/* Disabled CRS Categories */}
          <CategoryToggles
            disabled={settings.disabled_categories ?? []}
            onChange={(cats) => onChange({ ...settings, disabled_categories: cats.length > 0 ? cats : undefined })}
            compact
          />

          <Separator />

          {/* Disabled CRS Rules */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldMinus className="h-3.5 w-3.5 text-lv-cyan" />
                <Label className="text-xs font-medium">Disabled CRS Rules</Label>
                {loadingSkips && <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />}
              </div>

              {/* Add rule picker */}
              <Popover open={pickerOpen} onOpenChange={(o) => { setPickerOpen(o); if (!o) setPickerSearch(""); }}>
                <PopoverTrigger asChild>
                  <Button variant="outline" size="sm" className="h-7 text-xs gap-1" disabled={saving || crsRules.length === 0}>
                    <Plus className="h-3 w-3" />
                    Add Rule
                  </Button>
                </PopoverTrigger>
                <PopoverContent className="w-[340px] p-0" align="end" sideOffset={4}>
                  {/* Search */}
                  <div className="flex items-center border-b border-border px-3 py-2">
                    <Search className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                    <input
                      value={pickerSearch}
                      onChange={(e) => setPickerSearch(e.target.value)}
                      placeholder="Search by ID, name, or category..."
                      className="flex-1 ml-2 bg-transparent text-xs outline-none placeholder:text-muted-foreground/50"
                      autoFocus
                    />
                  </div>
                  {/* Rule list */}
                  <div className="max-h-[280px] overflow-y-auto py-1">
                    {filteredCrsRules.length === 0 ? (
                      <p className="px-3 py-4 text-xs text-muted-foreground text-center">No rules found</p>
                    ) : (
                      filteredCrsRules.map((rule) => {
                        const isSkipped = skippedSet.has(rule.id);
                        const cat = getCategoryShortName(rule.id);
                        return (
                          <button
                            key={rule.id}
                            onClick={() => { if (!isSkipped) addRuleId(rule.id); }}
                            disabled={saving}
                            className={`flex w-full items-start gap-2 px-3 py-1.5 text-left hover:bg-accent transition-colors ${
                              isSkipped ? "opacity-50" : ""
                            }`}
                          >
                            <div className="w-3.5 pt-0.5 shrink-0">
                              {isSkipped && <Check className="h-3.5 w-3.5 text-lv-cyan" />}
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2">
                                <span className="text-xs font-data font-medium">{rule.id}</span>
                                <span className="text-[10px] text-muted-foreground">{cat}</span>
                              </div>
                              {rule.description && (
                                <p className="text-[10px] text-muted-foreground truncate">{rule.description}</p>
                              )}
                            </div>
                          </button>
                        );
                      })
                    )}
                  </div>
                </PopoverContent>
              </Popover>
            </div>

            {/* Skipped rule ID pills */}
            {skippedIds.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {skippedIds.map((id) => {
                  const rule = crsRules.find((r) => r.id === id);
                  const cat = getCategoryShortName(id);
                  return (
                    <span
                      key={id}
                      className="inline-flex items-center gap-1 rounded-md bg-lv-cyan/10 border border-lv-cyan/20 px-2 py-0.5 text-xs font-data text-lv-cyan"
                      title={rule?.description ?? id}
                    >
                      {id}
                      <span className="text-[10px] text-lv-cyan/50">{cat}</span>
                      <button
                        onClick={() => removeRuleId(id)}
                        disabled={saving}
                        className="ml-0.5 rounded-full p-0.5 hover:bg-lv-red/20 hover:text-lv-red transition-colors disabled:opacity-50"
                      >
                        <X className="h-2.5 w-2.5" />
                      </button>
                    </span>
                  );
                })}
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">
                No CRS rules disabled. Click "Add Rule" to skip specific rules for this service.
              </p>
            )}

            {/* Deploy */}
            {dirty && (
              <Button
                size="sm"
                onClick={handleDeploy}
                disabled={deploying}
                className="w-full h-8 text-xs"
              >
                {deploying ? <Loader2 className="h-3 w-3 animate-spin" /> : <Rocket className="h-3 w-3" />}
                {deploying ? "Deploying..." : "Deploy Changes"}
              </Button>
            )}
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

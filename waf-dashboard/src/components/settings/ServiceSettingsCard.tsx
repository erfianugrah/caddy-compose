import { useState, useEffect, useCallback } from "react";
import { ChevronDown, ChevronRight, ShieldMinus, Plus, X, Loader2, Rocket } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import type { WAFServiceSettings, ServiceDetail, Exclusion } from "@/lib/api";
import { getExclusions, createExclusion, deleteExclusion, deployConfig } from "@/lib/api";
import { SensitivitySettings } from "./SettingsFormSections";

// ─── Helpers ────────────────────────────────────────────────────────

/** Find skip exclusions that target a specific host via conditions. */
function findSkipRulesForHost(exclusions: Exclusion[], hostname: string): Exclusion[] {
  return exclusions.filter((e) => {
    if (e.type !== "skip" || !e.enabled) return false;
    return e.conditions.some(
      (c) => c.field === "host" && c.operator === "eq" && c.value === hostname,
    );
  });
}

/** Extract all skipped rule IDs from a set of skip exclusions. */
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
  categories?: unknown;
  serviceDetail?: ServiceDetail;
  onChange: (s: WAFServiceSettings) => void;
  onRemove: () => void;
}) {
  const [expanded, setExpanded] = useState(false);

  // Skip rules state
  const [skipRules, setSkipRules] = useState<Exclusion[]>([]);
  const [skippedIds, setSkippedIds] = useState<string[]>([]);
  const [loadingSkips, setLoadingSkips] = useState(false);
  const [newRuleId, setNewRuleId] = useState("");
  const [saving, setSaving] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [dirty, setDirty] = useState(false);

  const loadSkipRules = useCallback(async () => {
    setLoadingSkips(true);
    try {
      const all = await getExclusions();
      const hostSkips = findSkipRulesForHost(all, hostname);
      setSkipRules(hostSkips);
      setSkippedIds(collectSkippedRuleIds(hostSkips));
    } catch {
      // silent — non-critical
    } finally {
      setLoadingSkips(false);
    }
  }, [hostname]);

  useEffect(() => {
    if (expanded) loadSkipRules();
  }, [expanded, loadSkipRules]);

  const addRuleIds = async () => {
    const ids = newRuleId
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter((s) => /^\d+$/.test(s) && !skippedIds.includes(s));
    if (ids.length === 0) return;

    setSaving(true);
    try {
      // If there's already a skip rule for this host, update it by creating a new
      // consolidated one and deleting the old ones. Otherwise create a new one.
      const allIds = [...skippedIds, ...ids];

      // Delete existing skip rules for this host
      for (const rule of skipRules) {
        await deleteExclusion(rule.id);
      }

      // Create a single consolidated skip rule
      await createExclusion({
        name: `Skip CRS rules for ${hostname}`,
        type: "skip",
        enabled: true,
        conditions: [{ field: "host", operator: "eq", value: hostname }],
        group_operator: "and",
        skip_targets: { rules: allIds, phases: ["detect"] },
      });

      setNewRuleId("");
      setDirty(true);
      await loadSkipRules();
    } catch (err) {
      console.error("Failed to add skip rules:", err);
    } finally {
      setSaving(false);
    }
  };

  const removeRuleId = async (idToRemove: string) => {
    setSaving(true);
    try {
      const remaining = skippedIds.filter((id) => id !== idToRemove);

      // Delete existing skip rules for this host
      for (const rule of skipRules) {
        await deleteExclusion(rule.id);
      }

      // Recreate with remaining IDs (if any)
      if (remaining.length > 0) {
        await createExclusion({
          name: `Skip CRS rules for ${hostname}`,
          type: "skip",
          enabled: true,
          conditions: [{ field: "host", operator: "eq", value: hostname }],
          group_operator: "and",
          skip_targets: { rules: remaining, phases: ["detect"] },
        });
      }

      setDirty(true);
      await loadSkipRules();
    } catch (err) {
      console.error("Failed to remove skip rule:", err);
    } finally {
      setSaving(false);
    }
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

          {/* Inline Skip Rule Management */}
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <ShieldMinus className="h-3.5 w-3.5 text-lv-cyan" />
              <Label className="text-xs font-medium">Disabled CRS Rules</Label>
              {loadingSkips && <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />}
            </div>

            {/* Skipped rule ID pills */}
            {skippedIds.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {skippedIds.map((id) => (
                  <span
                    key={id}
                    className="inline-flex items-center gap-1 rounded-md bg-lv-cyan/10 border border-lv-cyan/20 px-2 py-0.5 text-xs font-data text-lv-cyan"
                  >
                    {id}
                    <button
                      onClick={() => removeRuleId(id)}
                      disabled={saving}
                      className="ml-0.5 rounded-full p-0.5 hover:bg-lv-red/20 hover:text-lv-red transition-colors disabled:opacity-50"
                    >
                      <X className="h-2.5 w-2.5" />
                    </button>
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">
                No CRS rules disabled for this service. Add rule IDs below to skip specific rules.
              </p>
            )}

            {/* Add rule IDs input */}
            <div className="flex items-center gap-2">
              <Input
                value={newRuleId}
                onChange={(e) => setNewRuleId(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") addRuleIds(); }}
                placeholder="Rule IDs (e.g. 932236 942120)"
                className="flex-1 h-8 text-xs font-data"
                disabled={saving}
              />
              <Button
                variant="outline"
                size="sm"
                onClick={addRuleIds}
                disabled={saving || !newRuleId.trim()}
                className="h-8 text-xs"
              >
                {saving ? <Loader2 className="h-3 w-3 animate-spin" /> : <Plus className="h-3 w-3" />}
                Add
              </Button>
            </div>

            {/* Deploy button when dirty */}
            {dirty && (
              <Button
                size="sm"
                onClick={handleDeploy}
                disabled={deploying}
                className="w-full h-8 text-xs"
              >
                {deploying ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <Rocket className="h-3 w-3" />
                )}
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

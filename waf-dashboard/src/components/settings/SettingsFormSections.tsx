import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import {
  type WAFMode,
  type WAFPreset,
  type WAFServiceSettings,
  type CRSCategory,
  presetToSettings,
  settingsToPreset,
} from "@/lib/api";
import { T } from "@/lib/typography";
import { MODE_META, PARANOIA_DESCRIPTIONS } from "./constants";

// ─── Mode Selector ──────────────────────────────────────────────────

export function ModeSelector({
  value,
  onChange,
}: {
  value: WAFMode;
  onChange: (mode: WAFMode) => void;
}) {
  return (
    <div className="grid gap-3 sm:grid-cols-3">
      {(Object.keys(MODE_META) as WAFMode[]).map((mode) => {
        const meta = MODE_META[mode];
        return (
          <button
            key={mode}
            onClick={() => onChange(mode)}
            className={`rounded-lg border p-4 text-left transition-all ${
              value === mode
                ? meta.color
                : "border-border bg-lovelace-950 text-muted-foreground hover:border-border/80"
            }`}
          >
            <div className="flex items-center gap-2">
              <div
                className={`h-2.5 w-2.5 rounded-full ${
                  value === mode ? meta.dot : "bg-muted-foreground/30"
                }`}
              />
              <span className="text-sm font-medium">{meta.label}</span>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">{meta.desc}</p>
          </button>
        );
      })}
    </div>
  );
}

// ─── Sensitivity Settings (Preset + Paranoia + Thresholds) ──────────

export function SensitivitySettings({
  settings,
  onChange,
  compact,
}: {
  settings: WAFServiceSettings;
  onChange: (s: WAFServiceSettings) => void;
  compact?: boolean;
}) {
  const preset = settingsToPreset(settings);
  const isCustom = preset === "custom";

  const handlePresetChange = (p: WAFPreset) => {
    if (p === "custom") return;
    const vals = presetToSettings(p);
    onChange({ ...settings, ...vals });
  };

  return (
    <div className="space-y-4">
      {/* Preset Selector */}
      <div className="space-y-2">
        <Label className={T.formLabel}>
          Sensitivity Preset
        </Label>
        <div className={`grid gap-2 ${compact ? "grid-cols-2" : "grid-cols-4"}`}>
          {(["strict", "moderate", "tuning", "custom"] as WAFPreset[]).map((p) => (
            <button
              key={p}
              onClick={() => handlePresetChange(p)}
              disabled={p === "custom"}
              className={`rounded-md border px-3 py-2 text-xs font-medium transition-all ${
                preset === p
                  ? p === "strict"
                    ? "border-lv-green/40 bg-lv-green/10 text-lv-green"
                    : p === "moderate"
                      ? "border-lv-cyan/40 bg-lv-cyan/10 text-lv-cyan"
                      : p === "tuning"
                        ? "border-lv-peach/40 bg-lv-peach/10 text-lv-peach"
                        : "border-neon-purple/40 bg-neon-purple/10 text-neon-purple"
                  : p === "custom"
                    ? "border-border bg-lovelace-950 text-muted-foreground/40 cursor-default"
                    : "border-border bg-lovelace-950 text-muted-foreground hover:border-border/80"
              }`}
            >
              {p === "strict" ? "Strict (5/4)" : p === "moderate" ? "Moderate (15/15)" : p === "tuning" ? "Tuning (log only)" : "Custom"}
            </button>
          ))}
        </div>
      </div>

      {/* Paranoia Level */}
      <div className="space-y-2">
        <Label className={T.formLabel}>
          Paranoia Level
        </Label>
        <div className="flex items-center gap-4">
          <div className="flex-1">
            <Slider
              value={[settings.paranoia_level]}
              onValueChange={(v) =>
                onChange({ ...settings, paranoia_level: v[0] })
              }
              min={1}
              max={4}
              step={1}
            />
            <div className="mt-1 flex justify-between text-xs text-muted-foreground">
              <span>1</span><span>2</span><span>3</span><span>4</span>
            </div>
          </div>
          <span className="w-8 text-center text-lg font-bold text-lv-green">
            {settings.paranoia_level}
          </span>
        </div>
        <p className="text-xs text-muted-foreground">
          {PARANOIA_DESCRIPTIONS[settings.paranoia_level]?.desc}
        </p>
      </div>

      {/* Thresholds */}
      {settings.mode !== "detection_only" && (
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1">
            <Label className={T.formLabel}>
              Inbound Threshold
            </Label>
            <Input
              type="number"
              min={1}
              value={settings.inbound_threshold}
              onChange={(e) =>
                onChange({ ...settings, inbound_threshold: Number(e.target.value) || 1 })
              }
              className="w-24"
            />
          </div>
          <div className="space-y-1">
            <Label className={T.formLabel}>
              Outbound Threshold
            </Label>
            <Input
              type="number"
              min={1}
              value={settings.outbound_threshold}
              onChange={(e) =>
                onChange({ ...settings, outbound_threshold: Number(e.target.value) || 1 })
              }
              className="w-24"
            />
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Rule Group Toggles ─────────────────────────────────────────────

export function RuleGroupToggles({
  categories,
  disabledGroups,
  onChange,
}: {
  categories: CRSCategory[];
  disabledGroups: string[];
  onChange: (groups: string[]) => void;
}) {
  const disabledSet = new Set(disabledGroups);

  const toggle = (tag: string) => {
    const next = new Set(disabledSet);
    if (next.has(tag)) {
      next.delete(tag);
    } else {
      next.add(tag);
    }
    onChange([...next]);
  };

  // Deduplicate categories by tag (protocol-enforcement and protocol-attack share "attack-protocol").
  const seen = new Set<string>();
  const unique = categories.filter((c) => {
    if (seen.has(c.tag)) return false;
    seen.add(c.tag);
    return true;
  });

  return (
    <div className="space-y-2">
      <Label className={T.formLabel}>
        CRS Rule Groups
      </Label>
      <div className="grid gap-2 sm:grid-cols-2">
        {unique.map((cat) => {
          const isEnabled = !disabledSet.has(cat.tag);
          return (
            <div
              key={cat.tag}
              className="flex items-center justify-between rounded-md border border-border bg-lovelace-950 px-3 py-2"
            >
              <div className="min-w-0">
                <p className="text-xs font-medium truncate">{cat.name}</p>
                <p className="text-xs text-muted-foreground truncate">{cat.tag}</p>
              </div>
              <Switch
                checked={isEnabled}
                onCheckedChange={() => toggle(cat.tag)}
                className="ml-2 shrink-0"
              />
            </div>
          );
        })}
      </div>
    </div>
  );
}

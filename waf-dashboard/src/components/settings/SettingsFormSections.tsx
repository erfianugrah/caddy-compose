import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Slider } from "@/components/ui/slider";
import {
  type WAFPreset,
  type WAFServiceSettings,
  presetToSettings,
  settingsToPreset,
} from "@/lib/api";
import { T } from "@/lib/typography";
import { PARANOIA_DESCRIPTIONS } from "./constants";

// Dead settings removed: ModeSelector, RuleGroupToggles
// Policy engine uses only paranoia_level + inbound_threshold from WAFServiceSettings

// ─── Sensitivity Settings (Preset + Paranoia + Threshold) ───────────

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

      {/* Inbound Anomaly Threshold */}
      <div className="space-y-1">
        <Label className={T.formLabel}>
          Inbound Anomaly Threshold
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
        <p className="text-xs text-muted-foreground">
          Cumulative CRS anomaly score required to trigger an inbound detect rule block.
        </p>
      </div>

      {/* Outbound Anomaly Threshold */}
      <div className="space-y-1">
        <Label className={T.formLabel}>
          Outbound Anomaly Threshold
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
        <p className="text-xs text-muted-foreground">
          Cumulative score for response-phase rules (data leakage, error disclosure). Set high to log only.
        </p>
      </div>
    </div>
  );
}

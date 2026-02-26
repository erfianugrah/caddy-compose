import { useState, useEffect, useCallback, useRef } from "react";
import {
  Shield,
  AlertTriangle,
  Check,
  Save,
  Download,
  Upload,
  Info,
  ChevronDown,
  ChevronRight,
  Rocket,
  Globe,
  Settings2,
  Loader2,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Slider } from "@/components/ui/slider";
import { Separator } from "@/components/ui/separator";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  getConfig,
  updateConfig,
  fetchServices,
  fetchCRSRules,
  deployConfig,
  type WAFConfig,
  type WAFMode,
  type WAFServiceSettings,
  type WAFPreset,
  type ServiceDetail,
  type CRSCategory,
  presetToSettings,
  settingsToPreset,
} from "@/lib/api";

// ─── CRS v4 Exclusion Profiles ──────────────────────────────────────

const CRS_EXCLUSION_PROFILES: { value: string; label: string; desc: string }[] = [
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

const PARANOIA_DESCRIPTIONS: Record<number, { label: string; desc: string }> = {
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

const MODE_META: Record<WAFMode, { label: string; desc: string; color: string; dot: string }> = {
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

// ─── Mode Selector ──────────────────────────────────────────────────

function ModeSelector({
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
                : "border-border bg-navy-950 text-muted-foreground hover:border-border/80"
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

function SensitivitySettings({
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
        <Label className="text-xs uppercase tracking-wider text-muted-foreground">
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
                    ? "border-neon-green/40 bg-neon-green/10 text-neon-green"
                    : p === "moderate"
                      ? "border-neon-cyan/40 bg-neon-cyan/10 text-neon-cyan"
                      : p === "tuning"
                        ? "border-neon-amber/40 bg-neon-amber/10 text-neon-amber"
                        : "border-neon-purple/40 bg-neon-purple/10 text-neon-purple"
                  : p === "custom"
                    ? "border-border bg-navy-950 text-muted-foreground/40 cursor-default"
                    : "border-border bg-navy-950 text-muted-foreground hover:border-border/80"
              }`}
            >
              {p === "strict" ? "Strict (5/4)" : p === "moderate" ? "Moderate (15/15)" : p === "tuning" ? "Tuning (log only)" : "Custom"}
            </button>
          ))}
        </div>
      </div>

      {/* Paranoia Level */}
      <div className="space-y-2">
        <Label className="text-xs uppercase tracking-wider text-muted-foreground">
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
          <span className="w-8 text-center text-lg font-bold text-neon-green">
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
            <Label className="text-xs uppercase tracking-wider text-muted-foreground">
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
            <Label className="text-xs uppercase tracking-wider text-muted-foreground">
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

function RuleGroupToggles({
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
      <Label className="text-xs uppercase tracking-wider text-muted-foreground">
        CRS Rule Groups
      </Label>
      <div className="grid gap-2 sm:grid-cols-2">
        {unique.map((cat) => {
          const isEnabled = !disabledSet.has(cat.tag);
          return (
            <div
              key={cat.tag}
              className="flex items-center justify-between rounded-md border border-border bg-navy-950 px-3 py-2"
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

// ─── Advanced Paranoia (BPL / DPL Split) ────────────────────────────

function AdvancedParanoiaSettings({
  settings,
  onChange,
}: {
  settings: WAFServiceSettings;
  onChange: (s: WAFServiceSettings) => void;
}) {
  const bpl = settings.blocking_paranoia_level || settings.paranoia_level;
  const dpl = settings.detection_paranoia_level || settings.paranoia_level;
  const isSplit = bpl !== settings.paranoia_level || dpl !== settings.paranoia_level;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <Label className="text-xs uppercase tracking-wider text-muted-foreground">
          Blocking / Detection PL Split
        </Label>
        <Switch
          checked={isSplit}
          onCheckedChange={(checked) => {
            if (checked) {
              onChange({
                ...settings,
                blocking_paranoia_level: settings.paranoia_level,
                detection_paranoia_level: settings.paranoia_level,
              });
            } else {
              onChange({
                ...settings,
                blocking_paranoia_level: undefined,
                detection_paranoia_level: undefined,
              });
            }
          }}
        />
      </div>
      <p className="text-xs text-muted-foreground">
        Detect at a higher PL but only block at a lower PL — CRS v4's primary tuning knob.
      </p>
      {isSplit && (
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1">
            <Label className="text-xs text-muted-foreground">Blocking PL</Label>
            <Select
              value={String(bpl)}
              onValueChange={(v) => onChange({ ...settings, blocking_paranoia_level: Number(v) })}
            >
              <SelectTrigger className="w-20"><SelectValue /></SelectTrigger>
              <SelectContent>
                {[1, 2, 3, 4].map((n) => (
                  <SelectItem key={n} value={String(n)}>{n}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label className="text-xs text-muted-foreground">Detection PL</Label>
            <Select
              value={String(dpl)}
              onValueChange={(v) => onChange({ ...settings, detection_paranoia_level: Number(v) })}
            >
              <SelectTrigger className="w-20"><SelectValue /></SelectTrigger>
              <SelectContent>
                {[1, 2, 3, 4].map((n) => (
                  <SelectItem key={n} value={String(n)}>{n}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Request Policy Settings ────────────────────────────────────────

function RequestPolicySettings({
  settings,
  onChange,
}: {
  settings: WAFServiceSettings;
  onChange: (s: WAFServiceSettings) => void;
}) {
  return (
    <div className="space-y-4">
      <Label className="text-xs uppercase tracking-wider text-muted-foreground">
        Request Policy
      </Label>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1">
          <Label className="text-xs text-muted-foreground">Allowed Methods</Label>
          <Input
            placeholder="GET HEAD POST OPTIONS"
            value={settings.allowed_methods ?? ""}
            onChange={(e) => onChange({ ...settings, allowed_methods: e.target.value || undefined })}
            className="font-mono text-xs"
          />
          <p className="text-xs text-muted-foreground/60">Rule 911100. Space-separated.</p>
        </div>
        <div className="space-y-1">
          <Label className="text-xs text-muted-foreground">Allowed HTTP Versions</Label>
          <Input
            placeholder="HTTP/1.0 HTTP/1.1 HTTP/2 HTTP/2.0"
            value={settings.allowed_http_versions ?? ""}
            onChange={(e) => onChange({ ...settings, allowed_http_versions: e.target.value || undefined })}
            className="font-mono text-xs"
          />
          <p className="text-xs text-muted-foreground/60">Rule 920230. Space-separated.</p>
        </div>
      </div>
      <div className="space-y-1">
        <Label className="text-xs text-muted-foreground">Allowed Content Types</Label>
        <Input
          placeholder="|application/x-www-form-urlencoded| |multipart/form-data| |application/json|"
          value={settings.allowed_request_content_type ?? ""}
          onChange={(e) => onChange({ ...settings, allowed_request_content_type: e.target.value || undefined })}
          className="font-mono text-xs"
        />
        <p className="text-xs text-muted-foreground/60">Rule 920420. Pipe-delimited format.</p>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1">
          <Label className="text-xs text-muted-foreground">Restricted Extensions</Label>
          <Input
            placeholder=".asa .asax .backup .bak ..."
            value={settings.restricted_extensions ?? ""}
            onChange={(e) => onChange({ ...settings, restricted_extensions: e.target.value || undefined })}
            className="font-mono text-xs"
          />
          <p className="text-xs text-muted-foreground/60">Rule 920440.</p>
        </div>
        <div className="space-y-1">
          <Label className="text-xs text-muted-foreground">Restricted Headers</Label>
          <Input
            placeholder="/accept-charset/ /proxy/ ..."
            value={settings.restricted_headers ?? ""}
            onChange={(e) => onChange({ ...settings, restricted_headers: e.target.value || undefined })}
            className="font-mono text-xs"
          />
          <p className="text-xs text-muted-foreground/60">Rule 920450. Slash-delimited.</p>
        </div>
      </div>
    </div>
  );
}

// ─── Argument & File Limits ─────────────────────────────────────────

function LimitsSettings({
  settings,
  onChange,
}: {
  settings: WAFServiceSettings;
  onChange: (s: WAFServiceSettings) => void;
}) {
  const numField = (
    label: string, field: keyof WAFServiceSettings, placeholder: string, rule: string
  ) => (
    <div className="space-y-1">
      <Label className="text-xs text-muted-foreground">{label}</Label>
      <Input
        type="number"
        min={0}
        placeholder={placeholder}
        value={(settings[field] as number) || ""}
        onChange={(e) => {
          const val = e.target.value === "" ? undefined : Number(e.target.value);
          onChange({ ...settings, [field]: val });
        }}
        className="w-28"
      />
      <p className="text-xs text-muted-foreground/60">{rule}</p>
    </div>
  );

  return (
    <div className="space-y-4">
      <Label className="text-xs uppercase tracking-wider text-muted-foreground">
        Argument & File Limits
      </Label>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {numField("Max Arguments", "max_num_args", "255", "Rule 920300")}
        {numField("Arg Name Length", "arg_name_length", "100", "Rule 920310")}
        {numField("Arg Value Length", "arg_length", "400", "Rule 920320")}
        {numField("Total Arg Length", "total_arg_length", "64000", "Rule 920330")}
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        {numField("Max File Size (bytes)", "max_file_size", "1048576", "Rule 920400")}
        {numField("Combined File Sizes", "combined_file_sizes", "1048576", "Rule 920410")}
      </div>
    </div>
  );
}

// ─── CRS Exclusion Profiles ─────────────────────────────────────────

function CRSExclusionProfiles({
  exclusions,
  onChange,
}: {
  exclusions: string[];
  onChange: (exclusions: string[]) => void;
}) {
  const activeSet = new Set(exclusions);

  const toggle = (name: string) => {
    const next = new Set(activeSet);
    if (next.has(name)) {
      next.delete(name);
    } else {
      next.add(name);
    }
    onChange([...next]);
  };

  return (
    <div className="space-y-2">
      <Label className="text-xs uppercase tracking-wider text-muted-foreground">
        CRS Exclusion Profiles
      </Label>
      <p className="text-xs text-muted-foreground">
        Built-in CRS v4 exclusion profiles reduce false positives for known applications.
      </p>
      <div className="grid gap-2 sm:grid-cols-2">
        {CRS_EXCLUSION_PROFILES.map((profile) => {
          const isActive = activeSet.has(profile.value);
          return (
            <div
              key={profile.value}
              className="flex items-center justify-between rounded-md border border-border bg-navy-950 px-3 py-2"
            >
              <div className="min-w-0">
                <p className="text-xs font-medium truncate">{profile.label}</p>
                <p className="text-xs text-muted-foreground truncate">{profile.desc}</p>
              </div>
              <Switch
                checked={isActive}
                onCheckedChange={() => toggle(profile.value)}
                className="ml-2 shrink-0"
              />
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Advanced CRS Controls ──────────────────────────────────────────

function AdvancedCRSControls({
  settings,
  onChange,
}: {
  settings: WAFServiceSettings;
  onChange: (s: WAFServiceSettings) => void;
}) {
  return (
    <div className="space-y-4">
      <Label className="text-xs uppercase tracking-wider text-muted-foreground">
        Advanced CRS Controls
      </Label>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="flex items-center justify-between rounded-md border border-border bg-navy-950 px-3 py-2.5">
          <div>
            <p className="text-xs font-medium">Early Blocking</p>
            <p className="text-xs text-muted-foreground">Block at phase 1/2 before full inspection</p>
          </div>
          <Switch
            checked={settings.early_blocking ?? false}
            onCheckedChange={(v) => onChange({ ...settings, early_blocking: v || undefined })}
          />
        </div>
        <div className="flex items-center justify-between rounded-md border border-border bg-navy-950 px-3 py-2.5">
          <div>
            <p className="text-xs font-medium">Enforce URL-Encoded Body</p>
            <p className="text-xs text-muted-foreground">Force body processor for url-encoded POSTs</p>
          </div>
          <Switch
            checked={settings.enforce_bodyproc_urlencoded ?? false}
            onCheckedChange={(v) => onChange({ ...settings, enforce_bodyproc_urlencoded: v || undefined })}
          />
        </div>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1">
          <Label className="text-xs text-muted-foreground">Sampling Percentage</Label>
          <Input
            type="number"
            min={1}
            max={100}
            placeholder="100"
            value={settings.sampling_percentage ?? ""}
            onChange={(e) => {
              const val = e.target.value === "" ? undefined : Number(e.target.value);
              onChange({ ...settings, sampling_percentage: val });
            }}
            className="w-24"
          />
          <p className="text-xs text-muted-foreground/60">% of requests to inspect (1-100)</p>
        </div>
        <div className="space-y-1">
          <Label className="text-xs text-muted-foreground">Reporting Level</Label>
          <Select
            value={settings.reporting_level ? String(settings.reporting_level) : ""}
            onValueChange={(v) => onChange({ ...settings, reporting_level: v ? Number(v) : undefined })}
          >
            <SelectTrigger className="w-24">
              <SelectValue placeholder="Auto" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="">Auto (= PL)</SelectItem>
              {[1, 2, 3, 4].map((n) => (
                <SelectItem key={n} value={String(n)}>PL {n}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <p className="text-xs text-muted-foreground/60">PL for audit reporting</p>
        </div>
      </div>
    </div>
  );
}

// ─── Per-Service Card ───────────────────────────────────────────────

function ServiceSettingsCard({
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
            <Label className="text-xs uppercase tracking-wider text-muted-foreground">Mode</Label>
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

// ─── Main Settings Panel ────────────────────────────────────────────

export default function SettingsPanel() {
  const [config, setConfig] = useState<WAFConfig | null>(null);
  const [services, setServices] = useState<ServiceDetail[]>([]);
  const [categories, setCategories] = useState<CRSCategory[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [deployStep, setDeployStep] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);

  // Working copy of the config.
  const [defaults, setDefaults] = useState<WAFServiceSettings>({
    mode: "enabled",
    paranoia_level: 1,
    inbound_threshold: 5,
    outbound_threshold: 4,
  });
  const [serviceOverrides, setServiceOverrides] = useState<Record<string, WAFServiceSettings>>({});

  const loadData = useCallback(() => {
    setLoading(true);
    setError(null);
    Promise.all([getConfig(), fetchServices(), fetchCRSRules()])
      .then(([cfg, svcs, crs]) => {
        setConfig(cfg);
        setDefaults(cfg.defaults);
        setServiceOverrides(cfg.services);
        setServices(svcs);
        setCategories(crs.categories);
        setDirty(false);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const successTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const showSuccess = (msg: string) => {
    if (successTimerRef.current) clearTimeout(successTimerRef.current);
    setSuccessMsg(msg);
    successTimerRef.current = setTimeout(() => setSuccessMsg(null), 4000);
  };
  useEffect(() => () => { if (successTimerRef.current) clearTimeout(successTimerRef.current); }, []);

  const markDirty = () => setDirty(true);

  const buildConfig = (): WAFConfig => ({
    defaults,
    services: serviceOverrides,
  });

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    try {
      const updated = await updateConfig(buildConfig());
      setConfig(updated);
      setDefaults(updated.defaults);
      setServiceOverrides(updated.services);
      setDirty(false);
      showSuccess("Settings saved");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  const handleDeploy = async () => {
    setError(null);
    try {
      setDeployStep("Saving config...");
      await updateConfig(buildConfig());
      setDeployStep("Writing WAF files & reloading Caddy...");
      const result = await deployConfig();
      setDirty(false);
      if (result.reloaded) {
        showSuccess("Settings deployed and Caddy reloaded");
      } else {
        showSuccess("Config files written — Caddy reload may be needed");
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Deploy failed");
    } finally {
      setDeployStep(null);
    }
  };

  const handleDefaultsChange = (s: WAFServiceSettings) => {
    setDefaults(s);
    markDirty();
  };

  const handleServiceChange = (host: string, s: WAFServiceSettings) => {
    setServiceOverrides((prev) => ({ ...prev, [host]: s }));
    markDirty();
  };

  const handleServiceRemove = (host: string) => {
    setServiceOverrides((prev) => {
      const next = { ...prev };
      delete next[host];
      return next;
    });
    markDirty();
  };

  const handleAddServiceOverride = (host: string) => {
    if (serviceOverrides[host]) return;
    setServiceOverrides((prev) => ({
      ...prev,
      [host]: { ...defaults },
    }));
    markDirty();
  };

  const handleExport = () => {
    try {
      const data = buildConfig();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "waf-config.json";
      a.click();
      URL.revokeObjectURL(url);
      showSuccess("Configuration exported");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Export failed");
    }
  };

  const handleImport = () => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json";
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const data = JSON.parse(text) as WAFConfig;
        if (data.defaults) setDefaults(data.defaults);
        if (data.services) setServiceOverrides(data.services);
        setDirty(true);
        showSuccess("Configuration imported — save or deploy to apply");
      } catch (err: unknown) {
        setError("Failed to parse config: " + (err instanceof Error ? err.message : "unknown error"));
      }
    };
    input.click();
  };

  // Services that have overrides + services discovered from traffic.
  const allHosts = Array.from(
    new Set([
      ...Object.keys(serviceOverrides),
      ...services.map((s) => s.service),
    ])
  ).sort();
  const unconfiguredHosts = allHosts.filter((h) => !serviceOverrides[h]);

  if (loading) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className="text-lg font-semibold">Settings</h2>
          <p className="text-sm text-muted-foreground">Dynamic WAF configuration</p>
        </div>
        <div className="space-y-4">
          {[...Array(3)].map((_, i) => (
            <Card key={i}>
              <CardContent className="p-6">
                <Skeleton className="h-24 w-full" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-lg font-semibold">Settings</h2>
          <p className="text-sm text-muted-foreground">
            Configure WAF behavior per service. Changes take effect after deploy.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={handleExport}>
            <Download className="h-3.5 w-3.5" />
            Export
          </Button>
          <Button variant="outline" size="sm" onClick={handleImport}>
            <Upload className="h-3.5 w-3.5" />
            Import
          </Button>
          <Button size="sm" variant="outline" onClick={handleSave} disabled={!dirty || saving}>
            <Save className="h-3.5 w-3.5" />
            {saving ? "Saving..." : "Save"}
          </Button>
          <Button size="sm" onClick={handleDeploy} disabled={deployStep !== null}>
            {deployStep ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Rocket className="h-3.5 w-3.5" />
            )}
            {deployStep ?? "Save & Deploy"}
          </Button>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {successMsg && (
        <Alert variant="success">
          <Check className="h-4 w-4" />
          <AlertTitle>Success</AlertTitle>
          <AlertDescription>{successMsg}</AlertDescription>
        </Alert>
      )}
      {dirty && (
        <Alert>
          <Info className="h-4 w-4" />
          <AlertTitle>Unsaved Changes</AlertTitle>
          <AlertDescription>
            Click "Save & Deploy" to write config files and reload Caddy.
          </AlertDescription>
        </Alert>
      )}

      {/* ── Global Defaults ── */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Globe className="h-4 w-4 text-neon-cyan" />
            <CardTitle className="text-sm">Global Defaults</CardTitle>
          </div>
          <CardDescription>
            Applied to all services without explicit overrides
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          {/* Mode */}
          <ModeSelector
            value={defaults.mode}
            onChange={(mode) => handleDefaultsChange({ ...defaults, mode })}
          />

          {defaults.mode !== "disabled" && (
            <>
              <Separator />
              <SensitivitySettings settings={defaults} onChange={handleDefaultsChange} />
              <Separator />
              <RuleGroupToggles
                categories={categories}
                disabledGroups={defaults.disabled_groups ?? []}
                onChange={(groups) => handleDefaultsChange({ ...defaults, disabled_groups: groups })}
              />
              <Separator />
              <CRSExclusionProfiles
                exclusions={defaults.crs_exclusions ?? []}
                onChange={(excl) => handleDefaultsChange({ ...defaults, crs_exclusions: excl.length > 0 ? excl : undefined })}
              />
              <Separator />
              <AdvancedParanoiaSettings settings={defaults} onChange={handleDefaultsChange} />
              <Separator />
              <RequestPolicySettings settings={defaults} onChange={handleDefaultsChange} />
              <Separator />
              <LimitsSettings settings={defaults} onChange={handleDefaultsChange} />
              <Separator />
              <AdvancedCRSControls settings={defaults} onChange={handleDefaultsChange} />
            </>
          )}
        </CardContent>
      </Card>

      {/* ── Per-Service Overrides ── */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Settings2 className="h-4 w-4 text-neon-purple" />
            <h3 className="text-sm font-semibold">Per-Service Overrides</h3>
            <Badge variant="outline" className="text-xs">
              {Object.keys(serviceOverrides).length}
            </Badge>
          </div>
          {unconfiguredHosts.length > 0 && (
            <Select onValueChange={(v) => handleAddServiceOverride(v)}>
              <SelectTrigger className="w-[200px]">
                <SelectValue placeholder="Add service override..." />
              </SelectTrigger>
              <SelectContent>
                {unconfiguredHosts.map((host) => (
                  <SelectItem key={host} value={host}>
                    {host}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </div>

        {Object.keys(serviceOverrides).length === 0 && (
          <Card>
            <CardContent className="py-8 text-center text-xs text-muted-foreground">
              No per-service overrides configured. All services use the global defaults above.
              <br />
              Select a service from the dropdown to add an override.
            </CardContent>
          </Card>
        )}

        {Object.entries(serviceOverrides)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([host, settings]) => (
            <ServiceSettingsCard
              key={host}
              hostname={host}
              settings={settings}
              categories={categories}
              serviceDetail={services.find((s) => s.service === host)}
              onChange={(s) => handleServiceChange(host, s)}
              onRemove={() => handleServiceRemove(host)}
            />
          ))}
      </div>
    </div>
  );
}

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
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
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
import { T } from "@/lib/typography";

// ─── Tooltip Helper ─────────────────────────────────────────────────

function FieldTip({ tip, rule }: { tip: string; rule?: string }) {
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
      <Label className={T.formLabel}>
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
        <Label className={T.formLabel}>
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
            <Label className="inline-flex items-center text-xs text-muted-foreground">
              Blocking PL
              <FieldTip
                tip="Requests are blocked only when they match rules at this paranoia level or below. Set lower than Detection PL to log high-PL matches without blocking them."
                rule="tx.blocking_paranoia_level"
              />
            </Label>
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
            <Label className="inline-flex items-center text-xs text-muted-foreground">
              Detection PL
              <FieldTip
                tip="All rules up to this paranoia level are evaluated and logged. Set higher than Blocking PL to see what would trigger at stricter settings."
                rule="tx.detection_paranoia_level"
              />
            </Label>
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
      <Label className={T.formLabel}>
        Request Policy
      </Label>
      <p className="text-xs text-muted-foreground">
        Controls which HTTP methods, versions, content types, and file extensions the CRS considers valid. Requests that don't match are flagged.
      </p>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1">
          <Label className="inline-flex items-center text-xs text-muted-foreground">
            Allowed Methods
            <FieldTip
              tip="HTTP methods the CRS will accept. Requests using other methods (e.g., TRACE, DELETE) are flagged as anomalies. Space-separated list."
              rule="tx.allowed_methods — CRS Rule 911100"
            />
          </Label>
          <Input
            placeholder="GET HEAD POST OPTIONS"
            value={settings.allowed_methods ?? ""}
            onChange={(e) => onChange({ ...settings, allowed_methods: e.target.value || undefined })}
            className="font-mono text-xs"
          />
        </div>
        <div className="space-y-1">
          <Label className="inline-flex items-center text-xs text-muted-foreground">
            Allowed HTTP Versions
            <FieldTip
              tip="HTTP protocol versions the CRS will accept. Requests using other versions are flagged. Space-separated list."
              rule="tx.allowed_http_versions — CRS Rule 920230"
            />
          </Label>
          <Input
            placeholder="HTTP/1.0 HTTP/1.1 HTTP/2 HTTP/2.0"
            value={settings.allowed_http_versions ?? ""}
            onChange={(e) => onChange({ ...settings, allowed_http_versions: e.target.value || undefined })}
            className="font-mono text-xs"
          />
        </div>
      </div>
      <div className="space-y-1">
        <Label className="inline-flex items-center text-xs text-muted-foreground">
          Allowed Content Types
          <FieldTip
            tip="MIME types the CRS will accept in request bodies. Requests with other Content-Type headers are flagged. Each type must be wrapped in pipes: |type|."
            rule="tx.allowed_request_content_type — CRS Rule 920420"
          />
        </Label>
        <Input
          placeholder="|application/x-www-form-urlencoded| |multipart/form-data| |application/json|"
          value={settings.allowed_request_content_type ?? ""}
          onChange={(e) => onChange({ ...settings, allowed_request_content_type: e.target.value || undefined })}
          className="font-mono text-xs"
        />
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1">
          <Label className="inline-flex items-center text-xs text-muted-foreground">
            Restricted Extensions
            <FieldTip
              tip="File extensions that are blocked when found in the URL path. Used to prevent access to backup files, config files, etc. Space-separated list."
              rule="tx.restricted_extensions — CRS Rule 920440"
            />
          </Label>
          <Input
            placeholder=".asa .asax .backup .bak ..."
            value={settings.restricted_extensions ?? ""}
            onChange={(e) => onChange({ ...settings, restricted_extensions: e.target.value || undefined })}
            className="font-mono text-xs"
          />
        </div>
        <div className="space-y-1">
          <Label className="inline-flex items-center text-xs text-muted-foreground">
            Restricted Headers
            <FieldTip
              tip="HTTP request headers that should be flagged when present. Used to block headers that can be abused for cache poisoning or request smuggling. Slash-delimited: /header/."
              rule="tx.restricted_headers — CRS Rule 920450"
            />
          </Label>
          <Input
            placeholder="/accept-charset/ /proxy/ ..."
            value={settings.restricted_headers ?? ""}
            onChange={(e) => onChange({ ...settings, restricted_headers: e.target.value || undefined })}
            className="font-mono text-xs"
          />
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
  const LIMIT_FIELDS: {
    label: string; field: keyof WAFServiceSettings; placeholder: string; tip: string; rule: string;
  }[] = [
    { label: "Max Arguments", field: "max_num_args", placeholder: "255",
      tip: "Maximum number of query string or body arguments allowed per request. Requests exceeding this are flagged as potential parameter pollution.",
      rule: "tx.max_num_args — CRS Rule 920300" },
    { label: "Arg Name Length", field: "arg_name_length", placeholder: "100",
      tip: "Maximum length (characters) for any single argument name. Unusually long parameter names can indicate injection attempts.",
      rule: "tx.arg_name_length — CRS Rule 920310" },
    { label: "Arg Value Length", field: "arg_length", placeholder: "400",
      tip: "Maximum length (characters) for any single argument value. Helps detect buffer overflow and injection payloads in individual parameters.",
      rule: "tx.arg_length — CRS Rule 920320" },
    { label: "Total Arg Length", field: "total_arg_length", placeholder: "64000",
      tip: "Maximum combined length of all argument values. Limits the total payload size of query/body parameters.",
      rule: "tx.total_arg_length — CRS Rule 920330" },
  ];

  const FILE_FIELDS: typeof LIMIT_FIELDS = [
    { label: "Max File Size (bytes)", field: "max_file_size", placeholder: "1048576",
      tip: "Maximum size in bytes for any single uploaded file. Default is 1 MB. Set higher for services that accept large uploads.",
      rule: "tx.max_file_size — CRS Rule 920400" },
    { label: "Combined File Sizes", field: "combined_file_sizes", placeholder: "1048576",
      tip: "Maximum combined size in bytes for all uploaded files in a single request. Default is 1 MB.",
      rule: "tx.combined_file_sizes — CRS Rule 920410" },
  ];

  const numField = (f: typeof LIMIT_FIELDS[0]) => (
    <div key={f.field} className="space-y-1">
      <Label className="inline-flex items-center text-xs text-muted-foreground">
        {f.label}
        <FieldTip tip={f.tip} rule={f.rule} />
      </Label>
      <Input
        type="number"
        min={0}
        placeholder={f.placeholder}
        value={(settings[f.field] as number) || ""}
        onChange={(e) => {
          const val = e.target.value === "" ? undefined : Number(e.target.value);
          onChange({ ...settings, [f.field]: val });
        }}
        className="w-28"
      />
    </div>
  );

  return (
    <div className="space-y-4">
      <Label className={T.formLabel}>
        Argument & File Limits
      </Label>
      <p className="text-xs text-muted-foreground">
        Maximum sizes for request arguments and file uploads. Requests exceeding these limits are flagged. Leave blank to use CRS defaults.
      </p>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {LIMIT_FIELDS.map(numField)}
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        {FILE_FIELDS.map(numField)}
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
      <Label className={T.formLabel}>
        CRS Exclusion Profiles
      </Label>
      <p className="text-xs text-muted-foreground">
        Built-in CRS v4 exclusion profiles reduce false positives for known applications.
        Enable a profile to automatically skip rules that conflict with that application's normal behavior.
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
      <Label className={T.formLabel}>
        Advanced CRS Controls
      </Label>
      <p className="text-xs text-muted-foreground">
        Fine-grained CRS engine behavior. These are expert settings — defaults work well for most deployments.
      </p>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="flex items-center justify-between rounded-md border border-border bg-navy-950 px-3 py-2.5">
          <div>
            <p className="inline-flex items-center text-xs font-medium">
              Early Blocking
              <FieldTip
                tip="Block requests as soon as the anomaly score is reached, even before all rules have run (at phase 1 or 2). Reduces latency but may miss some rules. Off by default."
                rule="tx.early_blocking"
              />
            </p>
            <p className="text-xs text-muted-foreground">Block at phase 1/2 before full inspection</p>
          </div>
          <Switch
            checked={settings.early_blocking ?? false}
            onCheckedChange={(v) => onChange({ ...settings, early_blocking: v || undefined })}
          />
        </div>
        <div className="flex items-center justify-between rounded-md border border-border bg-navy-950 px-3 py-2.5">
          <div>
            <p className="inline-flex items-center text-xs font-medium">
              Enforce URL-Encoded Body
              <FieldTip
                tip="Force the URLENCODED body processor for POST requests with Content-Type: application/x-www-form-urlencoded. Prevents bypasses where attackers omit the Content-Type header."
                rule="tx.enforce_bodyproc_urlencoded"
              />
            </p>
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
          <Label className="inline-flex items-center text-xs text-muted-foreground">
            Sampling Percentage
            <FieldTip
              tip="Percentage of requests that are inspected by the CRS (1-100). Set to less than 100 to reduce CPU usage on high-traffic services at the cost of coverage. Leave blank for 100%."
              rule="tx.sampling_percentage"
            />
          </Label>
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
        </div>
        <div className="space-y-1">
          <Label className="inline-flex items-center text-xs text-muted-foreground">
            Reporting Level
            <FieldTip
              tip="Controls the paranoia level used for audit logging. Set higher than Blocking PL to log what *would* trigger at stricter settings without actually blocking. 'Auto' uses the same PL as detection."
              rule="tx.reporting_level"
            />
          </Label>
           <Select
            value={settings.reporting_level ? String(settings.reporting_level) : "auto"}
            onValueChange={(v) => onChange({ ...settings, reporting_level: v === "auto" ? undefined : Number(v) })}
          >
            <SelectTrigger className="w-24">
              <SelectValue placeholder="Auto" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="auto">Auto (= PL)</SelectItem>
              {[1, 2, 3, 4].map((n) => (
                <SelectItem key={n} value={String(n)}>PL {n}</SelectItem>
              ))}
            </SelectContent>
          </Select>
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
          <h2 className={T.pageTitle}>Settings</h2>
          <p className={T.pageDescription}>Dynamic WAF configuration</p>
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
    <TooltipProvider delayDuration={200}>
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className={T.pageTitle}>Settings</h2>
          <p className={T.pageDescription}>
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
            <CardTitle className={T.cardTitle}>Global Defaults</CardTitle>
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
            <h3 className={T.sectionHeading}>Per-Service Overrides</h3>
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
    </TooltipProvider>
  );
}

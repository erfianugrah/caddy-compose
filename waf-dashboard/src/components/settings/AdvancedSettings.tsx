import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { WAFServiceSettings } from "@/lib/api";
import { T } from "@/lib/typography";
import { FieldTip, CRS_EXCLUSION_PROFILES } from "./constants";

// ─── Advanced Paranoia (BPL / DPL Split) ────────────────────────────

export function AdvancedParanoiaSettings({
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

export function RequestPolicySettings({
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
            className="font-data text-xs"
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
            className="font-data text-xs"
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
          className="font-data text-xs"
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
            className="font-data text-xs"
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
            className="font-data text-xs"
          />
        </div>
      </div>
    </div>
  );
}

// ─── Argument & File Limits ─────────────────────────────────────────

export function LimitsSettings({
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

export function CRSExclusionProfiles({
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
              className="flex items-center justify-between rounded-md border border-border bg-lovelace-950 px-3 py-2"
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

export function AdvancedCRSControls({
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
        <div className="flex items-center justify-between rounded-md border border-border bg-lovelace-950 px-3 py-2.5">
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
        <div className="flex items-center justify-between rounded-md border border-border bg-lovelace-950 px-3 py-2.5">
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

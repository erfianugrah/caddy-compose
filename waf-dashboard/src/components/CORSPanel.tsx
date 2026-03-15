import { useState, useEffect, useCallback, useRef } from "react";
import {
  Globe,
  Save,
  Rocket,
  Loader2,
  Check,
  Plus,
  Trash2,
  X,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { T } from "@/lib/typography";
import {
  getCORS,
  updateCORS,
  deployConfig,
  fetchServices,
  type CORSConfig,
  type CORSSettings,
  type ServiceDetail,
} from "@/lib/api";

// ─── Constants ──────────────────────────────────────────────────────

const COMMON_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"];

const COMMON_HEADERS = [
  "Content-Type",
  "Authorization",
  "Accept",
  "X-Requested-With",
  "X-API-Key",
  "Origin",
  "Cache-Control",
];

function emptySettings(): CORSSettings {
  return {
    allowed_origins: [],
    allowed_methods: ["GET", "POST", "OPTIONS"],
    allowed_headers: ["Content-Type", "Authorization"],
    exposed_headers: [],
    max_age: 86400,
    allow_credentials: false,
  };
}

// ─── Tag Input Helper ───────────────────────────────────────────────

function TagList({
  items,
  onAdd,
  onRemove,
  placeholder,
}: {
  items: string[];
  onAdd: (v: string) => void;
  onRemove: (v: string) => void;
  placeholder: string;
}) {
  const [value, setValue] = useState("");
  const add = () => {
    const v = value.trim();
    if (v && !items.includes(v)) {
      onAdd(v);
      setValue("");
    }
  };
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-1.5">
        {items.map((item) => (
          <Badge key={item} variant="outline" className="gap-1 pr-1 font-mono text-xs">
            {item}
            <button
              type="button"
              onClick={() => onRemove(item)}
              className="ml-0.5 rounded-sm hover:text-destructive"
            >
              <X className="h-3 w-3" />
            </button>
          </Badge>
        ))}
      </div>
      <div className="flex items-center gap-2">
        <Input
          placeholder={placeholder}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), add())}
          className="h-8 text-xs font-mono"
        />
        <Button variant="outline" size="sm" className="h-8" onClick={add} disabled={!value.trim()}>
          <Plus className="h-3 w-3" />
        </Button>
      </div>
    </div>
  );
}

// ─── CORS Settings Block ────────────────────────────────────────────

function CORSSettingsBlock({
  settings,
  onChange,
}: {
  settings: CORSSettings;
  onChange: (s: CORSSettings) => void;
}) {
  const origins = settings.allowed_origins ?? [];
  const methods = settings.allowed_methods ?? [];
  const headers = settings.allowed_headers ?? [];
  const exposed = settings.exposed_headers ?? [];

  return (
    <div className="space-y-5">
      {/* Origins */}
      <div className="space-y-1.5">
        <Label className="text-xs">Allowed Origins</Label>
        <TagList
          items={origins}
          onAdd={(v) => onChange({ ...settings, allowed_origins: [...origins, v] })}
          onRemove={(v) => onChange({ ...settings, allowed_origins: origins.filter((o) => o !== v) })}
          placeholder="https://example.com or *"
        />
      </div>

      {/* Methods */}
      <div className="space-y-1.5">
        <Label className="text-xs">Allowed Methods</Label>
        <div className="flex flex-wrap gap-2">
          {COMMON_METHODS.map((m) => (
            <label key={m} className="flex items-center gap-1.5 text-xs">
              <input
                type="checkbox"
                checked={methods.includes(m)}
                onChange={(e) => {
                  const next = e.target.checked
                    ? [...methods, m]
                    : methods.filter((x) => x !== m);
                  onChange({ ...settings, allowed_methods: next });
                }}
                className="h-3.5 w-3.5 rounded border-border"
              />
              <span className="font-mono">{m}</span>
            </label>
          ))}
        </div>
      </div>

      {/* Allowed Headers */}
      <div className="space-y-1.5">
        <Label className="text-xs">Allowed Headers</Label>
        <TagList
          items={headers}
          onAdd={(v) => onChange({ ...settings, allowed_headers: [...headers, v] })}
          onRemove={(v) => onChange({ ...settings, allowed_headers: headers.filter((h) => h !== v) })}
          placeholder="Header-Name"
        />
      </div>

      {/* Exposed Headers */}
      <div className="space-y-1.5">
        <Label className="text-xs">Exposed Headers</Label>
        <TagList
          items={exposed}
          onAdd={(v) => onChange({ ...settings, exposed_headers: [...exposed, v] })}
          onRemove={(v) => onChange({ ...settings, exposed_headers: exposed.filter((h) => h !== v) })}
          placeholder="Header-Name"
        />
      </div>

      {/* Max-Age + Credentials */}
      <div className="flex items-end gap-6">
        <div className="space-y-1.5">
          <Label className="text-xs">Max-Age (seconds)</Label>
          <Input
            type="number"
            min={0}
            value={settings.max_age ?? 0}
            onChange={(e) => onChange({ ...settings, max_age: parseInt(e.target.value, 10) || 0 })}
            className="h-8 w-32 text-xs font-mono"
          />
        </div>
        <div className="flex items-center gap-2 pb-1">
          <Switch
            id="cors-credentials"
            checked={settings.allow_credentials ?? false}
            onCheckedChange={(v) => onChange({ ...settings, allow_credentials: v })}
          />
          <Label htmlFor="cors-credentials" className="text-xs text-muted-foreground">
            Allow Credentials
          </Label>
        </div>
      </div>
    </div>
  );
}

// ─── Component ──────────────────────────────────────────────────────

export default function CORSPanel() {
  const [config, setConfig] = useState<CORSConfig | null>(null);
  const [services, setServices] = useState<ServiceDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [flash, setFlash] = useState<{ type: "success" | "error"; msg: string } | null>(null);
  const [newServiceName, setNewServiceName] = useState("");

  const flashTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const showFlash = useCallback((type: "success" | "error", msg: string) => {
    if (flashTimerRef.current) clearTimeout(flashTimerRef.current);
    setFlash({ type, msg });
    flashTimerRef.current = setTimeout(() => setFlash(null), 4000);
  }, []);
  useEffect(() => () => { if (flashTimerRef.current) clearTimeout(flashTimerRef.current); }, []);

  const requestGenRef = useRef(0);

  // Load config + services on mount
  useEffect(() => {
    const gen = ++requestGenRef.current;
    Promise.all([
      getCORS(),
      fetchServices().catch(() => [] as ServiceDetail[]),
    ])
      .then(([cfg, svcs]) => {
        if (gen !== requestGenRef.current) return;
        setConfig(cfg);
        setServices(svcs);
      })
      .catch((err) => {
        if (gen !== requestGenRef.current) return;
        showFlash("error", err instanceof Error ? err.message : "Failed to load");
      })
      .finally(() => {
        if (gen !== requestGenRef.current) return;
        setLoading(false);
      });
  }, [showFlash]);

  const handleSave = async () => {
    if (!config) return;
    setSaving(true);
    try {
      const updated = await updateCORS(config);
      setConfig(updated);
      showFlash("success", "CORS configuration saved");
    } catch (err: unknown) {
      showFlash("error", err instanceof Error ? err.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  const handleDeploy = async () => {
    if (!config) return;
    setDeploying(true);
    try {
      await updateCORS(config);
      const res = await deployConfig();
      showFlash("success", res.message);
    } catch (err: unknown) {
      showFlash("error", err instanceof Error ? err.message : "Deploy failed");
    } finally {
      setDeploying(false);
    }
  };

  const updateGlobal = (s: CORSSettings) => {
    if (!config) return;
    setConfig({ ...config, global: s });
  };

  const addService = () => {
    if (!config) return;
    const name = newServiceName.trim();
    if (!name) return;
    if (config.per_service?.[name]) {
      showFlash("error", `Service "${name}" already has an override`);
      return;
    }
    setConfig({
      ...config,
      per_service: { ...(config.per_service || {}), [name]: emptySettings() },
    });
    setNewServiceName("");
  };

  const removeService = (name: string) => {
    if (!config) return;
    const svc = { ...(config.per_service || {}) };
    delete svc[name];
    setConfig({ ...config, per_service: svc });
  };

  const updateService = (name: string, s: CORSSettings) => {
    if (!config) return;
    setConfig({
      ...config,
      per_service: { ...(config.per_service || {}), [name]: s },
    });
  };

  if (loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (!config) {
    return (
      <Alert variant="destructive">
        <AlertDescription>Could not load CORS configuration.</AlertDescription>
      </Alert>
    );
  }

  const serviceNames = Object.keys(config.per_service || {}).sort();
  const availableServices = services
    .map((s) => s.service)
    .filter((s) => !config.per_service?.[s]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className={T.pageTitle}>CORS Configuration</h2>
          <p className={T.muted}>Cross-Origin Resource Sharing settings for the policy engine</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={handleSave} disabled={saving}>
            {saving ? <Loader2 className="mr-1 h-4 w-4 animate-spin" /> : <Save className="mr-1 h-4 w-4" />}
            Save
          </Button>
          <Button size="sm" onClick={handleDeploy} disabled={deploying}>
            {deploying ? <Loader2 className="mr-1 h-4 w-4 animate-spin" /> : <Rocket className="mr-1 h-4 w-4" />}
            Save & Deploy
          </Button>
        </div>
      </div>

      {/* Flash */}
      {flash && (
        <Alert variant={flash.type === "error" ? "destructive" : "default"}>
          {flash.type === "success" ? <Check className="h-4 w-4" /> : null}
          <AlertDescription>{flash.msg}</AlertDescription>
        </Alert>
      )}

      {/* Global Settings */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <Globe className="h-5 w-5 text-blue-400" />
              Global Settings
            </CardTitle>
            <div className="flex items-center gap-3">
              <Label htmlFor="cors-enabled" className="text-sm text-muted-foreground">
                {config.enabled !== false ? "Enabled" : "Disabled"}
              </Label>
              <Switch
                id="cors-enabled"
                checked={config.enabled !== false}
                onCheckedChange={(v) => setConfig({ ...config, enabled: v })}
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <CORSSettingsBlock settings={config.global} onChange={updateGlobal} />
        </CardContent>
      </Card>

      {/* Per-Service Overrides */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Per-Service Overrides ({serviceNames.length})</CardTitle>
            <div className="flex items-center gap-2">
              {availableServices.length > 0 && (
                <Select value={newServiceName} onValueChange={setNewServiceName}>
                  <SelectTrigger className="w-48 h-8 text-xs">
                    <SelectValue placeholder="Select service..." />
                  </SelectTrigger>
                  <SelectContent>
                    {availableServices.map((s) => (
                      <SelectItem key={s} value={s}>{s}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
              <Input
                placeholder="Or type name..."
                value={newServiceName}
                onChange={(e) => setNewServiceName(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && addService()}
                className="w-40 h-8 text-xs"
              />
              <Button variant="outline" size="sm" className="h-8" onClick={addService} disabled={!newServiceName.trim()}>
                <Plus className="mr-1 h-3 w-3" /> Add
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {serviceNames.length === 0 && (
            <p className={T.muted}>No per-service overrides. All services use the global CORS settings.</p>
          )}
          {serviceNames.map((svc) => (
            <div key={svc} className="rounded-lg border p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-medium">{svc}</span>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 text-destructive"
                  onClick={() => removeService(svc)}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
              <Separator />
              <CORSSettingsBlock
                settings={config.per_service?.[svc] || emptySettings()}
                onChange={(s) => updateService(svc, s)}
              />
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

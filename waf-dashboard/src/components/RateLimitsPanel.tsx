import { useState, useEffect, useCallback } from "react";
import {
  AlertTriangle,
  Check,
  Save,
  Rocket,
  Plus,
  Trash2,
  Info,
  RefreshCw,

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
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  getRateLimits,
  updateRateLimits,
  deployRateLimits,
  type RateLimitConfig,
  type RateLimitZone,
  type RateLimitDeployResult,
} from "@/lib/api";

// ─── Tier Presets ───────────────────────────────────────────────────

const TIER_PRESETS: Record<string, { events: number; window: string; label: string; shortLabel: string; desc: string }> = {
  admin: { events: 100, window: "1m", label: "Admin -- 100/min", shortLabel: "Admin", desc: "Low-traffic admin endpoints" },
  auth: { events: 200, window: "1m", label: "Auth -- 200/min", shortLabel: "Auth", desc: "Authentication services" },
  standard: { events: 300, window: "1m", label: "Standard -- 300/min", shortLabel: "Standard", desc: "Normal application traffic" },
  media: { events: 1000, window: "1m", label: "Media -- 1000/min", shortLabel: "Media", desc: "High-traffic media services" },
};

const WINDOW_OPTIONS = [
  { value: "10s", label: "10 seconds" },
  { value: "30s", label: "30 seconds" },
  { value: "1m", label: "1 minute" },
  { value: "2m", label: "2 minutes" },
  { value: "5m", label: "5 minutes" },
  { value: "10m", label: "10 minutes" },
  { value: "30m", label: "30 minutes" },
  { value: "1h", label: "1 hour" },
];

// Classify a zone into a tier for display
function getTierForZone(zone: RateLimitZone): string {
  if (zone.window !== "1m") return "custom";
  if (zone.events <= 100) return "admin";
  if (zone.events <= 200) return "auth";
  if (zone.events <= 300) return "standard";
  if (zone.events >= 1000) return "media";
  return "custom";
}

function getTierBadge(tier: string) {
  const colors: Record<string, string> = {
    admin: "bg-neon-pink/10 text-neon-pink border-neon-pink/30",
    auth: "bg-neon-amber/10 text-neon-amber border-neon-amber/30",
    standard: "bg-neon-blue/10 text-neon-blue border-neon-blue/30",
    media: "bg-neon-green/10 text-neon-green border-neon-green/30",
    custom: "bg-foreground/10 text-foreground border-foreground/30",
  };
  const labels: Record<string, string> = {
    admin: "Admin",
    auth: "Auth",
    standard: "Standard",
    media: "Media",
    custom: "Custom",
  };
  return (
    <Badge variant="outline" className={`text-[10px] ${colors[tier] ?? colors.custom}`}>
      {labels[tier] ?? "Custom"}
    </Badge>
  );
}

// ─── Add Zone Dialog ────────────────────────────────────────────────

function AddZoneDialog({
  onAdd,
  existingNames,
}: {
  onAdd: (zone: RateLimitZone) => void;
  existingNames: Set<string>;
}) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [events, setEvents] = useState(300);
  const [window, setWindow] = useState("1m");
  const [error, setError] = useState<string | null>(null);

  const handleAdd = () => {
    setError(null);
    const trimmed = name.trim().toLowerCase().replace(/\s+/g, "-");
    if (!trimmed) {
      setError("Zone name is required");
      return;
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(trimmed)) {
      setError("Zone name must be alphanumeric with hyphens/underscores");
      return;
    }
    if (existingNames.has(trimmed)) {
      setError("A zone with this name already exists");
      return;
    }
    if (events < 1 || events > 100000) {
      setError("Events must be between 1 and 100,000");
      return;
    }
    onAdd({ name: trimmed, events, window, enabled: true });
    setName("");
    setEvents(300);
    setWindow("1m");
    setOpen(false);
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm">
          <Plus className="h-3.5 w-3.5" />
          Add Zone
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add Rate Limit Zone</DialogTitle>
          <DialogDescription>
            Create a new rate limit zone. Remember to add{" "}
            <code className="text-xs bg-navy-900 px-1 py-0.5 rounded">
              import /data/caddy/rl/&lt;zone&gt;*.caddy
            </code>{" "}
            to the corresponding site block in the Caddyfile.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-2">
            <Label>Zone Name</Label>
            <Input
              placeholder="e.g. myservice"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div className="grid gap-4 grid-cols-2">
            <div className="space-y-2">
              <Label>Events (max requests)</Label>
              <Input
                type="number"
                min={1}
                max={100000}
                value={events}
                onChange={(e) => setEvents(Number(e.target.value))}
              />
            </div>
            <div className="space-y-2">
              <Label>Window</Label>
              <Select value={window} onValueChange={setWindow}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {WINDOW_OPTIONS.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value}>
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          {/* Quick preset buttons */}
          <div className="space-y-2">
            <Label className="text-xs text-muted-foreground">Quick Presets</Label>
            <div className="flex flex-wrap gap-2">
              {Object.entries(TIER_PRESETS).map(([key, preset]) => (
                <Button
                  key={key}
                  variant="outline"
                  size="sm"
                  className="text-xs"
                  onClick={() => {
                    setEvents(preset.events);
                    setWindow(preset.window);
                  }}
                >
                  {preset.label}
                </Button>
              ))}
            </div>
          </div>
          {error && (
            <p className="text-xs text-destructive">{error}</p>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button onClick={handleAdd}>Add Zone</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Main Panel ─────────────────────────────────────────────────────

export default function RateLimitsPanel() {
  const [config, setConfig] = useState<RateLimitConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);
  const [deployResult, setDeployResult] = useState<RateLimitDeployResult | null>(null);

  const loadData = useCallback(() => {
    setLoading(true);
    setError(null);
    getRateLimits()
      .then((cfg) => {
        setConfig(cfg);
        setDirty(false);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const showSuccess = (msg: string) => {
    setSuccessMsg(msg);
    setTimeout(() => setSuccessMsg(null), 4000);
  };

  const updateZone = (index: number, updates: Partial<RateLimitZone>) => {
    if (!config) return;
    const zones = [...config.zones];
    zones[index] = { ...zones[index], ...updates };
    setConfig({ zones });
    setDirty(true);
  };

  const removeZone = (index: number) => {
    if (!config) return;
    const zones = config.zones.filter((_, i) => i !== index);
    setConfig({ zones });
    setDirty(true);
  };

  const addZone = (zone: RateLimitZone) => {
    if (!config) return;
    setConfig({ zones: [...config.zones, zone] });
    setDirty(true);
  };

  const handleSave = async () => {
    if (!config) return;
    setSaving(true);
    setError(null);
    try {
      const updated = await updateRateLimits(config);
      setConfig(updated);
      setDirty(false);
      showSuccess("Rate limit configuration saved");
    } catch (err: any) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleDeploy = async () => {
    setDeploying(true);
    setError(null);
    setDeployResult(null);
    try {
      // Save first if dirty
      if (dirty && config) {
        await updateRateLimits(config);
        setDirty(false);
      }
      const result = await deployRateLimits();
      setDeployResult(result);
      if (result.status === "deployed") {
        showSuccess("Rate limits deployed and Caddy reloaded");
      } else {
        showSuccess("Zone files written but Caddy reload failed");
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setDeploying(false);
    }
  };

  const applyPreset = (index: number, presetKey: string) => {
    const preset = TIER_PRESETS[presetKey];
    if (!preset) return;
    updateZone(index, { events: preset.events, window: preset.window });
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className="text-lg font-semibold">Rate Limits</h2>
          <p className="text-sm text-muted-foreground">Per-service rate limit configuration</p>
        </div>
        <div className="space-y-4">
          {[...Array(3)].map((_, i) => (
            <Card key={i}>
              <CardContent className="p-6">
                <Skeleton className="h-20 w-full" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  const zones = config?.zones ?? [];
  const existingNames = new Set(zones.map((z) => z.name));
  const enabledCount = zones.filter((z) => z.enabled).length;
  const disabledCount = zones.length - enabledCount;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-lg font-semibold">Rate Limits</h2>
          <p className="text-sm text-muted-foreground">
            Configure per-service rate limiting. Changes require deploying to take effect.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={loadData} disabled={loading}>
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh
          </Button>
          <AddZoneDialog onAdd={addZone} existingNames={existingNames} />
          <Button
            variant="outline"
            size="sm"
            onClick={handleSave}
            disabled={!dirty || saving}
          >
            <Save className="h-3.5 w-3.5" />
            {saving ? "Saving..." : "Save"}
          </Button>
          <Button
            size="sm"
            onClick={handleDeploy}
            disabled={deploying}
          >
            <Rocket className="h-3.5 w-3.5" />
            {deploying ? "Deploying..." : "Apply Rate Limits"}
          </Button>
        </div>
      </div>

      {/* Status alerts */}
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
            You have unsaved changes. Save first, then click "Apply Rate Limits" to deploy.
          </AlertDescription>
        </Alert>
      )}

      {deployResult && (
        <Alert variant={deployResult.reloaded ? "success" : "default"}>
          <Info className="h-4 w-4" />
          <AlertTitle>Deploy Result</AlertTitle>
          <AlertDescription>
            {deployResult.message}
            {deployResult.files && deployResult.files.length > 0 && (
              <span className="block mt-1 text-xs text-muted-foreground">
                {deployResult.files.length} zone file(s) written
              </span>
            )}
          </AlertDescription>
        </Alert>
      )}

      {/* Summary stats */}
      <div className="grid gap-4 sm:grid-cols-3">
        <Card>
          <CardContent className="p-4">
            <div className="text-xs text-muted-foreground">Total Zones</div>
            <div className="text-2xl font-bold tabular-nums">{zones.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-xs text-muted-foreground">Active</div>
            <div className="text-2xl font-bold tabular-nums text-neon-green">{enabledCount}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-xs text-muted-foreground">Disabled</div>
            <div className="text-2xl font-bold tabular-nums text-muted-foreground">{disabledCount}</div>
          </CardContent>
        </Card>
      </div>

      {/* Zone table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Rate Limit Zones</CardTitle>
          <CardDescription>
            Each zone corresponds to a site block in the Caddyfile. Per-client IP, excludes WebSocket upgrades.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {zones.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Zone</TableHead>
                  <TableHead>Tier</TableHead>
                  <TableHead className="text-right">Events</TableHead>
                  <TableHead>Window</TableHead>
                  <TableHead>Preset</TableHead>
                  <TableHead className="text-center">Enabled</TableHead>
                  <TableHead className="w-10"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {zones.map((zone, idx) => {
                  const tier = getTierForZone(zone);
                  return (
                    <TableRow key={zone.name} className={!zone.enabled ? "opacity-50" : ""}>
                      <TableCell className="font-mono text-xs font-medium">
                        {zone.name}
                      </TableCell>
                      <TableCell>{getTierBadge(tier)}</TableCell>
                      <TableCell className="text-right">
                        <Input
                          type="number"
                          min={1}
                          max={100000}
                          value={zone.events}
                          onChange={(e) => updateZone(idx, { events: Number(e.target.value) })}
                          className="w-28 text-right tabular-nums"
                        />
                      </TableCell>
                      <TableCell>
                        <Select
                          value={zone.window}
                          onValueChange={(v) => updateZone(idx, { window: v })}
                        >
                          <SelectTrigger className="w-[140px]">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {WINDOW_OPTIONS.map((opt) => (
                              <SelectItem key={opt.value} value={opt.value}>
                                {opt.label}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </TableCell>
                      <TableCell>
                        <Select
                          value={tier !== "custom" ? tier : ""}
                          onValueChange={(v) => {
                            if (v) applyPreset(idx, v);
                          }}
                        >
                          <SelectTrigger className="w-[130px]">
                            <SelectValue placeholder="Custom" />
                          </SelectTrigger>
                          <SelectContent>
                            {Object.entries(TIER_PRESETS).map(([key, preset]) => (
                              <SelectItem key={key} value={key}>
                                {preset.shortLabel}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </TableCell>
                      <TableCell className="text-center">
                        <Switch
                          checked={zone.enabled}
                          onCheckedChange={(v) => updateZone(idx, { enabled: v })}
                        />
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-8 w-8 p-0 text-muted-foreground hover:text-destructive"
                          onClick={() => removeZone(idx)}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          ) : (
            <div className="py-8 text-center text-xs text-muted-foreground">
              No rate limit zones configured. Click "Add Zone" to create one.
            </div>
          )}
        </CardContent>
      </Card>

      {/* Info card */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">How It Works</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-xs text-muted-foreground">
          <p>
            Rate limits are applied per client IP address using a sliding window algorithm.
            WebSocket upgrade requests are automatically excluded.
          </p>
          <p>
            Each zone writes a <code className="bg-navy-900 px-1 py-0.5 rounded">.caddy</code> file
            that is imported by the corresponding site block in the Caddyfile via glob pattern.
            Disabled zones produce a comment-only file (no-op).
          </p>
          <p>
            To add rate limiting to a new service, create a zone here and add{" "}
            <code className="bg-navy-900 px-1 py-0.5 rounded">
              import /data/caddy/rl/&lt;zone&gt;*.caddy
            </code>{" "}
            to its site block.
          </p>
          <div className="grid gap-2 sm:grid-cols-4 pt-2">
            {Object.entries(TIER_PRESETS).map(([key, preset]) => (
              <div key={key} className="rounded-md border border-border bg-navy-950 p-2">
                <div className="font-medium text-foreground">{preset.label}</div>
                <div className="text-[10px]">{preset.desc}</div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

    </div>
  );
}

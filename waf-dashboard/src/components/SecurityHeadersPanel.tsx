import { useState, useEffect, useCallback } from "react";
import {
  Shield,
  ShieldOff,
  Save,
  Rocket,
  Loader2,
  Check,
  Plus,
  Trash2,
  Eye,
  Info,
  Download,
  Upload,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert";
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
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogFooter,
} from "@/components/ui/dialog";
import { T } from "@/lib/typography";
import {
  getSecurityHeaders,
  updateSecurityHeaders,
  deploySecurityHeaders,
  listSecurityProfiles,
  previewSecurityHeaders,
  fetchServices,
  type SecurityHeaderConfig,
  type SecurityServiceConfig,
  type SecurityProfile,
  type SecurityHeaderPreviewResponse,
  type ServiceDetail,
} from "@/lib/api";

// ─── Well-Known Security Headers ────────────────────────────────────

const HEADER_DESCRIPTIONS: Record<string, string> = {
  "Strict-Transport-Security": "Enforces HTTPS connections. max-age is in seconds.",
  "X-Content-Type-Options": "Prevents MIME-type sniffing. Use 'nosniff'.",
  "X-Frame-Options": "Controls framing. DENY or SAMEORIGIN.",
  "Referrer-Policy": "Controls Referer header. Options: no-referrer, strict-origin-when-cross-origin, etc.",
  "Permissions-Policy": "Controls browser features. Deny with feature=().",
  "Cross-Origin-Opener-Policy": "Controls cross-origin window references. same-origin or same-origin-allow-popups.",
  "Cross-Origin-Resource-Policy": "Controls cross-origin resource loading. same-origin, same-site, or cross-origin.",
  "Cross-Origin-Embedder-Policy": "Controls embedding. require-corp for strict isolation.",
  "X-Permitted-Cross-Domain-Policies": "Controls Flash/PDF cross-domain. Use 'none'.",
};

const PROFILE_COLORS: Record<string, string> = {
  strict: "bg-red-500/10 text-red-400 border-red-500/20",
  default: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  relaxed: "bg-amber-500/10 text-amber-400 border-amber-500/20",
  api: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
  custom: "bg-purple-500/10 text-purple-400 border-purple-500/20",
};

// ─── Component ──────────────────────────────────────────────────────

export default function SecurityHeadersPanel() {
  const [config, setConfig] = useState<SecurityHeaderConfig | null>(null);
  const [profiles, setProfiles] = useState<SecurityProfile[]>([]);
  const [services, setServices] = useState<ServiceDetail[]>([]);
  const [preview, setPreview] = useState<SecurityHeaderPreviewResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [showPreview, setShowPreview] = useState(false);
  const [flash, setFlash] = useState<{ type: "success" | "error"; msg: string } | null>(null);
  const [newServiceName, setNewServiceName] = useState("");
  const [addDialogOpen, setAddDialogOpen] = useState(false);

  const showFlash = useCallback((type: "success" | "error", msg: string) => {
    setFlash({ type, msg });
    setTimeout(() => setFlash(null), 4000);
  }, []);

  // Load config, profiles, and services
  useEffect(() => {
    Promise.all([
      getSecurityHeaders(),
      listSecurityProfiles(),
      fetchServices().catch(() => [] as ServiceDetail[]),
    ])
      .then(([cfg, profs, svcs]) => {
        setConfig(cfg);
        setProfiles(profs);
        setServices(svcs);
      })
      .catch((err) => showFlash("error", err.message))
      .finally(() => setLoading(false));
  }, [showFlash]);

  const handleSave = async () => {
    if (!config) return;
    setSaving(true);
    try {
      const updated = await updateSecurityHeaders(config);
      setConfig(updated);
      showFlash("success", "Security headers saved");
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
      await updateSecurityHeaders(config);
      const res = await deploySecurityHeaders();
      showFlash("success", res.message);
    } catch (err: unknown) {
      showFlash("error", err instanceof Error ? err.message : "Deploy failed");
    } finally {
      setDeploying(false);
    }
  };

  const handlePreview = async () => {
    try {
      const p = await previewSecurityHeaders();
      setPreview(p);
      setShowPreview(true);
    } catch (err: unknown) {
      showFlash("error", err instanceof Error ? err.message : "Preview failed");
    }
  };

  const handleProfileChange = (profileName: string) => {
    if (!config) return;
    const prof = profiles.find((p) => p.name === profileName);
    if (prof) {
      setConfig({
        ...config,
        profile: profileName,
        headers: { ...prof.headers },
        remove: [...prof.remove],
      });
    } else {
      setConfig({ ...config, profile: profileName });
    }
  };

  const handleToggleEnabled = (enabled: boolean) => {
    if (!config) return;
    setConfig({ ...config, enabled });
  };

  const handleHeaderChange = (name: string, value: string) => {
    if (!config) return;
    const headers = { ...(config.headers || {}) };
    if (value === "") {
      delete headers[name];
    } else {
      headers[name] = value;
    }
    setConfig({ ...config, headers, profile: "custom" });
  };

  const handleRemoveToggle = (headerName: string) => {
    if (!config) return;
    const remove = [...(config.remove || [])];
    const idx = remove.indexOf(headerName);
    if (idx >= 0) {
      remove.splice(idx, 1);
    } else {
      remove.push(headerName);
    }
    setConfig({ ...config, remove, profile: "custom" });
  };

  const addService = () => {
    if (!config || !newServiceName.trim()) return;
    const name = newServiceName.trim();
    if (config.services?.[name]) {
      showFlash("error", `Service "${name}" already has an override`);
      return;
    }
    setConfig({
      ...config,
      services: {
        ...(config.services || {}),
        [name]: { profile: "", headers: {}, remove: [] },
      },
    });
    setNewServiceName("");
    setAddDialogOpen(false);
  };

  const removeService = (name: string) => {
    if (!config) return;
    const svc = { ...(config.services || {}) };
    delete svc[name];
    setConfig({ ...config, services: svc });
  };

  const updateServiceProfile = (svc: string, profile: string) => {
    if (!config) return;
    const services = { ...(config.services || {}) };
    const existing = services[svc] || { headers: {}, remove: [] };

    if (profile && profile !== "custom") {
      const prof = profiles.find((p) => p.name === profile);
      if (prof) {
        services[svc] = {
          profile,
          headers: { ...prof.headers },
          remove: [...prof.remove],
        };
      } else {
        services[svc] = { ...existing, profile };
      }
    } else {
      services[svc] = { ...existing, profile };
    }
    setConfig({ ...config, services });
  };

  const updateServiceHeader = (svc: string, name: string, value: string) => {
    if (!config) return;
    const services = { ...(config.services || {}) };
    const existing = services[svc] || { headers: {}, remove: [] };
    const headers = { ...(existing.headers || {}) };
    if (value === "") {
      delete headers[name];
    } else {
      headers[name] = value;
    }
    services[svc] = { ...existing, headers, profile: "custom" };
    setConfig({ ...config, services });
  };

  const handleExport = () => {
    if (!config) return;
    const blob = new Blob([JSON.stringify(config, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "security-headers.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleImport = () => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json";
    input.onchange = async () => {
      const file = input.files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const imported = JSON.parse(text) as SecurityHeaderConfig;
        setConfig(imported);
        showFlash("success", "Config imported — save to apply");
      } catch {
        showFlash("error", "Invalid JSON file");
      }
    };
    input.click();
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
        <AlertTitle>Failed to load</AlertTitle>
        <AlertDescription>Could not load security header configuration.</AlertDescription>
      </Alert>
    );
  }

  const enabled = config.enabled !== false;
  const profileName = config.profile || "default";
  const serviceNames = Object.keys(config.services || {}).sort();
  const availableServices = services
    .map((s) => s.name)
    .filter((s) => !config.services?.[s]);

  return (
    <TooltipProvider>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <T.H2>Security Headers</T.H2>
            <T.Muted>Manage HTTP security headers injected by the policy engine</T.Muted>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleExport}>
              <Download className="mr-1 h-4 w-4" /> Export
            </Button>
            <Button variant="outline" size="sm" onClick={handleImport}>
              <Upload className="mr-1 h-4 w-4" /> Import
            </Button>
            <Button variant="outline" size="sm" onClick={handlePreview}>
              <Eye className="mr-1 h-4 w-4" /> Preview
            </Button>
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

        {/* Enable toggle + Profile selector */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                {enabled ? <Shield className="h-5 w-5 text-emerald-400" /> : <ShieldOff className="h-5 w-5 text-muted-foreground" />}
                Global Configuration
              </CardTitle>
              <div className="flex items-center gap-3">
                <Label htmlFor="sec-enabled" className="text-sm text-muted-foreground">
                  {enabled ? "Enabled" : "Disabled"}
                </Label>
                <Switch
                  id="sec-enabled"
                  checked={enabled}
                  onCheckedChange={handleToggleEnabled}
                />
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Profile selector */}
            <div className="space-y-2">
              <Label>Profile</Label>
              <div className="flex items-center gap-3">
                <Select value={profileName} onValueChange={handleProfileChange}>
                  <SelectTrigger className="w-48">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {profiles.map((p) => (
                      <SelectItem key={p.name} value={p.name}>
                        <span className="capitalize">{p.name}</span>
                      </SelectItem>
                    ))}
                    <SelectItem value="custom">Custom</SelectItem>
                  </SelectContent>
                </Select>
                <Badge variant="outline" className={PROFILE_COLORS[profileName] || PROFILE_COLORS.custom}>
                  {profileName}
                </Badge>
                {profiles.find((p) => p.name === profileName) && (
                  <T.Muted className="text-xs">
                    {profiles.find((p) => p.name === profileName)!.description}
                  </T.Muted>
                )}
              </div>
            </div>

            <Separator />

            {/* Headers table */}
            <div className="space-y-2">
              <Label>Response Headers</Label>
              <div className="rounded-lg border">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b bg-muted/50">
                      <th className="px-3 py-2 text-left font-medium">Header</th>
                      <th className="px-3 py-2 text-left font-medium">Value</th>
                      <th className="px-3 py-2 text-right font-medium w-16"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(config.headers || {}).sort(([a], [b]) => a.localeCompare(b)).map(([name, value]) => (
                      <tr key={name} className="border-b last:border-b-0">
                        <td className="px-3 py-2 font-mono text-xs">
                          <div className="flex items-center gap-1">
                            {name}
                            {HEADER_DESCRIPTIONS[name] && (
                              <Tooltip>
                                <TooltipTrigger>
                                  <Info className="h-3 w-3 text-muted-foreground" />
                                </TooltipTrigger>
                                <TooltipContent className="max-w-xs">
                                  {HEADER_DESCRIPTIONS[name]}
                                </TooltipContent>
                              </Tooltip>
                            )}
                          </div>
                        </td>
                        <td className="px-3 py-2">
                          <Input
                            value={value}
                            onChange={(e) => handleHeaderChange(name, e.target.value)}
                            className="h-7 font-mono text-xs"
                          />
                        </td>
                        <td className="px-3 py-2 text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive"
                            onClick={() => handleHeaderChange(name, "")}
                          >
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <AddHeaderRow
                onAdd={(name, value) => handleHeaderChange(name, value)}
                existingHeaders={Object.keys(config.headers || {})}
              />
            </div>

            <Separator />

            {/* Remove headers */}
            <div className="space-y-2">
              <Label>Headers to Remove</Label>
              <T.Muted className="text-xs">These headers are stripped from responses (e.g. Server, X-Powered-By)</T.Muted>
              <div className="flex flex-wrap gap-2">
                {(config.remove || []).map((h) => (
                  <Badge
                    key={h}
                    variant="outline"
                    className="cursor-pointer bg-red-500/10 text-red-400 border-red-500/20 hover:bg-red-500/20"
                    onClick={() => handleRemoveToggle(h)}
                  >
                    -{h} <span className="ml-1 opacity-60">x</span>
                  </Badge>
                ))}
                <AddRemoveHeaderInput
                  onAdd={(h) => handleRemoveToggle(h)}
                  existing={config.remove || []}
                />
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Per-Service Overrides */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Per-Service Overrides</CardTitle>
              <Dialog open={addDialogOpen} onOpenChange={setAddDialogOpen}>
                <DialogTrigger asChild>
                  <Button variant="outline" size="sm">
                    <Plus className="mr-1 h-4 w-4" /> Add Service
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Add Service Override</DialogTitle>
                  </DialogHeader>
                  <div className="space-y-3">
                    {availableServices.length > 0 ? (
                      <Select value={newServiceName} onValueChange={setNewServiceName}>
                        <SelectTrigger>
                          <SelectValue placeholder="Select a service..." />
                        </SelectTrigger>
                        <SelectContent>
                          {availableServices.map((s) => (
                            <SelectItem key={s} value={s}>{s}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    ) : null}
                    <div className="flex items-center gap-2">
                      <Input
                        placeholder="Or type service name..."
                        value={newServiceName}
                        onChange={(e) => setNewServiceName(e.target.value)}
                        onKeyDown={(e) => e.key === "Enter" && addService()}
                      />
                    </div>
                  </div>
                  <DialogFooter>
                    <Button onClick={addService} disabled={!newServiceName.trim()}>Add</Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {serviceNames.length === 0 && (
              <T.Muted>No per-service overrides. All services use the global configuration.</T.Muted>
            )}
            {serviceNames.map((svc) => {
              const sc = config.services?.[svc] || {};
              return (
                <ServiceOverrideCard
                  key={svc}
                  name={svc}
                  config={sc}
                  profiles={profiles}
                  onProfileChange={(p) => updateServiceProfile(svc, p)}
                  onHeaderChange={(n, v) => updateServiceHeader(svc, n, v)}
                  onRemove={() => removeService(svc)}
                />
              );
            })}
          </CardContent>
        </Card>

        {/* Preview Dialog */}
        {showPreview && preview && (
          <PreviewDialog
            preview={preview}
            open={showPreview}
            onClose={() => setShowPreview(false)}
          />
        )}
      </div>
    </TooltipProvider>
  );
}

// ─── Sub-Components ─────────────────────────────────────────────────

function AddHeaderRow({
  onAdd,
  existingHeaders,
}: {
  onAdd: (name: string, value: string) => void;
  existingHeaders: string[];
}) {
  const [name, setName] = useState("");
  const [value, setValue] = useState("");

  const wellKnown = Object.keys(HEADER_DESCRIPTIONS).filter(
    (h) => !existingHeaders.includes(h),
  );

  const handleAdd = () => {
    if (name.trim() && value.trim()) {
      onAdd(name.trim(), value.trim());
      setName("");
      setValue("");
    }
  };

  return (
    <div className="flex items-center gap-2">
      {wellKnown.length > 0 ? (
        <Select value={name} onValueChange={setName}>
          <SelectTrigger className="w-64 h-8 text-xs">
            <SelectValue placeholder="Add header..." />
          </SelectTrigger>
          <SelectContent>
            {wellKnown.map((h) => (
              <SelectItem key={h} value={h} className="text-xs font-mono">{h}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      ) : (
        <Input
          placeholder="Header-Name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="w-64 h-8 text-xs font-mono"
        />
      )}
      <Input
        placeholder="Value"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        className="flex-1 h-8 text-xs font-mono"
        onKeyDown={(e) => e.key === "Enter" && handleAdd()}
      />
      <Button variant="outline" size="sm" className="h-8" onClick={handleAdd} disabled={!name || !value}>
        <Plus className="h-3 w-3" />
      </Button>
    </div>
  );
}

function AddRemoveHeaderInput({
  onAdd,
  existing,
}: {
  onAdd: (name: string) => void;
  existing: string[];
}) {
  const [value, setValue] = useState("");
  const common = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"].filter(
    (h) => !existing.includes(h),
  );

  return (
    <div className="flex items-center gap-1">
      {common.length > 0 && (
        <Select value="" onValueChange={(v) => { onAdd(v); }}>
          <SelectTrigger className="w-40 h-7 text-xs">
            <SelectValue placeholder="Add..." />
          </SelectTrigger>
          <SelectContent>
            {common.map((h) => (
              <SelectItem key={h} value={h} className="text-xs font-mono">-{h}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
      <Input
        placeholder="Custom..."
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && value.trim()) {
            onAdd(value.trim());
            setValue("");
          }
        }}
        className="w-32 h-7 text-xs font-mono"
      />
    </div>
  );
}

function ServiceOverrideCard({
  name,
  config,
  profiles,
  onProfileChange,
  onHeaderChange,
  onRemove,
}: {
  name: string;
  config: SecurityServiceConfig;
  profiles: SecurityProfile[];
  onProfileChange: (profile: string) => void;
  onHeaderChange: (header: string, value: string) => void;
  onRemove: () => void;
}) {
  const profileName = config.profile || "inherit";
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="rounded-lg border p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="font-mono text-sm font-medium">{name}</span>
          <Badge variant="outline" className={PROFILE_COLORS[profileName] || "bg-muted/50 text-muted-foreground"}>
            {profileName === "" ? "inherit" : profileName}
          </Badge>
        </div>
        <div className="flex items-center gap-2">
          <Select value={profileName || "inherit"} onValueChange={(v) => onProfileChange(v === "inherit" ? "" : v)}>
            <SelectTrigger className="w-36 h-8 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="inherit">Inherit global</SelectItem>
              {profiles.map((p) => (
                <SelectItem key={p.name} value={p.name}>
                  <span className="capitalize">{p.name}</span>
                </SelectItem>
              ))}
              <SelectItem value="custom">Custom</SelectItem>
            </SelectContent>
          </Select>
          <Button
            variant="ghost"
            size="sm"
            className="h-8 text-muted-foreground"
            onClick={() => setExpanded(!expanded)}
          >
            {expanded ? "Collapse" : "Expand"}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-8 text-destructive"
            onClick={onRemove}
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      </div>
      {expanded && config.headers && Object.keys(config.headers).length > 0 && (
        <div className="rounded border">
          <table className="w-full text-xs">
            <tbody>
              {Object.entries(config.headers).sort(([a], [b]) => a.localeCompare(b)).map(([h, v]) => (
                <tr key={h} className="border-b last:border-b-0">
                  <td className="px-3 py-1.5 font-mono text-muted-foreground w-1/3">{h}</td>
                  <td className="px-3 py-1.5">
                    <Input
                      value={v}
                      onChange={(e) => onHeaderChange(h, e.target.value)}
                      className="h-6 font-mono text-xs"
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function PreviewDialog({
  preview,
  open,
  onClose,
}: {
  preview: SecurityHeaderPreviewResponse;
  open: boolean;
  onClose: () => void;
}) {
  const serviceNames = Object.keys(preview.services).sort();

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Security Headers Preview</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          {/* Global defaults */}
          <div>
            <T.H4 className="mb-2">Global Defaults</T.H4>
            <HeaderTable headers={preview.global.headers} remove={preview.global.remove} />
          </div>

          <Separator />

          {/* Per-service */}
          {serviceNames.map((svc) => {
            const resolved = preview.services[svc];
            return (
              <div key={svc}>
                <T.H4 className="mb-2 font-mono">{svc}</T.H4>
                <HeaderTable headers={resolved.headers} remove={resolved.remove} />
              </div>
            );
          })}
        </div>
      </DialogContent>
    </Dialog>
  );
}

function HeaderTable({ headers, remove }: { headers: Record<string, string>; remove: string[] }) {
  return (
    <div className="rounded border text-xs">
      <table className="w-full">
        <tbody>
          {Object.entries(headers).sort(([a], [b]) => a.localeCompare(b)).map(([name, value]) => (
            <tr key={name} className="border-b last:border-b-0">
              <td className="px-3 py-1.5 font-mono text-emerald-400 w-1/3">{name}</td>
              <td className="px-3 py-1.5 font-mono text-muted-foreground">{value}</td>
            </tr>
          ))}
          {remove.map((h) => (
            <tr key={`rm-${h}`} className="border-b last:border-b-0">
              <td className="px-3 py-1.5 font-mono text-red-400">-{h}</td>
              <td className="px-3 py-1.5 font-mono text-muted-foreground italic">removed</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

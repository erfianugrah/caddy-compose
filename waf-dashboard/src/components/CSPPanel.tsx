import { useState, useEffect, useCallback, useRef } from "react";
import {
  Shield,
  ShieldOff,
  Save,
  Rocket,
  Loader2,
  AlertTriangle,
  Check,
  Info,
  Plus,
  Globe,
  Download,
  Upload,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
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
import { T } from "@/lib/typography";
import { downloadJSON } from "@/lib/download";
import {
  getCSPConfig,
  updateCSPConfig,
  deployCSP,
  previewCSP,
  fetchServices,
  type CSPConfig,
  type CSPPolicy,
  type CSPServiceConfig,
  type CSPPreviewResponse,
  type ServiceDetail,
} from "@/lib/api";
import { DirectiveEditor } from "./csp/DirectiveEditor";
import { ServiceCard, PreviewPanel } from "./csp/PreviewPanel";

// ─── Main CSP Panel ─────────────────────────────────────────────────

export default function CSPPanel() {
  const [config, setConfig] = useState<CSPConfig | null>(null);
  const [services, setServices] = useState<ServiceDetail[]>([]);
  const [preview, setPreview] = useState<CSPPreviewResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [deployStep, setDeployStep] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);

  // Working copies
  const [enabled, setEnabled] = useState(true);
  const [globalDefaults, setGlobalDefaults] = useState<CSPPolicy>({});
  const [serviceConfigs, setServiceConfigs] = useState<Record<string, CSPServiceConfig>>({});

  // Guard against stale responses when rapid reloads fire concurrent requests.
  const requestGenRef = useRef(0);

  const loadData = useCallback(() => {
    const gen = ++requestGenRef.current;
    setLoading(true);
    setError(null);
    Promise.all([getCSPConfig(), fetchServices(), previewCSP()])
      .then(([cfg, svcs, prev]) => {
        if (gen !== requestGenRef.current) return;
        setConfig(cfg);
        setEnabled(cfg.enabled !== false);
        setGlobalDefaults(cfg.global_defaults);
        setServiceConfigs(cfg.services);
        setServices(svcs);
        setPreview(prev);
        setDirty(false);
      })
      .catch((err) => {
        if (gen !== requestGenRef.current) return;
        setError(err.message);
      })
      .finally(() => {
        if (gen !== requestGenRef.current) return;
        setLoading(false);
      });
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

  const buildConfig = (): CSPConfig => ({
    enabled,
    global_defaults: globalDefaults,
    services: serviceConfigs,
  });

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    try {
      const updated = await updateCSPConfig(buildConfig());
      setConfig(updated);
      setEnabled(updated.enabled !== false);
      setGlobalDefaults(updated.global_defaults);
      setServiceConfigs(updated.services);
      setDirty(false);
      // Refresh preview
      const prev = await previewCSP();
      setPreview(prev);
      showSuccess("CSP config saved");
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
      await updateCSPConfig(buildConfig());
      setDeployStep("Generating CSP files & reloading Caddy...");
      const result = await deployCSP();
      setDirty(false);
      // Refresh preview
      const prev = await previewCSP();
      setPreview(prev);
      if (result.reloaded) {
        showSuccess(`CSP deployed (${result.files.length} files) and Caddy reloaded`);
      } else {
        showSuccess(`CSP files written (${result.files.length}) — Caddy reload may be needed`);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Deploy failed");
    } finally {
      setDeployStep(null);
    }
  };

  const handleGlobalChange = (policy: CSPPolicy) => {
    setGlobalDefaults(policy);
    markDirty();
  };

  const handleServiceChange = (name: string, cfg: CSPServiceConfig) => {
    setServiceConfigs((prev) => ({ ...prev, [name]: cfg }));
    markDirty();
  };

  const handleServiceRemove = (name: string) => {
    setServiceConfigs((prev) => {
      const next = { ...prev };
      delete next[name];
      return next;
    });
    markDirty();
  };

  const handleAddService = (name: string) => {
    if (serviceConfigs[name]) return;
    setServiceConfigs((prev) => ({
      ...prev,
      [name]: {
        mode: "set",
        report_only: false,
        inherit: true,
        policy: {},
      },
    }));
    markDirty();
  };

  const handleExport = () => {
    try {
      const data = buildConfig();
      downloadJSON(data, "csp-config.json");
      showSuccess("CSP configuration exported");
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
        const data = JSON.parse(text);
        if (!data || typeof data !== "object") {
          throw new Error("Invalid CSP config: must be a JSON object");
        }
        const typed = data as CSPConfig;
        if (typed.enabled !== undefined) setEnabled(typed.enabled !== false);
        if (typed.global_defaults) setGlobalDefaults(typed.global_defaults);
        if (typed.services) setServiceConfigs(typed.services);
        setDirty(true);
        showSuccess("CSP config imported — save or deploy to apply");
      } catch (err: unknown) {
        setError("Failed to parse config: " + (err instanceof Error ? err.message : "unknown error"));
      }
    };
    input.click();
  };

  // All known service hosts
  const allHosts = Array.from(
    new Set([
      ...Object.keys(serviceConfigs),
      ...services.map((s) => s.service),
    ])
  ).sort();
  const unconfiguredHosts = allHosts.filter((h) => !serviceConfigs[h]);

  // ── Loading state ──
  if (loading) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className={T.pageTitle}>Content Security Policy</h2>
          <p className={T.pageDescription}>Per-service CSP header management</p>
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
            <h2 className={T.pageTitle}>Content Security Policy</h2>
            <p className={T.pageDescription}>
              Configure CSP headers per service. Inherit from global defaults or override individually.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant={enabled ? "outline" : "destructive"}
                  size="sm"
                  onClick={() => { setEnabled(!enabled); markDirty(); }}
                >
                  {enabled ? (
                    <><Shield className="h-3.5 w-3.5" /> Enabled</>
                  ) : (
                    <><ShieldOff className="h-3.5 w-3.5" /> Disabled</>
                  )}
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                {enabled
                  ? "CSP is active. Click to disable all CSP headers across all services."
                  : "CSP is disabled. All services will have no CSP headers. Click to re-enable."}
              </TooltipContent>
            </Tooltip>
            <Separator orientation="vertical" className="h-6" />
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

        {/* CSP disabled banner */}
        {!enabled && (
          <Alert variant="destructive">
            <ShieldOff className="h-4 w-4" />
            <AlertTitle>CSP Disabled</AlertTitle>
            <AlertDescription>
              All CSP headers are disabled. Deploy to remove CSP headers from all services.
              Your configuration is preserved and will be restored when re-enabled.
            </AlertDescription>
          </Alert>
        )}

        {/* Alerts */}
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
              Click "Save & Deploy" to write CSP files and reload Caddy.
            </AlertDescription>
          </Alert>
        )}

        {/* Global Defaults */}
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Globe className="h-4 w-4 text-lv-cyan" />
              <CardTitle className={T.cardTitle}>Global Defaults</CardTitle>
            </div>
            <p className={T.muted}>
              Baseline CSP policy inherited by services with "Inherit Global" enabled.
            </p>
          </CardHeader>
          <CardContent>
            <DirectiveEditor
              policy={globalDefaults}
              onChange={handleGlobalChange}
            />
          </CardContent>
        </Card>

        {/* Service Overrides */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className={T.sectionHeading}>Service Overrides</h3>
              <p className={T.muted}>
                Per-service CSP configuration. Services without overrides get no CSP header by default.
              </p>
            </div>
            {unconfiguredHosts.length > 0 && (
              <Select onValueChange={handleAddService}>
                <SelectTrigger className="w-[200px] h-8 text-xs">
                  <Plus className="h-3 w-3 mr-1" />
                  <SelectValue placeholder="Add service..." />
                </SelectTrigger>
                <SelectContent>
                  {unconfiguredHosts.map((host) => (
                    <SelectItem key={host} value={host} className="text-xs">
                      {host}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </div>

          {Object.keys(serviceConfigs).length === 0 && (
            <Card>
              <CardContent className="p-6 text-center">
                <p className={T.muted}>No service overrides configured. Use the dropdown above to add one.</p>
              </CardContent>
            </Card>
          )}

          {Object.entries(serviceConfigs)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([name, cfg]) => (
              <ServiceCard
                key={name}
                name={name}
                config={cfg}
                onChange={(c) => handleServiceChange(name, c)}
                onRemove={() => handleServiceRemove(name)}
                previewHeader={preview?.services[name]?.header}
              />
            ))}
        </div>

        {/* Preview */}
        <PreviewPanel preview={preview} />
      </div>
    </TooltipProvider>
  );
}

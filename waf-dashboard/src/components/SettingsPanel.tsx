import { useState, useEffect, useCallback, useRef } from "react";
import {
  AlertTriangle,
  Check,
  Save,
  Download,
  Upload,
  Info,
  Rocket,
  Globe,
  Settings2,
  Loader2,
  DatabaseBackup,
  FileUp,
  CheckCircle2,
  XCircle,
  SkipForward,
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
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { TooltipProvider } from "@/components/ui/tooltip";
import {
  getConfig,
  updateConfig,
  fetchServices,
  fetchCRSRules,
  deployConfig,
  downloadBackup,
  restoreBackup,
  type WAFConfig,
  type WAFServiceSettings,
  type ServiceDetail,
  type CRSCategory,
  type FullBackup,
  type RestoreResult,
} from "@/lib/api";
import { T } from "@/lib/typography";
import { ModeSelector, SensitivitySettings, RuleGroupToggles } from "./settings/SettingsFormSections";
import {
  AdvancedParanoiaSettings,
  RequestPolicySettings,
  LimitsSettings,
  AdvancedCRSControls,
  CRSExclusionProfiles,
} from "./settings/AdvancedSettings";
import { ServiceSettingsCard } from "./settings/ServiceSettingsCard";

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

  // Backup/restore state
  const [backupLoading, setBackupLoading] = useState(false);
  const [restoreLoading, setRestoreLoading] = useState(false);
  const [restoreResult, setRestoreResult] = useState<RestoreResult | null>(null);

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
        const data = JSON.parse(text);
        if (!data || typeof data !== "object" || (!data.defaults && !data.services)) {
          throw new Error("Invalid config: must contain 'defaults' or 'services'");
        }
        const typed = data as WAFConfig;
        if (typed.defaults) setDefaults(typed.defaults);
        if (typed.services) setServiceOverrides(typed.services);
        setDirty(true);
        showSuccess("Configuration imported — save or deploy to apply");
      } catch (err: unknown) {
        setError("Failed to parse config: " + (err instanceof Error ? err.message : "unknown error"));
      }
    };
    input.click();
  };

  // ─── Backup / Restore ─────────────────────────────────────────────

  const handleBackupDownload = async () => {
    setBackupLoading(true);
    setError(null);
    try {
      await downloadBackup();
      showSuccess("Backup downloaded");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Backup failed");
    } finally {
      setBackupLoading(false);
    }
  };

  const handleRestoreUpload = () => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json";
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;
      setRestoreLoading(true);
      setError(null);
      setRestoreResult(null);
      try {
        const text = await file.text();
        const data = JSON.parse(text) as FullBackup;
        if (!data.version) {
          throw new Error("Invalid backup file: missing version field");
        }
        const result = await restoreBackup(data);
        setRestoreResult(result);
        if (result.status === "restored") {
          showSuccess("All stores restored successfully — deploy to apply");
        } else {
          setError("Partial restore — some stores failed. See details below.");
        }
        // Reload config to reflect restored data
        loadData();
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "Restore failed");
      } finally {
        setRestoreLoading(false);
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
            <Globe className="h-4 w-4 text-lv-cyan" />
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

      <Separator className="my-2" />

      {/* ── Unified Backup / Restore ── */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <DatabaseBackup className="h-4 w-4 text-lv-purple" />
            <CardTitle className={T.cardTitle}>Backup & Restore</CardTitle>
          </div>
          <CardDescription>
            Download or restore a unified backup of all configuration stores
            (WAF config, CSP, policy rules, rate limits, managed lists).
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-3">
            <Button
              variant="outline"
              size="sm"
              onClick={handleBackupDownload}
              disabled={backupLoading}
            >
              {backupLoading ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Download className="h-3.5 w-3.5" />
              )}
              {backupLoading ? "Downloading..." : "Download Backup"}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleRestoreUpload}
              disabled={restoreLoading}
            >
              {restoreLoading ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <FileUp className="h-3.5 w-3.5" />
              )}
              {restoreLoading ? "Restoring..." : "Restore from Backup"}
            </Button>
          </div>

          {restoreResult && (
            <div className="rounded-md border p-3 space-y-2">
              <div className="flex items-center gap-2 text-sm font-medium">
                {restoreResult.status === "restored" ? (
                  <CheckCircle2 className="h-4 w-4 text-lv-green" />
                ) : (
                  <AlertTriangle className="h-4 w-4 text-lv-peach" />
                )}
                <span>
                  {restoreResult.status === "restored"
                    ? "All stores restored"
                    : "Partial restore — some stores failed"}
                </span>
              </div>
              <div className="grid gap-1.5">
                {Object.entries(restoreResult.results).map(([store, msg]) => {
                  const isOk = msg.startsWith("restored");
                  const isSkipped = msg.startsWith("skipped");
                  const isFailed = msg.startsWith("failed");
                  return (
                    <div
                      key={store}
                      className="flex items-center gap-2 text-xs"
                    >
                      {isOk && <CheckCircle2 className="h-3 w-3 text-lv-green shrink-0" />}
                      {isSkipped && <SkipForward className="h-3 w-3 text-muted-foreground shrink-0" />}
                      {isFailed && <XCircle className="h-3 w-3 text-destructive shrink-0" />}
                      <span className="font-data text-muted-foreground w-24 shrink-0">
                        {store.replace(/_/g, " ")}
                      </span>
                      <span className={isFailed ? "text-destructive" : "text-muted-foreground"}>
                        {msg}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          <p className="text-xs text-muted-foreground">
            The backup includes all five config stores. IPsum blocklists are excluded
            (they auto-refresh from upstream). After restoring, deploy to apply changes.
          </p>
        </CardContent>
      </Card>
    </div>
    </TooltipProvider>
  );
}

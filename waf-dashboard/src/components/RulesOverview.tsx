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
  ChevronRight,
  Shield,
  BookOpen,
} from "lucide-react";
// Dead CRS settings removed — policy engine uses only paranoia_level + inbound_threshold
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
  deployConfig,
  downloadBackup,
  restoreBackup,
  listDefaultRules,
  getCategoryForRule,
  type WAFConfig,
  type WAFServiceSettings,
  type ServiceDetail,
  type FullBackup,
  type RestoreResult,
} from "@/lib/api";
import { T } from "@/lib/typography";
import { SensitivitySettings } from "./settings/SettingsFormSections";
import { CategoryToggles } from "./settings/CategoryToggles";
import { ServiceSettingsCard } from "./settings/ServiceSettingsCard";

// ─── Main Rules Overview ────────────────────────────────────────────

export default function RulesOverview() {
  const [config, setConfig] = useState<WAFConfig | null>(null);
  const [services, setServices] = useState<ServiceDetail[]>([]);
  // categories state removed — RuleGroupToggles was dead (CRS group toggles not used by policy engine)
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

  // CRS ruleset stats
  const [rulesetStats, setRulesetStats] = useState<{
    total: number;
    enabled: number;
    overridden: number;
    plCounts: Record<number, { total: number; enabled: number }>;
    catCounts: Record<string, { total: number; enabled: number }>;
    crsVersion: string;
  } | null>(null);

  // Working copy of the config (only live fields: paranoia_level + inbound_threshold)
  const [defaults, setDefaults] = useState<WAFServiceSettings>({
    mode: "enabled",
    paranoia_level: 1,
    inbound_threshold: 5,
    outbound_threshold: 4,  // kept for API compat — not shown in UI
  });
  const [serviceOverrides, setServiceOverrides] = useState<Record<string, WAFServiceSettings>>({});

  // Collapsible sections
  const [settingsExpanded, setSettingsExpanded] = useState(true);
  const [servicesExpanded, setServicesExpanded] = useState(false);
  const [backupExpanded, setBackupExpanded] = useState(false);

  const loadData = useCallback(() => {
    setLoading(true);
    setError(null);
    const healthP = fetch("/api/health").then(r => r.json()).catch(() => ({}));
    Promise.all([getConfig(), fetchServices(), listDefaultRules(), healthP])
      .then(([cfg, svcs, rules, health]) => {
        setConfig(cfg);
        setDefaults(cfg.defaults);
        setServiceOverrides(cfg.services);
        setServices(svcs);
        setDirty(false);

        // Compute CRS ruleset stats
        const plCounts: Record<number, { total: number; enabled: number }> = {};
        const catCounts: Record<string, { total: number; enabled: number }> = {};
        let enabled = 0;
        let overridden = 0;
        for (const r of rules) {
          if (r.enabled) enabled++;
          if (r.has_override) overridden++;
          const pl = r.paranoia_level ?? 1;
          if (!plCounts[pl]) plCounts[pl] = { total: 0, enabled: 0 };
          plCounts[pl].total++;
          if (r.enabled) plCounts[pl].enabled++;
          const cat = getCategoryForRule(r.id);
          const catKey = cat?.shortName ?? "Other";
          if (!catCounts[catKey]) catCounts[catKey] = { total: 0, enabled: 0 };
          catCounts[catKey].total++;
          if (r.enabled) catCounts[catKey].enabled++;
        }
        setRulesetStats({
          total: rules.length,
          enabled,
          overridden,
          plCounts,
          catCounts,
          crsVersion: health?.crs_version || "unknown",
        });
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
        loadData();
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "Restore failed");
      } finally {
        setRestoreLoading(false);
      }
    };
    input.click();
  };

  // Services that have overrides + services discovered from traffic
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
          <h2 className={T.pageTitle}>Rules</h2>
          <p className={T.pageDescription}>WAF engine configuration and managed rulesets</p>
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
          <h2 className={T.pageTitle}>Rules</h2>
          <p className={T.pageDescription}>
            WAF engine configuration and managed rulesets
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

      {/* ── Managed Rulesets ── */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <BookOpen className="h-4 w-4 text-lv-cyan" />
          <h3 className={T.sectionHeading}>Managed Rulesets</h3>
        </div>

        {rulesetStats && (
          <a
            href="/rules/crs"
            className="block group"
          >
            <Card className="transition-colors hover:border-lv-cyan/40">
              <CardContent className="p-5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-lv-cyan/10">
                      <Shield className="h-5 w-5 text-lv-cyan" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h4 className="text-sm font-semibold">OWASP CRS</h4>
                        <Badge variant="outline" className="text-xs">v{rulesetStats.crsVersion}</Badge>
                      </div>
                      <p className="text-xs text-muted-foreground mt-0.5">
                        {rulesetStats.total} rules &middot; {rulesetStats.enabled} enabled
                        {rulesetStats.overridden > 0 && ` \u00b7 ${rulesetStats.overridden} overridden`}
                      </p>
                    </div>
                  </div>
                  <ChevronRight className="h-5 w-5 text-muted-foreground group-hover:text-lv-cyan transition-colors" />
                </div>

                {/* PL breakdown */}
                <div className="mt-4 grid grid-cols-4 gap-3">
                  {[1, 2, 3, 4].map((pl) => {
                    const s = rulesetStats.plCounts[pl];
                    if (!s) return (
                      <div key={pl} className="rounded-md border border-border bg-lovelace-950 px-3 py-2 text-center">
                        <p className="text-xs text-muted-foreground">PL{pl}</p>
                        <p className="text-sm font-semibold text-muted-foreground/50">0</p>
                      </div>
                    );
                    return (
                      <div key={pl} className="rounded-md border border-border bg-lovelace-950 px-3 py-2 text-center">
                        <p className="text-xs text-muted-foreground">PL{pl}</p>
                        <p className="text-sm font-semibold">
                          {s.enabled}<span className="text-muted-foreground font-normal">/{s.total}</span>
                        </p>
                      </div>
                    );
                  })}
                </div>

                {/* Category mini-pills */}
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {Object.entries(rulesetStats.catCounts)
                    .sort(([, a], [, b]) => b.total - a.total)
                    .map(([cat, s]) => (
                      <span
                        key={cat}
                        className="inline-flex items-center gap-1 rounded-md bg-muted/50 px-2 py-0.5 text-[10px] text-muted-foreground"
                      >
                        {cat}
                        <span className="font-data">{s.enabled}/{s.total}</span>
                      </span>
                    ))}
                </div>
              </CardContent>
            </Card>
          </a>
        )}
      </div>

      {/* ── WAF Engine Settings (collapsible) ── */}
      <Card>
        <div
          className="flex items-center justify-between cursor-pointer px-6 py-4 hover:bg-lovelace-900/30 transition-colors"
          onClick={() => setSettingsExpanded(!settingsExpanded)}
        >
          <div className="flex items-center gap-2">
            <Globe className="h-4 w-4 text-lv-cyan" />
            <h3 className="text-sm font-semibold">WAF Engine Settings</h3>
            <Badge variant="outline" className="text-xs">
              PL{defaults.paranoia_level} · In {defaults.inbound_threshold} · Out {defaults.outbound_threshold}
              {(defaults.disabled_categories?.length ?? 0) > 0 && ` · ${defaults.disabled_categories!.length} cat off`}
            </Badge>
          </div>
          <svg
            className={`h-4 w-4 text-muted-foreground transition-transform ${settingsExpanded ? "rotate-90" : ""}`}
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <polyline points="9 18 15 12 9 6" />
          </svg>
        </div>
        {settingsExpanded && (
          <CardContent className="space-y-5 border-t border-border pt-4">
            <SensitivitySettings settings={defaults} onChange={handleDefaultsChange} />
            <CategoryToggles
              disabled={defaults.disabled_categories ?? []}
              onChange={(cats) => handleDefaultsChange({ ...defaults, disabled_categories: cats.length > 0 ? cats : undefined })}
            />
          </CardContent>
        )}
      </Card>

      {/* ── Per-Service Overrides (collapsible) ── */}
      <Card>
        <div
          className="flex items-center justify-between cursor-pointer px-6 py-4 hover:bg-lovelace-900/30 transition-colors"
          onClick={() => setServicesExpanded(!servicesExpanded)}
        >
          <div className="flex items-center gap-2">
            <Settings2 className="h-4 w-4 text-neon-purple" />
            <h3 className="text-sm font-semibold">Per-Service Overrides</h3>
            <Badge variant="outline" className="text-xs">
              {Object.keys(serviceOverrides).length}
            </Badge>
          </div>
          <svg
            className={`h-4 w-4 text-muted-foreground transition-transform ${servicesExpanded ? "rotate-90" : ""}`}
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <polyline points="9 18 15 12 9 6" />
          </svg>
        </div>
        {servicesExpanded && (
          <CardContent className="space-y-3 border-t border-border pt-4">
            {unconfiguredHosts.length > 0 && (
              <div className="flex justify-end">
                <Select key={Object.keys(serviceOverrides).length} onValueChange={(v) => handleAddServiceOverride(v)}>
                  <SelectTrigger className="w-[260px] text-muted-foreground">
                    <SelectValue placeholder="+ Add service override..." />
                  </SelectTrigger>
                  <SelectContent>
                    {unconfiguredHosts.map((host) => (
                      <SelectItem key={host} value={host}>
                        {host}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            {Object.keys(serviceOverrides).length === 0 ? (
              <p className="text-center text-xs text-muted-foreground py-4">
                No per-service overrides configured. All services use global defaults.
              </p>
            ) : (
              Object.entries(serviceOverrides)
                .sort(([a], [b]) => a.localeCompare(b))
                .map(([host, settings]) => (
                  <ServiceSettingsCard
                    key={host}
                    hostname={host}
                    settings={settings}
                    serviceDetail={services.find((s) => s.service === host)}
                    onChange={(s) => handleServiceChange(host, s)}
                    onRemove={() => handleServiceRemove(host)}
                  />
                ))
            )}
          </CardContent>
        )}
      </Card>

      {/* ── Backup & Restore (collapsible) ── */}
      <Card>
        <div
          className="flex items-center justify-between cursor-pointer px-6 py-4 hover:bg-lovelace-900/30 transition-colors"
          onClick={() => setBackupExpanded(!backupExpanded)}
        >
          <div className="flex items-center gap-2">
            <DatabaseBackup className="h-4 w-4 text-lv-purple" />
            <h3 className="text-sm font-semibold">Backup & Restore</h3>
          </div>
          <svg
            className={`h-4 w-4 text-muted-foreground transition-transform ${backupExpanded ? "rotate-90" : ""}`}
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <polyline points="9 18 15 12 9 6" />
          </svg>
        </div>
        {backupExpanded && (
          <CardContent className="space-y-4 border-t border-border pt-4">
            <p className="text-xs text-muted-foreground">
              Download or restore a unified backup of all configuration stores
              (WAF config, CSP, policy rules, rate limits, managed lists).
            </p>
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
                      <div key={store} className="flex items-center gap-2 text-xs">
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
              The backup includes all config stores. IPsum blocklists are excluded
              (they auto-refresh from upstream). After restoring, deploy to apply changes.
            </p>
          </CardContent>
        )}
      </Card>
    </div>
    </TooltipProvider>
  );
}

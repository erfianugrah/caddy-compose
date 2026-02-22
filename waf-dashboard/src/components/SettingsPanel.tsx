import { useState, useEffect, useCallback } from "react";
import {
  Shield,
  AlertTriangle,
  Check,
  Save,
  Download,
  Upload,
  RefreshCw,
  Info,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  CardFooter,
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
  getConfig,
  updateConfig,
  exportExclusions,
  importExclusions,
  fetchServices,
  type WAFConfig,
  type WAFEngineMode,
  type ServiceProfileMode,
  type ServiceProfile,
  type ServiceDetail,
} from "@/lib/api";

// ─── Paranoia Level Descriptions ────────────────────────────────────

const PARANOIA_DESCRIPTIONS: Record<number, { label: string; desc: string }> = {
  1: {
    label: "Low (PL1)",
    desc: "Minimal false positives. Catches only the most obvious attacks. Recommended for most sites as a starting point.",
  },
  2: {
    label: "Moderate (PL2)",
    desc: "More rules active, some additional false positives possible. Good for sites that have been tuned.",
  },
  3: {
    label: "High (PL3)",
    desc: "Aggressive rule set. Expect false positives that need tuning. For security-sensitive applications.",
  },
  4: {
    label: "Ultra (PL4)",
    desc: "Maximum paranoia. Many false positives expected. Only for highly sensitive applications with extensive tuning.",
  },
};

// ─── Engine Mode Component ──────────────────────────────────────────

function EngineModeSelector({
  value,
  onChange,
}: {
  value: WAFEngineMode;
  onChange: (mode: WAFEngineMode) => void;
}) {
  const modes: { value: WAFEngineMode; label: string; desc: string; color: string }[] = [
    {
      value: "on",
      label: "Enabled",
      desc: "WAF actively blocks malicious requests",
      color: "text-neon-green border-neon-green/30 bg-neon-green/5",
    },
    {
      value: "detection_only",
      label: "Detection Only",
      desc: "WAF logs but does not block requests",
      color: "text-neon-amber border-neon-amber/30 bg-neon-amber/5",
    },
    {
      value: "off",
      label: "Disabled",
      desc: "WAF engine is completely disabled",
      color: "text-neon-pink border-neon-pink/30 bg-neon-pink/5",
    },
  ];

  return (
    <div className="grid gap-3 sm:grid-cols-3">
      {modes.map((mode) => (
        <button
          key={mode.value}
          onClick={() => onChange(mode.value)}
          className={`rounded-lg border p-4 text-left transition-all ${
            value === mode.value
              ? mode.color
              : "border-border bg-navy-950 text-muted-foreground hover:border-border/80"
          }`}
        >
          <div className="flex items-center gap-2">
            <div
              className={`h-2.5 w-2.5 rounded-full ${
                value === mode.value
                  ? mode.value === "on"
                    ? "bg-neon-green"
                    : mode.value === "detection_only"
                      ? "bg-neon-amber"
                      : "bg-neon-pink"
                  : "bg-muted-foreground/30"
              }`}
            />
            <span className="text-sm font-medium">{mode.label}</span>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">{mode.desc}</p>
        </button>
      ))}
    </div>
  );
}

// ─── Main Settings Panel ────────────────────────────────────────────

export default function SettingsPanel() {
  const [config, setConfig] = useState<WAFConfig | null>(null);
  const [services, setServices] = useState<ServiceDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);

  // Local form state
  const [engineMode, setEngineMode] = useState<WAFEngineMode>("on");
  const [paranoiaLevel, setParanoiaLevel] = useState(1);
  const [inboundThreshold, setInboundThreshold] = useState(5);
  const [outboundThreshold, setOutboundThreshold] = useState(4);
  const [serviceProfiles, setServiceProfiles] = useState<ServiceProfile[]>([]);

  const loadData = useCallback(() => {
    setLoading(true);
    setError(null);
    Promise.all([getConfig(), fetchServices()])
      .then(([cfg, svcs]) => {
        setConfig(cfg);
        setServices(svcs);
        setEngineMode(cfg.engine_mode);
        setParanoiaLevel(cfg.paranoia_level);
        setInboundThreshold(cfg.inbound_anomaly_threshold);
        setOutboundThreshold(cfg.outbound_anomaly_threshold);
        setServiceProfiles(cfg.service_profiles);
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
    setTimeout(() => setSuccessMsg(null), 3000);
  };

  const markDirty = () => setDirty(true);

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    try {
      const updated = await updateConfig({
        engine_mode: engineMode,
        paranoia_level: paranoiaLevel,
        inbound_anomaly_threshold: inboundThreshold,
        outbound_anomaly_threshold: outboundThreshold,
        service_profiles: serviceProfiles,
      });
      setConfig(updated);
      setDirty(false);
      showSuccess("Settings saved successfully");
    } catch (err: any) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleProfileChange = (service: string, profile: ServiceProfileMode) => {
    setServiceProfiles((prev) => {
      const existing = prev.find((p) => p.service === service);
      if (existing) {
        return prev.map((p) => (p.service === service ? { ...p, profile } : p));
      }
      return [...prev, { service, profile }];
    });
    markDirty();
  };

  const getProfileForService = (service: string): ServiceProfileMode => {
    return serviceProfiles.find((p) => p.service === service)?.profile ?? "strict";
  };

  const handleExportConfig = async () => {
    try {
      const configData = {
        engine_mode: engineMode,
        paranoia_level: paranoiaLevel,
        inbound_anomaly_threshold: inboundThreshold,
        outbound_anomaly_threshold: outboundThreshold,
        service_profiles: serviceProfiles,
      };
      const blob = new Blob([JSON.stringify(configData, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "waf-config.json";
      a.click();
      URL.revokeObjectURL(url);
      showSuccess("Configuration exported");
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleImportConfig = () => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json";
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const data = JSON.parse(text) as Partial<WAFConfig>;
        if (data.engine_mode) setEngineMode(data.engine_mode);
        if (data.paranoia_level) setParanoiaLevel(data.paranoia_level);
        if (data.inbound_anomaly_threshold !== undefined)
          setInboundThreshold(data.inbound_anomaly_threshold);
        if (data.outbound_anomaly_threshold !== undefined)
          setOutboundThreshold(data.outbound_anomaly_threshold);
        if (data.service_profiles) setServiceProfiles(data.service_profiles);
        setDirty(true);
        showSuccess("Configuration imported — save to apply");
      } catch (err: any) {
        setError("Failed to parse config file: " + err.message);
      }
    };
    input.click();
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className="text-lg font-semibold">Settings</h2>
          <p className="text-sm text-muted-foreground">WAF engine configuration</p>
        </div>
        <div className="space-y-4">
          {[...Array(4)].map((_, i) => (
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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-lg font-semibold">Settings</h2>
          <p className="text-sm text-muted-foreground">
            Configure the WAF engine, paranoia level, and anomaly scoring thresholds.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={handleExportConfig}>
            <Download className="h-3.5 w-3.5" />
            Export
          </Button>
          <Button variant="outline" size="sm" onClick={handleImportConfig}>
            <Upload className="h-3.5 w-3.5" />
            Import
          </Button>
          <Button
            size="sm"
            onClick={handleSave}
            disabled={!dirty || saving}
          >
            <Save className="h-3.5 w-3.5" />
            {saving ? "Saving..." : "Save Changes"}
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
            You have unsaved configuration changes. Click "Save Changes" to apply.
          </AlertDescription>
        </Alert>
      )}

      {/* WAF Engine Status */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-neon-green" />
            <CardTitle className="text-sm">WAF Engine Status</CardTitle>
          </div>
          <CardDescription>
            Control whether the WAF engine is actively blocking, detection-only, or disabled
          </CardDescription>
        </CardHeader>
        <CardContent>
          <EngineModeSelector
            value={engineMode}
            onChange={(mode) => {
              setEngineMode(mode);
              markDirty();
            }}
          />
        </CardContent>
      </Card>

      {/* Paranoia Level */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Paranoia Level</CardTitle>
          <CardDescription>
            Higher levels enable more rules but may cause more false positives
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-6">
            <div className="flex-1">
              <Slider
                value={[paranoiaLevel]}
                onValueChange={(v) => {
                  setParanoiaLevel(v[0]);
                  markDirty();
                }}
                min={1}
                max={4}
                step={1}
              />
              <div className="mt-2 flex justify-between text-xs text-muted-foreground">
                <span>1</span>
                <span>2</span>
                <span>3</span>
                <span>4</span>
              </div>
            </div>
            <div className="w-16 text-center">
              <span className="text-2xl font-bold text-neon-green">
                {paranoiaLevel}
              </span>
            </div>
          </div>

          <div className="rounded-md border border-border bg-navy-950 p-3">
            <p className="text-xs font-medium text-foreground">
              {PARANOIA_DESCRIPTIONS[paranoiaLevel]?.label}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              {PARANOIA_DESCRIPTIONS[paranoiaLevel]?.desc}
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Anomaly Thresholds */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Anomaly Scoring Thresholds</CardTitle>
          <CardDescription>
            Requests scoring above these thresholds will be blocked (when engine is enabled)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-6 sm:grid-cols-2">
            <div className="space-y-2">
              <Label className="text-xs uppercase tracking-wider text-muted-foreground">
                Inbound Anomaly Threshold
              </Label>
              <div className="flex items-center gap-3">
                <Input
                  type="number"
                  min={1}
                  max={100}
                  value={inboundThreshold}
                  onChange={(e) => {
                    setInboundThreshold(Number(e.target.value));
                    markDirty();
                  }}
                  className="w-24"
                />
                <span className="text-xs text-muted-foreground">
                  Default: 5
                </span>
              </div>
              <p className="text-xs text-muted-foreground">
                Cumulative anomaly score threshold for incoming requests
              </p>
            </div>

            <div className="space-y-2">
              <Label className="text-xs uppercase tracking-wider text-muted-foreground">
                Outbound Anomaly Threshold
              </Label>
              <div className="flex items-center gap-3">
                <Input
                  type="number"
                  min={1}
                  max={100}
                  value={outboundThreshold}
                  onChange={(e) => {
                    setOutboundThreshold(Number(e.target.value));
                    markDirty();
                  }}
                  className="w-24"
                />
                <span className="text-xs text-muted-foreground">
                  Default: 4
                </span>
              </div>
              <p className="text-xs text-muted-foreground">
                Cumulative anomaly score threshold for outgoing responses
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Per-Service Profiles */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Per-Service Profiles</CardTitle>
          <CardDescription>
            Override WAF behavior for individual services
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {services.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Service</TableHead>
                  <TableHead className="text-right">Events</TableHead>
                  <TableHead className="text-right">Block Rate</TableHead>
                  <TableHead>Profile</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {services.map((svc) => (
                  <TableRow key={svc.service}>
                    <TableCell className="font-medium text-xs">
                      {svc.service}
                    </TableCell>
                    <TableCell className="text-right tabular-nums text-xs">
                      {svc.total_events.toLocaleString()}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-2">
                        <div className="h-2 w-12 overflow-hidden rounded-full bg-navy-800">
                          <div
                            className={`h-full rounded-full transition-all ${
                              svc.block_rate > 50
                                ? "bg-neon-pink"
                                : svc.block_rate > 20
                                  ? "bg-neon-amber"
                                  : "bg-neon-green"
                            }`}
                            style={{ width: `${Math.min(svc.block_rate, 100)}%` }}
                          />
                        </div>
                        <span className="text-xs tabular-nums text-muted-foreground">
                          {svc.block_rate.toFixed(1)}%
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Select
                        value={getProfileForService(svc.service)}
                        onValueChange={(v) =>
                          handleProfileChange(svc.service, v as ServiceProfileMode)
                        }
                      >
                        <SelectTrigger className="w-[120px]">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="strict">
                            <div className="flex items-center gap-2">
                              <div className="h-2 w-2 rounded-full bg-neon-green" />
                              Strict
                            </div>
                          </SelectItem>
                          <SelectItem value="tuning">
                            <div className="flex items-center gap-2">
                              <div className="h-2 w-2 rounded-full bg-neon-amber" />
                              Tuning
                            </div>
                          </SelectItem>
                          <SelectItem value="off">
                            <div className="flex items-center gap-2">
                              <div className="h-2 w-2 rounded-full bg-neon-pink" />
                              Off
                            </div>
                          </SelectItem>
                        </SelectContent>
                      </Select>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="py-8 text-center text-xs text-muted-foreground">
              No services discovered yet. Services will appear as traffic flows through the WAF.
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

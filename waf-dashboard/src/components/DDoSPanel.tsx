import { useState, useEffect, useCallback } from "react";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Plus,
  Trash2,
  Save,
  Loader2,
  RefreshCw,
  AlertTriangle,
  Activity,
  Lock,
  Fingerprint,
  Timer,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { StatCard } from "@/components/StatCard";
import { T } from "@/lib/typography";
import { cn } from "@/lib/utils";
import {
  fetchDosStatus,
  fetchJail,
  addJail,
  removeJail,
  getDosConfig,
  updateDosConfig,
  fetchSpikeReports,
  type DosStatus,
  type JailEntry,
  type DosConfig,
  type SpikeReport,
} from "@/lib/api";

// ─── Status Banner ──────────────────────────────────────────────────

function StatusBanner({ status, loading }: { status: DosStatus | null; loading: boolean }) {
  if (loading || !status) {
    return (
      <Card>
        <CardContent className="pt-6">
          <div className="flex items-center gap-3">
            <Skeleton className="h-10 w-10 rounded-full" />
            <div className="space-y-2">
              <Skeleton className="h-5 w-32" />
              <Skeleton className="h-4 w-24" />
            </div>
          </div>
        </CardContent>
      </Card>
    );
  }

  const isSpike = status.mode === "spike";

  return (
    <Card className={cn(
      "transition-colors",
      isSpike && "border-lv-peach-bright/50 bg-lv-peach-bright/5"
    )}>
      <CardContent className="pt-6">
        <div className="flex items-center gap-4">
          <div className={cn(
            "rounded-full p-3",
            isSpike ? "bg-lv-peach-bright/15 text-lv-peach-bright animate-pulse" : "bg-lv-green/15 text-lv-green"
          )}>
            {isSpike ? <ShieldAlert className="h-6 w-6" /> : <ShieldCheck className="h-6 w-6" />}
          </div>
          <div>
            <p className={cn(T.pageTitle, isSpike ? "text-lv-peach-bright" : "text-lv-green")}>
              {isSpike ? "SPIKE DETECTED" : "MONITORING"}
            </p>
            <p className={T.muted}>
              {status.eps.toFixed(1)} events/sec
              {isSpike && ` \u00b7 peak: ${status.peak_eps.toFixed(1)}`}
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Stat Cards Row ─────────────────────────────────────────────────

function StatsRow({ status, jail, loading }: { status: DosStatus | null; jail: JailEntry[]; loading: boolean }) {
  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <StatCard
        title="Events / sec"
        value={status ? Math.round(status.eps * 10) / 10 : 0}
        icon={Activity}
        color="cyan"
        loading={loading}
      />
      <StatCard
        title="Jailed IPs"
        value={jail.length}
        icon={Lock}
        color={jail.length > 0 ? "red" : "green"}
        loading={loading}
      />
      <StatCard
        title="Strategy"
        value={0}
        icon={Fingerprint}
        color="purple"
        loading={loading}
      />
      <StatCard
        title="Peak EPS"
        value={status ? Math.round(status.peak_eps * 10) / 10 : 0}
        icon={AlertTriangle}
        color={status && status.peak_eps > 50 ? "orange" : "blue"}
        loading={loading}
      />
    </div>
  );
}

// ─── Jail Table ─────────────────────────────────────────────────────

function JailTable({
  entries,
  loading,
  onRemove,
  onAdd,
}: {
  entries: JailEntry[];
  loading: boolean;
  onRemove: (ip: string) => void;
  onAdd: (ip: string, ttl: string, reason: string) => void;
}) {
  const [showAdd, setShowAdd] = useState(false);
  const [newIP, setNewIP] = useState("");
  const [newTTL, setNewTTL] = useState("1h");
  const [newReason, setNewReason] = useState("manual");

  const handleAdd = () => {
    if (!newIP.trim()) return;
    onAdd(newIP.trim(), newTTL, newReason);
    setNewIP("");
    setShowAdd(false);
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className={T.cardTitle}>IP Jail ({entries.length})</CardTitle>
            <CardDescription>IPs blocked by adaptive detection or manual action</CardDescription>
          </div>
          <Button size="sm" onClick={() => setShowAdd(!showAdd)}>
            <Plus className="h-3.5 w-3.5" />
            Jail IP
          </Button>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        {showAdd && (
          <div className="flex gap-2 mx-6 mb-4 p-3 rounded-md border bg-muted/30">
            <Input
              placeholder="IP address"
              value={newIP}
              onChange={(e) => setNewIP(e.target.value)}
              className="flex-1"
              onKeyDown={(e) => e.key === "Enter" && handleAdd()}
            />
            <Input
              placeholder="TTL"
              value={newTTL}
              onChange={(e) => setNewTTL(e.target.value)}
              className="w-24"
            />
            <Input
              placeholder="Reason"
              value={newReason}
              onChange={(e) => setNewReason(e.target.value)}
              className="w-32"
            />
            <Button size="sm" onClick={handleAdd}>Add</Button>
          </div>
        )}

        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead>IP Address</TableHead>
                <TableHead>Reason</TableHead>
                <TableHead className="text-right">Infractions</TableHead>
                <TableHead>TTL Remaining</TableHead>
                <TableHead>Jailed At</TableHead>
                <TableHead className="w-10"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && [...Array(3)].map((_, i) => (
                <TableRow key={i}>
                  {[...Array(6)].map((_, j) => (
                    <TableCell key={j}><Skeleton className="h-4 w-full" /></TableCell>
                  ))}
                </TableRow>
              ))}

              {!loading && entries.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="py-8 text-center text-muted-foreground">
                    No jailed IPs — all traffic is flowing normally
                  </TableCell>
                </TableRow>
              )}

              {entries.map((e) => (
                <TableRow key={e.ip}>
                  <TableCell className={T.tableCellMono}>{e.ip}</TableCell>
                  <TableCell>
                    <Badge
                      variant={e.reason.startsWith("auto") ? "destructive" : "secondary"}
                      className={T.badgeMono}
                    >
                      {e.reason}
                    </Badge>
                  </TableCell>
                  <TableCell className={T.tableCellNumeric}>{e.infractions}</TableCell>
                  <TableCell className={T.tableCellMono}>{e.ttl}</TableCell>
                  <TableCell className={T.muted}>
                    {new Date(e.jailed_at).toLocaleString()}
                  </TableCell>
                  <TableCell>
                    <Button size="sm" variant="ghost" onClick={() => onRemove(e.ip)} title="Unjail">
                      <Trash2 className="h-3.5 w-3.5 text-destructive" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Config Panel ───────────────────────────────────────────────────

function ConfigPanel({
  config,
  loading,
  onSave,
  saving,
}: {
  config: DosConfig | null;
  loading: boolean;
  onSave: (cfg: DosConfig) => void;
  saving: boolean;
}) {
  const [draft, setDraft] = useState<DosConfig | null>(null);
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    if (config) {
      setDraft({ ...config });
      setDirty(false);
    }
  }, [config]);

  if (loading || !draft) {
    return (
      <Card>
        <CardHeader><Skeleton className="h-5 w-40" /></CardHeader>
        <CardContent><Skeleton className="h-64 w-full" /></CardContent>
      </Card>
    );
  }

  const update = <K extends keyof DosConfig>(key: K, value: DosConfig[K]) => {
    setDraft((d) => (d ? { ...d, [key]: value } : d));
    setDirty(true);
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className={T.cardTitle}>Configuration</CardTitle>
            <CardDescription>Adaptive detection thresholds and penalties</CardDescription>
          </div>
          <Button onClick={() => onSave(draft)} disabled={!dirty || saving} size="sm">
            {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
            Save
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Detection */}
        <div>
          <p className={T.sectionLabel}>Detection</p>
          <div className="grid gap-4 sm:grid-cols-2 mt-3">
            <div>
              <label className={T.formLabel}>Z-Score Threshold</label>
              <Input
                type="number"
                step="0.5"
                min="1"
                max="10"
                value={draft.threshold}
                onChange={(e) => update("threshold", parseFloat(e.target.value) || 4)}
              />
              <p className={cn(T.muted, "mt-1")}>Higher = fewer auto-jails</p>
            </div>
            <div>
              <label className={T.formLabel}>Fingerprint Strategy</label>
              <Select value={draft.strategy} onValueChange={(v) => update("strategy", v)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="auto">Auto (adaptive)</SelectItem>
                  <SelectItem value="full">Full (IP+method+path+UA)</SelectItem>
                  <SelectItem value="ip_path">IP + Path</SelectItem>
                  <SelectItem value="ip_only">IP Only</SelectItem>
                  <SelectItem value="path_ua">Path + UA</SelectItem>
                  <SelectItem value="path_only">Path Only</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </div>

        <Separator />

        {/* Penalties */}
        <div>
          <p className={T.sectionLabel}>Penalties</p>
          <div className="grid gap-4 sm:grid-cols-2 mt-3">
            <div>
              <label className={T.formLabel}>Base Penalty</label>
              <Input value={draft.base_penalty} onChange={(e) => update("base_penalty", e.target.value)} />
            </div>
            <div>
              <label className={T.formLabel}>Max Penalty</label>
              <Input value={draft.max_penalty} onChange={(e) => update("max_penalty", e.target.value)} />
            </div>
          </div>
        </div>

        <Separator />

        {/* Spike Detection */}
        <div>
          <p className={T.sectionLabel}>Spike Detection</p>
          <div className="grid gap-4 sm:grid-cols-3 mt-3">
            <div>
              <label className={T.formLabel}>EPS Trigger</label>
              <Input
                type="number"
                value={draft.eps_trigger}
                onChange={(e) => update("eps_trigger", parseFloat(e.target.value) || 50)}
              />
            </div>
            <div>
              <label className={T.formLabel}>EPS Cooldown</label>
              <Input
                type="number"
                value={draft.eps_cooldown}
                onChange={(e) => update("eps_cooldown", parseFloat(e.target.value) || 10)}
              />
            </div>
            <div>
              <label className={T.formLabel}>Cooldown Delay</label>
              <Input value={draft.cooldown_delay} onChange={(e) => update("cooldown_delay", e.target.value)} />
            </div>
          </div>
        </div>

        <Separator />

        {/* Whitelist */}
        <div>
          <p className={T.sectionLabel}>Whitelist (CIDR)</p>
          <div className="mt-3">
            <Input
              value={draft.whitelist.join(", ")}
              onChange={(e) =>
                update("whitelist", e.target.value.split(",").map((s) => s.trim()).filter(Boolean))
              }
              placeholder="192.168.0.0/16, 10.0.0.0/8"
            />
            <p className={cn(T.muted, "mt-1")}>Comma-separated CIDR prefixes that bypass jail checks</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Main Panel ─────────────────────────────────────────────────────

export default function DDoSPanel() {
  const [status, setStatus] = useState<DosStatus | null>(null);
  const [jail, setJail] = useState<JailEntry[]>([]);
  const [config, setConfig] = useState<DosConfig | null>(null);
  const [reports, setReports] = useState<SpikeReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [s, j, c, r] = await Promise.all([fetchDosStatus(), fetchJail(), getDosConfig(), fetchSpikeReports()]);
      setStatus(s);
      setJail(j);
      setConfig(c);
      setReports(r || []);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, status?.mode === "spike" ? 5000 : 30000);
    return () => clearInterval(id);
  }, [refresh, status?.mode]);

  // Auto-dismiss success after 3s
  useEffect(() => {
    if (success) {
      const t = setTimeout(() => setSuccess(null), 3000);
      return () => clearTimeout(t);
    }
  }, [success]);

  const handleAddJail = async (ip: string, ttl: string, reason: string) => {
    try {
      await addJail(ip, ttl, reason);
      setSuccess(`Jailed ${ip} for ${ttl}`);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const handleRemoveJail = async (ip: string) => {
    try {
      await removeJail(ip);
      setSuccess(`Unjailed ${ip}`);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const handleSaveConfig = async (cfg: DosConfig) => {
    setSaving(true);
    try {
      await updateDosConfig(cfg);
      setConfig(cfg);
      setSuccess("Configuration saved");
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className={T.pageTitle}>DDoS Protection</h2>
          <p className={T.pageDescription}>Adaptive fingerprint-based mitigation with IP jail</p>
        </div>
        <Button variant="outline" size="sm" onClick={refresh} disabled={loading}>
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
          Refresh
        </Button>
      </div>

      {/* Alerts */}
      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {success && (
        <Alert>
          <ShieldCheck className="h-4 w-4" />
          <AlertDescription>{success}</AlertDescription>
        </Alert>
      )}

      {/* Status banner */}
      <StatusBanner status={status} loading={loading} />

      {/* Stat cards */}
      <StatsRow status={status} jail={jail} loading={loading} />

      {/* Jail table */}
      <JailTable entries={jail} loading={loading} onRemove={handleRemoveJail} onAdd={handleAddJail} />

      {/* Spike Reports */}
      {reports.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className={T.cardTitle}>Spike Reports ({reports.length})</CardTitle>
            <CardDescription>Forensic snapshots from detected traffic spikes</CardDescription>
          </CardHeader>
          <CardContent className="p-0 overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>ID</TableHead>
                  <TableHead>Start</TableHead>
                  <TableHead>Duration</TableHead>
                  <TableHead className="text-right">Peak EPS</TableHead>
                  <TableHead className="text-right">Events</TableHead>
                  <TableHead className="text-right">Jailed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {reports.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell className={T.tableCellMono}>{r.id}</TableCell>
                    <TableCell className={T.muted}>{new Date(r.start_time).toLocaleString()}</TableCell>
                    <TableCell className={T.tableCellMono}>{r.duration}</TableCell>
                    <TableCell className={T.tableCellNumeric}>{r.peak_eps.toFixed(1)}</TableCell>
                    <TableCell className={T.tableCellNumeric}>{r.total_events.toLocaleString()}</TableCell>
                    <TableCell className={T.tableCellNumeric}>{r.jailed_ips}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Configuration */}
      <ConfigPanel config={config} loading={loading} onSave={handleSaveConfig} saving={saving} />
    </div>
  );
}

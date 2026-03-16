import { useState, useEffect, useCallback } from "react";
import {
  Shield,
  ShieldAlert,
  Plus,
  Trash2,
  Save,
  Loader2,
  RefreshCw,
  AlertTriangle,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import { T } from "@/lib/typography";
import { cn } from "@/lib/utils";
import {
  fetchDosStatus,
  fetchJail,
  addJail,
  removeJail,
  getDosConfig,
  updateDosConfig,
  type DosStatus,
  type JailEntry,
  type DosConfig,
} from "@/lib/api";

// ─── Status Banner ──────────────────────────────────────────────────

function StatusBanner({ status }: { status: DosStatus | null }) {
  if (!status) return <Skeleton className="h-20 w-full" />;

  const isSpike = status.mode === "spike";
  return (
    <Card className={isSpike ? "border-amber-500 bg-amber-500/5" : ""}>
      <CardContent className="pt-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            {isSpike ? (
              <ShieldAlert className="h-8 w-8 text-amber-500 animate-pulse" />
            ) : (
              <Shield className="h-8 w-8 text-emerald-500" />
            )}
            <div>
              <p className="text-lg font-semibold">
                {isSpike ? "SPIKE DETECTED" : "MONITORING"}
              </p>
              <p className={T.muted}>
                {status.eps.toFixed(1)} events/sec
                {isSpike && ` (peak: ${status.peak_eps.toFixed(1)})`}
              </p>
            </div>
          </div>
          <div className="flex gap-4 text-sm">
            <div className="text-center">
              <p className={T.muted}>Jailed IPs</p>
              <p className="text-2xl font-bold">{status.jail_count}</p>
            </div>
            <div className="text-center">
              <p className={T.muted}>Strategy</p>
              <p className="font-mono">{status.strategy}</p>
            </div>
            {status.kernel_drop && (
              <Badge variant="outline" className="self-center">nftables</Badge>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
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
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-base">IP Jail</CardTitle>
        <Button size="sm" variant="outline" onClick={() => setShowAdd(!showAdd)}>
          <Plus className="h-4 w-4 mr-1" /> Jail IP
        </Button>
      </CardHeader>
      <CardContent>
        {showAdd && (
          <div className="flex gap-2 mb-4 p-3 rounded-md border bg-muted/30">
            <Input
              placeholder="IP address"
              value={newIP}
              onChange={(e) => setNewIP(e.target.value)}
              className="flex-1"
              onKeyDown={(e) => e.key === "Enter" && handleAdd()}
            />
            <Input
              placeholder="TTL (e.g. 1h)"
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

        {loading ? (
          <Skeleton className="h-32 w-full" />
        ) : entries.length === 0 ? (
          <p className={cn(T.muted, "text-center py-8")}>No jailed IPs</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left">
                  <th className="py-2 pr-4">IP</th>
                  <th className="py-2 pr-4">Reason</th>
                  <th className="py-2 pr-4">Infractions</th>
                  <th className="py-2 pr-4">TTL</th>
                  <th className="py-2 pr-4">Jailed At</th>
                  <th className="py-2 w-10"></th>
                </tr>
              </thead>
              <tbody>
                {entries.map((e) => (
                  <tr key={e.ip} className="border-b hover:bg-muted/50">
                    <td className="py-2 pr-4 font-mono">{e.ip}</td>
                    <td className="py-2 pr-4">
                      <Badge variant={e.reason.startsWith("auto") ? "destructive" : "secondary"}>
                        {e.reason}
                      </Badge>
                    </td>
                    <td className="py-2 pr-4">{e.infractions}</td>
                    <td className="py-2 pr-4 font-mono text-xs">{e.ttl}</td>
                    <td className="py-2 pr-4 text-xs text-muted-foreground">
                      {new Date(e.jailed_at).toLocaleString()}
                    </td>
                    <td className="py-2">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => onRemove(e.ip)}
                        title="Unjail"
                      >
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Config Panel ───────────────────────────────────────────────────

function ConfigPanel({
  config,
  loading,
  onSave,
}: {
  config: DosConfig | null;
  loading: boolean;
  onSave: (cfg: DosConfig) => void;
}) {
  const [draft, setDraft] = useState<DosConfig | null>(null);

  useEffect(() => {
    if (config) setDraft({ ...config });
  }, [config]);

  if (loading || !draft) return <Skeleton className="h-64 w-full" />;

  const update = <K extends keyof DosConfig>(key: K, value: DosConfig[K]) => {
    setDraft((d) => (d ? { ...d, [key]: value } : d));
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Configuration</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <Label>Z-Score Threshold</Label>
            <Input
              type="number"
              step="0.5"
              value={draft.threshold}
              onChange={(e) => update("threshold", parseFloat(e.target.value) || 4)}
            />
            <p className={cn(T.muted, "mt-1")}>Higher = fewer auto-jails, lower = more aggressive</p>
          </div>
          <div>
            <Label>Fingerprint Strategy</Label>
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

        <Separator />

        <div className="grid grid-cols-2 gap-4">
          <div>
            <Label>Base Penalty</Label>
            <Input
              value={draft.base_penalty}
              onChange={(e) => update("base_penalty", e.target.value)}
            />
          </div>
          <div>
            <Label>Max Penalty</Label>
            <Input
              value={draft.max_penalty}
              onChange={(e) => update("max_penalty", e.target.value)}
            />
          </div>
        </div>

        <Separator />
        <p className={T.sectionLabel}>Spike Detection</p>

        <div className="grid grid-cols-3 gap-4">
          <div>
            <Label>EPS Trigger</Label>
            <Input
              type="number"
              value={draft.eps_trigger}
              onChange={(e) => update("eps_trigger", parseFloat(e.target.value) || 50)}
            />
          </div>
          <div>
            <Label>EPS Cooldown</Label>
            <Input
              type="number"
              value={draft.eps_cooldown}
              onChange={(e) => update("eps_cooldown", parseFloat(e.target.value) || 10)}
            />
          </div>
          <div>
            <Label>Cooldown Delay</Label>
            <Input
              value={draft.cooldown_delay}
              onChange={(e) => update("cooldown_delay", e.target.value)}
            />
          </div>
        </div>

        <Separator />
        <p className={T.sectionLabel}>Whitelist (CIDR)</p>
        <Input
          value={draft.whitelist.join(", ")}
          onChange={(e) =>
            update("whitelist", e.target.value.split(",").map((s) => s.trim()).filter(Boolean))
          }
          placeholder="192.168.0.0/16, 10.0.0.0/8"
        />

        <div className="flex justify-end">
          <Button onClick={() => onSave(draft)}>
            <Save className="h-4 w-4 mr-1" /> Save Configuration
          </Button>
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
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [s, j, c] = await Promise.all([fetchDosStatus(), fetchJail(), getDosConfig()]);
      setStatus(s);
      setJail(j);
      setConfig(c);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    // Poll status every 5s during spike, 30s normally
    const id = setInterval(refresh, status?.mode === "spike" ? 5000 : 30000);
    return () => clearInterval(id);
  }, [refresh, status?.mode]);

  const handleAddJail = async (ip: string, ttl: string, reason: string) => {
    try {
      await addJail(ip, ttl, reason);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const handleRemoveJail = async (ip: string) => {
    try {
      await removeJail(ip);
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
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className={T.pageTitle}>DDoS Protection</h3>
          <p className={T.pageDescription}>Adaptive fingerprint-based mitigation with IP jail</p>
        </div>
        <Button variant="outline" size="sm" onClick={refresh} disabled={loading}>
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
        </Button>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <StatusBanner status={status} />

      <JailTable
        entries={jail}
        loading={loading}
        onRemove={handleRemoveJail}
        onAdd={handleAddJail}
      />

      <ConfigPanel config={config} loading={loading} onSave={handleSaveConfig} />
    </div>
  );
}

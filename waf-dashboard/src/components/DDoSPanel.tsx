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
  Users,
  Zap,
  ChevronDown,
  ChevronRight,
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
import { DurationInput } from "@/components/ui/duration-input";
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
  fetchProfiles,
  type DosStatus,
  type JailEntry,
  type DosConfig,
  type SpikeReport,
  type IPProfile,
} from "@/lib/api";

// ─── Status Banner ──────────────────────────────────────────────────

function Sparkline({
  data,
  threshold,
  width = 200,
  height = 40,
}: {
  data: number[];
  threshold?: number;
  width?: number;
  height?: number;
}) {
  if (!data || data.length < 2) return null;
  const max = Math.max(...data, threshold ?? 0, 1);
  const points = data
    .map((v, i) => `${(i / (data.length - 1)) * width},${height - (v / max) * height}`)
    .join(" ");
  const thresholdY = threshold != null ? height - (threshold / max) * height : null;

  return (
    <svg width={width} height={height} className="opacity-70">
      {/* Fill area under curve */}
      <defs>
        <linearGradient id="spark-fill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="currentColor" stopOpacity="0.3" />
          <stop offset="100%" stopColor="currentColor" stopOpacity="0.02" />
        </linearGradient>
      </defs>
      <polygon
        points={`0,${height} ${points} ${width},${height}`}
        fill="url(#spark-fill)"
      />
      <polyline
        points={points}
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* Threshold line */}
      {thresholdY != null && (
        <line
          x1={0} y1={thresholdY} x2={width} y2={thresholdY}
          stroke="currentColor"
          strokeWidth="1"
          strokeDasharray="3,3"
          opacity="0.4"
        />
      )}
    </svg>
  );
}

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
        <div className="flex items-center justify-between">
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
                {isSpike && ` · peak: ${status.peak_eps.toFixed(1)}`}
              </p>
            </div>
          </div>
          <div className={cn("text-muted-foreground", isSpike && "text-lv-peach-bright")}>
            <Sparkline data={status.eps_history} threshold={status ? undefined : undefined} />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Stat Cards Row ─────────────────────────────────────────────────

function StatsRow({ status, jail, loading }: { status: DosStatus | null; jail: JailEntry[]; loading: boolean }) {
  const rateJails = status?.rate_jail_count ?? 0;
  const behavJails = status?.behav_jail_count ?? 0;
  const totalJails = rateJails + behavJails;

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
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardDescription className={T.statLabelUpper}>Jail Breakdown</CardDescription>
          <div className="rounded-md p-2 text-lv-purple bg-lv-purple/15">
            <Zap className="h-4 w-4" />
          </div>
        </CardHeader>
        <CardContent>
          {loading ? <Skeleton className="h-7 w-20" /> : (
            <div>
              <p className={cn(T.statValue, "text-lv-purple")}>{totalJails}</p>
              <p className={cn(T.muted, "text-xs mt-1")}>
                {rateJails > 0 && <span className="text-lv-peach-bright">{rateJails} rate</span>}
                {rateJails > 0 && behavJails > 0 && " · "}
                {behavJails > 0 && <span className="text-lv-red">{behavJails} behavioral</span>}
                {totalJails === 0 && "none in window"}
              </p>
            </div>
          )}
        </CardContent>
      </Card>
      <StatCard
        title="Peak EPS"
        value={status ? Math.round(Math.max(status.peak_eps, ...(status.eps_history ?? [0])) * 10) / 10 : 0}
        icon={AlertTriangle}
        color={status && Math.max(status.peak_eps, ...(status.eps_history ?? [0])) > 50 ? "orange" : "blue"}
        loading={loading}
      />
    </div>
  );
}

// ─── Jail Table ─────────────────────────────────────────────────────

function reasonBadgeClass(reason: string): string {
  if (reason === "auto:rate") return "bg-lv-peach-bright/15 text-lv-peach-bright border-lv-peach-bright/30";
  if (reason.startsWith("auto:behavioral") || reason.startsWith("auto:")) return "bg-lv-red/15 text-lv-red border-lv-red/30";
  return "bg-lovelace-800 text-muted-foreground border-lovelace-700";
}

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
                <TableHead className="text-right">Score</TableHead>
                <TableHead className="text-right">Infractions</TableHead>
                <TableHead>TTL Remaining</TableHead>
                <TableHead>Jailed At</TableHead>
                <TableHead className="w-10"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && [...Array(3)].map((_, i) => (
                <TableRow key={i}>
                  {[...Array(7)].map((_, j) => (
                    <TableCell key={j}><Skeleton className="h-4 w-full" /></TableCell>
                  ))}
                </TableRow>
              ))}

              {!loading && entries.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="py-8 text-center text-muted-foreground">
                    No jailed IPs — all traffic is flowing normally
                  </TableCell>
                </TableRow>
              )}

              {entries.map((e) => (
                <TableRow key={e.ip}>
                  <TableCell className={T.tableCellMono}>{e.ip}</TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={cn(T.badgeMono, reasonBadgeClass(e.reason))}
                    >
                      {e.reason}
                    </Badge>
                  </TableCell>
                  <TableCell className={T.tableCellNumeric}>
                    {e.anomaly_score > 0 ? (
                      <span className={e.anomaly_score >= 0.65 ? "text-lv-red" : "text-lv-yellow"}>
                        {e.anomaly_score.toFixed(2)}
                      </span>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
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

// ─── Behavioral Profiles Tab ─────────────────────────────────────────

function ProfilesTable({ profiles, loading }: { profiles: IPProfile[]; loading: boolean }) {
  const [expanded, setExpanded] = useState<string | null>(null);

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-5 w-48" />
        </CardHeader>
        <CardContent><Skeleton className="h-32 w-full" /></CardContent>
      </Card>
    );
  }

  if (profiles.length === 0) {
    return (
      <Card>
        <CardContent className="py-10 text-center text-muted-foreground">
          No suspicious IPs in recent window — traffic is clean.
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className={T.cardTitle}>Behavioral Profiles ({profiles.length})</CardTitle>
        <CardDescription>
          IPs with recent DDoS events. Score reflects L2 path diversity; L3 host diversity
          dampening is applied at jail-decision time by the plugin.
        </CardDescription>
      </CardHeader>
      <CardContent className="p-0 overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="w-6"></TableHead>
              <TableHead>IP Address</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Score</TableHead>
              <TableHead>Hosts</TableHead>
              <TableHead className="text-right">Blocked</TableHead>
              <TableHead className="text-right">Jailed Events</TableHead>
              <TableHead>TTL</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {profiles.map((p) => (
              <>
                <TableRow
                  key={p.ip}
                  className="cursor-pointer"
                  onClick={() => setExpanded(expanded === p.ip ? null : p.ip)}
                >
                  <TableCell>
                    {expanded === p.ip
                      ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
                      : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
                    }
                  </TableCell>
                  <TableCell className={T.tableCellMono}>{p.ip}</TableCell>
                  <TableCell>
                    {p.is_jailed ? (
                      <Badge variant="destructive" className={T.badgeMono}>jailed</Badge>
                    ) : (
                      <Badge variant="outline" className={cn(T.badgeMono, "text-lv-yellow border-lv-yellow/30")}>
                        monitoring
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className={T.tableCellNumeric}>
                    <span className={p.anomaly_score >= 0.65 ? "text-lv-red" : p.anomaly_score >= 0.4 ? "text-lv-yellow" : "text-muted-foreground"}>
                      {p.anomaly_score > 0 ? p.anomaly_score.toFixed(3) : "—"}
                    </span>
                  </TableCell>
                  <TableCell>
                    <span className={cn(T.muted, "text-xs")}>
                      {p.hosts && p.hosts.length > 0
                        ? `${p.hosts.length} service${p.hosts.length > 1 ? "s" : ""}`
                        : "—"}
                    </span>
                  </TableCell>
                  <TableCell className={T.tableCellNumeric}>{p.blocked_reqs}</TableCell>
                  <TableCell className={T.tableCellNumeric}>{p.jailed_reqs}</TableCell>
                  <TableCell className={cn(T.tableCellMono, "text-xs")}>{p.ttl ?? "—"}</TableCell>
                </TableRow>

                {expanded === p.ip && (
                  <TableRow key={`${p.ip}-detail`} className="bg-muted/20 hover:bg-muted/20">
                    <TableCell colSpan={8} className="py-3 px-6">
                      <div className="grid gap-3 sm:grid-cols-2">
                        {p.hosts && p.hosts.length > 0 && (
                          <div>
                            <p className={cn(T.formLabel, "mb-1.5")}>Services hit</p>
                            <div className="flex flex-wrap gap-1">
                              {p.hosts.map((h) => (
                                <Badge key={h} variant="outline" className="text-xs font-mono">
                                  {h}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        )}
                        {p.top_paths && p.top_paths.length > 0 && (
                          <div>
                            <p className={cn(T.formLabel, "mb-1.5")}>Top paths</p>
                            <div className="space-y-0.5">
                              {p.top_paths.map((path) => (
                                <p key={path} className="font-mono text-xs text-muted-foreground truncate">
                                  {path}
                                </p>
                              ))}
                            </div>
                          </div>
                        )}
                        {p.jail_reason && (
                          <div>
                            <p className={cn(T.formLabel, "mb-1")}>Jail reason</p>
                            <Badge variant="outline" className={cn(T.badgeMono, reasonBadgeClass(p.jail_reason))}>
                              {p.jail_reason}
                            </Badge>
                          </div>
                        )}
                        <div>
                          <p className={cn(T.formLabel, "mb-1")}>L3 dampening</p>
                          <p className="text-xs text-muted-foreground">
                            {p.hosts && p.hosts.length > 1
                              ? `${p.hosts.length} hosts → ÷${Math.log2(p.hosts.length + 1).toFixed(2)} factor`
                              : "1 host — no dampening applied"}
                          </p>
                        </div>
                      </div>
                    </TableCell>
                  </TableRow>
                )}
              </>
            ))}
          </TableBody>
        </Table>
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

        {/* Detection — L2 */}
        <div>
          <p className={T.sectionLabel}>Detection — L2 Behavioral (per-service)</p>
          <div className="grid gap-4 sm:grid-cols-2 mt-3">
            <div>
              <label className={T.formLabel}>Anomaly Score Threshold</label>
              <Select
                value={String(draft.threshold)}
                onValueChange={(v) => update("threshold", parseFloat(v))}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="0.50">0.50 — Very aggressive</SelectItem>
                  <SelectItem value="0.55">0.55 — Aggressive</SelectItem>
                  <SelectItem value="0.60">0.60 — Strict</SelectItem>
                  <SelectItem value="0.65">0.65 — Balanced (default)</SelectItem>
                  <SelectItem value="0.70">0.70 — Permissive</SelectItem>
                  <SelectItem value="0.75">0.75 — More permissive</SelectItem>
                  <SelectItem value="0.80">0.80 — Very permissive</SelectItem>
                  <SelectItem value="0.90">0.90 — Minimal</SelectItem>
                </SelectContent>
              </Select>
              <p className={cn(T.muted, "mt-1")}>Per-(IP, service) path diversity threshold</p>
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

        {/* L1 Rate Gate */}
        <div>
          <p className={T.sectionLabel}>L1 Rate Gate (global per-IP)</p>
          <div className="grid gap-4 sm:grid-cols-2 mt-3">
            <div>
              <label className={T.formLabel}>Global Rate Threshold (req/s)</label>
              <Select
                value={String(draft.global_rate_threshold ?? 0)}
                onValueChange={(v) => update("global_rate_threshold", parseFloat(v))}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="0">0 — Disabled</SelectItem>
                  <SelectItem value="20">20 — Strict</SelectItem>
                  <SelectItem value="50">50 — Moderate</SelectItem>
                  <SelectItem value="100">100 — Permissive</SelectItem>
                  <SelectItem value="200">200 — High traffic</SelectItem>
                  <SelectItem value="500">500 — Very high</SelectItem>
                </SelectContent>
              </Select>
              <p className={cn(T.muted, "mt-1")}>Sustained req/s per IP before L1 rate jail fires</p>
            </div>
            <div>
              <label className={T.formLabel}>Min Hosts for L3 Exculpation</label>
              <Select
                value={String(draft.min_host_exculpation ?? 2)}
                onValueChange={(v) => update("min_host_exculpation", parseInt(v))}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">1 — Always dampen (even single-service)</SelectItem>
                  <SelectItem value="2">2 — Default (2+ services needed)</SelectItem>
                  <SelectItem value="3">3 — Stricter (3+ services needed)</SelectItem>
                  <SelectItem value="5">5 — Very strict</SelectItem>
                </SelectContent>
              </Select>
              <p className={cn(T.muted, "mt-1")}>Unique services before host-diversity dampening activates</p>
            </div>
          </div>
        </div>

        <Separator />

        {/* Profile Tuning */}
        <div>
          <p className={T.sectionLabel}>Profile Tuning</p>
          <div className="grid gap-4 sm:grid-cols-2 mt-3">
            <div>
              <label className={T.formLabel}>Profile TTL</label>
              <Select
                value={draft.profile_ttl || "10m"}
                onValueChange={(v) => update("profile_ttl", v)}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="2m">2m — Short window</SelectItem>
                  <SelectItem value="5m">5m — Moderate</SelectItem>
                  <SelectItem value="10m">10m — Default</SelectItem>
                  <SelectItem value="15m">15m — Extended</SelectItem>
                  <SelectItem value="30m">30m — Long</SelectItem>
                </SelectContent>
              </Select>
              <p className={cn(T.muted, "mt-1")}>How long per-(IP, service) profiles are retained</p>
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
              <DurationInput
                value={draft.base_penalty}
                onChange={(v) => update("base_penalty", v)}
                presets={["30s", "60s", "2m", "5m", "10m", "30m"]}
              />
              <p className={cn(T.muted, "mt-1")}>First offense jail duration</p>
            </div>
            <div>
              <label className={T.formLabel}>Max Penalty</label>
              <DurationInput
                value={draft.max_penalty}
                onChange={(v) => update("max_penalty", v)}
                presets={["1h", "6h", "12h", "24h", "3d", "7d"]}
              />
              <p className={cn(T.muted, "mt-1")}>Cap for exponential backoff</p>
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
              <Select
                value={String(draft.eps_trigger)}
                onValueChange={(v) => update("eps_trigger", parseFloat(v) || 50)}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="10">10 — Low traffic</SelectItem>
                  <SelectItem value="25">25 — Light</SelectItem>
                  <SelectItem value="50">50 — Moderate (default)</SelectItem>
                  <SelectItem value="100">100 — Busy</SelectItem>
                  <SelectItem value="250">250 — High traffic</SelectItem>
                  <SelectItem value="500">500 — Very high</SelectItem>
                  <SelectItem value="1000">1000 — Enterprise</SelectItem>
                </SelectContent>
              </Select>
              <p className={cn(T.muted, "mt-1")}>Events/sec to trigger spike mode</p>
            </div>
            <div>
              <label className={T.formLabel}>EPS Cooldown</label>
              <Select
                value={String(draft.eps_cooldown)}
                onValueChange={(v) => update("eps_cooldown", parseFloat(v) || 10)}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="5">5 — Quick recovery</SelectItem>
                  <SelectItem value="10">10 — Normal (default)</SelectItem>
                  <SelectItem value="20">20 — Cautious</SelectItem>
                  <SelectItem value="50">50 — Conservative</SelectItem>
                </SelectContent>
              </Select>
              <p className={cn(T.muted, "mt-1")}>EPS to exit spike mode</p>
            </div>
            <div>
              <label className={T.formLabel}>Cooldown Delay</label>
              <DurationInput
                value={draft.cooldown_delay}
                onChange={(v) => update("cooldown_delay", v)}
                presets={["10s", "15s", "30s", "60s", "2m"]}
              />
              <p className={cn(T.muted, "mt-1")}>Wait before exiting spike mode</p>
            </div>
          </div>
        </div>

        <Separator />

        {/* Whitelist */}
        <div>
          <p className={T.sectionLabel}>Whitelist (CIDR)</p>
          <div className="mt-3 space-y-2">
            <div className="flex flex-wrap gap-1.5 min-h-[2rem]">
              {draft.whitelist.map((cidr, i) => (
                <Badge key={i} variant="outline" className="text-xs px-2 py-1 bg-lovelace-950 border-lovelace-700 text-lv-cyan gap-1 font-mono">
                  {cidr}
                  <button
                    type="button"
                    className="ml-0.5 text-muted-foreground hover:text-lv-red transition-colors"
                    onClick={() => update("whitelist", draft.whitelist.filter((_, j) => j !== i))}
                  >
                    ×
                  </button>
                </Badge>
              ))}
            </div>
            <div className="flex gap-2">
              <Input
                placeholder="10.0.0.0/8"
                className="font-mono text-sm"
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === ",") {
                    e.preventDefault();
                    const val = (e.target as HTMLInputElement).value.trim();
                    if (val && !draft.whitelist.includes(val)) {
                      update("whitelist", [...draft.whitelist, val]);
                      (e.target as HTMLInputElement).value = "";
                    }
                  }
                }}
              />
            </div>
            <p className={cn(T.muted, "text-xs")}>Press Enter to add a CIDR prefix. These IPs bypass jail checks.</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Spike Reports ──────────────────────────────────────────────────

function SpikeReports({ reports, loading }: { reports: SpikeReport[]; loading: boolean }) {
  const [expanded, setExpanded] = useState<string | null>(null);

  if (!loading && reports.length === 0) {
    return (
      <Card>
        <CardContent className="py-10 text-center text-muted-foreground">
          No spike reports recorded — traffic has been within normal parameters.
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className={T.cardTitle}>Spike Reports ({reports.length})</CardTitle>
        <CardDescription>Forensic snapshots from detected traffic spikes</CardDescription>
      </CardHeader>
      <CardContent className="p-0 overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="w-6"></TableHead>
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
              <>
                <TableRow
                  key={r.id}
                  className="cursor-pointer"
                  onClick={() => setExpanded(expanded === r.id ? null : r.id)}
                >
                  <TableCell>
                    {expanded === r.id
                      ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
                      : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
                    }
                  </TableCell>
                  <TableCell className={T.tableCellMono}>{r.id}</TableCell>
                  <TableCell className={T.muted}>{new Date(r.start_time).toLocaleString()}</TableCell>
                  <TableCell className={T.tableCellMono}>{r.duration}</TableCell>
                  <TableCell className={T.tableCellNumeric}>{r.peak_eps.toFixed(1)}</TableCell>
                  <TableCell className={T.tableCellNumeric}>{r.total_events.toLocaleString()}</TableCell>
                  <TableCell className={T.tableCellNumeric}>{r.jailed_ips}</TableCell>
                </TableRow>
                {expanded === r.id && (r.top_ips || r.top_paths) && (
                  <TableRow key={`${r.id}-detail`} className="bg-muted/20 hover:bg-muted/20">
                    <TableCell colSpan={7} className="py-3 px-6">
                      <div className="grid gap-3 sm:grid-cols-2">
                        {r.top_ips && r.top_ips.length > 0 && (
                          <div>
                            <p className={cn(T.formLabel, "mb-1.5")}>Top IPs</p>
                            <div className="space-y-0.5">
                              {r.top_ips.slice(0, 5).map((entry) => (
                                <div key={entry.key} className="flex justify-between text-xs">
                                  <span className="font-mono text-muted-foreground">{entry.key}</span>
                                  <span className="text-muted-foreground">{entry.count}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                        {r.top_paths && r.top_paths.length > 0 && (
                          <div>
                            <p className={cn(T.formLabel, "mb-1.5")}>Top paths</p>
                            <div className="space-y-0.5">
                              {r.top_paths.slice(0, 5).map((entry) => (
                                <div key={entry.key} className="flex justify-between text-xs">
                                  <span className="font-mono text-muted-foreground truncate max-w-[200px]">{entry.key}</span>
                                  <span className="text-muted-foreground ml-2">{entry.count}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                )}
              </>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

// ─── Main Panel ─────────────────────────────────────────────────────

type Tab = "jail" | "profiles" | "reports" | "config";

export default function DDoSPanel() {
  const [tab, setTab] = useState<Tab>("jail");
  const [status, setStatus] = useState<DosStatus | null>(null);
  const [jail, setJail] = useState<JailEntry[]>([]);
  const [config, setConfig] = useState<DosConfig | null>(null);
  const [reports, setReports] = useState<SpikeReport[]>([]);
  const [profiles, setProfiles] = useState<IPProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [s, j, c, r, p] = await Promise.all([
        fetchDosStatus(),
        fetchJail(),
        getDosConfig(),
        fetchSpikeReports(),
        fetchProfiles(),
      ]);
      setStatus(s);
      setJail(j);
      setConfig(c);
      setReports(r || []);
      setProfiles(p || []);
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

  const tabs: { id: Tab; label: string; badge?: number }[] = [
    { id: "jail", label: "IP Jail", badge: jail.length > 0 ? jail.length : undefined },
    { id: "profiles", label: "Profiles", badge: profiles.length > 0 ? profiles.length : undefined },
    { id: "reports", label: "Spike Reports", badge: reports.length > 0 ? reports.length : undefined },
    { id: "config", label: "Configuration" },
  ];

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className={T.pageTitle}>DDoS Protection</h2>
          <p className={T.pageDescription}>
            Three-layer adaptive mitigation: L1 rate gate · L2 per-service behavioral · L3 host diversity exculpation
          </p>
        </div>
        <div className="flex items-center gap-3">
          {status?.updated_at && (
            <p className={T.muted}>
              Updated {new Date(status.updated_at).toLocaleTimeString()}
            </p>
          )}
          <Badge variant="outline" className={cn(T.badgeMono, "text-muted-foreground")}>
            {status?.mode === "spike" ? "5s" : "30s"} poll
          </Badge>
          <Button variant="outline" size="sm" onClick={refresh} disabled={loading}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
          </Button>
        </div>
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

      {/* Tab navigation */}
      <div className="flex gap-1 border-b border-lovelace-800">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={cn(
              "px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px flex items-center gap-1.5",
              tab === t.id
                ? "border-lv-cyan text-lv-cyan"
                : "border-transparent text-muted-foreground hover:text-foreground"
            )}
          >
            {t.label}
            {t.badge != null && (
              <Badge variant="secondary" className="text-xs h-4 px-1 min-w-[1rem]">
                {t.badge}
              </Badge>
            )}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === "jail" && (
        <JailTable entries={jail} loading={loading} onRemove={handleRemoveJail} onAdd={handleAddJail} />
      )}
      {tab === "profiles" && (
        <ProfilesTable profiles={profiles} loading={loading} />
      )}
      {tab === "reports" && (
        <SpikeReports reports={reports} loading={loading} />
      )}
      {tab === "config" && (
        <ConfigPanel config={config} loading={loading} onSave={handleSaveConfig} saving={saving} />
      )}
    </div>
  );
}

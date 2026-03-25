import { useState, useEffect, useCallback } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  RefreshCw,
  Loader2,
  AlertTriangle,
  Users,
  ShieldAlert,
  MousePointerClick,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import {
  fetchSessionStats,
  fetchSessionConfig,
  updateSessionConfig,
  type SessionStats,
  type SessionSummary,
  type SessionScoringConfig,
} from "@/lib/api";

// ─── Theme tokens (matches other panels) ────────────────────────────
const T = {
  pageTitle: "text-xl font-semibold tracking-tight",
  pageDescription: "text-sm text-muted-foreground",
  statLabelUpper: "text-[11px] font-medium uppercase tracking-wider text-muted-foreground",
  statValue: "text-2xl font-bold tabular-nums",
  cardTitle: "text-sm font-medium",
  tableCellMono: "font-mono text-xs",
  tableCellNumeric: "text-right tabular-nums text-xs",
  badgeMono: "font-mono text-[10px]",
};

// ─── Score color helpers ────────────────────────────────────────────
function scoreColor(score: number): string {
  if (score >= 0.6) return "text-lv-red";
  if (score >= 0.4) return "text-lv-yellow";
  return "text-lv-green";
}

function scoreBadgeVariant(score: number): "destructive" | "secondary" | "outline" {
  if (score >= 0.6) return "destructive";
  if (score >= 0.4) return "secondary";
  return "outline";
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rs = s % 60;
  return rs > 0 ? `${m}m ${rs}s` : `${m}m`;
}

function formatTime(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

// ─── Flag badge colors ──────────────────────────────────────────────
const flagColors: Record<string, string> = {
  single_page: "bg-lv-red/15 text-lv-red border-lv-red/30",
  short_session: "bg-lv-peach/15 text-lv-peach border-lv-peach/30",
  uniform_dwell: "bg-lv-red/15 text-lv-red border-lv-red/30",
  no_scroll: "bg-lv-yellow/15 text-lv-yellow border-lv-yellow/30",
  no_interaction: "bg-lv-yellow/15 text-lv-yellow border-lv-yellow/30",
  low_visible: "bg-lv-peach/15 text-lv-peach border-lv-peach/30",
  organic_browsing: "bg-lv-green/15 text-lv-green border-lv-green/30",
};

const flagLabels: Record<string, string> = {
  single_page: "Single Page",
  short_session: "Short Session",
  uniform_dwell: "Uniform Dwell",
  no_scroll: "No Scroll",
  no_interaction: "No Interaction",
  low_visible: "Low Visibility",
  organic_browsing: "Organic",
};

// ─── Main Component ─────────────────────────────────────────────────

export default function SessionsPanel() {
  const [stats, setStats] = useState<SessionStats | null>(null);
  const [config, setConfig] = useState<SessionScoringConfig | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [s, c] = await Promise.all([fetchSessionStats(), fetchSessionConfig()]);
      setStats(s);
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
    const id = setInterval(refresh, 30000);
    return () => clearInterval(id);
  }, [refresh]);

  return (
    <div className="space-y-6">
      {/* ── Header ──────────────────────────────────────────── */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className={T.pageTitle}>Session Tracking</h2>
          <p className={T.pageDescription}>
            Behavioral analysis of post-challenge browsing sessions
          </p>
        </div>
        <div className="flex items-center gap-3">
          {config?.denylist_enabled && (
            <Badge className="bg-lv-red/15 text-lv-red border-lv-red/30 text-[10px]">
              Denylist Active
            </Badge>
          )}
          <Badge variant="outline" className={cn(T.badgeMono, "text-muted-foreground")}>
            30s poll
          </Badge>
          <Button
            variant={showSettings ? "secondary" : "outline"}
            size="sm"
            onClick={() => setShowSettings(!showSettings)}
          >
            Settings
          </Button>
          <Button variant="outline" size="sm" onClick={refresh} disabled={loading}>
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4" />
            )}
          </Button>
        </div>
      </div>

      {/* ── Error alert ─────────────────────────────────────── */}
      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* ── Success alert ──────────────────────────────────── */}
      {success && (
        <Alert>
          <AlertDescription>{success}</AlertDescription>
        </Alert>
      )}

      {/* ── Settings panel ──────────────────────────────────── */}
      {showSettings && config && (
        <Card>
          <CardHeader>
            <CardTitle className={T.cardTitle}>Scoring Configuration</CardTitle>
            <CardDescription>
              Adjust behavioral scoring weights and denylist settings. Changes take effect immediately
              and re-score all active sessions.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <Label htmlFor="denylist-toggle" className="text-sm font-medium">
                  Denylist Enabled
                </Label>
                <p className="text-xs text-muted-foreground">
                  When enabled, suspicious JTIs are written to the denylist file and
                  the plugin rejects those cookies, forcing re-challenge.
                </p>
              </div>
              <Switch
                id="denylist-toggle"
                checked={config.denylist_enabled}
                onCheckedChange={(checked) => setConfig({ ...config, denylist_enabled: checked })}
              />
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <Label className="text-xs">Denylist Threshold</Label>
                <Input
                  type="number"
                  min={0} max={1} step={0.05}
                  value={config.denylist_threshold}
                  onChange={(e) => setConfig({ ...config, denylist_threshold: parseFloat(e.target.value) || 0 })}
                  className="mt-1 h-8 text-xs"
                />
                <p className="text-[10px] text-muted-foreground mt-0.5">Score at which JTIs get denied (0-1)</p>
              </div>
              <div>
                <Label className="text-xs">Organic Bonus</Label>
                <Input
                  type="number"
                  min={-1} max={0} step={0.05}
                  value={config.organic_bonus}
                  onChange={(e) => setConfig({ ...config, organic_bonus: parseFloat(e.target.value) || 0 })}
                  className="mt-1 h-8 text-xs"
                />
                <p className="text-[10px] text-muted-foreground mt-0.5">Subtracted for organic browsing (negative)</p>
              </div>
            </div>

            <div>
              <Label className="text-xs font-medium mb-2 block">Indicator Weights</Label>
              <div className="grid gap-2 sm:grid-cols-3">
                {([
                  ["weight_single_page", "Single Page"],
                  ["weight_short_session", "Short Session"],
                  ["weight_uniform_dwell", "Uniform Dwell"],
                  ["weight_no_scroll", "No Scroll"],
                  ["weight_no_interaction", "No Interaction"],
                  ["weight_low_visible", "Low Visibility"],
                ] as [keyof SessionScoringConfig, string][]).map(([key, label]) => (
                  <div key={key}>
                    <Label className="text-[10px] text-muted-foreground">{label}</Label>
                    <Input
                      type="number"
                      min={0} max={1} step={0.05}
                      value={config[key] as number}
                      onChange={(e) => setConfig({ ...config, [key]: parseFloat(e.target.value) || 0 })}
                      className="mt-0.5 h-7 text-xs"
                    />
                  </div>
                ))}
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => { refresh(); setShowSettings(false); }}
              >
                Cancel
              </Button>
              <Button
                size="sm"
                disabled={saving}
                onClick={async () => {
                  setSaving(true);
                  setSuccess(null);
                  try {
                    const updated = await updateSessionConfig(config);
                    setConfig(updated);
                    setSuccess("Configuration saved. All sessions re-scored.");
                    setTimeout(() => setSuccess(null), 3000);
                  } catch (e) {
                    setError(e instanceof Error ? e.message : String(e));
                  } finally {
                    setSaving(false);
                  }
                }}
              >
                {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : "Save"}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── Stat cards ──────────────────────────────────────── */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardDescription className={T.statLabelUpper}>Active Sessions</CardDescription>
            <div className="rounded-md p-2 text-lv-cyan bg-lv-cyan/15">
              <Users className="h-4 w-4" />
            </div>
          </CardHeader>
          <CardContent>
            {loading ? (
              <Skeleton className="h-7 w-16" />
            ) : (
              <p className={cn(T.statValue, "text-lv-cyan")}>
                {stats?.active_sessions ?? 0}
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardDescription className={T.statLabelUpper}>Suspicious</CardDescription>
            <div className="rounded-md p-2 text-lv-red bg-lv-red/15">
              <ShieldAlert className="h-4 w-4" />
            </div>
          </CardHeader>
          <CardContent>
            {loading ? (
              <Skeleton className="h-7 w-16" />
            ) : (
              <p className={cn(T.statValue, stats?.suspicious_sessions ? "text-lv-red" : "text-lv-green")}>
                {stats?.suspicious_sessions ?? 0}
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardDescription className={T.statLabelUpper}>Total Navigations</CardDescription>
            <div className="rounded-md p-2 text-lv-purple bg-lv-purple/15">
              <MousePointerClick className="h-4 w-4" />
            </div>
          </CardHeader>
          <CardContent>
            {loading ? (
              <Skeleton className="h-7 w-16" />
            ) : (
              <p className={cn(T.statValue, "text-lv-purple")}>
                {stats?.total_navigations ?? 0}
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* ── Suspicious sessions table ───────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle className={T.cardTitle}>
            Flagged Sessions{" "}
            {stats?.top_suspicious && stats.top_suspicious.length > 0 && (
              <span className="text-muted-foreground font-normal">
                ({stats.top_suspicious.length})
              </span>
            )}
          </CardTitle>
          <CardDescription>
            Sessions with suspicious behavioral patterns (score &ge; 0.4)
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>JTI</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>Service</TableHead>
                  <TableHead className="text-right">Score</TableHead>
                  <TableHead className="text-right">Pages</TableHead>
                  <TableHead className="text-right">Duration</TableHead>
                  <TableHead>Flags</TableHead>
                  <TableHead>Last Seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading &&
                  [...Array(3)].map((_, i) => (
                    <TableRow key={i}>
                      {[...Array(8)].map((_, j) => (
                        <TableCell key={j}>
                          <Skeleton className="h-4 w-full" />
                        </TableCell>
                      ))}
                    </TableRow>
                  ))}

                {!loading &&
                  (!stats?.top_suspicious || stats.top_suspicious.length === 0) && (
                    <TableRow>
                      <TableCell
                        colSpan={8}
                        className="py-12 text-center text-muted-foreground"
                      >
                        No suspicious sessions detected. Sessions are tracked after
                        challenge PoW solve.
                      </TableCell>
                    </TableRow>
                  )}

                {stats?.top_suspicious?.map((s: SessionSummary) => (
                  <TableRow key={s.jti}>
                    <TableCell className={T.tableCellMono}>
                      {s.jti.substring(0, 12)}...
                    </TableCell>
                    <TableCell className={T.tableCellMono}>{s.ip}</TableCell>
                    <TableCell className="text-xs">{s.service}</TableCell>
                    <TableCell className={cn(T.tableCellNumeric, scoreColor(s.score))}>
                      {(s.score * 100).toFixed(0)}%
                    </TableCell>
                    <TableCell className={T.tableCellNumeric}>{s.page_count}</TableCell>
                    <TableCell className={T.tableCellNumeric}>
                      {formatDuration(s.duration_ms)}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {s.flags?.map((flag) => (
                          <Badge
                            key={flag}
                            variant={scoreBadgeVariant(s.score)}
                            className={cn(
                              "text-[9px] px-1.5 py-0",
                              flagColors[flag] || ""
                            )}
                          >
                            {flagLabels[flag] || flag}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {formatTime(s.last_seen)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

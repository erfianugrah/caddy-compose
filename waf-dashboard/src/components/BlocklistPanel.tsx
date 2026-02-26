import { useState, useEffect, useCallback } from "react";
import { Ban, RefreshCw, Search, ExternalLink, Clock, Database, Shield, Download } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  getBlocklistStats,
  checkBlocklistIP,
  refreshBlocklist,
  type BlocklistStats,
  type BlocklistCheckResult,
  type BlocklistRefreshResult,
} from "@/lib/api";
import { formatNumberLocale as formatNumber } from "@/lib/format";

// ─── Helpers ────────────────────────────────────────────────────────

function formatBlocklistDate(ts: string): string {
  if (!ts) return "Unknown";
  try {
    const d = new Date(ts);
    return d.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch {
    return ts;
  }
}

// ─── Stat Card with left border accent ──────────────────────────────

function BlocklistStat({
  title,
  value,
  subtitle,
  color,
  loading,
}: {
  title: string;
  value: string;
  subtitle: string;
  color: string;
  loading: boolean;
}) {
  const borderMap: Record<string, string> = {
    pink: "border-l-neon-pink",
    green: "border-l-neon-green",
    cyan: "border-l-neon-cyan",
  };

  return (
    <Card className={`border-l-2 ${borderMap[color] ?? "border-l-neon-cyan"}`}>
      <CardContent className="pt-4 pb-4">
        {loading ? (
          <div className="space-y-2">
            <Skeleton className="h-3 w-20" />
            <Skeleton className="h-6 w-28" />
            <Skeleton className="h-3 w-32" />
          </div>
        ) : (
          <>
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
              {title}
            </p>
            <p className="mt-1 text-xl font-bold tabular-nums text-foreground">
              {value}
            </p>
            <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p>
          </>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Main Component ─────────────────────────────────────────────────

export default function BlocklistPanel() {
  const [stats, setStats] = useState<BlocklistStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Refresh (update from upstream) state
  const [refreshing, setRefreshing] = useState(false);
  const [refreshResult, setRefreshResult] = useState<BlocklistRefreshResult | null>(null);
  const [refreshError, setRefreshError] = useState<string | null>(null);

  // IP check state
  const [checkIP, setCheckIP] = useState("");
  const [checkResult, setCheckResult] = useState<BlocklistCheckResult | null>(null);
  const [checking, setChecking] = useState(false);
  const [checkError, setCheckError] = useState<string | null>(null);

  const loadStats = useCallback(() => {
    setLoading(true);
    setError(null);
    getBlocklistStats()
      .then(setStats)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = useCallback(async () => {
    setRefreshing(true);
    setRefreshResult(null);
    setRefreshError(null);
    try {
      const result = await refreshBlocklist();
      setRefreshResult(result);
      // Reload stats to reflect the new data.
      loadStats();
    } catch (err: unknown) {
      setRefreshError(err instanceof Error ? err.message : "Refresh failed");
    } finally {
      setRefreshing(false);
    }
  }, [loadStats]);

  // Auto-dismiss refresh result after 10 seconds.
  useEffect(() => {
    if (!refreshResult && !refreshError) return;
    const timer = setTimeout(() => {
      setRefreshResult(null);
      setRefreshError(null);
    }, 10_000);
    return () => clearTimeout(timer);
  }, [refreshResult, refreshError]);

  useEffect(() => {
    loadStats();
  }, [loadStats]);

  const handleCheck = useCallback(async () => {
    const ip = checkIP.trim();
    if (!ip) return;

    // Basic client-side IP validation
    const ipv4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    const ipv6 = /^[0-9a-fA-F:]+$/;
    if (!ipv4.test(ip) && !ipv6.test(ip)) {
      setCheckError("Invalid IP address format");
      return;
    }

    setChecking(true);
    setCheckError(null);
    setCheckResult(null);
    try {
      const result = await checkBlocklistIP(ip);
      setCheckResult(result);
    } catch (err: unknown) {
      setCheckError(err instanceof Error ? err.message : "Check failed");
    } finally {
      setChecking(false);
    }
  }, [checkIP]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter") handleCheck();
    },
    [handleCheck]
  );

  if (error) {
    return (
      <div className="flex items-center justify-center py-20">
        <Card className="max-w-md">
          <CardHeader>
            <CardTitle className="text-neon-pink">Connection Error</CardTitle>
            <CardDescription>
              Could not reach the WAF API.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <pre className="rounded-md bg-navy-950 p-3 text-xs text-muted-foreground">
              {error}
            </pre>
            <Button
              variant="outline"
              size="sm"
              className="mt-3"
              onClick={loadStats}
            >
              Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-lg font-semibold">Blocklist</h2>
          <p className="text-sm text-muted-foreground">
            IPsum threat intelligence blocklist
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            disabled={refreshing || loading}
          >
            <Download className={`mr-2 h-3.5 w-3.5 ${refreshing ? "animate-bounce" : ""}`} />
            {refreshing ? "Updating\u2026" : "Update Now"}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={loadStats}
            disabled={loading}
          >
            <RefreshCw className={`mr-2 h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 sm:grid-cols-3">
        <BlocklistStat
          title="Blocked IPs"
          value={stats ? formatNumber(stats.blocked_ips) : "0"}
          subtitle={`IPsum score \u2265 ${stats?.min_score ?? 3}`}
          color="pink"
          loading={loading}
        />
        <BlocklistStat
          title="Last Updated"
          value={stats ? formatBlocklistDate(stats.last_updated) : "Unknown"}
          subtitle="Daily 06:00 UTC via CronJob"
          color="green"
          loading={loading}
        />
        <BlocklistStat
          title="Source"
          value="IPsum"
          subtitle="github.com/stamparm/ipsum"
          color="cyan"
          loading={loading}
        />
      </div>

      {/* Refresh result/error */}
      {refreshResult && (
        <Alert
          variant={refreshResult.status === "error" ? "destructive" : "default"}
          className={
            refreshResult.status === "error"
              ? ""
              : "border-neon-green/30 bg-neon-green/5"
          }
        >
          <AlertTitle className="text-xs font-medium">
            {refreshResult.status === "updated"
              ? "Blocklist Updated"
              : refreshResult.status === "partial"
                ? "Blocklist Updated (Caddy reload failed)"
                : "Update Failed"}
          </AlertTitle>
          <AlertDescription className="text-xs">
            {refreshResult.message}
          </AlertDescription>
        </Alert>
      )}
      {refreshError && (
        <Alert variant="destructive">
          <AlertTitle className="text-xs font-medium">Update Failed</AlertTitle>
          <AlertDescription className="text-xs">{refreshError}</AlertDescription>
        </Alert>
      )}

      {/* Check IP */}
      <Card className="border-l-2 border-l-neon-green">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Search className="h-4 w-4 text-neon-green" />
              <CardTitle className="text-sm">Check IP</CardTitle>
            </div>
            <CardDescription>Search blocklist</CardDescription>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-3">
            <input
              type="text"
              value={checkIP}
              onChange={(e) => {
                setCheckIP(e.target.value);
                setCheckResult(null);
                setCheckError(null);
              }}
              onKeyDown={handleKeyDown}
              placeholder="Enter IP to check ..."
              className="flex-1 rounded-md border border-border bg-navy-950 px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:border-neon-green focus:outline-none focus:ring-1 focus:ring-neon-green/50 font-mono"
            />
            <Button
              variant="outline"
              size="sm"
              onClick={handleCheck}
              disabled={checking || !checkIP.trim()}
              className="px-4"
            >
              {checking ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Search className="h-3.5 w-3.5" />
              )}
            </Button>
          </div>

          {/* Check result */}
          {checkResult && (
            <div
              className={`flex items-center gap-3 rounded-md border p-3 ${
                checkResult.blocked
                  ? "border-neon-pink/30 bg-neon-pink/5"
                  : "border-neon-green/30 bg-neon-green/5"
              }`}
            >
              {checkResult.blocked ? (
                <Ban className="h-5 w-5 shrink-0 text-neon-pink" />
              ) : (
                <Shield className="h-5 w-5 shrink-0 text-neon-green" />
              )}
              <div className="flex-1 min-w-0">
                <p className="text-sm font-mono font-medium">{checkResult.ip}</p>
                <p className="text-xs text-muted-foreground">
                  {checkResult.blocked
                    ? `Blocked by ${checkResult.source} blocklist`
                    : "Not found in blocklist"}
                </p>
              </div>
              <Badge
                variant={checkResult.blocked ? "destructive" : "secondary"}
                className="text-xs px-2 py-0.5"
              >
                {checkResult.blocked ? "BLOCKED" : "CLEAN"}
              </Badge>
            </div>
          )}

          {checkError && (
            <Alert variant="destructive" className="py-2">
              <AlertTitle className="text-xs">Error</AlertTitle>
              <AlertDescription className="text-xs">{checkError}</AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Info */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Database className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-sm">About IPsum</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="space-y-3 text-xs text-muted-foreground">
          <p>
            IPsum is a daily-updated threat intelligence feed that aggregates
            suspicious IP addresses from multiple public blocklists. IPs are
            scored based on how many lists they appear on.
          </p>
          <div className="flex flex-wrap gap-4">
            <div className="flex items-center gap-1.5">
              <Clock className="h-3.5 w-3.5" />
              <span>Updated daily at 06:00 UTC</span>
            </div>
            <div className="flex items-center gap-1.5">
              <Shield className="h-3.5 w-3.5" />
              <span>
                Minimum score: {stats?.min_score ?? 3} (appears on {stats?.min_score ?? 3}+ blocklists)
              </span>
            </div>
            <a
              href="https://github.com/stamparm/ipsum"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 text-neon-cyan hover:underline"
            >
              <ExternalLink className="h-3.5 w-3.5" />
              <span>github.com/stamparm/ipsum</span>
            </a>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

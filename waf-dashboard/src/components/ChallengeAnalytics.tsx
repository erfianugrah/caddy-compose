import { useState, useEffect, useCallback } from "react";
import { Shield, ShieldCheck, ShieldAlert, ShieldX, ShieldOff, RefreshCw, Radar, Plus } from "lucide-react";
import { Card, CardContent, CardHeader, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { StatCard } from "@/components/StatCard";
import { T } from "@/lib/typography";
import { cn } from "@/lib/utils";
import { fetchChallengeStats, fetchEndpointDiscovery } from "@/lib/api/challenge";
import { Input } from "@/components/ui/input";
import type { ChallengeStats, ScoreBucket, ChallengeClient, ChallengeService, ChallengeJA4, EndpointDiscoveryResponse, DiscoveredEndpoint } from "@/lib/api/challenge";

// ─── Helpers ────────────────────────────────────────────────────────

function pct(n: number): string {
  return `${(n * 100).toFixed(1)}%`;
}

function scoreBadge(score: number): { label: string; cls: string } {
  if (score >= 70) return { label: "Automated", cls: "text-lv-red bg-lv-red/15" };
  if (score >= 40) return { label: "Suspicious", cls: "text-lv-yellow bg-lv-yellow/15" };
  if (score >= 20) return { label: "Moderate", cls: "text-lv-peach bg-lv-peach/15" };
  return { label: "Clean", cls: "text-lv-green bg-lv-green/15" };
}

// ─── Funnel Bar ─────────────────────────────────────────────────────

function FunnelBar({ stats }: { stats: ChallengeStats }) {
  const total = stats.issued + stats.passed + stats.failed + stats.bypassed;
  if (total === 0) return <p className={T.muted}>No challenge events in this period.</p>;

  const segments = [
    { label: "Issued", value: stats.issued, color: "bg-lv-yellow" },
    { label: "Passed", value: stats.passed, color: "bg-lv-green" },
    { label: "Failed", value: stats.failed, color: "bg-lv-red" },
    { label: "Bypassed", value: stats.bypassed, color: "bg-lv-cyan" },
  ];

  return (
    <div className="space-y-3">
      <div className="flex h-6 w-full overflow-hidden rounded-full bg-lovelace-900">
        {segments.map((seg) => seg.value > 0 && (
          <div
            key={seg.label}
            className={cn(seg.color, "transition-all")}
            style={{ width: `${(seg.value / total) * 100}%` }}
            title={`${seg.label}: ${seg.value} (${((seg.value / total) * 100).toFixed(1)}%)`}
          />
        ))}
      </div>
      <div className="flex flex-wrap gap-4 text-xs">
        {segments.map((seg) => (
          <div key={seg.label} className="flex items-center gap-1.5">
            <div className={cn("h-2.5 w-2.5 rounded-full", seg.color)} />
            <span className="text-muted-foreground">{seg.label}:</span>
            <span className="font-medium text-foreground">{seg.value.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Score Distribution ─────────────────────────────────────────────

function ScoreDistribution({ buckets }: { buckets: ScoreBucket[] }) {
  const maxCount = Math.max(...buckets.map((b) => b.count), 1);
  const total = buckets.reduce((sum, b) => sum + b.count, 0);

  if (total === 0) return <p className={T.muted}>No scored events yet.</p>;

  return (
    <div className="space-y-2">
      {buckets.map((b) => (
        <div key={b.label} className="flex items-center gap-3 text-xs">
          <span className="w-32 shrink-0 text-muted-foreground font-data">{b.label}</span>
          <div className="flex-1 h-5 bg-lovelace-900 rounded overflow-hidden">
            <div
              className={cn(
                "h-full rounded transition-all",
                b.min >= 70 ? "bg-lv-red" : b.min >= 40 ? "bg-lv-yellow" : b.min >= 20 ? "bg-lv-peach" : "bg-lv-green"
              )}
              style={{ width: `${(b.count / maxCount) * 100}%` }}
            />
          </div>
          <span className="w-12 text-right tabular-nums text-foreground">{b.count}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Timeline Sparkline ─────────────────────────────────────────────

function Timeline({ stats }: { stats: ChallengeStats }) {
  if (!stats.timeline || stats.timeline.length === 0) {
    return <p className={T.muted}>No timeline data.</p>;
  }

  const maxVal = Math.max(...stats.timeline.map((h) => h.issued + h.passed + h.failed + h.bypassed), 1);

  return (
    <div className="space-y-1">
      <div className="flex items-end gap-px h-24">
        {stats.timeline.map((h) => {
          const total = h.issued + h.passed + h.failed + h.bypassed;
          const height = (total / maxVal) * 100;
          const failPct = total > 0 ? (h.failed / total) * 100 : 0;
          return (
            <div
              key={h.hour}
              className="flex-1 flex flex-col justify-end group relative"
              title={`${new Date(h.hour).toLocaleString()}\nIssued: ${h.issued}\nPassed: ${h.passed}\nFailed: ${h.failed}\nBypassed: ${h.bypassed}`}
            >
              <div className="flex flex-col justify-end" style={{ height: `${height}%` }}>
                {h.failed > 0 && (
                  <div className="bg-lv-red rounded-t-sm" style={{ height: `${failPct}%`, minHeight: "1px" }} />
                )}
                <div className="bg-lv-green/70 rounded-t-sm flex-1" style={{ minHeight: total > 0 ? "1px" : 0 }} />
              </div>
            </div>
          );
        })}
      </div>
      <div className="flex justify-between text-[10px] text-muted-foreground/50">
        <span>{stats.timeline.length > 0 ? new Date(stats.timeline[0].hour).toLocaleDateString() : ""}</span>
        <span>{stats.timeline.length > 0 ? new Date(stats.timeline[stats.timeline.length - 1].hour).toLocaleDateString() : ""}</span>
      </div>
    </div>
  );
}

// ─── Endpoint Discovery Panel ───────────────────────────────────────

function EndpointDiscoveryPanel({ hours, service }: { hours: string; service: string }) {
  const [data, setData] = useState<EndpointDiscoveryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [uncoveredOnly, setUncoveredOnly] = useState(false);
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);
  const [sortBy, setSortBy] = useState<"requests" | "non_browser_pct" | "unique_ips">("requests");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setData(await fetchEndpointDiscovery(parseInt(hours), service || undefined));
    } catch (e) {
      console.error("Failed to fetch endpoint discovery:", e);
    } finally {
      setLoading(false);
    }
  }, [hours, service]);

  useEffect(() => { load(); }, [load]);

  if (loading) return <Skeleton className="h-64 w-full" />;
  if (!data || data.endpoints.length === 0) {
    return (
      <Card>
        <CardContent className="py-12 text-center">
          <Radar className="h-12 w-12 mx-auto text-muted-foreground/30 mb-4" />
          <p className={T.muted}>No traffic observed in the selected period.</p>
        </CardContent>
      </Card>
    );
  }

  let filtered = data.endpoints;
  if (uncoveredOnly) filtered = filtered.filter((e) => !e.has_challenge);
  if (suspiciousOnly) filtered = filtered.filter((e) => e.non_browser_pct > 0.2);

  const sorted = [...filtered].sort((a, b) => {
    if (sortBy === "non_browser_pct") return b.non_browser_pct - a.non_browser_pct;
    if (sortBy === "unique_ips") return b.unique_ips - a.unique_ips;
    return b.requests - a.requests;
  });

  const uncoveredCount = data.endpoints.filter((e) => !e.has_challenge).length;

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className="grid grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-5 pb-4 text-center">
            <p className="text-2xl font-bold text-foreground">{data.total_paths}</p>
            <p className="text-xs text-muted-foreground">Endpoints Discovered</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-5 pb-4 text-center">
            <p className={cn("text-2xl font-bold", uncoveredCount > 0 ? "text-lv-red" : "text-lv-green")}>{uncoveredCount}</p>
            <p className="text-xs text-muted-foreground">Without Challenge Protection</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-5 pb-4 text-center">
            <p className={cn("text-2xl font-bold", data.uncovered_pct > 0.3 ? "text-lv-red" : data.uncovered_pct > 0 ? "text-lv-yellow" : "text-lv-green")}>
              {(data.uncovered_pct * 100).toFixed(1)}%
            </p>
            <p className="text-xs text-muted-foreground">Traffic Unprotected</p>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <input type="checkbox" checked={uncoveredOnly} onChange={(e) => setUncoveredOnly(e.target.checked)} className="h-3.5 w-3.5 rounded" />
          Uncovered only
        </label>
        <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <input type="checkbox" checked={suspiciousOnly} onChange={(e) => setSuspiciousOnly(e.target.checked)} className="h-3.5 w-3.5 rounded" />
          High non-browser traffic (&gt;20%)
        </label>
        <Select value={sortBy} onValueChange={(v) => setSortBy(v as typeof sortBy)}>
          <SelectTrigger className="w-36 h-7 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="requests">Sort by requests</SelectItem>
            <SelectItem value="non_browser_pct">Sort by non-browser %</SelectItem>
            <SelectItem value="unique_ips">Sort by unique IPs</SelectItem>
          </SelectContent>
        </Select>
        <Button variant="outline" size="sm" onClick={load} className="h-7 text-xs">
          <RefreshCw className={cn("h-3 w-3 mr-1", loading && "animate-spin")} /> Refresh
        </Button>
      </div>

      {/* Endpoint table */}
      <Card>
        <CardContent className="pt-4">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-lovelace-800 text-muted-foreground">
                  <th className="text-left py-2 pr-3">Endpoint</th>
                  <th className="text-right py-2 px-2">Requests</th>
                  <th className="text-right py-2 px-2">IPs</th>
                  <th className="text-right py-2 px-2">JA4s</th>
                  <th className="text-right py-2 px-2">UAs</th>
                  <th className="text-right py-2 px-2">Non-Browser</th>
                  <th className="text-center py-2 px-2">Coverage</th>
                  <th className="text-right py-2 pl-2">Action</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((ep: DiscoveredEndpoint) => (
                  <tr key={`${ep.service}:${ep.method}:${ep.path}`} className="border-b border-lovelace-900/50 hover:bg-lovelace-900/30">
                    <td className="py-2 pr-3">
                      <span className="inline-flex items-center gap-1.5">
                        <span className={cn(
                          "rounded px-1 py-0.5 text-[10px] font-bold uppercase",
                          ep.method === "GET" ? "bg-lv-green/15 text-lv-green" :
                          ep.method === "POST" ? "bg-lv-yellow/15 text-lv-yellow" :
                          ep.method === "PUT" ? "bg-lv-cyan/15 text-lv-cyan" :
                          ep.method === "DELETE" ? "bg-lv-red/15 text-lv-red" :
                          "bg-muted/50 text-muted-foreground"
                        )}>{ep.method}</span>
                        <code className="font-data text-foreground">{ep.path}</code>
                      </span>
                      {ep.service && <span className="ml-1.5 text-muted-foreground/40 text-[10px]">{ep.service}</span>}
                    </td>
                    <td className="text-right py-2 px-2 tabular-nums text-foreground">{ep.requests.toLocaleString()}</td>
                    <td className="text-right py-2 px-2 tabular-nums text-muted-foreground">{ep.unique_ips}</td>
                    <td className="text-right py-2 px-2 tabular-nums text-muted-foreground">{ep.unique_ja4s}</td>
                    <td className="text-right py-2 px-2 tabular-nums text-muted-foreground">{ep.unique_uas}</td>
                    <td className="text-right py-2 px-2">
                      <span className={cn(
                        "tabular-nums",
                        ep.non_browser_pct >= 0.5 ? "text-lv-red font-semibold" :
                        ep.non_browser_pct >= 0.2 ? "text-lv-yellow" :
                        "text-muted-foreground"
                      )}>{(ep.non_browser_pct * 100).toFixed(0)}%</span>
                    </td>
                    <td className="text-center py-2 px-2">
                      <div className="flex justify-center gap-1">
                        {ep.has_challenge && (
                          <span className="inline-flex items-center rounded bg-lv-green/15 px-1.5 py-0.5 text-[10px] text-lv-green" title="Challenge rule covers this path">
                            <ShieldCheck className="h-3 w-3 mr-0.5" />PoW
                          </span>
                        )}
                        {ep.has_rate_limit && (
                          <span className="inline-flex items-center rounded bg-lv-cyan/15 px-1.5 py-0.5 text-[10px] text-lv-cyan" title="Rate limit rule covers this path">
                            <Shield className="h-3 w-3 mr-0.5" />RL
                          </span>
                        )}
                        {!ep.has_challenge && !ep.has_rate_limit && (
                          <span className="inline-flex items-center rounded bg-lv-red/15 px-1.5 py-0.5 text-[10px] text-lv-red" title="No protection">
                            <ShieldOff className="h-3 w-3 mr-0.5" />None
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="text-right py-2 pl-2">
                      {!ep.has_challenge && (
                        <a
                          href={`/policy?action=challenge&prefill_path=${encodeURIComponent(ep.path)}&prefill_service=${encodeURIComponent(ep.service)}`}
                          className="inline-flex items-center gap-0.5 text-[10px] text-lv-purple hover:text-lv-purple-bright hover:underline"
                          title="Create a challenge rule for this endpoint"
                        >
                          <Plus className="h-3 w-3" />Challenge
                        </a>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {sorted.length === 0 && (
            <p className="text-center py-8 text-xs text-muted-foreground">No endpoints match the current filters.</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Main Component ─────────────────────────────────────────────────

export default function ChallengeAnalytics() {
  const [stats, setStats] = useState<ChallengeStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [hours, setHours] = useState("24");
  const [filterService, setFilterService] = useState("");
  const [filterClient, setFilterClient] = useState("");
  const [activeTab, setActiveTab] = useState<"analytics" | "discovery">("analytics");

  // Read initial filters from URL params (client-side only).
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("service")) setFilterService(params.get("service")!);
    if (params.get("client")) setFilterClient(params.get("client")!);
    if (params.get("hours")) setHours(params.get("hours")!);
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchChallengeStats(
        parseInt(hours),
        filterService || undefined,
        filterClient || undefined,
      );
      setStats(data);
    } catch (e) {
      console.error("Failed to fetch challenge stats:", e);
    } finally {
      setLoading(false);
    }
  }, [hours, filterService, filterClient]);

  useEffect(() => { load(); }, [load]);

  const totalEvents = stats ? stats.issued + stats.passed + stats.failed + stats.bypassed : 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className={T.pageTitle}>Challenge Analytics</h1>
          <div className="flex gap-1 mt-2">
            <button
              onClick={() => setActiveTab("analytics")}
              className={cn("px-3 py-1 rounded text-xs font-medium transition-colors", activeTab === "analytics" ? "bg-lv-purple/20 text-lv-purple border border-lv-purple/30" : "text-muted-foreground hover:text-foreground")}
            >Challenge Stats</button>
            <button
              onClick={() => setActiveTab("discovery")}
              className={cn("px-3 py-1 rounded text-xs font-medium transition-colors", activeTab === "discovery" ? "bg-lv-cyan/20 text-lv-cyan border border-lv-cyan/30" : "text-muted-foreground hover:text-foreground")}
            >
              <Radar className="h-3 w-3 inline mr-1" />Endpoint Discovery
            </button>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Input
            placeholder="Filter by service..."
            value={filterService}
            onChange={(e) => setFilterService(e.target.value)}
            className="w-40 h-8 text-xs"
          />
          <Input
            placeholder="Filter by client IP..."
            value={filterClient}
            onChange={(e) => setFilterClient(e.target.value)}
            className="w-40 h-8 text-xs"
          />
          <Select value={hours} onValueChange={setHours}>
            <SelectTrigger className="w-28 h-8">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="1">1 hour</SelectItem>
              <SelectItem value="6">6 hours</SelectItem>
              <SelectItem value="24">24 hours</SelectItem>
              <SelectItem value="72">3 days</SelectItem>
              <SelectItem value="168">7 days</SelectItem>
            </SelectContent>
          </Select>
          <Button variant="outline" size="sm" onClick={load} disabled={loading} className="h-8">
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
          </Button>
          {(filterService || filterClient) && (
            <Button variant="ghost" size="sm" className="h-8 text-xs text-muted-foreground" onClick={() => { setFilterService(""); setFilterClient(""); }}>
              Clear filters
            </Button>
          )}
        </div>
      </div>
      {/* Active filter indicator */}
      {(filterService || filterClient) && (
        <div className="flex gap-2 text-xs">
          {filterService && (
            <span className="inline-flex items-center rounded bg-lv-purple/10 border border-lv-purple/30 px-2 py-0.5 text-lv-purple">
              Service: {filterService}
              <button className="ml-1.5 hover:text-lv-red" onClick={() => setFilterService("")}>&times;</button>
            </span>
          )}
          {filterClient && (
            <span className="inline-flex items-center rounded bg-lv-cyan/10 border border-lv-cyan/30 px-2 py-0.5 text-lv-cyan">
              Client: {filterClient}
              <button className="ml-1.5 hover:text-lv-red" onClick={() => setFilterClient("")}>&times;</button>
            </span>
          )}
        </div>
      )}

      {/* Discovery Tab */}
      {activeTab === "discovery" && (
        <EndpointDiscoveryPanel hours={hours} service={filterService} />
      )}

      {/* Analytics Tab */}
      {activeTab === "analytics" && <>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard title="Challenges Issued" value={stats?.issued ?? 0} icon={Shield} color="yellow" loading={loading} href="/events?type=challenge_issued" />
        <StatCard title="Challenges Passed" value={stats?.passed ?? 0} icon={ShieldCheck} color="green" loading={loading} href="/events?type=challenge_passed" />
        <StatCard title="Challenges Failed" value={stats?.failed ?? 0} icon={ShieldX} color="red" loading={loading} href="/events?type=challenge_failed" />
        <StatCard title="Cookie Bypasses" value={stats?.bypassed ?? 0} icon={ShieldAlert} color="cyan" loading={loading} />
      </div>

      {/* Funnel + Rates */}
      {stats && !loading && totalEvents > 0 && (
        <Card>
          <CardHeader>
            <CardDescription className={T.sectionLabel}>Challenge Funnel</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <FunnelBar stats={stats} />
            <div className="grid grid-cols-5 gap-4 pt-2">
              <div className="text-center">
                <p className="text-2xl font-bold text-lv-green">{pct(stats.pass_rate)}</p>
                <p className="text-xs text-muted-foreground">Pass Rate</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-lv-red">{pct(stats.fail_rate)}</p>
                <p className="text-xs text-muted-foreground">Fail Rate</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-lv-cyan">{pct(stats.bypass_rate)}</p>
                <p className="text-xs text-muted-foreground">Bypass Rate</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-foreground">
                  {stats.avg_solve_ms > 0 ? stats.avg_solve_ms >= 1000 ? `${(stats.avg_solve_ms / 1000).toFixed(1)}s` : `${Math.round(stats.avg_solve_ms)}ms` : "-"}
                </p>
                <p className="text-xs text-muted-foreground">Avg Solve Time</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-foreground">
                  {stats.avg_difficulty > 0 ? stats.avg_difficulty.toFixed(1) : "-"}
                </p>
                <p className="text-xs text-muted-foreground">Avg Difficulty</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Timeline + Score Distribution */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardDescription className={T.sectionLabel}>Challenge Timeline</CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? <Skeleton className="h-24 w-full" /> : stats ? <Timeline stats={stats} /> : null}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardDescription className={T.sectionLabel}>Bot Score Distribution</CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? <Skeleton className="h-40 w-full" /> : stats ? <ScoreDistribution buckets={stats.score_buckets} /> : null}
          </CardContent>
        </Card>
      </div>

      {/* Top Clients */}
      {stats && stats.top_clients && stats.top_clients.length > 0 && (
        <Card>
          <CardHeader>
            <CardDescription className={T.sectionLabel}>Top Challenged Clients</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-lovelace-800 text-muted-foreground">
                    <th className="text-left py-2 pr-4">Client</th>
                    <th className="text-right py-2 px-2">Issued</th>
                    <th className="text-right py-2 px-2">Passed</th>
                    <th className="text-right py-2 px-2">Failed</th>
                    <th className="text-right py-2 px-2">Bypassed</th>
                    <th className="text-right py-2 px-2">Tokens</th>
                    <th className="text-right py-2 px-2">Avg Score</th>
                    <th className="text-right py-2 pl-2">Max Score</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.top_clients.map((c: ChallengeClient) => {
                    const badge = scoreBadge(c.max_bot_score);
                    return (
                      <tr key={c.client} className="border-b border-lovelace-900/50 hover:bg-lovelace-900/30">
                        <td className="py-2 pr-4">
                          <button onClick={() => setFilterClient(c.client)} className="text-lv-green hover:underline font-data text-left" title="Filter by this client">
                            {c.client}
                          </button>
                          {c.country && <span className="ml-1.5 text-muted-foreground/50">{c.country}</span>}
                          <a href={`/analytics?ip=${encodeURIComponent(c.client)}`} className="ml-1.5 text-muted-foreground/40 hover:text-lv-purple text-[10px]" title="IP Lookup">lookup</a>
                        </td>
                        <td className="text-right py-2 px-2 tabular-nums text-lv-yellow">{c.issued}</td>
                        <td className="text-right py-2 px-2 tabular-nums text-lv-green">{c.passed}</td>
                        <td className="text-right py-2 px-2 tabular-nums text-lv-red">{c.failed}</td>
                        <td className="text-right py-2 px-2 tabular-nums text-lv-cyan">{c.bypassed}</td>
                        <td className="text-right py-2 px-2 tabular-nums text-muted-foreground" title="Unique cookie tokens — high count = repeated solves">{c.unique_tokens || "-"}</td>
                        <td className="text-right py-2 px-2 tabular-nums">{c.avg_bot_score > 0 ? c.avg_bot_score.toFixed(0) : "-"}</td>
                        <td className="text-right py-2 pl-2">
                          <span className={cn("inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium", badge.cls)}>
                            {c.max_bot_score > 0 ? `${c.max_bot_score} ${badge.label}` : "-"}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Top Services */}
      {stats && stats.top_services && stats.top_services.length > 0 && (
        <Card>
          <CardHeader>
            <CardDescription className={T.sectionLabel}>Top Challenged Services</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-lovelace-800 text-muted-foreground">
                    <th className="text-left py-2 pr-4">Service</th>
                    <th className="text-right py-2 px-2">Issued</th>
                    <th className="text-right py-2 px-2">Passed</th>
                    <th className="text-right py-2 px-2">Failed</th>
                    <th className="text-right py-2 px-2">Bypassed</th>
                    <th className="text-right py-2 pl-2">Fail Rate</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.top_services.map((s: ChallengeService) => {
                    const failRate = s.fail_rate ?? (s.issued > 0 ? (s.failed / s.issued) : 0);
                    return (
                      <tr key={s.service} className="border-b border-lovelace-900/50 hover:bg-lovelace-900/30">
                        <td className="py-2 pr-4">
                          <button onClick={() => setFilterService(s.service)} className="font-data text-foreground hover:underline text-left" title="Filter by this service">
                            {s.service}
                          </button>
                        </td>
                        <td className="text-right py-2 px-2 tabular-nums text-lv-yellow">{s.issued}</td>
                        <td className="text-right py-2 px-2 tabular-nums text-lv-green">{s.passed}</td>
                        <td className="text-right py-2 px-2 tabular-nums text-lv-red">{s.failed}</td>
                        <td className="text-right py-2 px-2 tabular-nums text-lv-cyan">{s.bypassed}</td>
                        <td className="text-right py-2 pl-2">
                          <span className={cn("tabular-nums", failRate >= 0.5 ? "text-lv-red font-semibold" : failRate >= 0.2 ? "text-lv-yellow" : "text-muted-foreground")}>
                            {pct(failRate)}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* JA4 Fingerprints */}
      {stats && stats.top_ja4s && stats.top_ja4s.length > 0 && (
        <Card>
          <CardHeader>
            <CardDescription className={T.sectionLabel}>Top JA4 TLS Fingerprints</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-lovelace-800 text-muted-foreground">
                    <th className="text-left py-2 pr-4">JA4 Fingerprint</th>
                    <th className="text-right py-2 px-2">Total</th>
                    <th className="text-right py-2 px-2">Passed</th>
                    <th className="text-right py-2 px-2">Failed</th>
                    <th className="text-right py-2 px-2">Unique IPs</th>
                    <th className="text-right py-2 pl-2">Fail Rate</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.top_ja4s.map((j: ChallengeJA4) => {
                    const scored = j.passed + j.failed;
                    const jr = scored > 0 ? j.failed / scored : 0;
                    return (
                      <tr key={j.ja4} className="border-b border-lovelace-900/50 hover:bg-lovelace-900/30">
                        <td className="py-2 pr-4">
                          <a href={`/events?ja4=${encodeURIComponent(j.ja4)}`} className="font-data text-lv-cyan hover:underline" title="View events with this JA4">
                            {j.ja4}
                          </a>
                        </td>
                        <td className="text-right py-2 px-2 tabular-nums text-foreground">{j.total}</td>
                        <td className="text-right py-2 px-2 tabular-nums text-lv-green">{j.passed}</td>
                        <td className="text-right py-2 px-2 tabular-nums text-lv-red">{j.failed}</td>
                        <td className="text-right py-2 px-2 tabular-nums text-muted-foreground">{j.clients}</td>
                        <td className="text-right py-2 pl-2">
                          <span className={cn("tabular-nums", jr >= 0.5 ? "text-lv-red font-semibold" : jr >= 0.2 ? "text-lv-yellow" : "text-muted-foreground")}>
                            {pct(jr)}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <p className="text-[10px] text-muted-foreground/50 mt-2">
              JA4 identifies the TLS client implementation. Non-browser JA4s (no ALPN, TLS 1.2) with high fail rates indicate bot traffic.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Empty state */}
      {!loading && totalEvents === 0 && (
        <Card>
          <CardContent className="py-12 text-center">
            <Shield className="h-12 w-12 mx-auto text-muted-foreground/30 mb-4" />
            <p className={T.muted}>No challenge events in the selected period.</p>
            <p className="text-xs text-muted-foreground/50 mt-1">Create a challenge rule in the Policy Engine to start collecting data.</p>
          </CardContent>
        </Card>
      )}

      </>}
    </div>
  );
}

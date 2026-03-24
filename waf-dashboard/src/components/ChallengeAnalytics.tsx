import { useState, useEffect, useCallback } from "react";
import { Shield, ShieldCheck, ShieldAlert, ShieldX, RefreshCw } from "lucide-react";
import { Card, CardContent, CardHeader, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { StatCard } from "@/components/StatCard";
import { T } from "@/lib/typography";
import { cn } from "@/lib/utils";
import { fetchChallengeStats } from "@/lib/api/challenge";
import type { ChallengeStats, ScoreBucket, ChallengeClient, ChallengeService } from "@/lib/api/challenge";

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

// ─── Main Component ─────────────────────────────────────────────────

export default function ChallengeAnalytics() {
  const [stats, setStats] = useState<ChallengeStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [hours, setHours] = useState("24");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchChallengeStats(parseInt(hours));
      setStats(data);
    } catch (e) {
      console.error("Failed to fetch challenge stats:", e);
    } finally {
      setLoading(false);
    }
  }, [hours]);

  useEffect(() => { load(); }, [load]);

  const totalEvents = stats ? stats.issued + stats.passed + stats.failed + stats.bypassed : 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className={T.pageTitle}>Challenge Analytics</h1>
          <p className={T.muted}>PoW challenge funnel, bot score distribution, and top challenged clients.</p>
        </div>
        <div className="flex items-center gap-3">
          <Select value={hours} onValueChange={setHours}>
            <SelectTrigger className="w-28">
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
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
          </Button>
        </div>
      </div>

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
            <div className="grid grid-cols-3 gap-4 pt-2">
              <div className="text-center">
                <p className="text-2xl font-bold text-lv-green">{pct(stats.pass_rate)}</p>
                <p className="text-xs text-muted-foreground">Pass Rate</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-lv-red">{pct(stats.fail_rate)}</p>
                <p className="text-xs text-muted-foreground">Fail Rate (bot pressure)</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-lv-cyan">{pct(stats.bypass_rate)}</p>
                <p className="text-xs text-muted-foreground">Bypass Rate (cookie reuse)</p>
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
                          <a href={`/analytics?ip=${encodeURIComponent(c.client)}`} className="text-lv-green hover:underline font-data">
                            {c.client}
                          </a>
                          {c.country && <span className="ml-1.5 text-muted-foreground/50">{c.country}</span>}
                        </td>
                        <td className="text-right py-2 px-2 tabular-nums text-lv-yellow">{c.issued}</td>
                        <td className="text-right py-2 px-2 tabular-nums text-lv-green">{c.passed}</td>
                        <td className="text-right py-2 px-2 tabular-nums text-lv-red">{c.failed}</td>
                        <td className="text-right py-2 px-2 tabular-nums text-lv-cyan">{c.bypassed}</td>
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
                    const failRate = s.issued > 0 ? (s.failed / s.issued) : 0;
                    return (
                      <tr key={s.service} className="border-b border-lovelace-900/50 hover:bg-lovelace-900/30">
                        <td className="py-2 pr-4 font-data text-foreground">{s.service}</td>
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
    </div>
  );
}

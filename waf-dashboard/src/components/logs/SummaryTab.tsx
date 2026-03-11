import { formatNumber, formatTime, formatDate, countryFlag } from "@/lib/format";
import type { GeneralLogsSummary } from "@/lib/api";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Globe2, Server, ArrowRight, Link2 } from "lucide-react";

import { statusBadge, formatDuration } from "./helpers";

// ─── Props ──────────────────────────────────────────────────────────

export interface SummaryTabProps {
  summary: GeneralLogsSummary;
}

// ─── Status bucket colors ───────────────────────────────────────────

function bucketColor(bucket: string): { bar: string; text: string; bg: string } {
  switch (bucket) {
    case "2xx": return { bar: "bg-lv-green", text: "text-lv-green", bg: "bg-lv-green/10" };
    case "3xx": return { bar: "bg-blue-500", text: "text-blue-400", bg: "bg-blue-500/10" };
    case "4xx": return { bar: "bg-amber-500", text: "text-lv-peach", bg: "bg-amber-500/10" };
    case "5xx": return { bar: "bg-lv-red", text: "text-lv-red", bg: "bg-lv-red/10" };
    default:   return { bar: "bg-muted", text: "text-muted-foreground", bg: "bg-muted/10" };
  }
}

// ─── Latency indicator ──────────────────────────────────────────────

function LatencyBadge({ seconds }: { seconds: number }) {
  const cls = seconds >= 1 ? "text-lv-red" : seconds >= 0.1 ? "text-lv-peach" : "text-lv-green";
  return <span className={`font-data text-xs ${cls}`}>{formatDuration(seconds)}</span>;
}

// ─── Latency Percentiles ────────────────────────────────────────────

function latencyColor(seconds: number): string {
  if (seconds >= 2) return "text-lv-red";
  if (seconds >= 1) return "text-lv-red/80";
  if (seconds >= 0.5) return "text-lv-peach";
  if (seconds >= 0.1) return "text-lv-peach/70";
  return "text-lv-green";
}

function latencyBarColor(seconds: number): string {
  if (seconds >= 1) return "bg-lv-red";
  if (seconds >= 0.5) return "bg-amber-500";
  if (seconds >= 0.1) return "bg-amber-500/70";
  return "bg-lv-green";
}

function LatencyPercentiles({ summary }: { summary: GeneralLogsSummary }) {
  const percentiles = [
    { label: "P50", value: summary.p50_duration, description: "Median" },
    { label: "Avg", value: summary.avg_duration, description: "Mean" },
    { label: "P95", value: summary.p95_duration, description: "95th pct" },
    { label: "P99", value: summary.p99_duration, description: "99th pct" },
  ];
  const maxVal = Math.max(...percentiles.map((p) => p.value), 0.001);

  return (
    <div className="space-y-3">
      {percentiles.map((p) => {
        const barWidth = (p.value / maxVal) * 100;
        return (
          <div key={p.label} className="space-y-1">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="font-data text-xs font-medium w-8">{p.label}</span>
                <span className="text-xs text-muted-foreground">{p.description}</span>
              </div>
              <span className={`font-data text-xs font-medium ${latencyColor(p.value)}`}>
                {formatDuration(p.value)}
              </span>
            </div>
            <div className="h-2 rounded-full bg-muted/30 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${latencyBarColor(p.value)}`}
                style={{ width: `${Math.max(barWidth, 1)}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── Component ──────────────────────────────────────────────────────

export default function SummaryTab({ summary }: SummaryTabProps) {
  const statusEntries = Object.entries(summary.status_distribution)
    .sort(([a], [b]) => a.localeCompare(b));
  const maxCount = Math.max(...statusEntries.map(([, count]) => count), 1);

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      {/* Status Distribution */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">Status Distribution</CardTitle>
          <p className="text-xs text-muted-foreground">
            Response status code breakdown across {formatNumber(summary.total_requests)} requests
          </p>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {statusEntries.map(([bucket, count]) => {
              const pct = summary.total_requests > 0 ? (count / summary.total_requests) * 100 : 0;
              const barWidth = (count / maxCount) * 100;
              const colors = bucketColor(bucket);
              return (
                <a
                  key={bucket}
                  href={`/logs?status=${bucket}`}
                  className="block group"
                >
                  <div className="flex items-center gap-3">
                    <Badge className={`${colors.bg} ${colors.text} font-data text-xs border-transparent w-10 justify-center`}>
                      {bucket}
                    </Badge>
                    <div className="flex-1 h-6 rounded bg-muted/20 overflow-hidden relative">
                      <div
                        className={`h-full ${colors.bar} rounded transition-all group-hover:brightness-125`}
                        style={{ width: `${Math.max(barWidth, 0.5)}%` }}
                      />
                      <span className="absolute inset-y-0 right-2 flex items-center font-data text-xs text-foreground">
                        {formatNumber(count)}
                      </span>
                    </div>
                    <span className="w-14 text-right text-xs text-muted-foreground font-data">
                      {pct.toFixed(1)}%
                    </span>
                  </div>
                </a>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Latency Percentiles */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">Latency Percentiles</CardTitle>
          <p className="text-xs text-muted-foreground">
            Response time distribution across {formatNumber(summary.total_requests)} requests
          </p>
        </CardHeader>
        <CardContent>
          <LatencyPercentiles summary={summary} />
        </CardContent>
      </Card>

      {/* Top Services */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">Top Services</CardTitle>
          <p className="text-xs text-muted-foreground">
            Request volume, error count, and average latency
          </p>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {summary.top_services.map((s) => {
              const pct = summary.total_requests > 0 ? (s.count / summary.total_requests) * 100 : 0;
              return (
                <a
                  key={s.service}
                  href={`/logs?service=${encodeURIComponent(s.service)}`}
                  className="flex items-center justify-between text-xs group hover:bg-muted/30 rounded-md px-2 py-1.5 -mx-2 transition-colors"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <Server className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                    <span className="truncate group-hover:text-foreground">{s.service}</span>
                    <span className="text-muted-foreground/50 font-data">{pct.toFixed(0)}%</span>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="font-data">{formatNumber(s.count)}</span>
                    {s.error_count > 0 && (
                      <Badge variant="destructive" className="text-xs px-1 py-0 font-data">
                        {s.error_count} err
                      </Badge>
                    )}
                    <LatencyBadge seconds={s.avg_duration} />
                    <ArrowRight className="h-3 w-3 text-muted-foreground/30 group-hover:text-muted-foreground transition-colors" />
                  </div>
                </a>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Top URIs */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">Top URIs</CardTitle>
          <p className="text-xs text-muted-foreground">
            Most requested paths with error counts
          </p>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {summary.top_uris.map((u) => (
              <div key={u.uri} className="flex items-center justify-between text-xs hover:bg-muted/30 rounded-md px-2 py-1.5 -mx-2 transition-colors">
                <div className="flex items-center gap-2 min-w-0">
                  <Link2 className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                  <span className="font-data truncate max-w-[55%] text-muted-foreground">{u.uri}</span>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <span className="font-data">{formatNumber(u.count)}</span>
                  {u.error_count > 0 && (
                    <Badge variant="destructive" className="text-xs px-1 py-0 font-data">
                      {u.error_count} err
                    </Badge>
                  )}
                  {u.avg_duration > 0 && <LatencyBadge seconds={u.avg_duration} />}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Top Clients */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">Top Clients</CardTitle>
          <p className="text-xs text-muted-foreground">
            Busiest client IPs — click to investigate
          </p>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {summary.top_clients.map((c) => (
              <a
                key={c.client_ip}
                href={`/analytics?tab=ip&q=${encodeURIComponent(c.client_ip)}`}
                className="flex items-center justify-between text-xs group hover:bg-muted/30 rounded-md px-2 py-1.5 -mx-2 transition-colors"
              >
                <div className="flex items-center gap-2 font-data">
                  <Globe2 className="h-3.5 w-3.5 text-muted-foreground" />
                  {c.country && <span>{countryFlag(c.country)}</span>}
                  <span className="group-hover:text-lv-cyan transition-colors">{c.client_ip}</span>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <span className="font-data">{formatNumber(c.count)}</span>
                  {c.error_count > 0 && (
                    <Badge variant="destructive" className="text-xs px-1 py-0 font-data">
                      {c.error_count} err
                    </Badge>
                  )}
                  <ArrowRight className="h-3 w-3 text-muted-foreground/30 group-hover:text-muted-foreground transition-colors" />
                </div>
              </a>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Recent Errors */}
      {summary.recent_errors.length > 0 && (
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Recent Errors</CardTitle>
            <p className="text-xs text-muted-foreground">
              Last {Math.min(summary.recent_errors.length, 10)} error responses (4xx/5xx)
            </p>
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {summary.recent_errors.slice(0, 10).map((e, i) => (
                <div key={i} className="flex items-center gap-3 text-xs hover:bg-muted/30 rounded-md px-2 py-1.5 -mx-2 transition-colors">
                  {statusBadge(e.status)}
                  <span className="font-data text-muted-foreground w-12">{e.method}</span>
                  <span className="truncate text-muted-foreground w-28">{e.service}</span>
                  <span className="font-data truncate text-muted-foreground flex-1">{e.uri}</span>
                  <span className="text-muted-foreground whitespace-nowrap">
                    {formatDate(e.timestamp)} {formatTime(e.timestamp)}
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

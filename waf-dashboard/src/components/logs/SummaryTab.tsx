import { formatNumber, formatTime, formatDate, countryFlag } from "@/lib/format";
import type { GeneralLogsSummary } from "@/lib/api";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Globe2, Server } from "lucide-react";

import { statusBadge, formatDuration } from "./helpers";

// ─── Props ──────────────────────────────────────────────────────────

export interface SummaryTabProps {
  summary: GeneralLogsSummary;
}

// ─── Component ──────────────────────────────────────────────────────

export default function SummaryTab({ summary }: SummaryTabProps) {
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      {/* Status Distribution */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">Status Distribution</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {Object.entries(summary.status_distribution)
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([bucket, count]) => {
                const pct = summary.total_requests > 0 ? (count / summary.total_requests) * 100 : 0;
                const color = bucket === "2xx" ? "bg-emerald-500" : bucket === "3xx" ? "bg-blue-500" : bucket === "4xx" ? "bg-amber-500" : bucket === "5xx" ? "bg-red-500" : "bg-muted";
                return (
                  <div key={bucket} className="flex items-center gap-3">
                    <span className="w-8 font-mono text-xs text-muted-foreground">{bucket}</span>
                    <div className="flex-1 h-5 rounded-full bg-muted/30 overflow-hidden">
                      <div className={`h-full ${color} rounded-full transition-all`} style={{ width: `${Math.max(pct, 0.5)}%` }} />
                    </div>
                    <span className="w-16 text-right font-mono text-xs">{formatNumber(count)}</span>
                    <span className="w-12 text-right text-xs text-muted-foreground">{pct.toFixed(1)}%</span>
                  </div>
                );
              })}
          </div>
        </CardContent>
      </Card>

      {/* Top Services */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">Top Services</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {summary.top_services.map((s) => (
              <div key={s.service} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2 min-w-0">
                  <Server className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                  <span className="truncate">{s.service}</span>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <span className="font-mono">{formatNumber(s.count)}</span>
                  {s.error_count > 0 && (
                    <span className="text-red-400 font-mono">{s.error_count} err</span>
                  )}
                  <span className="text-muted-foreground w-16 text-right">
                    {formatDuration(s.avg_duration)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Top URIs */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">Top URIs</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {summary.top_uris.map((u) => (
              <div key={u.uri} className="flex items-center justify-between text-xs">
                <span className="font-mono truncate max-w-[60%] text-muted-foreground">{u.uri}</span>
                <div className="flex items-center gap-3 shrink-0">
                  <span className="font-mono">{formatNumber(u.count)}</span>
                  {u.error_count > 0 && (
                    <span className="text-red-400 font-mono">{u.error_count} err</span>
                  )}
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
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {summary.top_clients.map((c) => (
              <div key={c.client_ip} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2 font-mono">
                  <Globe2 className="h-3.5 w-3.5 text-muted-foreground" />
                  {c.country && <span>{countryFlag(c.country)}</span>}
                  <span>{c.client_ip}</span>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <span className="font-mono">{formatNumber(c.count)}</span>
                  {c.error_count > 0 && (
                    <span className="text-red-400 font-mono">{c.error_count} err</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Recent Errors */}
      {summary.recent_errors.length > 0 && (
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Recent Errors</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {summary.recent_errors.slice(0, 10).map((e, i) => (
                <div key={i} className="flex items-center gap-3 text-xs">
                  {statusBadge(e.status)}
                  <span className="font-mono text-muted-foreground">{e.method}</span>
                  <span className="truncate text-muted-foreground">{e.service}</span>
                  <span className="font-mono truncate text-muted-foreground flex-1">{e.uri}</span>
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

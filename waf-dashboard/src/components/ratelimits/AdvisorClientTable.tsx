import { useState, useMemo, Fragment } from "react";
import {
  ChevronRight,
  ChevronDown,
  Info,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
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
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import type { RateAdvisorClient } from "@/lib/api";
import { ClassificationBadge } from "../AdvisorCharts";
import { T } from "@/lib/typography";

// ─── Props ──────────────────────────────────────────────────────────

export interface AdvisorClientTableProps {
  clients: RateAdvisorClient[];
  threshold: number;
}

// ─── Column Header Tooltip ──────────────────────────────────────────

function ColTip({ label, tip }: { label: string; tip: string }) {
  return (
    <span className="inline-flex items-center gap-1 justify-end">
      {label}
      <Tooltip>
        <TooltipTrigger asChild>
          <Info className="h-3 w-3 text-muted-foreground/40 cursor-help" />
        </TooltipTrigger>
        <TooltipContent side="top" className="max-w-xs text-xs">
          {tip}
        </TooltipContent>
      </Tooltip>
    </span>
  );
}

// ─── Client Table ───────────────────────────────────────────────────

type ClientSortKey = "requests" | "anomaly_score" | "error_rate";

export function AdvisorClientTable({ clients, threshold }: AdvisorClientTableProps) {
  const [clientSort, setClientSort] = useState<ClientSortKey>("requests");
  const [expandedClients, setExpandedClients] = useState<Set<string>>(new Set());

  const toggleClientExpand = (ip: string) => {
    setExpandedClients((prev) => {
      const next = new Set(prev);
      if (next.has(ip)) next.delete(ip);
      else next.add(ip);
      return next;
    });
  };

  const sortedClients = useMemo(() => {
    const sorted = [...clients];
    if (clientSort === "anomaly_score") {
      sorted.sort((a, b) => b.anomaly_score - a.anomaly_score);
    } else if (clientSort === "error_rate") {
      sorted.sort((a, b) => b.error_rate - a.error_rate);
    } else {
      sorted.sort((a, b) => b.requests - a.requests);
    }
    return sorted;
  }, [clients, clientSort]);

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className={T.cardTitle}>
            Top {clients.length} Clients
          </CardTitle>
          <div className="flex items-center gap-2">
            <Label className="text-xs text-muted-foreground">Sort by</Label>
            <Select value={clientSort} onValueChange={(v) => setClientSort(v as ClientSortKey)}>
              <SelectTrigger className="h-7 text-xs w-32">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="requests">Requests</SelectItem>
                <SelectItem value="anomaly_score">Anomaly Score</SelectItem>
                <SelectItem value="error_rate">Error Rate</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0 overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
               <TableHead className="w-8" />
               <TableHead>Client IP</TableHead>
               <TableHead>Country</TableHead>
               <TableHead className="text-right">
                 <ColTip label="Requests" tip="Total requests from this client in the selected window." />
               </TableHead>
               <TableHead className="text-right">
                 <ColTip label="Req/s" tip="Requests per second — normalized rate for cross-window comparison." />
               </TableHead>
               <TableHead className="text-right">
                 <ColTip label="Error %" tip="Percentage of 4xx/5xx responses. High error rates may indicate scanning or brute-force attempts." />
               </TableHead>
               <TableHead className="text-right">
                 <ColTip label="Diversity" tip="Path diversity — unique paths / total requests. Low values (near 0) mean the client hammers one endpoint; high values (near 1) mean varied browsing." />
               </TableHead>
               <TableHead className="text-right">
                 <ColTip label="Burstiness" tip="Fano factor over 10-second sub-windows. 1.0 = evenly spread (Poisson). Values well above 1 indicate bursty, bot-like request patterns." />
               </TableHead>
               <TableHead className="text-right">
                 <ColTip label="Score" tip="Composite anomaly score (0–100). Weighted: 40% volume deviation, 30% burstiness, 30% path concentration. Higher = more anomalous." />
               </TableHead>
               <TableHead>Class</TableHead>
               <TableHead>Top Paths</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sortedClients.map((client) => {
              const isAbove = client.requests >= threshold;
              const isExpanded = expandedClients.has(client.client_ip);
              return (
                <Fragment key={client.client_ip}>
                <TableRow
                  className={`cursor-pointer ${isAbove ? "bg-lv-red/5" : ""}`}
                  onClick={() => toggleClientExpand(client.client_ip)}
                >
                  <TableCell className="w-8">
                    {isExpanded ? (
                      <ChevronDown className="h-4 w-4 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="h-4 w-4 text-muted-foreground" />
                    )}
                  </TableCell>
                  <TableCell className="font-data text-xs">{client.client_ip}</TableCell>
                  <TableCell className="text-xs">{client.country || "—"}</TableCell>
                  <TableCell className={`text-xs font-data tabular-nums text-right ${isAbove ? "text-lv-red font-medium" : ""}`}>
                    {client.requests.toLocaleString()}
                  </TableCell>
                  <TableCell className="text-xs font-data tabular-nums text-right text-lv-cyan">
                    {client.requests_per_sec > 0 ? client.requests_per_sec.toFixed(2) : "—"}
                  </TableCell>
                  <TableCell className={`text-xs font-data tabular-nums text-right ${client.error_rate > 0.3 ? "text-lv-red" : client.error_rate > 0.1 ? "text-lv-peach" : ""}`}>
                    {(client.error_rate * 100).toFixed(0)}%
                  </TableCell>
                  <TableCell className={`text-xs font-data tabular-nums text-right ${client.path_diversity < 0.05 ? "text-lv-red" : client.path_diversity < 0.2 ? "text-lv-peach" : ""}`}>
                    {client.path_diversity.toFixed(2)}
                  </TableCell>
                  <TableCell className={`text-xs font-data tabular-nums text-right ${client.burstiness > 5 ? "text-lv-red" : client.burstiness > 2 ? "text-lv-peach" : ""}`}>
                    {client.burstiness.toFixed(1)}
                  </TableCell>
                  <TableCell className="text-xs font-data tabular-nums text-right">
                    {client.anomaly_score.toFixed(0)}
                  </TableCell>
                  <TableCell>
                    <ClassificationBadge classification={client.classification} />
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {client.top_paths && client.top_paths.length > 0
                      ? `${client.top_paths.length} path${client.top_paths.length !== 1 ? "s" : ""}`
                      : "—"}
                  </TableCell>
                </TableRow>
                {isExpanded && (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={11} className="bg-lovelace-950/50 p-4">
                      <div className="grid gap-4 sm:grid-cols-2">
                        {/* Left: all paths with bars */}
                        <div className="space-y-1.5">
                          <div className={T.sectionLabel}>Request Paths</div>
                          {client.top_paths && client.top_paths.length > 0 ? (
                            <div className="space-y-1">
                              {client.top_paths.map((p, i) => {
                                const maxCount = client.top_paths![0].count;
                                const pct = maxCount > 0 ? (p.count / maxCount) * 100 : 0;
                                return (
                                  <div key={i} className="relative">
                                    <div
                                      className="absolute inset-y-0 left-0 rounded-sm bg-lv-cyan/10"
                                      style={{ width: `${pct}%` }}
                                    />
                                    <div className="relative flex items-center justify-between gap-3 px-2 py-0.5 text-xs">
                                      <span className="font-data text-muted-foreground truncate" title={p.path}>
                                        {p.path}
                                      </span>
                                      <span className="font-data tabular-nums text-foreground shrink-0">
                                        {p.count.toLocaleString()}
                                      </span>
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          ) : (
                            <span className="text-xs text-muted-foreground/50">No path data</span>
                          )}
                        </div>
                        {/* Right: metrics summary */}
                        <div className="space-y-1.5">
                          <div className={T.sectionLabel}>Anomaly Metrics</div>
                          <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
                            <div className="text-muted-foreground">Classification</div>
                            <div><ClassificationBadge classification={client.classification} /></div>
                            <div className="text-muted-foreground">Anomaly Score</div>
                            <div className="font-data tabular-nums">{client.anomaly_score.toFixed(1)} / 100</div>
                            <div className="text-muted-foreground">Requests</div>
                            <div className="font-data tabular-nums">{client.requests.toLocaleString()} total ({client.requests_per_sec > 0 ? `${client.requests_per_sec.toFixed(2)} req/s` : "—"})</div>
                            <div className="text-muted-foreground">Error Rate</div>
                            <div className={`font-data tabular-nums ${client.error_rate > 0.3 ? "text-lv-red" : client.error_rate > 0.1 ? "text-lv-peach" : ""}`}>
                              {(client.error_rate * 100).toFixed(1)}%
                            </div>
                            <div className="text-muted-foreground">Path Diversity</div>
                            <div className={`font-data tabular-nums ${client.path_diversity < 0.05 ? "text-lv-red" : client.path_diversity < 0.2 ? "text-lv-peach" : ""}`}>
                              {client.path_diversity.toFixed(3)} <span className="text-muted-foreground font-normal">({client.path_diversity < 0.05 ? "very focused" : client.path_diversity < 0.2 ? "focused" : client.path_diversity < 0.5 ? "moderate" : "varied"})</span>
                            </div>
                            <div className="text-muted-foreground">Burstiness (Fano)</div>
                            <div className={`font-data tabular-nums ${client.burstiness > 5 ? "text-lv-red" : client.burstiness > 2 ? "text-lv-peach" : ""}`}>
                              {client.burstiness.toFixed(2)} <span className="text-muted-foreground font-normal">({client.burstiness <= 1.2 ? "even" : client.burstiness <= 3 ? "moderate" : "bursty"})</span>
                            </div>
                            <div className="text-muted-foreground">Country</div>
                            <div>{client.country || "Unknown"}</div>
                          </div>
                        </div>
                      </div>
                    </TableCell>
                  </TableRow>
                )}
                </Fragment>
              );
            })}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

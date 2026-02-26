import { useState, useEffect, useCallback, useMemo } from "react";
import {
  Zap,
  BarChart3,
  Loader2,
  ArrowRight,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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
import { Slider } from "@/components/ui/slider";
import {
  TooltipProvider,
} from "@/components/ui/tooltip";
import {
  getRateAdvisor,
  type RateLimitRuleCreateData,
  type RateAdvisorResponse,
  type ServiceDetail,
  type Condition,
  type ConditionField,
  type RLRuleAction,
} from "@/lib/api";
import {
  ClassificationBadge,
  ConfidenceBadge,
  DistributionHistogram,
  ImpactCurve,
  TimeOfDayChart,
} from "./AdvisorCharts";

// ─── Rate Advisor Panel ─────────────────────────────────────────────

export function RateAdvisorPanel({
  services,
  onCreateRule,
}: {
  services: ServiceDetail[];
  onCreateRule: (data: RateLimitRuleCreateData) => void;
}) {
  const [data, setData] = useState<RateAdvisorResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [window, setWindow] = useState("1m");
  const [service, setService] = useState("");
  const [path, setPath] = useState("");
  const [method, setMethod] = useState("");
  const [threshold, setThreshold] = useState<number>(0);
  const [maxRate, setMaxRate] = useState(100);
  const [clientSort, setClientSort] = useState<"requests" | "anomaly_score" | "error_rate">("requests");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await getRateAdvisor({
        window,
        service: service || undefined,
        path: path || undefined,
        method: method || undefined,
        limit: 50,
      });
      setData(result);
      // Auto-set threshold to recommendation or P95.
      if (result.recommendation && result.recommendation.threshold > 0) {
        setThreshold(result.recommendation.threshold);
      } else if (result.percentiles.p95 > 0) {
        setThreshold(result.percentiles.p95);
      }
      // Set max for slider.
      const topRate = result.clients.length > 0 ? result.clients[0].requests : 100;
      setMaxRate(Math.max(topRate, 10));
    } catch {
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [window, service, path, method]);

  useEffect(() => { load(); }, [load]);

  const affectedClients = useMemo(
    () => data?.clients.filter((c) => c.requests >= threshold) ?? [],
    [data, threshold]
  );
  const affectedRequests = useMemo(
    () => affectedClients.reduce((sum, c) => sum + c.requests, 0),
    [affectedClients]
  );

  const sortedClients = useMemo(() => {
    if (!data) return [];
    const sorted = [...data.clients];
    if (clientSort === "anomaly_score") {
      sorted.sort((a, b) => b.anomaly_score - a.anomaly_score);
    } else if (clientSort === "error_rate") {
      sorted.sort((a, b) => b.error_rate - a.error_rate);
    } else {
      sorted.sort((a, b) => b.requests - a.requests);
    }
    return sorted;
  }, [data, clientSort]);

  const classifications = useMemo(() => {
    if (!data) return { normal: 0, suspicious: 0, abusive: 0 };
    return data.clients.reduce((acc, c) => {
      acc[c.classification] = (acc[c.classification] || 0) + 1;
      return acc;
    }, { normal: 0, suspicious: 0, abusive: 0 } as Record<string, number>);
  }, [data]);

  const handleCreateRule = () => {
    const conditions: Condition[] = [];
    if (path) {
      conditions.push({ field: "path" as ConditionField, operator: "begins_with", value: path });
    }
    if (method) {
      conditions.push({ field: "method" as ConditionField, operator: "eq", value: method });
    }
    onCreateRule({
      name: service ? `${service}-rate-limit` : "rate-limit",
      description: `Auto-generated from Rate Advisor (${threshold} req/${window})`,
      service: service || "",
      conditions: conditions.length > 0 ? conditions : undefined,
      group_operator: conditions.length > 1 ? "and" : undefined,
      key: "client_ip",
      events: threshold,
      window,
      action: "log_only" as RLRuleAction,
      priority: 0,
      enabled: true,
    });
  };

  const rec = data?.recommendation;

  return (
    <TooltipProvider delayDuration={200}>
    <div className="space-y-4">
      {/* Filters */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-neon-cyan" />
            <CardTitle className="text-sm">Request Rate Analysis</CardTitle>
          </div>
          <CardDescription>
            Analyze request rates using statistical anomaly detection (MAD-based) to find optimal
            rate limiting thresholds. Clients are classified as normal, suspicious, or abusive.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap gap-3 items-end">
            <div className="space-y-1">
              <Label className="text-xs text-muted-foreground">Window</Label>
              <Select value={window} onValueChange={setWindow}>
                <SelectTrigger className="w-24"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="1m">1 min</SelectItem>
                  <SelectItem value="5m">5 min</SelectItem>
                  <SelectItem value="10m">10 min</SelectItem>
                  <SelectItem value="1h">1 hour</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label className="text-xs text-muted-foreground">Service</Label>
              <Select value={service || "all"} onValueChange={(v) => setService(v === "all" ? "" : v)}>
                <SelectTrigger className="w-40"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All services</SelectItem>
                  {services.map((s) => (
                    <SelectItem key={s.service} value={s.service}>{s.service}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label className="text-xs text-muted-foreground">Method</Label>
              <Select value={method || "all"} onValueChange={(v) => setMethod(v === "all" ? "" : v)}>
                <SelectTrigger className="w-28"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All</SelectItem>
                  {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((m) => (
                    <SelectItem key={m} value={m}>{m}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label className="text-xs text-muted-foreground">Path prefix</Label>
              <Input
                placeholder="/api/..."
                value={path}
                onChange={(e) => setPath(e.target.value)}
                className="w-36 font-mono text-xs"
              />
            </div>
            <Button variant="outline" size="sm" onClick={load} disabled={loading}>
              {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : "Analyze"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {data && !loading && data.total_requests > 0 && (
        <>
          {/* Recommendation banner */}
          {rec && (
            <div className="flex items-center justify-between rounded-lg border border-neon-cyan/30 bg-neon-cyan/5 px-4 py-3">
              <div className="flex items-center gap-3">
                <Zap className="h-4 w-4 text-neon-cyan shrink-0" />
                <div className="text-sm">
                  <span className="text-muted-foreground">Recommended threshold: </span>
                  <span className="font-mono font-semibold text-neon-cyan">{rec.threshold}</span>
                  <span className="text-muted-foreground"> req/{window} </span>
                  <ConfidenceBadge confidence={rec.confidence} />
                  <span className="text-muted-foreground text-xs ml-2">
                    ({rec.method.toUpperCase()}-based — would affect{" "}
                    <span className="font-mono">{rec.affected_clients}</span> client{rec.affected_clients !== 1 ? "s" : ""},{" "}
                    <span className="font-mono">{rec.affected_requests.toLocaleString()}</span> requests)
                  </span>
                </div>
              </div>
              <Button
                variant="outline"
                size="sm"
                className="shrink-0 text-xs"
                onClick={() => setThreshold(rec.threshold)}
              >
                Apply
              </Button>
            </div>
          )}

          {/* Stats */}
          <div className="grid gap-4 sm:grid-cols-5">
            <Card>
              <CardContent className="p-4">
                <div className="text-xs text-muted-foreground">Total Requests</div>
                <div className="text-2xl font-bold tabular-nums">{data.total_requests.toLocaleString()}</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="text-xs text-muted-foreground">Unique Clients</div>
                <div className="text-2xl font-bold tabular-nums">{data.unique_clients.toLocaleString()}</div>
                <div className="flex gap-1.5 mt-1">
                  <span className="text-[9px] text-neon-green">{classifications.normal} ok</span>
                  <span className="text-[9px] text-neon-amber">{classifications.suspicious} sus</span>
                  <span className="text-[9px] text-red-400">{classifications.abusive} bad</span>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="text-xs text-muted-foreground">P95 Rate</div>
                <div className="text-2xl font-bold tabular-nums text-neon-yellow">{data.percentiles.p95}</div>
                <div className="text-[10px] text-muted-foreground">
                  req/{window}
                  {data.normalized_percentiles && data.window_seconds > 0 && (
                    <span className="ml-1 text-neon-cyan">({data.normalized_percentiles.p95.toFixed(2)} rps)</span>
                  )}
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="text-xs text-muted-foreground">Median / MAD</div>
                <div className="text-lg font-bold tabular-nums">
                  {rec ? `${rec.median}` : data.percentiles.p50}
                  {rec && <span className="text-xs text-muted-foreground font-normal"> ±{rec.mad}</span>}
                </div>
                <div className="text-[10px] text-muted-foreground">
                  {rec ? `separation: ${rec.separation}σ` : "req/" + window}
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="text-xs text-muted-foreground">Would Be Limited</div>
                <div className="text-2xl font-bold tabular-nums text-neon-red">{affectedClients.length}</div>
                <div className="text-[10px] text-muted-foreground">
                  {affectedRequests.toLocaleString()} requests ({data.total_requests > 0 ? ((affectedRequests / data.total_requests) * 100).toFixed(1) : 0}%)
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Threshold + Histogram + Impact Curve row */}
          <div className="grid gap-4 lg:grid-cols-3">
            {/* Threshold slider */}
            <Card className="lg:col-span-2">
              <CardContent className="p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <Label className="text-xs text-muted-foreground">Rate Limit Threshold</Label>
                    <div className="flex items-center gap-2">
                      <Input
                        type="number"
                        min={1}
                        max={maxRate}
                        value={threshold}
                        onChange={(e) => setThreshold(Number(e.target.value) || 1)}
                        className="w-20 tabular-nums"
                      />
                      <span className="text-xs text-muted-foreground">req / {window}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                    <span>P50: {data.percentiles.p50}</span>
                    <span>P75: {data.percentiles.p75}</span>
                    <span>P90: {data.percentiles.p90}</span>
                    <span className="font-medium text-neon-yellow">P95: {data.percentiles.p95}</span>
                    <span>P99: {data.percentiles.p99}</span>
                  </div>
                </div>
                <Slider
                  min={1}
                  max={maxRate}
                  step={1}
                  value={[threshold]}
                  onValueChange={([v]) => setThreshold(v)}
                  className="py-2"
                />
                {/* Distribution histogram */}
                {data.histogram && data.histogram.length > 0 && (
                  <div className="pt-2">
                    <div className="text-[10px] text-muted-foreground mb-1">
                      Client rate distribution (yellow line = threshold, red = above)
                    </div>
                    <DistributionHistogram histogram={data.histogram} threshold={threshold} />
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Impact curve */}
            <Card>
              <CardContent className="p-4 space-y-2">
                <div className="text-xs text-muted-foreground">Impact Sensitivity</div>
                <p className="text-[10px] text-muted-foreground">
                  % of clients/requests affected as threshold changes
                </p>
                {data.impact_curve && data.impact_curve.length >= 2 ? (
                  <ImpactCurve curve={data.impact_curve} threshold={threshold} />
                ) : (
                  <div className="text-[10px] text-muted-foreground/50 py-4 text-center">Not enough data</div>
                )}
                {/* Current impact summary */}
                <div className="flex items-center gap-3 text-[10px] pt-1 border-t border-border">
                  <div>
                    <span className="text-muted-foreground">Clients: </span>
                    <span className="font-mono text-neon-cyan">{affectedClients.length}/{data.unique_clients}</span>
                    <span className="text-muted-foreground"> ({data.unique_clients > 0 ? ((affectedClients.length / data.unique_clients) * 100).toFixed(1) : 0}%)</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Reqs: </span>
                    <span className="font-mono text-pink-400">{affectedRequests.toLocaleString()}/{data.total_requests.toLocaleString()}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Time-of-Day Baselines */}
          {data.time_of_day_baselines && data.time_of_day_baselines.length >= 2 && (
            <Card>
              <CardContent className="p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-xs text-muted-foreground">Traffic by Hour of Day</div>
                    <p className="text-[10px] text-muted-foreground">
                      Median &amp; P95 request rates per client, per hour
                    </p>
                  </div>
                  <div className="flex items-center gap-3 text-[9px] text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <span className="inline-block w-2 h-2 rounded-sm" style={{ background: "rgba(34,211,238,0.5)" }} />
                      Median
                    </span>
                    <span className="flex items-center gap-1">
                      <span className="inline-block w-2 h-2 rounded-sm" style={{ background: "rgba(34,211,238,0.15)" }} />
                      P95
                    </span>
                  </div>
                </div>
                <TimeOfDayChart baselines={data.time_of_day_baselines} width={800} height={120} />
                <div className="flex gap-3 text-[9px] text-muted-foreground pt-1 border-t border-border flex-wrap">
                  {data.time_of_day_baselines.map((b) => (
                    <span key={b.hour} className="font-mono">
                      {String(b.hour).padStart(2, "0")}h: {b.median_rps.toFixed(3)}/{b.p95_rps.toFixed(3)} rps
                      <span className="text-muted-foreground/50"> ({b.clients}c, {b.requests}r)</span>
                    </span>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Client table */}
          <Card>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-xs">
                  Top {data.clients.length} Clients
                </CardTitle>
                <div className="flex items-center gap-2">
                  <Label className="text-[10px] text-muted-foreground">Sort by</Label>
                  <Select value={clientSort} onValueChange={(v) => setClientSort(v as typeof clientSort)}>
                    <SelectTrigger className="h-6 text-[10px] w-28">
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
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[10px]">Client IP</TableHead>
                    <TableHead className="text-[10px]">Country</TableHead>
                    <TableHead className="text-[10px] text-right">Requests</TableHead>
                    <TableHead className="text-[10px] text-right">Req/s</TableHead>
                    <TableHead className="text-[10px] text-right">Error %</TableHead>
                    <TableHead className="text-[10px] text-right">Diversity</TableHead>
                    <TableHead className="text-[10px] text-right">Burstiness</TableHead>
                    <TableHead className="text-[10px] text-right">Score</TableHead>
                    <TableHead className="text-[10px]">Class</TableHead>
                    <TableHead className="text-[10px]">Top Paths</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sortedClients.map((client) => {
                    const isAbove = client.requests >= threshold;
                    return (
                      <TableRow key={client.client_ip} className={isAbove ? "bg-red-500/5" : ""}>
                        <TableCell className="font-mono text-[11px]">{client.client_ip}</TableCell>
                        <TableCell className="text-[10px]">{client.country || "—"}</TableCell>
                        <TableCell className={`text-[11px] font-mono tabular-nums text-right ${isAbove ? "text-red-400 font-medium" : ""}`}>
                          {client.requests.toLocaleString()}
                        </TableCell>
                        <TableCell className="text-[10px] font-mono tabular-nums text-right text-neon-cyan">
                          {client.requests_per_sec > 0 ? client.requests_per_sec.toFixed(2) : "—"}
                        </TableCell>
                        <TableCell className={`text-[10px] font-mono tabular-nums text-right ${client.error_rate > 0.3 ? "text-red-400" : client.error_rate > 0.1 ? "text-neon-amber" : ""}`}>
                          {(client.error_rate * 100).toFixed(0)}%
                        </TableCell>
                        <TableCell className={`text-[10px] font-mono tabular-nums text-right ${client.path_diversity < 0.05 ? "text-red-400" : client.path_diversity < 0.2 ? "text-neon-amber" : ""}`}>
                          {client.path_diversity.toFixed(2)}
                        </TableCell>
                        <TableCell className={`text-[10px] font-mono tabular-nums text-right ${client.burstiness > 5 ? "text-red-400" : client.burstiness > 2 ? "text-neon-amber" : ""}`}>
                          {client.burstiness.toFixed(1)}
                        </TableCell>
                        <TableCell className="text-[10px] font-mono tabular-nums text-right">
                          {client.anomaly_score.toFixed(0)}
                        </TableCell>
                        <TableCell>
                          <ClassificationBadge classification={client.classification} />
                        </TableCell>
                        <TableCell className="text-[10px] font-mono text-muted-foreground max-w-[200px] truncate">
                          {client.top_paths?.map((p) => `${p.count}× ${p.path}`).join(", ") || "—"}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          {/* Create Rule action */}
          {threshold > 0 && (
            <div className="flex items-center justify-between rounded-lg border border-border bg-navy-950 px-4 py-3">
              <div className="text-sm">
                <span className="text-muted-foreground">Create a rule that limits clients to </span>
                <span className="font-mono font-medium text-neon-cyan">{threshold}</span>
                <span className="text-muted-foreground"> requests per </span>
                <span className="font-mono font-medium text-neon-cyan">{window}</span>
                {service && (
                  <>
                    <span className="text-muted-foreground"> on </span>
                    <span className="font-mono font-medium text-neon-cyan">{service}</span>
                  </>
                )}
                <span className="text-muted-foreground">
                  ? Starts in <span className="text-neon-yellow">monitor mode</span> — switch to deny when confident.
                </span>
              </div>
              <Button size="sm" onClick={handleCreateRule} className="gap-1.5 shrink-0 ml-4">
                Create Rule <ArrowRight className="h-3.5 w-3.5" />
              </Button>
            </div>
          )}
        </>
      )}

      {loading && (
        <div className="flex items-center justify-center py-12 text-muted-foreground">
          <Loader2 className="h-5 w-5 animate-spin mr-2" />
          Scanning access log...
        </div>
      )}

      {!loading && data && data.total_requests === 0 && (
        <Card>
          <CardContent className="py-8 text-center text-xs text-muted-foreground">
            No traffic found in the selected time window. Try a longer window or remove filters.
          </CardContent>
        </Card>
      )}
    </div>
    </TooltipProvider>
  );
}

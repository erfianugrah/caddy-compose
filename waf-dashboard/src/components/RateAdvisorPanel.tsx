import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import {
  Zap,
  BarChart3,
  Loader2,
  ArrowRight,
  Filter,
  Plus,
  X,
  ChevronRight,
  Search,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
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
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Slider } from "@/components/ui/slider";
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
import { T } from "@/lib/typography";

// ─── Advisor Filter Constants ───────────────────────────────────────

const WINDOW_OPTIONS = [
  { value: "1m", label: "1 min" },
  { value: "5m", label: "5 min" },
  { value: "10m", label: "10 min" },
  { value: "1h", label: "1 hour" },
] as const;

const WINDOW_LABELS: Record<string, string> = Object.fromEntries(
  WINDOW_OPTIONS.map((o) => [o.value, o.label])
);

const METHOD_OPTIONS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

type AdvisorField = "service" | "method" | "path";

const ADVISOR_FIELD_META: { field: AdvisorField; label: string; placeholder: string }[] = [
  { field: "service", label: "Service", placeholder: "Search services..." },
  { field: "method", label: "Method", placeholder: "Select method" },
  { field: "path", label: "Path", placeholder: "/api/..." },
];

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

  // Filter bar state
  const [filterPopoverOpen, setFilterPopoverOpen] = useState(false);
  const [windowPopoverOpen, setWindowPopoverOpen] = useState(false);
  const [editingField, setEditingField] = useState<AdvisorField | null>(null);
  const [filterInput, setFilterInput] = useState("");
  const filterInputRef = useRef<HTMLInputElement>(null);

  // Focus input when editing a text field
  useEffect(() => {
    if (editingField === "service" || editingField === "path") {
      const t = setTimeout(() => filterInputRef.current?.focus(), 50);
      return () => clearTimeout(t);
    }
  }, [editingField]);

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
      if (result.recommendation && result.recommendation.threshold > 0) {
        setThreshold(result.recommendation.threshold);
      } else if (result.percentiles.p95 > 0) {
        setThreshold(result.percentiles.p95);
      }
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
    if (!data) return { normal: 0, elevated: 0, suspicious: 0, abusive: 0 };
    return data.clients.reduce((acc, c) => {
      acc[c.classification] = (acc[c.classification] || 0) + 1;
      return acc;
    }, { normal: 0, elevated: 0, suspicious: 0, abusive: 0 } as Record<string, number>);
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

  // Which optional fields are currently active
  const activeOptionalFields = useMemo(() => {
    const active: AdvisorField[] = [];
    if (service) active.push("service");
    if (method) active.push("method");
    if (path) active.push("path");
    return active;
  }, [service, method, path]);

  const availableFields = useMemo(
    () => ADVISOR_FIELD_META.filter((f) => !activeOptionalFields.includes(f.field)),
    [activeOptionalFields]
  );

  const resetFilterPopover = useCallback(() => {
    setEditingField(null);
    setFilterInput("");
  }, []);

  const applyFilter = useCallback((field: AdvisorField, value: string) => {
    const trimmed = value.trim();
    if (!trimmed) return;
    if (field === "service") setService(trimmed);
    else if (field === "method") setMethod(trimmed);
    else if (field === "path") setPath(trimmed);
    setFilterPopoverOpen(false);
    resetFilterPopover();
  }, [resetFilterPopover]);

  const removeFilter = useCallback((field: AdvisorField) => {
    if (field === "service") setService("");
    else if (field === "method") setMethod("");
    else if (field === "path") setPath("");
  }, []);

  function renderFilterPopoverContent() {
    // Step 1: Pick a field
    if (!editingField) {
      if (availableFields.length === 0) {
        return <p className="px-2 py-2 text-xs text-muted-foreground">All filters are active</p>;
      }
      return (
        <div className="space-y-1">
          <p className="px-2 py-1 text-xs font-medium text-muted-foreground">Add filter</p>
          {availableFields.map((f) => (
            <button
              key={f.field}
              className="flex w-full items-center justify-between rounded-sm px-2 py-1.5 text-sm hover:bg-accent hover:text-accent-foreground transition-colors cursor-pointer"
              onClick={() => setEditingField(f.field)}
            >
              <span>{f.label}</span>
              <ChevronRight className="h-3 w-3 text-muted-foreground" />
            </button>
          ))}
        </div>
      );
    }

    // Step 2: Enter value
    const meta = ADVISOR_FIELD_META.find((f) => f.field === editingField)!;

    // Method: button list
    if (editingField === "method") {
      return (
        <div className="space-y-1">
          <button
            className="flex items-center gap-1 px-2 py-1 text-xs text-muted-foreground hover:text-foreground cursor-pointer"
            onClick={() => setEditingField(null)}
          >
            &larr; Back
          </button>
          <p className="px-2 py-1 text-xs font-medium text-muted-foreground">Select method</p>
          {METHOD_OPTIONS.map((m) => (
            <button
              key={m}
              className="flex w-full items-center rounded-sm px-2 py-1.5 text-sm font-mono hover:bg-accent hover:text-accent-foreground transition-colors cursor-pointer"
              onClick={() => applyFilter("method", m)}
            >
              {m}
            </button>
          ))}
        </div>
      );
    }

    // Service: searchable list + free text
    if (editingField === "service") {
      const serviceNames = services.map((s) => s.service);
      const filtered = filterInput
        ? serviceNames.filter((s) => s.toLowerCase().includes(filterInput.toLowerCase()))
        : serviceNames;

      return (
        <div className="space-y-1.5">
          <button
            className="flex items-center gap-1 px-2 py-1 text-xs text-muted-foreground hover:text-foreground cursor-pointer"
            onClick={() => { setEditingField(null); setFilterInput(""); }}
          >
            &larr; Back
          </button>
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              ref={filterInputRef}
              placeholder={meta.placeholder}
              value={filterInput}
              onChange={(e) => setFilterInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && filterInput.trim()) {
                  e.preventDefault();
                  applyFilter("service", filterInput);
                }
                if (e.key === "Escape") {
                  setFilterPopoverOpen(false);
                  resetFilterPopover();
                }
              }}
              className="h-8 text-sm pl-7"
            />
          </div>
          <div className="max-h-64 overflow-y-auto">
            {filtered.length > 0 ? (
              filtered.map((s) => (
                <button
                  key={s}
                  className="flex w-full items-center rounded-sm px-2 py-1.5 text-sm font-mono hover:bg-accent hover:text-accent-foreground transition-colors cursor-pointer"
                  onClick={() => applyFilter("service", s)}
                >
                  {s}
                </button>
              ))
            ) : filterInput.trim() ? (
              <button
                className="flex w-full items-center rounded-sm px-2 py-1.5 text-sm hover:bg-accent hover:text-accent-foreground transition-colors cursor-pointer"
                onClick={() => applyFilter("service", filterInput)}
              >
                Use &quot;{filterInput}&quot;
              </button>
            ) : (
              <p className="px-2 py-2 text-xs text-muted-foreground">Type a service name...</p>
            )}
          </div>
        </div>
      );
    }

    // Path: free text input
    return (
      <div className="space-y-2">
        <button
          className="flex items-center gap-1 px-2 py-1 text-xs text-muted-foreground hover:text-foreground cursor-pointer"
          onClick={() => { setEditingField(null); setFilterInput(""); }}
        >
          &larr; Back
        </button>
        <p className="px-2 py-1 text-xs font-medium text-muted-foreground">Path prefix</p>
        <Input
          ref={filterInputRef}
          placeholder={meta.placeholder}
          value={filterInput}
          onChange={(e) => setFilterInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && filterInput.trim()) {
              e.preventDefault();
              applyFilter("path", filterInput);
            }
            if (e.key === "Escape") {
              setFilterPopoverOpen(false);
              resetFilterPopover();
            }
          }}
          className="h-8 text-sm font-mono"
        />
        <Button
          size="sm"
          className="h-7 w-full text-xs"
          disabled={!filterInput.trim()}
          onClick={() => applyFilter("path", filterInput)}
        >
          Apply
        </Button>
      </div>
    );
  }

  const rec = data?.recommendation;

  // Helper to render a filter chip
  const FilterChip = ({ field, label, value, mono }: { field: AdvisorField; label: string; value: string; mono?: boolean }) => (
    <Badge
      variant="secondary"
      className="gap-1 pl-2 pr-1 py-0.5 text-xs font-normal bg-neon-cyan/10 border-neon-cyan/20 hover:bg-neon-cyan/20 transition-colors"
    >
      <span className="text-muted-foreground font-medium">{label}</span>
      <span className="text-neon-cyan/70 font-mono text-xs">=</span>
      <span className={mono ? "font-mono" : ""}>{value}</span>
      <button
        className="ml-0.5 rounded-sm p-0.5 hover:bg-neon-cyan/30 transition-colors cursor-pointer"
        onClick={() => removeFilter(field)}
        title={`Remove ${label} filter`}
      >
        <X className="h-3 w-3" />
      </button>
    </Badge>
  );

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="space-y-1">
        <div className="flex items-center gap-2">
          <BarChart3 className="h-4 w-4 text-neon-cyan" />
          <h3 className={T.sectionHeading}>Request Rate Analysis</h3>
        </div>
        <p className="text-xs text-muted-foreground">
          Analyze request rates using statistical anomaly detection (MAD-based) to find optimal
          rate limiting thresholds. Clients are classified as normal, suspicious, or abusive.
        </p>
      </div>

      {/* Filter Bar */}
      <div className="flex items-center gap-2 rounded-lg border border-neon-cyan/20 bg-neon-cyan/5 px-3 py-2">
        <Filter className="h-3.5 w-3.5 text-neon-cyan shrink-0" />
        <div className="flex flex-wrap items-center gap-1.5 flex-1 min-w-0">
          {/* Window chip (always present, click to change) */}
          <Popover open={windowPopoverOpen} onOpenChange={setWindowPopoverOpen}>
            <PopoverTrigger asChild>
              <button className="inline-flex items-center gap-1 rounded-md border border-neon-cyan/30 bg-neon-cyan/15 px-2 py-0.5 text-xs transition-colors hover:bg-neon-cyan/25 cursor-pointer">
                <span className="text-muted-foreground font-medium">Window</span>
                <span className="text-neon-cyan/70 font-mono">=</span>
                <span className="font-medium">{WINDOW_LABELS[window] || window}</span>
              </button>
            </PopoverTrigger>
            <PopoverContent className="w-36 p-2" align="start">
              {WINDOW_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  className={`flex w-full items-center rounded-sm px-2 py-1.5 text-sm transition-colors cursor-pointer ${
                    window === opt.value ? "bg-neon-cyan/10 text-neon-cyan" : "hover:bg-accent hover:text-accent-foreground"
                  }`}
                  onClick={() => { setWindow(opt.value); setWindowPopoverOpen(false); }}
                >
                  {opt.label}
                </button>
              ))}
            </PopoverContent>
          </Popover>

          {/* Active filter chips */}
          {service && <FilterChip field="service" label="Service" value={service} mono />}
          {method && <FilterChip field="method" label="Method" value={method} mono />}
          {path && <FilterChip field="path" label="Path" value={path} mono />}

          {/* Add filter button */}
          {availableFields.length > 0 && (
            <Popover open={filterPopoverOpen} onOpenChange={(open) => {
              setFilterPopoverOpen(open);
              if (!open) resetFilterPopover();
            }}>
              <PopoverTrigger asChild>
                <button className="flex items-center gap-1 rounded-sm px-1.5 py-0.5 text-xs text-muted-foreground hover:text-foreground hover:bg-accent/50 transition-colors cursor-pointer">
                  <Plus className="h-3 w-3" />
                  Add
                </button>
              </PopoverTrigger>
              <PopoverContent className="w-64 p-3" align="start">
                {renderFilterPopoverContent()}
              </PopoverContent>
            </Popover>
          )}
        </div>

        <Button variant="outline" size="sm" onClick={load} disabled={loading} className="shrink-0 gap-1.5">
          {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : "Analyze"}
        </Button>
      </div>

      {data && !loading && data.total_requests > 0 && (
        <>
          {/* Recommendation banner */}
          {rec && (
            <div className="flex items-center justify-between rounded-lg border border-neon-cyan/30 bg-neon-cyan/5 px-5 py-4">
              <div className="flex items-center gap-3">
                <Zap className="h-5 w-5 text-neon-cyan shrink-0" />
                <div>
                  <div className="text-sm">
                    <span className="text-muted-foreground">Recommended threshold: </span>
                    <span className="font-mono font-semibold text-neon-cyan text-base">{rec.threshold}</span>
                    <span className="text-muted-foreground"> req/{window} </span>
                    <ConfidenceBadge confidence={rec.confidence} />
                  </div>
                  <div className="text-xs text-muted-foreground mt-0.5">
                    {rec.method.toUpperCase()}-based — would affect{" "}
                    <span className="font-mono">{rec.affected_clients}</span> client{rec.affected_clients !== 1 ? "s" : ""},{" "}
                    <span className="font-mono">{rec.affected_requests.toLocaleString()}</span> requests
                  </div>
                </div>
              </div>
              <Button
                variant="outline"
                size="sm"
                className="shrink-0"
                onClick={() => setThreshold(rec.threshold)}
              >
                Apply
              </Button>
            </div>
          )}

          {/* Stats */}
          <div className="grid gap-4 sm:grid-cols-5">
            <Card>
              <CardContent className="p-5">
                <div className={`${T.statLabel} mb-1`}>Total Requests</div>
                <div className={T.statValue}>{data.total_requests.toLocaleString()}</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-5">
                <div className={`${T.statLabel} mb-1`}>Unique Clients</div>
                <div className={T.statValue}>{data.unique_clients.toLocaleString()}</div>
                <div className="flex gap-2 mt-1.5 text-xs">
                  <span className="text-neon-green">{classifications.normal} ok</span>
                  <span className="text-neon-amber">{classifications.suspicious} sus</span>
                  <span className="text-red-400">{classifications.abusive} bad</span>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-5">
                <div className={`${T.statLabel} mb-1`}>P95 Rate</div>
                <div className={`${T.statValue} text-neon-yellow`}>{data.percentiles.p95}</div>
                <div className="text-xs text-muted-foreground mt-0.5">
                  req/{window}
                  {data.normalized_percentiles && data.window_seconds > 0 && (
                    <span className="ml-1 text-neon-cyan">({data.normalized_percentiles.p95.toFixed(2)} rps)</span>
                  )}
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-5">
                <div className={`${T.statLabel} mb-1`}>Median / MAD</div>
                <div className={T.statValueSm}>
                  {rec ? `${rec.median}` : data.percentiles.p50}
                  {rec && <span className="text-sm text-muted-foreground font-normal ml-1">±{rec.mad}</span>}
                </div>
                <div className="text-xs text-muted-foreground mt-0.5">
                  {rec ? `separation: ${rec.separation}σ` : "req/" + window}
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-5">
                <div className={`${T.statLabel} mb-1`}>Would Be Limited</div>
                <div className={`${T.statValue} text-neon-red`}>{affectedClients.length}</div>
                <div className="text-xs text-muted-foreground mt-0.5">
                  {affectedRequests.toLocaleString()} requests ({data.total_requests > 0 ? ((affectedRequests / data.total_requests) * 100).toFixed(1) : 0}%)
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Threshold + Histogram + Impact Curve */}
          <div className="grid gap-5 lg:grid-cols-2">
          <Card>
              <CardContent className="p-5 space-y-4">
                <div className="flex items-center justify-between gap-4">
                  <div className="space-y-1.5">
                    <Label className="text-xs text-muted-foreground">Rate Limit Threshold</Label>
                    <div className="flex items-center gap-2">
                      <Input
                        type="number"
                        min={1}
                        max={maxRate}
                        value={threshold}
                        onChange={(e) => setThreshold(Number(e.target.value) || 1)}
                        className="w-24 tabular-nums"
                      />
                      <span className="text-sm text-muted-foreground">req / {window}</span>
                    </div>
                  </div>
                  {/* Percentile display — high contrast */}
                  <div className="flex items-center gap-4 tabular-nums font-mono">
                    {([
                      { label: "P50", value: data.percentiles.p50, highlight: false },
                      { label: "P75", value: data.percentiles.p75, highlight: false },
                      { label: "P90", value: data.percentiles.p90, highlight: false },
                      { label: "P95", value: data.percentiles.p95, highlight: true },
                      { label: "P99", value: data.percentiles.p99, highlight: false },
                    ] as const).map(({ label, value, highlight }) => (
                      <span key={label} className={highlight ? "text-neon-yellow" : ""}>
                        <span className={`text-xs mr-1 ${highlight ? "text-neon-yellow/70" : "text-muted-foreground"}`}>{label}</span>
                        <span className={`text-sm font-medium ${highlight ? "font-semibold" : "text-foreground"}`}>{value}</span>
                      </span>
                    ))}
                  </div>
                </div>
                <Slider
                  min={1}
                  max={maxRate}
                  step={1}
                  value={[threshold]}
                  onValueChange={([v]) => setThreshold(v)}
                  className="py-1"
                />
                {/* Distribution histogram */}
                {data.histogram && data.histogram.length > 0 && (
                  <div className="pt-3">
                    <div className="text-xs text-muted-foreground mb-2">
                      Client rate distribution <span className="text-neon-yellow">(yellow line = threshold</span>, <span className="text-red-400">red = above)</span>
                    </div>
                    <DistributionHistogram histogram={data.histogram} threshold={threshold} />
                  </div>
                )}
              </CardContent>
            </Card>

          {/* Impact curve */}
          <Card>
            <CardContent className="p-5 space-y-3">
              <div>
                <div className="text-xs font-medium mb-0.5">Impact Sensitivity</div>
                <p className="text-xs text-muted-foreground">
                  % of clients/requests affected as threshold changes
                </p>
              </div>
              {data.impact_curve && data.impact_curve.length >= 2 ? (
                <ImpactCurve curve={data.impact_curve} threshold={threshold} />
              ) : (
                <div className="text-xs text-muted-foreground/50 py-8 text-center">Not enough data</div>
              )}
              <div className="flex items-center gap-4 text-xs pt-2 border-t border-border">
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
              <CardContent className="p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-xs font-medium mb-0.5">Traffic by Hour of Day</div>
                    <p className="text-xs text-muted-foreground">
                      Median &amp; P95 request rates per client, per hour
                    </p>
                  </div>
                  <div className="flex items-center gap-4 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1.5">
                      <span className="inline-block w-2.5 h-2.5 rounded-sm" style={{ background: "rgba(34,211,238,0.5)" }} />
                      Median
                    </span>
                    <span className="flex items-center gap-1.5">
                      <span className="inline-block w-2.5 h-2.5 rounded-sm" style={{ background: "rgba(34,211,238,0.15)" }} />
                      P95
                    </span>
                  </div>
                </div>
                <TimeOfDayChart baselines={data.time_of_day_baselines} />
                <div className="flex gap-4 text-xs text-muted-foreground pt-2 border-t border-border flex-wrap">
                  {data.time_of_day_baselines.map((b) => (
                    <span key={b.hour} className="font-mono">
                      {String(b.hour).padStart(2, "0")}h: {b.median_rps.toFixed(3)}/{b.p95_rps.toFixed(3)} rps
                      <span className="text-muted-foreground/50 ml-1">({b.clients}c, {b.requests}r)</span>
                    </span>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Client table */}
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className={T.cardTitle}>
                  Top {data.clients.length} Clients
                </CardTitle>
                <div className="flex items-center gap-2">
                  <Label className="text-xs text-muted-foreground">Sort by</Label>
                  <Select value={clientSort} onValueChange={(v) => setClientSort(v as typeof clientSort)}>
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
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead>Client IP</TableHead>
                    <TableHead>Country</TableHead>
                    <TableHead className="text-right">Requests</TableHead>
                    <TableHead className="text-right">Req/s</TableHead>
                    <TableHead className="text-right">Error %</TableHead>
                    <TableHead className="text-right">Diversity</TableHead>
                    <TableHead className="text-right">Burstiness</TableHead>
                    <TableHead className="text-right">Score</TableHead>
                    <TableHead>Class</TableHead>
                    <TableHead>Top Paths</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sortedClients.map((client) => {
                    const isAbove = client.requests >= threshold;
                    return (
                      <TableRow key={client.client_ip} className={isAbove ? "bg-red-500/5" : ""}>
                        <TableCell className="font-mono text-xs">{client.client_ip}</TableCell>
                        <TableCell className="text-xs">{client.country || "—"}</TableCell>
                        <TableCell className={`text-xs font-mono tabular-nums text-right ${isAbove ? "text-red-400 font-medium" : ""}`}>
                          {client.requests.toLocaleString()}
                        </TableCell>
                        <TableCell className="text-xs font-mono tabular-nums text-right text-neon-cyan">
                          {client.requests_per_sec > 0 ? client.requests_per_sec.toFixed(2) : "—"}
                        </TableCell>
                        <TableCell className={`text-xs font-mono tabular-nums text-right ${client.error_rate > 0.3 ? "text-red-400" : client.error_rate > 0.1 ? "text-neon-amber" : ""}`}>
                          {(client.error_rate * 100).toFixed(0)}%
                        </TableCell>
                        <TableCell className={`text-xs font-mono tabular-nums text-right ${client.path_diversity < 0.05 ? "text-red-400" : client.path_diversity < 0.2 ? "text-neon-amber" : ""}`}>
                          {client.path_diversity.toFixed(2)}
                        </TableCell>
                        <TableCell className={`text-xs font-mono tabular-nums text-right ${client.burstiness > 5 ? "text-red-400" : client.burstiness > 2 ? "text-neon-amber" : ""}`}>
                          {client.burstiness.toFixed(1)}
                        </TableCell>
                        <TableCell className="text-xs font-mono tabular-nums text-right">
                          {client.anomaly_score.toFixed(0)}
                        </TableCell>
                        <TableCell>
                          <ClassificationBadge classification={client.classification} />
                        </TableCell>
                        <TableCell className="text-xs font-mono text-muted-foreground max-w-[250px] truncate">
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
            <div className="flex items-center justify-between rounded-lg border border-border bg-navy-950 px-5 py-4">
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
        <div className="flex items-center justify-center py-16 text-muted-foreground">
          <Loader2 className="h-5 w-5 animate-spin mr-2" />
          Scanning access log...
        </div>
      )}

      {!loading && data && data.total_requests === 0 && (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            No traffic found in the selected time window. Try a longer window or remove filters.
          </CardContent>
        </Card>
      )}
    </div>
  );
}

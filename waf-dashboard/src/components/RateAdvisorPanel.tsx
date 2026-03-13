import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import {
  BarChart3,
  Loader2,
  Filter,
  Plus,
  X,
  ChevronRight,
  Search,
} from "lucide-react";
import {
  Card,
  CardContent,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
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
import { isValidWindow } from "@/lib/format";
import { T } from "@/lib/typography";
import {
  StatTip,
  ADVISOR_WINDOW_OPTIONS,
  windowLabel,
  METHOD_OPTIONS,
  ADVISOR_FIELD_META,
  type AdvisorField,
} from "./ratelimits/advisorConstants";
import { AdvisorClientTable } from "./ratelimits/AdvisorClientTable";
import { AdvisorRecommendations } from "./ratelimits/AdvisorRecommendations";

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
  const [error, setError] = useState<string | null>(null);
  const [window, setWindow] = useState("1m");
  const [service, setService] = useState("");
  const [path, setPath] = useState("");
  const [method, setMethod] = useState("");
  const [threshold, setThreshold] = useState<number>(0);
  const [maxRate, setMaxRate] = useState(100);

  // Filter bar state
  const [filterPopoverOpen, setFilterPopoverOpen] = useState(false);
  const [windowPopoverOpen, setWindowPopoverOpen] = useState(false);
  const [customWindow, setCustomWindow] = useState("");
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
    setError(null);
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
    } catch (err) {
      console.error("Rate advisor load failed:", err);
      setData(null);
      setError("Failed to load advisor data");
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
              className="flex w-full items-center rounded-sm px-2 py-1.5 text-sm font-data hover:bg-accent hover:text-accent-foreground transition-colors cursor-pointer"
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
                  className="flex w-full items-center rounded-sm px-2 py-1.5 text-sm font-data hover:bg-accent hover:text-accent-foreground transition-colors cursor-pointer"
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
          className="h-8 text-sm font-data"
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
      className="gap-1 pl-2 pr-1 py-0.5 text-xs font-normal bg-lv-cyan/10 border-lv-cyan/20 hover:bg-lv-cyan/20 transition-colors"
    >
      <span className="text-muted-foreground font-medium">{label}</span>
      <span className="text-lv-cyan/70 font-data text-xs">=</span>
      <span className={mono ? "font-data" : ""}>{value}</span>
      <button
        className="ml-0.5 rounded-sm p-0.5 hover:bg-lv-cyan/30 transition-colors cursor-pointer"
        onClick={() => removeFilter(field)}
        title={`Remove ${label} filter`}
      >
        <X className="h-3 w-3" />
      </button>
    </Badge>
  );

  return (
    <TooltipProvider delayDuration={200}>
    <div className="space-y-5">
      {/* Header */}
      <div className="space-y-1">
        <div className="flex items-center gap-2">
          <BarChart3 className="h-4 w-4 text-lv-cyan" />
          <h3 className={T.sectionHeading}>Request Rate Analysis</h3>
        </div>
        <p className="text-xs text-muted-foreground">
          Analyze request rates using statistical anomaly detection (MAD-based) to find optimal
          rate limiting thresholds. Clients are classified as normal, suspicious, or abusive.
        </p>
      </div>

      {/* Filter Bar */}
      <div className="flex items-center gap-2 rounded-lg border border-lv-cyan/20 bg-lv-cyan/5 px-3 py-2">
        <Filter className="h-3.5 w-3.5 text-lv-cyan shrink-0" />
        <div className="flex flex-wrap items-center gap-1.5 flex-1 min-w-0">
          {/* Window chip (always present, click to change) */}
          <Popover open={windowPopoverOpen} onOpenChange={(open) => {
            setWindowPopoverOpen(open);
            if (!open) setCustomWindow("");
          }}>
            <PopoverTrigger asChild>
              <button className="inline-flex items-center gap-1 rounded-md border border-lv-cyan/30 bg-lv-cyan/15 px-2 py-0.5 text-xs transition-colors hover:bg-lv-cyan/25 cursor-pointer">
                <span className="text-muted-foreground font-medium">Window</span>
                <span className="text-lv-cyan/70 font-data">=</span>
                <span className="font-medium">{windowLabel(window)}</span>
              </button>
            </PopoverTrigger>
            <PopoverContent className="w-48 p-2" align="start">
              {ADVISOR_WINDOW_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  className={`flex w-full items-center rounded-sm px-2 py-1.5 text-sm transition-colors cursor-pointer ${
                    window === opt.value ? "bg-lv-cyan/10 text-lv-cyan" : "hover:bg-accent hover:text-accent-foreground"
                  }`}
                  onClick={() => { setWindow(opt.value); setWindowPopoverOpen(false); }}
                >
                  {opt.label}
                </button>
              ))}
              <div className="border-t border-border mt-1.5 pt-1.5">
                <p className="px-2 py-0.5 text-xs text-muted-foreground">Custom</p>
                <div className="flex items-center gap-1.5 px-1 mt-1">
                  <Input
                    placeholder="e.g. 3m, 45s"
                    value={customWindow}
                    onChange={(e) => setCustomWindow(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        const v = customWindow.trim().toLowerCase();
                        if (isValidWindow(v)) {
                          setWindow(v);
                          setWindowPopoverOpen(false);
                          setCustomWindow("");
                        }
                      }
                    }}
                    className="h-7 text-xs font-data flex-1"
                  />
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 px-2 text-xs"
                    disabled={!isValidWindow(customWindow)}
                    onClick={() => {
                      const v = customWindow.trim().toLowerCase();
                      setWindow(v);
                      setWindowPopoverOpen(false);
                      setCustomWindow("");
                    }}
                  >
                    Go
                  </Button>
                </div>
              </div>
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
          {/* Recommendations: banner + create rule + threshold/charts */}
          <AdvisorRecommendations
            data={data}
            threshold={threshold}
            maxRate={maxRate}
            window={window}
            service={service}
            affectedClients={affectedClients.length}
            affectedRequests={affectedRequests}
            onThresholdChange={setThreshold}
            onCreateRule={handleCreateRule}
          />

          {/* Stats */}
          <div className="grid gap-4 grid-cols-2 sm:grid-cols-3 lg:grid-cols-5">
            <Card>
              <CardContent className="p-4">
                <div className={`${T.statLabelUpper} mb-1`}>
                  Total Requests
                  <StatTip tip="Total number of requests seen in the selected time window, after applying any service/path/method filters." />
                </div>
                <div className={T.statValue}>{data.total_requests.toLocaleString()}</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className={`${T.statLabelUpper} mb-1`}>
                  Unique Clients
                  <StatTip tip="Distinct client IPs observed. Classified by composite anomaly score: normal (<30), elevated (30–59), suspicious (60–79), or abusive (80+)." />
                </div>
                <div className={T.statValue}>{data.unique_clients.toLocaleString()}</div>
                <div className="flex gap-2 mt-1.5 text-xs">
                  <span className="text-lv-green">{classifications.normal} ok</span>
                  <span className="text-lv-peach">{classifications.suspicious} sus</span>
                  <span className="text-lv-red">{classifications.abusive} bad</span>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className={`${T.statLabelUpper} mb-1`}>
                  P95 Rate
                  <StatTip tip="95th percentile of per-client request counts within the window. 95% of clients made fewer requests than this value." />
                </div>
                <div className={`${T.statValue} text-neon-yellow`}>{data.percentiles.p95}</div>
                <div className="text-xs text-muted-foreground mt-0.5">
                  req/{window}
                  {data.normalized_percentiles && data.window_seconds > 0 && (
                    <span className="ml-1 text-lv-cyan">({data.normalized_percentiles.p95.toFixed(2)} rps)</span>
                  )}
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className={`${T.statLabelUpper} mb-1`}>
                  Median / MAD
                  <StatTip tip="Median: the middle client's request count. MAD (Median Absolute Deviation): a robust measure of spread. Separation (σ) indicates how many MADs the threshold is from the median — higher means clearer distinction between normal and anomalous traffic." />
                </div>
                <div className={T.statValue}>
                  {rec ? `${rec.median}` : data.percentiles.p50}
                  {rec && <span className="text-sm text-muted-foreground font-normal ml-1">±{rec.mad}</span>}
                </div>
                <div className="text-xs text-muted-foreground mt-0.5">
                  {rec ? `separation: ${rec.separation}σ` : "req/" + window}
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className={`${T.statLabelUpper} mb-1`}>
                  Would Be Limited
                  <StatTip tip="Number of clients whose request count exceeds the current threshold. Adjust the slider below to see the impact of different thresholds." />
                </div>
                <div className={`${T.statValue} text-neon-red`}>{affectedClients.length}</div>
                <div className="text-xs text-muted-foreground mt-0.5">
                  {affectedRequests.toLocaleString()} requests ({data.total_requests > 0 ? ((affectedRequests / data.total_requests) * 100).toFixed(1) : 0}%)
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Client table */}
          <AdvisorClientTable
            clients={data.clients}
            threshold={threshold}
          />
        </>
      )}

      {loading && (
        <div className="flex items-center justify-center py-16 text-muted-foreground">
          <Loader2 className="h-5 w-5 animate-spin mr-2" />
          Scanning access log...
        </div>
      )}

      {!loading && error && (
        <Card className="border-lv-red/20">
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            {error}
          </CardContent>
        </Card>
      )}

      {!loading && !error && data && data.total_requests === 0 && (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            No traffic found in the selected time window. Try a longer window or remove filters.
          </CardContent>
        </Card>
      )}
    </div>
    </TooltipProvider>
  );
}

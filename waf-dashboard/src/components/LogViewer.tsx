import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import TimeRangePicker, { rangeToParams, type TimeRange } from "@/components/TimeRangePicker";
import { useTableSort } from "@/hooks/useTableSort";
import { formatNumber } from "@/lib/format";
import {
  fetchGeneralLogs,
  fetchGeneralLogsSummary,
  type GeneralLogEvent,
  type GeneralLogsResponse,
  type GeneralLogsSummary,
  type GeneralLogsParams,
} from "@/lib/api";

import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Activity,
  AlertTriangle,
  Clock,
  RefreshCw,
  ShieldAlert,
} from "lucide-react";

import type { SortKey, ViewTab } from "./logs/helpers";
import { formatDuration, StatCard } from "./logs/helpers";
import LogStreamTab from "./logs/LogStreamTab";
import SummaryTab from "./logs/SummaryTab";
import HeaderComplianceTab from "./logs/HeaderComplianceTab";

// ─── Main Component ─────────────────────────────────────────────────

export default function LogViewer() {
  const [response, setResponse] = useState<GeneralLogsResponse | null>(null);
  const [summary, setSummary] = useState<GeneralLogsSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<ViewTab>("logs");

  // Filters
  const [timeRange, setTimeRange] = useState<TimeRange>({ type: "relative", hours: 1, label: "Last 1 hour" });
  const [serviceFilter, setServiceFilter] = useState("");
  const [methodFilter, setMethodFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [levelFilter, setLevelFilter] = useState("");
  const [missingHeaderFilter, setMissingHeaderFilter] = useState("");
  const [uriFilter, setUriFilter] = useState("");

  // Pagination
  const [page, setPage] = useState(1);
  const perPage = 50;

  // Expanded rows (keyed by timestamp+index for stable identity)
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const toggleExpand = useCallback((key: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  const collapseAll = useCallback(() => setExpanded(new Set()), []);

  // Auto-refresh
  const refreshTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const buildParams = useCallback((): GeneralLogsParams => {
    const params: GeneralLogsParams = {
      ...rangeToParams(timeRange),
      page,
      per_page: perPage,
    };
    if (serviceFilter) params.service = serviceFilter;
    if (methodFilter) params.method = methodFilter;
    if (statusFilter) params.status = statusFilter;
    if (levelFilter) params.level = levelFilter;
    if (missingHeaderFilter) params.missing_header = missingHeaderFilter;
    if (uriFilter) { params.uri = uriFilter; params.uri_op = "contains"; }
    return params;
  }, [timeRange, page, serviceFilter, methodFilter, statusFilter, levelFilter, missingHeaderFilter, uriFilter]);

  const loadLogs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = buildParams();
      const [logsResp, summaryResp] = await Promise.all([
        fetchGeneralLogs(params),
        fetchGeneralLogsSummary(params),
      ]);
      setResponse(logsResp);
      setSummary(summaryResp);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load logs");
    } finally {
      setLoading(false);
    }
  }, [buildParams]);

  useEffect(() => { loadLogs(); }, [loadLogs]);

  // URL params on mount
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("status")) setStatusFilter(params.get("status")!);
    if (params.get("service")) setServiceFilter(params.get("service")!);
    if (params.get("missing_header")) setMissingHeaderFilter(params.get("missing_header")!);
    if (params.get("level")) setLevelFilter(params.get("level")!);
    if (params.has("status") || params.has("service") || params.has("missing_header") || params.has("level")) {
      window.history.replaceState({}, "", window.location.pathname);
    }
  }, []);

  // Sort
  const comparators = useMemo(() => ({
    time: (a: GeneralLogEvent, b: GeneralLogEvent) =>
      new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
    status: (a: GeneralLogEvent, b: GeneralLogEvent) => a.status - b.status,
    duration: (a: GeneralLogEvent, b: GeneralLogEvent) => a.duration - b.duration,
    size: (a: GeneralLogEvent, b: GeneralLogEvent) => a.size - b.size,
    service: (a: GeneralLogEvent, b: GeneralLogEvent) => a.service.localeCompare(b.service),
    method: (a: GeneralLogEvent, b: GeneralLogEvent) => a.method.localeCompare(b.method),
  }), []);

  const { sortState, toggleSort, sortedData } = useTableSort<GeneralLogEvent, SortKey>(
    response?.events ?? [],
    comparators,
  );

  const totalPages = response ? Math.ceil(response.total / perPage) : 0;

  const clearFilters = () => {
    setServiceFilter("");
    setMethodFilter("");
    setStatusFilter("");
    setLevelFilter("");
    setMissingHeaderFilter("");
    setUriFilter("");
    setPage(1);
  };

  const hasFilters = !!(serviceFilter || methodFilter || statusFilter || levelFilter || missingHeaderFilter || uriFilter);

  // ─── Render ──────────────────────────────────────────────────────

  if (error && !response) {
    return (
      <Card className="border-red-500/30 bg-red-500/5">
        <CardContent className="py-8 text-center">
          <AlertTriangle className="mx-auto mb-2 h-8 w-8 text-red-400" />
          <p className="text-sm text-red-400">{error}</p>
          <Button variant="outline" size="sm" className="mt-4" onClick={loadLogs}>Retry</Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground">Access Logs</h1>
          <p className="text-sm text-muted-foreground">
            All HTTP traffic — debug CSP, CORS, security headers, latency, and errors
          </p>
        </div>
        <div className="flex items-center gap-2">
          <TimeRangePicker value={timeRange} onChange={(tr) => { setTimeRange(tr); setPage(1); }} onRefresh={loadLogs} />
          <Button variant="outline" size="sm" onClick={loadLogs} disabled={loading}>
            <RefreshCw className={`mr-1.5 h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 rounded-lg bg-muted/50 p-1">
        {(["logs", "summary", "headers"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
              tab === t
                ? "bg-background text-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {t === "logs" ? "Log Stream" : t === "summary" ? "Overview" : "Header Compliance"}
          </button>
        ))}
      </div>

      {/* Summary Cards (always visible) */}
      {summary && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-6">
          <StatCard
            label="Total Requests"
            value={formatNumber(summary.total_requests)}
            icon={<Activity className="h-4 w-4 text-neon-cyan" />}
          />
          <StatCard
            label="5xx Errors"
            value={formatNumber(summary.error_count)}
            icon={<AlertTriangle className="h-4 w-4 text-red-400" />}
            accent={summary.error_count > 0 ? "red" : undefined}
          />
          <StatCard
            label="4xx Errors"
            value={formatNumber(summary.client_error_count)}
            icon={<ShieldAlert className="h-4 w-4 text-amber-400" />}
          />
          <StatCard
            label="Avg Latency"
            value={formatDuration(summary.avg_duration)}
            icon={<Clock className="h-4 w-4 text-blue-400" />}
          />
          <StatCard
            label="P95 Latency"
            value={formatDuration(summary.p95_duration)}
            icon={<Clock className="h-4 w-4 text-amber-400" />}
          />
          <StatCard
            label="P99 Latency"
            value={formatDuration(summary.p99_duration)}
            icon={<Clock className="h-4 w-4 text-red-400" />}
          />
        </div>
      )}

      {/* Tab content */}
      {tab === "logs" && (
        <LogStreamTab
          response={response}
          loading={loading}
          sortState={sortState}
          toggleSort={toggleSort}
          sortedData={sortedData}
          page={page}
          totalPages={totalPages}
          setPage={setPage}
          expanded={expanded}
          toggleExpand={toggleExpand}
          collapseAll={collapseAll}
          serviceFilter={serviceFilter}
          setServiceFilter={(v) => { setServiceFilter(v); setPage(1); }}
          methodFilter={methodFilter}
          setMethodFilter={(v) => { setMethodFilter(v); setPage(1); }}
          statusFilter={statusFilter}
          setStatusFilter={(v) => { setStatusFilter(v); setPage(1); }}
          levelFilter={levelFilter}
          setLevelFilter={(v) => { setLevelFilter(v); setPage(1); }}
          missingHeaderFilter={missingHeaderFilter}
          setMissingHeaderFilter={(v) => { setMissingHeaderFilter(v); setPage(1); }}
          uriFilter={uriFilter}
          setUriFilter={(v) => { setUriFilter(v); setPage(1); }}
          hasFilters={hasFilters}
          clearFilters={clearFilters}
        />
      )}
      {tab === "summary" && summary && <SummaryTab summary={summary} />}
      {tab === "headers" && summary && <HeaderComplianceTab compliance={summary.header_compliance} />}
    </div>
  );
}

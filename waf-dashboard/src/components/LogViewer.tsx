import { useState, useEffect, useCallback, useMemo } from "react";
import TimeRangePicker, { rangeToParams, type TimeRange } from "@/components/TimeRangePicker";
import DashboardFilterBar from "@/components/DashboardFilterBar";
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

import type { LogFilterField, DashboardFilter } from "@/components/filters/types";
import { LOG_FILTER_CONFIG } from "@/components/filters/constants";
import { parseLogFiltersFromURL, filtersToGeneralLogsParams } from "@/components/filters/filterUtils";

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

  // Filters — now managed as structured DashboardFilter array
  const [timeRange, setTimeRange] = useState<TimeRange>({ type: "relative", hours: 1, label: "Last 1 hour" });
  const [filters, setFilters] = useState<DashboardFilter<LogFilterField>[]>([]);

  // Service list for dynamic autocomplete in filter bar
  const [knownServices, setKnownServices] = useState<string[]>([]);

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

  const buildParams = useCallback((): GeneralLogsParams => {
    const params: GeneralLogsParams = {
      ...rangeToParams(timeRange),
      ...filtersToGeneralLogsParams(filters),
      page,
      per_page: perPage,
    };
    return params;
  }, [timeRange, page, filters]);

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
      // Collect known services for autocomplete
      if (summaryResp?.top_services) {
        setKnownServices(summaryResp.top_services.map((s: { service: string }) => s.service));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load logs");
    } finally {
      setLoading(false);
    }
  }, [buildParams]);

  useEffect(() => { loadLogs(); }, [loadLogs]);

  // URL params on mount (client-only)
  useEffect(() => {
    const search = window.location.search;
    if (!search) return;
    const parsed = parseLogFiltersFromURL(search);
    if (parsed.length > 0) {
      setFilters(parsed);
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

  const handleFiltersChange = useCallback((newFilters: DashboardFilter<LogFilterField>[]) => {
    setFilters(newFilters);
    setPage(1);
  }, []);

  // ─── Render ──────────────────────────────────────────────────────

  if (error && !response) {
    return (
      <Card className="border-lv-red/30 bg-lv-red/5">
        <CardContent className="py-8 text-center">
          <AlertTriangle className="mx-auto mb-2 h-8 w-8 text-lv-red" />
          <p className="text-sm text-lv-red">{error}</p>
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

      {/* Filter bar */}
      <DashboardFilterBar<LogFilterField>
        filters={filters}
        onChange={handleFiltersChange}
        config={LOG_FILTER_CONFIG}
        dynamicOptions={{ services: knownServices }}
      />

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
            icon={<Activity className="h-4 w-4 text-lv-cyan" />}
          />
          <StatCard
            label="5xx Errors"
            value={formatNumber(summary.error_count)}
            icon={<AlertTriangle className="h-4 w-4 text-lv-red" />}
            accent={summary.error_count > 0 ? "red" : undefined}
          />
          <StatCard
            label="4xx Errors"
            value={formatNumber(summary.client_error_count)}
            icon={<ShieldAlert className="h-4 w-4 text-lv-peach" />}
          />
          <StatCard
            label="Avg Latency"
            value={formatDuration(summary.avg_duration)}
            icon={<Clock className="h-4 w-4 text-blue-400" />}
          />
          <StatCard
            label="P95 Latency"
            value={formatDuration(summary.p95_duration)}
            icon={<Clock className="h-4 w-4 text-lv-peach" />}
          />
          <StatCard
            label="P99 Latency"
            value={formatDuration(summary.p99_duration)}
            icon={<Clock className="h-4 w-4 text-lv-red" />}
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
        />
      )}
      {tab === "summary" && summary && <SummaryTab summary={summary} />}
      {tab === "headers" && summary && <HeaderComplianceTab compliance={summary.header_compliance} />}
    </div>
  );
}

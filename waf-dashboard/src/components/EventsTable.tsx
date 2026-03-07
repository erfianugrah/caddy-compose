import { Fragment, useState, useEffect, useCallback, useRef, useMemo } from "react";
import {
  ChevronDown,
  ChevronRight,
  ChevronLeft,
  ChevronsLeft,
  ChevronsRight,
  ChevronsDownUp,
  Download,
} from "lucide-react";
import { useTableSort } from "@/hooks/useTableSort";
import { SortableTableHead } from "@/components/SortableTableHead";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  fetchEvents,
  fetchAllEvents,
  fetchServices,
  getExclusions,
  type WAFEvent,
  type EventsResponse,
  type ServiceDetail,
} from "@/lib/api";
import TimeRangePicker, { rangeToParams, type TimeRange } from "@/components/TimeRangePicker";
import { countryFlag, formatTime, formatDate } from "@/lib/format";
import { T } from "@/lib/typography";
import { downloadJSON } from "@/lib/download";
import { EventTypeBadge } from "./EventTypeBadge";
import DashboardFilterBar, {
  parseFiltersFromURL,
  filtersToEventsParams,
  type DashboardFilter,
} from "./DashboardFilterBar";
import { isPolicyRuleEvent, policyRuleLink } from "./events/helpers";
import { EventDetailPanel } from "./events/EventDetailPanel";

// Re-export EventDetailPanel for backward compatibility
export { EventDetailPanel } from "./events/EventDetailPanel";

export default function EventsTable() {
  const [response, setResponse] = useState<EventsResponse | null>(null);
  const [services, setServices] = useState<ServiceDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  // Time range
  const [timeRange, setTimeRange] = useState<TimeRange>({
    type: "relative",
    hours: 24,
    label: "Last 24 hours",
  });

  // Filters — shared DashboardFilterBar state
  const [filters, setFilters] = useState<DashboardFilter[]>([]);
  const filtersInitRef = useRef(false);

  // Track event_id to auto-expand once events load.
  // fallbackParamsRef holds filter+time params for RL/ipsum events whose
  // ephemeral IDs won't match the fast-path ID lookup.
  const pendingExpandRef = useRef<string | null>(null);
  const fallbackParamsRef = useRef<{ filters: DashboardFilter[]; timeRange: TimeRange } | null>(null);
  // Skip the next loadEvents cycle (used after ID fast-path to avoid double fetch
  // when setFilters/setTimeRange trigger a re-render).
  const skipNextLoadRef = useRef(false);
  // Request generation counter — prevents stale responses from overwriting newer ones.
  // When filters change, a new loadEvents fires with a higher generation; if the old
  // unfiltered response arrives after the new filtered one, it's discarded.
  const requestGenRef = useRef(0);

  // Read URL params on mount (client-only to avoid hydration mismatch)
  useEffect(() => {
    if (filtersInitRef.current) return;
    filtersInitRef.current = true;
    if (typeof window === "undefined") return;
    const search = window.location.search;
    if (!search) return;

    const params = new URLSearchParams(search);
    const eventId = params.get("event_id");
    const start = params.get("start");
    const end = params.get("end");

    // Deep-link to a specific event: try ID lookup first, keep filters as fallback only
    if (eventId && start && end) {
      pendingExpandRef.current = eventId;
      const deepLinkRange: TimeRange = { type: "absolute", start, end };
      const deepLinkFilters = parseFiltersFromURL(search);
      // Store filters + time range as fallback (not in state — no chips shown)
      fallbackParamsRef.current = { filters: deepLinkFilters, timeRange: deepLinkRange };
      window.history.replaceState({}, "", window.location.pathname);
      return;
    }

    const parsed = parseFiltersFromURL(search);
    if (parsed.length > 0) {
      setFilters(parsed);
    }
    window.history.replaceState({}, "", window.location.pathname);
  }, []);

  const [page, setPage] = useState(1);
  const perPage = 25;

  // Service names for filter bar autocomplete
  const serviceNames = useMemo(
    () => services.map((s) => s.service),
    [services],
  );

  // Rule names for filter bar autocomplete
  const [ruleNames, setRuleNames] = useState<string[]>([]);
  const [exportingAll, setExportingAll] = useState(false);

  const loadEvents = useCallback(() => {
    // Skip this cycle if flagged (e.g. after ID fast-path set filters/timeRange).
    if (skipNextLoadRef.current) {
      skipNextLoadRef.current = false;
      return;
    }

    const gen = ++requestGenRef.current;
    setLoading(true);
    const timeParams = rangeToParams(timeRange);
    const filterParams = filtersToEventsParams(filters);

    // If we have a pending event ID, try fast-path lookup first.
    const pendingId = pendingExpandRef.current;
    const fb = fallbackParamsRef.current;
    if (pendingId && fb && page === 1) {
      // Consume the fallback so we don't loop.
      fallbackParamsRef.current = null;
      fetchEvents({ id: pendingId })
        .then((resp) => {
          if (requestGenRef.current !== gen) return; // stale
          if (resp.total > 0) {
            // Found via ID — show the event_id chip + absolute time range.
            setResponse(resp);
            // Set state so the filter bar shows "Event ID = ..." chip and
            // the time picker shows the narrow deep-link window.
            // Skip the next loadEvents cycle that these state changes trigger.
            skipNextLoadRef.current = true;
            setFilters([{ field: "event_id", operator: "eq", value: pendingId }]);
            setTimeRange(fb.timeRange);
            return;
          }
          // Not found by ID (e.g. ephemeral RL event) — apply fallback
          // filters+time to state. This triggers a re-render that fetches
          // via the normal path below (fb is now null so we won't loop).
          setFilters(fb.filters);
          setTimeRange(fb.timeRange);
        })
        .catch((err) => {
          if (requestGenRef.current === gen) setError(err.message);
        })
        .finally(() => {
          if (requestGenRef.current === gen) setLoading(false);
        });
      return;
    }

    fetchEvents({
      page,
      per_page: perPage,
      ...filterParams,
      ...timeParams,
    })
      .then((resp) => {
        if (requestGenRef.current === gen) setResponse(resp);
      })
      .catch((err) => {
        if (requestGenRef.current === gen) setError(err.message);
      })
      .finally(() => {
        if (requestGenRef.current === gen) setLoading(false);
      });
  }, [page, filters, timeRange]);

  useEffect(() => {
    fetchServices()
      .then(setServices)
      .catch(() => {}); // Non-critical
    getExclusions()
      .then((excl) => setRuleNames(excl.map((e) => e.name).filter(Boolean)))
      .catch(() => {}); // Non-critical
  }, []);

  useEffect(() => {
    loadEvents();
  }, [loadEvents]);

  // Auto-expand a specific event when deep-linked from Overview Dashboard
  useEffect(() => {
    if (!pendingExpandRef.current || loading || !response || response.events.length === 0) return;
    const id = pendingExpandRef.current;
    // Try exact ID match first; for ephemeral RL/ipsum IDs, expand the first result
    // (the narrow time window + filters should isolate the exact event).
    const match = response.events.find((e) => e.id === id) ?? response.events[0];
    const expandId = match.id;
    setExpanded(new Set([expandId]));
    pendingExpandRef.current = null;
    requestAnimationFrame(() => {
      const row = document.querySelector(`[data-event-id="${expandId}"]`);
      row?.scrollIntoView({ behavior: "smooth", block: "center" });
    });
  }, [loading, response]);

  // Reset page when filters change
  useEffect(() => {
    setPage(1);
  }, [filters, timeRange]);

  const toggleExpand = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const events = response?.events ?? [];
  const totalPages = response?.total_pages ?? 1;

  const evtSortComparators = useMemo(() => ({
    time: (a: WAFEvent, b: WAFEvent) => a.timestamp.localeCompare(b.timestamp),
    service: (a: WAFEvent, b: WAFEvent) => a.service.localeCompare(b.service),
    method: (a: WAFEvent, b: WAFEvent) => a.method.localeCompare(b.method),
    uri: (a: WAFEvent, b: WAFEvent) => a.uri.localeCompare(b.uri),
    client_ip: (a: WAFEvent, b: WAFEvent) => a.client_ip.localeCompare(b.client_ip),
    country: (a: WAFEvent, b: WAFEvent) => (a.country ?? "").localeCompare(b.country ?? ""),
    rule: (a: WAFEvent, b: WAFEvent) => (a.rule_id ?? 0) - (b.rule_id ?? 0),
    score: (a: WAFEvent, b: WAFEvent) => a.anomaly_score - b.anomaly_score,
    type: (a: WAFEvent, b: WAFEvent) => a.event_type.localeCompare(b.event_type),
  }), []);
  const evtSort = useTableSort(events, evtSortComparators);
  const sortedEvents = evtSort.sortedData;

  if (error) {
    return (
      <Card className="max-w-md">
        <CardHeader>
          <CardTitle className="text-neon-pink">Error</CardTitle>
          <CardDescription>{error}</CardDescription>
        </CardHeader>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className={T.pageTitle}>Security Event Log</h2>
          <p className={T.pageDescription}>
            WAF, rate limit, and policy events with filtering and detail view.
          </p>
        </div>
        <TimeRangePicker
          value={timeRange}
          onChange={setTimeRange}
          onRefresh={loadEvents}
        />
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex-1 min-w-0">
          <DashboardFilterBar
            filters={filters}
            onChange={setFilters}
            services={serviceNames}
            ruleNames={ruleNames}
          />
        </div>

        {response && (
          <div className="flex items-center gap-2 shrink-0">
            <span className="text-xs text-muted-foreground">
              {response.total.toLocaleString()} events
            </span>
            <div className="flex gap-1">
              <Button
                variant="ghost"
                size="xs"
                className="text-muted-foreground hover:text-foreground"
                onClick={() => downloadJSON(events, `events-page-${page}.json`)}
                title="Export current page as JSON"
              >
                <Download className="h-3 w-3 mr-1" />
                Page
              </Button>
              <Button
                variant="ghost"
                size="xs"
                className="text-muted-foreground hover:text-foreground"
                disabled={exportingAll}
                onClick={async () => {
                  setExportingAll(true);
                  try {
                    const timeParams = rangeToParams(timeRange);
                    const filterParams = filtersToEventsParams(filters);
                    const all = await fetchAllEvents({
                      ...filterParams,
                      ...timeParams,
                    });
                    downloadJSON(all, `events-all-${new Date().toISOString().slice(0, 10)}.json`);
                  } catch {
                    // Best-effort: alert on failure since this is a transient action
                    alert("Failed to export events. Please try again.");
                  } finally {
                    setExportingAll(false);
                  }
                }}
                title="Export all matching events as JSON"
              >
                {exportingAll ? (
                  "Exporting..."
                ) : (
                  <>
                    <Download className="h-3 w-3 mr-1" />
                    All ({response.total.toLocaleString()})
                  </>
                )}
              </Button>
              {expanded.size > 0 && (
                <Button
                  variant="ghost"
                  size="xs"
                  className="text-muted-foreground hover:text-foreground"
                  onClick={() => setExpanded(new Set())}
                  title="Collapse all expanded rows"
                >
                  <ChevronsDownUp className="h-3 w-3 mr-1" />
                  Collapse ({expanded.size})
                </Button>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Events Table */}
      <Card>
        <CardContent className="p-0 overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-8" />
                <SortableTableHead sortKey="time" activeKey={evtSort.sortState.key} direction={evtSort.sortState.direction} onSort={evtSort.toggleSort}>Time</SortableTableHead>
                <SortableTableHead sortKey="service" activeKey={evtSort.sortState.key} direction={evtSort.sortState.direction} onSort={evtSort.toggleSort}>Service</SortableTableHead>
                <SortableTableHead sortKey="method" activeKey={evtSort.sortState.key} direction={evtSort.sortState.direction} onSort={evtSort.toggleSort}>Method</SortableTableHead>
                <SortableTableHead sortKey="uri" activeKey={evtSort.sortState.key} direction={evtSort.sortState.direction} onSort={evtSort.toggleSort} className="max-w-[200px]">URI</SortableTableHead>
                <SortableTableHead sortKey="client_ip" activeKey={evtSort.sortState.key} direction={evtSort.sortState.direction} onSort={evtSort.toggleSort}>Client IP</SortableTableHead>
                <SortableTableHead sortKey="country" activeKey={evtSort.sortState.key} direction={evtSort.sortState.direction} onSort={evtSort.toggleSort}>Country</SortableTableHead>
                <SortableTableHead sortKey="rule" activeKey={evtSort.sortState.key} direction={evtSort.sortState.direction} onSort={evtSort.toggleSort}>Rule</SortableTableHead>
                <SortableTableHead sortKey="score" activeKey={evtSort.sortState.key} direction={evtSort.sortState.direction} onSort={evtSort.toggleSort} title="Inbound / Outbound anomaly score">Score</SortableTableHead>
                <SortableTableHead sortKey="type" activeKey={evtSort.sortState.key} direction={evtSort.sortState.direction} onSort={evtSort.toggleSort}>Type</SortableTableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading &&
                [...Array(10)].map((_, i) => (
                  <TableRow key={i}>
                    <TableCell />
                    {[...Array(9)].map((_, j) => (
                      <TableCell key={j}>
                        <Skeleton className="h-4 w-full" />
                      </TableCell>
                    ))}
                  </TableRow>
                ))}

              {!loading &&
                sortedEvents.map((evt) => (
                  <Fragment key={evt.id}>
                    <TableRow
                      className="cursor-pointer"
                      data-event-id={evt.id}
                      onClick={() => toggleExpand(evt.id)}
                    >
                      <TableCell className="w-8">
                        {expanded.has(evt.id) ? (
                          <ChevronDown className="h-4 w-4 text-muted-foreground" />
                        ) : (
                          <ChevronRight className="h-4 w-4 text-muted-foreground" />
                        )}
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-xs">
                        <div className="text-foreground">
                          {formatTime(evt.timestamp)}
                        </div>
                        <div className="text-muted-foreground">
                          {formatDate(evt.timestamp)}
                        </div>
                      </TableCell>
                      <TableCell className="text-xs">{evt.service}</TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={T.badgeMono}
                        >
                          {evt.method}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-[200px] truncate text-xs font-mono" title={evt.uri}>
                        {evt.uri}
                      </TableCell>
                      <TableCell className="text-xs font-mono">
                        <a
                          href={`/analytics?tab=ip&q=${encodeURIComponent(evt.client_ip)}`}
                          onClick={(e) => e.stopPropagation()}
                          className="hover:text-neon-green transition-colors"
                        >
                          {evt.client_ip}
                        </a>
                      </TableCell>
                      <TableCell className="text-xs">
                        {evt.country && evt.country !== "XX" ? (
                          <span className="inline-flex items-center gap-1">
                            <span>{countryFlag(evt.country)}</span>
                            <span className="font-mono">{evt.country}</span>
                          </span>
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </TableCell>
                      <TableCell className="text-xs">
                        {evt.rule_id ? (
                          isPolicyRuleEvent(evt) && policyRuleLink(evt.rule_msg) ? (
                            <a href={policyRuleLink(evt.rule_msg)!} className="inline-flex items-center gap-1 group" onClick={(e) => e.stopPropagation()}>
                              <Badge variant="outline" className={`${T.badgeMono} group-hover:border-emerald-500/50 group-hover:text-emerald-400 transition-colors`}>
                                {evt.rule_id}
                              </Badge>
                            </a>
                          ) : (
                            <Badge variant="outline" className={T.badgeMono}>
                              {evt.rule_id}
                            </Badge>
                          )
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </TableCell>
                      <TableCell className="text-xs tabular-nums">
                        {evt.anomaly_score > 0 || evt.outbound_anomaly_score > 0 ? (
                          <span className="flex items-center gap-1">
                            <span className={
                              evt.anomaly_score >= 25 ? "text-neon-pink font-bold" :
                              evt.anomaly_score >= 10 ? "text-neon-amber font-medium" :
                              evt.anomaly_score > 0 ? "text-neon-cyan" :
                              "text-muted-foreground"
                            }>
                              {evt.anomaly_score || 0}
                            </span>
                            {evt.outbound_anomaly_score > 0 && (
                              <>
                                <span className="text-muted-foreground">/</span>
                                <span className={
                                  evt.outbound_anomaly_score >= 25 ? "text-neon-pink font-bold" :
                                  evt.outbound_anomaly_score >= 10 ? "text-neon-amber font-medium" :
                                  "text-neon-cyan"
                                }>
                                  {evt.outbound_anomaly_score}
                                </span>
                              </>
                            )}
                          </span>
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <EventTypeBadge eventType={evt.event_type} blocked={evt.blocked} />
                      </TableCell>
                    </TableRow>
                    {expanded.has(evt.id) && (
                      <TableRow className="hover:bg-transparent">
                        <TableCell colSpan={10} className="bg-navy-950/50 p-0">
                          <EventDetailPanel event={evt} />
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                ))}

              {!loading && events.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={10}
                    className="py-8 text-center text-muted-foreground"
                  >
                    {filters.some((f) => f.field === "request_id")
                      ? "No correlated security events found for this request ID. The request may have passed through without triggering any security rules, or the event may not yet be indexed."
                      : "No events found matching the current filters."}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <span className="text-xs text-muted-foreground">
            Page {page} of {totalPages}
          </span>
          <div className="flex items-center gap-1">
            <Button
              variant="outline"
              size="icon"
              onClick={() => setPage(1)}
              disabled={page <= 1}
            >
              <ChevronsLeft className="h-4 w-4" />
            </Button>
            <Button
              variant="outline"
              size="icon"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <Button
              variant="outline"
              size="icon"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
            <Button
              variant="outline"
              size="icon"
              onClick={() => setPage(totalPages)}
              disabled={page >= totalPages}
            >
              <ChevronsRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

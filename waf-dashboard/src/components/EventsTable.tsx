import { Fragment, useState, useEffect, useCallback } from "react";
import {
  ChevronDown,
  ChevronRight,
  ChevronLeft,
  ChevronsLeft,
  ChevronsRight,
  Filter,
} from "lucide-react";
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  fetchEvents,
  fetchServices,
  type WAFEvent,
  type EventsResponse,
  type ServiceDetail,
  type EventType,
} from "@/lib/api";
import TimeRangePicker, { rangeToParams, type TimeRange } from "@/components/TimeRangePicker";

function formatTime(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return ts;
  }
}

function formatDate(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
    });
  } catch {
    return "";
  }
}

const SEVERITY_MAP: Record<number, { label: string; color: string }> = {
  2: { label: "CRITICAL", color: "text-neon-pink" },
  3: { label: "ERROR", color: "text-neon-amber" },
  4: { label: "WARNING", color: "text-yellow-400" },
  5: { label: "NOTICE", color: "text-neon-blue" },
};

function formatSeverity(severity: number): { label: string; color: string } {
  return SEVERITY_MAP[severity] ?? { label: severity ? `Level ${severity}` : "N/A", color: "text-muted-foreground" };
}

export function EventDetailPanel({ event }: { event: WAFEvent }) {
  return (
    <div className="space-y-3 p-4">
      <div className="grid gap-4 md:grid-cols-2">
        <div className="space-y-2">
          <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Request Details
          </h4>
          <div className="space-y-1 rounded-md bg-navy-950 p-3 text-xs">
            <div className="flex gap-2">
              <span className="text-muted-foreground">Method:</span>
              <span className="font-medium text-neon-cyan">{event.method}</span>
            </div>
            <div className="flex gap-2">
              <span className="text-muted-foreground">URI:</span>
              <code className="break-all text-foreground">{event.uri}</code>
            </div>
            <div className="flex gap-2">
              <span className="text-muted-foreground">Client:</span>
              <span className="text-foreground">{event.client_ip}</span>
            </div>
            <div className="flex gap-2">
              <span className="text-muted-foreground">Status:</span>
              <span
                className={
                  event.status >= 400 ? "text-neon-pink" : "text-neon-green"
                }
              >
                {event.status}
              </span>
            </div>
          </div>
        </div>

        <div className="space-y-2">
          <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            {event.event_type === "ipsum_blocked" ? "IPsum Blocklist Details" : event.event_type === "rate_limited" ? "Rate Limit Details" : "Rule Match"}
          </h4>
          <div className="space-y-1 rounded-md bg-navy-950 p-3 text-xs">
            {event.event_type === "ipsum_blocked" ? (
              <>
                <div className="flex gap-2">
                  <span className="text-muted-foreground">Action:</span>
                  <span className="text-violet-400 font-medium">IPsum Blocklist (403)</span>
                </div>
                <div className="flex gap-2">
                  <span className="text-muted-foreground">Response:</span>
                  <span className="text-neon-pink">403 Forbidden</span>
                </div>
                <div className="flex gap-2">
                  <span className="text-muted-foreground">Source:</span>
                  <span className="text-violet-400">IPsum threat intelligence blocklist</span>
                </div>
                {event.user_agent && (
                  <div className="flex gap-2">
                    <span className="text-muted-foreground">User-Agent:</span>
                    <code className="break-all text-foreground">{event.user_agent}</code>
                  </div>
                )}
              </>
            ) : event.event_type === "rate_limited" ? (
              <>
                <div className="flex gap-2">
                  <span className="text-muted-foreground">Action:</span>
                  <span className="text-amber-400 font-medium">Rate Limited (429)</span>
                </div>
                <div className="flex gap-2">
                  <span className="text-muted-foreground">Response:</span>
                  <span className="text-neon-pink">429 Too Many Requests</span>
                </div>
                {event.user_agent && (
                  <div className="flex gap-2">
                    <span className="text-muted-foreground">User-Agent:</span>
                    <code className="break-all text-foreground">{event.user_agent}</code>
                  </div>
                )}
              </>
            ) : (
              <>
                <div className="flex gap-2">
                  <span className="text-muted-foreground">Rule ID:</span>
                  <Badge variant="outline" className="text-[10px] px-1.5 py-0 font-mono">
                    {event.rule_id ? event.rule_id : "N/A"}
                  </Badge>
                </div>
                <div className="flex gap-2">
                  <span className="text-muted-foreground">Message:</span>
                  <span className="text-foreground">
                    {event.rule_msg || "N/A"}
                  </span>
                </div>
                <div className="flex gap-2">
                  <span className="text-muted-foreground">Severity:</span>
                  {(() => {
                    const sev = formatSeverity(event.severity);
                    return <span className={sev.color}>{sev.label}</span>;
                  })()}
                </div>
                {event.anomaly_score > 0 && (
                  <div className="flex gap-2">
                    <span className="text-muted-foreground">Anomaly Score:</span>
                    <span className={
                      event.anomaly_score >= 25 ? "text-neon-pink font-bold" :
                      event.anomaly_score >= 10 ? "text-neon-amber font-medium" :
                      "text-neon-cyan"
                    }>
                      {event.anomaly_score}
                    </span>
                  </div>
                )}
                {event.matched_data && (
                  <div className="flex gap-2">
                    <span className="text-muted-foreground">Matched:</span>
                    <code className="break-all text-neon-amber">
                      {event.matched_data}
                    </code>
                  </div>
                )}
                {event.rule_tags && event.rule_tags.length > 0 && (
                  <div className="flex flex-wrap gap-1 pt-1">
                    <span className="text-muted-foreground">Tags:</span>
                    {event.rule_tags.map((tag) => (
                      <Badge key={tag} variant="outline" className="text-[9px] px-1 py-0 font-mono text-muted-foreground">
                        {tag}
                      </Badge>
                    ))}
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </div>

      {event.request_headers &&
        Object.keys(event.request_headers).length > 0 && (
          <div className="space-y-2">
            <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
              Request Headers
            </h4>
            <div className="rounded-md bg-navy-950 p-3">
              <pre className="text-xs text-muted-foreground">
                {Object.entries(event.request_headers)
                  .map(([k, v]) => `${k}: ${v}`)
                  .join("\n")}
              </pre>
            </div>
          </div>
        )}
    </div>
  );
}

const METHODS = ["ALL", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"];

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

  // Filters
  const [page, setPage] = useState(1);
  const [serviceFilter, setServiceFilter] = useState("all");
  const [blockedFilter, setBlockedFilter] = useState<string>("all");
  const [methodFilter, setMethodFilter] = useState("ALL");
  const [eventTypeFilter, setEventTypeFilter] = useState<string>("all");

  const perPage = 25;

  const loadEvents = useCallback(() => {
    setLoading(true);
    const timeParams = rangeToParams(timeRange);
    fetchEvents({
      page,
      per_page: perPage,
      service: serviceFilter === "all" ? undefined : serviceFilter,
      blocked:
        blockedFilter === "all"
          ? null
          : blockedFilter === "blocked"
            ? true
            : false,
      method: methodFilter === "ALL" ? undefined : methodFilter,
      event_type: eventTypeFilter === "all" ? undefined : eventTypeFilter as EventType,
      ...timeParams,
    })
      .then(setResponse)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [page, serviceFilter, blockedFilter, methodFilter, eventTypeFilter, timeRange]);

  useEffect(() => {
    fetchServices()
      .then(setServices)
      .catch(() => {}); // Non-critical
  }, []);

  useEffect(() => {
    loadEvents();
  }, [loadEvents]);

  // Reset page when filters change
  useEffect(() => {
    setPage(1);
  }, [serviceFilter, blockedFilter, methodFilter, eventTypeFilter, timeRange]);

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
          <h2 className="text-lg font-semibold">Event Log</h2>
          <p className="text-sm text-muted-foreground">
            All WAF and rate limit events with filtering and detail view.
          </p>
        </div>
        <TimeRangePicker
          value={timeRange}
          onChange={setTimeRange}
          onRefresh={loadEvents}
        />
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="p-4">
          <div className="flex flex-wrap items-center gap-3">
            <Filter className="h-4 w-4 text-muted-foreground" />

            <Select value={serviceFilter} onValueChange={setServiceFilter}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="Service" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Services</SelectItem>
                {services.map((s) => (
                  <SelectItem key={s.service} value={s.service}>
                    {s.service}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={blockedFilter} onValueChange={setBlockedFilter}>
              <SelectTrigger className="w-[140px]">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Events</SelectItem>
                <SelectItem value="blocked">Blocked Only</SelectItem>
                <SelectItem value="logged">Logged Only</SelectItem>
              </SelectContent>
            </Select>

            <Select value={methodFilter} onValueChange={setMethodFilter}>
              <SelectTrigger className="w-[120px]">
                <SelectValue placeholder="Method" />
              </SelectTrigger>
              <SelectContent>
                {METHODS.map((m) => (
                  <SelectItem key={m} value={m}>
                    {m}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={eventTypeFilter} onValueChange={setEventTypeFilter}>
              <SelectTrigger className="w-[150px]">
                <SelectValue placeholder="Event Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="blocked">Blocked</SelectItem>
                <SelectItem value="logged">Logged</SelectItem>
                <SelectItem value="rate_limited">Rate Limited</SelectItem>
                <SelectItem value="ipsum_blocked">IPsum Blocked</SelectItem>
              </SelectContent>
            </Select>

            {response && (
              <span className="ml-auto text-xs text-muted-foreground">
                {response.total.toLocaleString()} total events
              </span>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Events Table */}
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-8" />
                <TableHead>Time</TableHead>
                <TableHead>Service</TableHead>
                <TableHead>Method</TableHead>
                <TableHead className="max-w-[200px]">URI</TableHead>
                <TableHead>Client IP</TableHead>
                <TableHead>Rule</TableHead>
                <TableHead>Score</TableHead>
                <TableHead>Type</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading &&
                [...Array(10)].map((_, i) => (
                  <TableRow key={i}>
                    <TableCell />
                    {[...Array(7)].map((_, j) => (
                      <TableCell key={j}>
                        <Skeleton className="h-4 w-full" />
                      </TableCell>
                    ))}
                  </TableRow>
                ))}

              {!loading &&
                events.map((evt) => (
                  <Fragment key={evt.id}>
                    <TableRow
                      className="cursor-pointer"
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
                          className="text-[10px] font-mono px-1.5 py-0"
                        >
                          {evt.method}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-[200px] truncate text-xs font-mono">
                        {evt.uri}
                      </TableCell>
                      <TableCell className="text-xs font-mono">
                        {evt.client_ip}
                      </TableCell>
                      <TableCell className="text-xs">
                        {evt.rule_id ? (
                          <Badge variant="outline" className="text-[10px] px-1.5 py-0 font-mono">
                            {evt.rule_id}
                          </Badge>
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </TableCell>
                      <TableCell className="text-xs tabular-nums">
                        {evt.anomaly_score > 0 ? (
                          <span className={
                            evt.anomaly_score >= 25 ? "text-neon-pink font-bold" :
                            evt.anomaly_score >= 10 ? "text-neon-amber font-medium" :
                            "text-neon-cyan"
                          }>
                            {evt.anomaly_score}
                          </span>
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </TableCell>
                      <TableCell>
                        {evt.event_type === "ipsum_blocked" ? (
                          <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-violet-500/50 text-violet-400">
                            IPSUM
                          </Badge>
                        ) : evt.event_type === "rate_limited" ? (
                          <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-amber-500/50 text-amber-400">
                            RATE LIMITED
                          </Badge>
                        ) : evt.event_type === "blocked" || evt.blocked ? (
                          <Badge variant="destructive" className="text-[10px] px-1.5 py-0">
                            BLOCKED
                          </Badge>
                        ) : (
                          <Badge variant="secondary" className="text-[10px] px-1.5 py-0">
                            LOGGED
                          </Badge>
                        )}
                      </TableCell>
                    </TableRow>
                    {expanded.has(evt.id) && (
                      <TableRow className="hover:bg-transparent">
                        <TableCell colSpan={9} className="bg-navy-950/50 p-0">
                          <EventDetailPanel event={evt} />
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                ))}

              {!loading && events.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={8}
                    className="py-8 text-center text-muted-foreground"
                  >
                    No events found matching the current filters.
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

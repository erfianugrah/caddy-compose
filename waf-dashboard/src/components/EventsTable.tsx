import { Fragment, useState, useEffect, useCallback } from "react";
import {
  ChevronDown,
  ChevronRight,
  ChevronLeft,
  ChevronsLeft,
  ChevronsRight,
  ChevronsDownUp,
  Download,
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
  fetchAllEvents,
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

/** Parse CRS matched_data string into structured parts. */
function parseMatchedData(raw: string): { trigger: string; variable: string; fullValue: string } | null {
  // Format: "Matched Data: <trigger> found within <VARIABLE>: <full_value>"
  const m = raw.match(/^Matched Data:\s*(.+?)\s+found within\s+(\S+?):\s*(.+)$/s);
  if (m) return { trigger: m[1], variable: m[2], fullValue: m[3] };
  return null;
}

/** Render text with all occurrences of `highlight` wrapped in a highlight span. */
function HighlightedText({ text, highlight }: { text: string; highlight: string }) {
  if (!highlight || !text) return <>{text}</>;
  // Escape regex special chars in the highlight string
  const escaped = highlight.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const parts = text.split(new RegExp(`(${escaped})`, "gi"));
  return (
    <>
      {parts.map((part, i) =>
        part.toLowerCase() === highlight.toLowerCase() ? (
          <mark key={i} className="bg-neon-amber/25 text-neon-amber rounded px-0.5">{part}</mark>
        ) : (
          <span key={i}>{part}</span>
        )
      )}
    </>
  );
}

export function EventDetailPanel({ event }: { event: WAFEvent }) {
  return (
    <div className="space-y-3 p-4">
      <div className="flex justify-end">
        <Button
          variant="ghost"
          size="xs"
          className="text-muted-foreground hover:text-foreground"
          onClick={(e) => {
            e.stopPropagation();
            downloadJSON(event, `event-${event.id}.json`);
          }}
        >
          <Download className="h-3 w-3 mr-1" />
          Export JSON
        </Button>
      </div>
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
            {event.event_type === "ipsum_blocked" ? "IPsum Blocklist Details"
              : event.event_type === "rate_limited" ? "Rate Limit Details"
              : event.blocked_by === "anomaly_inbound" || event.blocked_by === "anomaly_outbound"
                ? "Anomaly Score Block"
                : "Rule Match"}
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
                {/* Anomaly score block: show the blocking reason prominently */}
                {(event.blocked_by === "anomaly_inbound" || event.blocked_by === "anomaly_outbound") && (
                  <div className="flex gap-2 items-center pb-1 mb-1 border-b border-navy-800">
                    <span className="text-muted-foreground">Blocked By:</span>
                    <span className="text-neon-pink font-medium">
                      {event.blocked_by === "anomaly_inbound"
                        ? `Inbound Anomaly Score (${event.anomaly_score}) exceeded threshold`
                        : `Outbound Anomaly Score (${event.outbound_anomaly_score}) exceeded threshold`}
                    </span>
                  </div>
                )}

                {/* Scores */}
                {(event.anomaly_score > 0 || event.outbound_anomaly_score > 0) && (
                  <div className="flex gap-4">
                    {event.anomaly_score > 0 && (
                      <div className="flex gap-2">
                        <span className="text-muted-foreground">Inbound Score:</span>
                        <span className={
                          event.anomaly_score >= 25 ? "text-neon-pink font-bold" :
                          event.anomaly_score >= 10 ? "text-neon-amber font-medium" :
                          "text-neon-cyan"
                        }>
                          {event.anomaly_score}
                        </span>
                      </div>
                    )}
                    {event.outbound_anomaly_score > 0 && (
                      <div className="flex gap-2">
                        <span className="text-muted-foreground">Outbound Score:</span>
                        <span className={
                          event.outbound_anomaly_score >= 25 ? "text-neon-pink font-bold" :
                          event.outbound_anomaly_score >= 10 ? "text-neon-amber font-medium" :
                          "text-neon-cyan"
                        }>
                          {event.outbound_anomaly_score}
                        </span>
                      </div>
                    )}
                  </div>
                )}

                {/* Primary rule — labeled differently for anomaly vs direct blocks */}
                {event.rule_id > 0 && (
                  <>
                    {(event.blocked_by === "anomaly_inbound" || event.blocked_by === "anomaly_outbound") && (
                      <div className="text-[10px] uppercase tracking-wider text-muted-foreground/60 pt-1">
                        Highest Severity Rule
                      </div>
                    )}
                    <div className="flex gap-2">
                      <span className="text-muted-foreground">Rule ID:</span>
                      <Badge variant="outline" className="text-[10px] px-1.5 py-0 font-mono">
                        {event.rule_id}
                      </Badge>
                    </div>
                    <div className="flex gap-2">
                      <span className="text-muted-foreground">Message:</span>
                      <span className="text-foreground">{event.rule_msg || "N/A"}</span>
                    </div>
                    <div className="flex gap-2">
                      <span className="text-muted-foreground">Severity:</span>
                      {(() => {
                        const sev = formatSeverity(event.severity);
                        return <span className={sev.color}>{sev.label}</span>;
                      })()}
                    </div>
                  </>
                )}

                {/* Matched data with parsing and highlighting */}
                {event.matched_data && (() => {
                  const parsed = parseMatchedData(event.matched_data);
                  if (parsed) {
                    return (
                      <div className="space-y-1">
                        <div className="flex gap-2">
                          <span className="text-muted-foreground">Variable:</span>
                          <code className="text-neon-cyan">{parsed.variable}</code>
                        </div>
                        <div className="flex gap-2">
                          <span className="text-muted-foreground">Trigger:</span>
                          <code className="text-neon-amber">{parsed.trigger}</code>
                        </div>
                        <div className="flex gap-2 items-start">
                          <span className="text-muted-foreground shrink-0">Full Value:</span>
                          <code className="break-all text-foreground/80">
                            <HighlightedText text={parsed.fullValue} highlight={parsed.trigger} />
                          </code>
                        </div>
                      </div>
                    );
                  }
                  return (
                    <div className="flex gap-2">
                      <span className="text-muted-foreground">Matched:</span>
                      <code className="break-all text-neon-amber">{event.matched_data}</code>
                    </div>
                  );
                })()}

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

      {/* All Matched Rules (when multiple rules fired) */}
      {event.matched_rules && event.matched_rules.length > 1 && (
        <ExpandableSection title={`All Matched Rules (${event.matched_rules.length})`}>
          <div className="space-y-3">
            {event.matched_rules.map((rule) => {
              const sev = formatSeverity(rule.severity);
              const parsed = rule.matched_data ? parseMatchedData(rule.matched_data) : null;
              return (
                <div key={rule.id} className="rounded border border-navy-800 bg-navy-950/50 p-2 space-y-1 text-xs">
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-[10px] px-1.5 py-0 font-mono">{rule.id}</Badge>
                    <span className={sev.color + " text-[10px] font-medium"}>{sev.label}</span>
                    <span className="text-foreground/80 truncate">{rule.msg}</span>
                  </div>
                  {parsed ? (
                    <div className="pl-2 space-y-0.5">
                      <div className="flex gap-2">
                        <span className="text-muted-foreground">Variable:</span>
                        <code className="text-neon-cyan">{parsed.variable}</code>
                      </div>
                      <div className="flex gap-2 items-start">
                        <span className="text-muted-foreground shrink-0">Value:</span>
                        <code className="break-all text-foreground/80">
                          <HighlightedText text={parsed.fullValue} highlight={parsed.trigger} />
                        </code>
                      </div>
                    </div>
                  ) : rule.matched_data ? (
                    <div className="pl-2">
                      <code className="break-all text-neon-amber text-[10px]">{rule.matched_data}</code>
                    </div>
                  ) : null}
                  {rule.file && (
                    <div className="pl-2 text-[10px] text-muted-foreground/60">{rule.file}</div>
                  )}
                </div>
              );
            })}
          </div>
        </ExpandableSection>
      )}

      {/* Request Context */}
      {(event.request_args && Object.keys(event.request_args).length > 0) ||
       event.request_body ||
       (event.request_headers && Object.keys(event.request_headers).length > 0) ? (
        <ExpandableSection title="Request Context">
          <div className="space-y-3">
            {event.request_args && Object.keys(event.request_args).length > 0 && (
              <div className="space-y-1">
                <h5 className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground/70">Query / Form Args</h5>
                <div className="rounded border border-navy-800 bg-navy-950/50 p-2">
                  {Object.entries(event.request_args).map(([key, value]) => {
                    const trigger = event.matched_data ? parseMatchedData(event.matched_data)?.trigger : undefined;
                    return (
                      <div key={key} className="flex gap-1 text-xs">
                        <span className="text-neon-cyan shrink-0">{key}:</span>
                        <code className="break-all text-foreground/80">
                          {trigger ? <HighlightedText text={value} highlight={trigger} /> : value}
                        </code>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {event.request_body && (
              <div className="space-y-1">
                <h5 className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground/70">Request Body</h5>
                <div className="rounded border border-navy-800 bg-navy-950/50 p-2">
                  <pre className="text-xs text-foreground/80 whitespace-pre-wrap break-all">
                    {(() => {
                      const trigger = event.matched_data ? parseMatchedData(event.matched_data)?.trigger : undefined;
                      return trigger
                        ? <HighlightedText text={event.request_body} highlight={trigger} />
                        : event.request_body;
                    })()}
                  </pre>
                </div>
              </div>
            )}

            {event.request_headers && Object.keys(event.request_headers).length > 0 && (
              <div className="space-y-1">
                <h5 className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground/70">Headers</h5>
                <div className="rounded border border-navy-800 bg-navy-950/50 p-2">
                  <pre className="text-xs text-muted-foreground whitespace-pre-wrap break-all">
                    {Object.entries(event.request_headers)
                      .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : v}`)
                      .join("\n")}
                  </pre>
                </div>
              </div>
            )}
          </div>
        </ExpandableSection>
      ) : null}
    </div>
  );
}

/** Download data as a JSON file. */
function downloadJSON(data: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/** Collapsible section for the detail panel. */
function ExpandableSection({ title, children }: { title: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="space-y-2">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1 text-xs font-medium uppercase tracking-wider text-muted-foreground hover:text-foreground transition-colors"
      >
        {open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
        {title}
      </button>
      {open && <div className="pl-4">{children}</div>}
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
              <div className="ml-auto flex items-center gap-2">
                <span className="text-xs text-muted-foreground">
                  {response.total.toLocaleString()} total events
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
                    onClick={async () => {
                      const timeParams = rangeToParams(timeRange);
                      const all = await fetchAllEvents({
                        service: serviceFilter === "all" ? undefined : serviceFilter,
                        blocked: blockedFilter === "all" ? null : blockedFilter === "true",
                        method: methodFilter === "ALL" ? undefined : methodFilter,
                        event_type: eventTypeFilter === "all" ? undefined : (eventTypeFilter as EventType),
                        ...timeParams,
                      });
                      downloadJSON(all, `events-all-${new Date().toISOString().slice(0, 10)}.json`);
                    }}
                    title="Export all matching events as JSON"
                  >
                    <Download className="h-3 w-3 mr-1" />
                    All ({response.total.toLocaleString()})
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
                <TableHead title="Inbound / Outbound anomaly score">Score</TableHead>
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

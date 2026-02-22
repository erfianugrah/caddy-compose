import { useState, useEffect, useCallback } from "react";
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
} from "@/lib/api";

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

function EventDetailPanel({ event }: { event: WAFEvent }) {
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
            Rule Match
          </h4>
          <div className="space-y-1 rounded-md bg-navy-950 p-3 text-xs">
            <div className="flex gap-2">
              <span className="text-muted-foreground">Rule ID:</span>
              <Badge variant="outline" className="text-[10px] px-1.5 py-0 font-mono">
                {event.rule_id || "N/A"}
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
              <span className="text-foreground">
                {event.severity || "N/A"}
              </span>
            </div>
            {event.matched_data && (
              <div className="flex gap-2">
                <span className="text-muted-foreground">Matched:</span>
                <code className="break-all text-neon-amber">
                  {event.matched_data}
                </code>
              </div>
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

  // Filters
  const [page, setPage] = useState(1);
  const [serviceFilter, setServiceFilter] = useState("all");
  const [blockedFilter, setBlockedFilter] = useState<string>("all");
  const [methodFilter, setMethodFilter] = useState("ALL");

  const perPage = 25;

  const loadEvents = useCallback(() => {
    setLoading(true);
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
    })
      .then(setResponse)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [page, serviceFilter, blockedFilter, methodFilter]);

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
  }, [serviceFilter, blockedFilter, methodFilter]);

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
      <div>
        <h2 className="text-lg font-semibold">Event Log</h2>
        <p className="text-sm text-muted-foreground">
          All WAF events with filtering and detail view.
        </p>
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
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading &&
                [...Array(10)].map((_, i) => (
                  <TableRow key={i}>
                    <TableCell />
                    {[...Array(6)].map((_, j) => (
                      <TableCell key={j}>
                        <Skeleton className="h-4 w-full" />
                      </TableCell>
                    ))}
                  </TableRow>
                ))}

              {!loading &&
                events.map((evt) => (
                  <>
                    <TableRow
                      key={evt.id}
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
                      <TableCell>
                        {evt.blocked ? (
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
                      <TableRow
                        key={`${evt.id}-detail`}
                        className="hover:bg-transparent"
                      >
                        <TableCell colSpan={7} className="bg-navy-950/50 p-0">
                          <EventDetailPanel event={evt} />
                        </TableCell>
                      </TableRow>
                    )}
                  </>
                ))}

              {!loading && events.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={7}
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

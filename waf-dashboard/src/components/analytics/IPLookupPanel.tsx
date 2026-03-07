import { useState, useEffect, useCallback, useRef } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { Search, Globe, AlertTriangle } from "lucide-react";
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
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { lookupIP, type IPLookupData } from "@/lib/api";
import { ACTION_COLORS, CHART_TOOLTIP_STYLE } from "@/lib/utils";
import { T } from "@/lib/typography";
import { formatDateTime } from "@/lib/format";
import { EventTypeBadge } from "../EventTypeBadge";
import { EventDetailModal } from "../EventDetailModal";
import { TablePagination } from "../TablePagination";
import type { WAFEvent } from "@/lib/api";

const chartTooltipStyle = CHART_TOOLTIP_STYLE;

const IP_EVENTS_PAGE_SIZE = 20;

export function IPLookupPanel({ initialIP }: { initialIP?: string }) {
  const [query, setQuery] = useState(initialIP ?? "");
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<IPLookupData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [eventsPage, setEventsPage] = useState(1);
  const [eventsLoading, setEventsLoading] = useState(false);
  const autoSearched = useRef(false);

  // Event detail modal
  const [selectedEvent, setSelectedEvent] = useState<WAFEvent | null>(null);
  const [modalOpen, setModalOpen] = useState(false);

  const handleSearch = useCallback(() => {
    const ip = query.trim();
    if (!ip) return;
    setLoading(true);
    setError(null);
    setEventsPage(1);
    lookupIP(ip, IP_EVENTS_PAGE_SIZE, 0)
      .then(setData)
      .catch((err) => {
        setError(err.message);
        setData(null);
      })
      .finally(() => setLoading(false));
  }, [query]);

  // Paginate events server-side
  const handleEventsPageChange = useCallback((newPage: number) => {
    if (!data) return;
    setEventsPage(newPage);
    setEventsLoading(true);
    const offset = (newPage - 1) * IP_EVENTS_PAGE_SIZE;
    lookupIP(data.ip, IP_EVENTS_PAGE_SIZE, offset)
      .then((result) => {
        // Keep summary data, update only events
        setData((prev) => prev ? { ...prev, recent_events: result.recent_events } : result);
      })
      .catch(() => {}) // silently fail pagination
      .finally(() => setEventsLoading(false));
  }, [data]);

  // Sync query state when initialIP prop arrives (it may be undefined on first render)
  useEffect(() => {
    if (initialIP && !autoSearched.current) {
      setQuery(initialIP);
    }
  }, [initialIP]);

  // Auto-trigger lookup when initialIP is provided and query has been synced
  useEffect(() => {
    if (initialIP && query === initialIP && !autoSearched.current) {
      autoSearched.current = true;
      handleSearch();
    }
  }, [initialIP, query, handleSearch]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") handleSearch();
  };

  return (
    <div className="space-y-4">
      {/* Search bar */}
      <Card>
        <CardContent className="p-4">
          <div className="flex items-center gap-3">
            <Search className="h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Enter IP address (e.g., 192.168.1.100)"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              className="flex-1"
            />
            <Button
              onClick={handleSearch}
              disabled={!query.trim() || loading}
              size="sm"
            >
              {loading ? "Searching..." : "Lookup"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Lookup Failed</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {loading && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card>
            <CardContent className="p-6">
              <div className="space-y-3">
                {[...Array(5)].map((_, i) => (
                  <Skeleton key={i} className="h-5 w-full" />
                ))}
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-6">
              <Skeleton className="h-[200px] w-full" />
            </CardContent>
          </Card>
        </div>
      )}

      {data && !loading && (
        <div className="space-y-4">
          {/* IP Details + Timeline */}
          <div className="grid gap-4 lg:grid-cols-2">
            {/* IP Details Card */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Globe className="h-4 w-4 text-neon-cyan" />
                  <CardTitle className="text-sm font-mono">{data.ip}</CardTitle>
                </div>
                <CardDescription>IP address details</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-1">
                    <p className={T.formLabel}>
                      First Seen
                    </p>
                    <p className="text-sm font-medium">
                      {formatDateTime(data.first_seen)}
                    </p>
                  </div>
                  <div className="space-y-1">
                    <p className={T.formLabel}>
                      Last Seen
                    </p>
                    <p className="text-sm font-medium">
                      {formatDateTime(data.last_seen)}
                    </p>
                  </div>
                  <div className="space-y-1">
                    <p className={T.formLabel}>
                      Total Events
                    </p>
                    <p className="text-sm font-bold text-neon-cyan">
                      {data.total_events.toLocaleString()}
                    </p>
                  </div>
                  <div className="space-y-1">
                    <p className={T.formLabel}>
                      Blocked
                    </p>
                    <p className="text-sm font-bold text-neon-pink">
                      {data.blocked_count.toLocaleString()}
                    </p>
                  </div>
                </div>

                {/* Per-service breakdown */}
                {data.services.length > 0 && (
                  <div className="mt-4 space-y-2">
                    <p className={T.formLabel}>
                      Per-Service Breakdown
                    </p>
                    <div className="space-y-1">
                      {data.services.map((svc) => (
                        <div
                          key={svc.service}
                          className="flex items-center justify-between rounded-md bg-navy-950 px-3 py-1.5 text-xs"
                        >
                          <span className="font-medium">{svc.service}</span>
                          <div className="flex items-center gap-3">
                            <span className="tabular-nums text-muted-foreground">
                              {svc.total} total
                            </span>
                            {svc.blocked > 0 && (
                              <Badge
                                variant="destructive"
                                className="text-xs px-1.5 py-0"
                              >
                                {svc.blocked} blocked
                              </Badge>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Event Timeline for this IP */}
            <Card>
              <CardHeader>
                <CardTitle className={T.cardTitle}>Event Timeline</CardTitle>
                <CardDescription>Events from this IP over time</CardDescription>
              </CardHeader>
              <CardContent>
                {data.timeline.length > 0 ? (
                  <ResponsiveContainer width="100%" height={220}>
                    <AreaChart
                      data={data.timeline}
                      margin={{ top: 5, right: 10, left: 0, bottom: 0 }}
                    >
                      <defs>
                        <linearGradient id="ipGradBlocked" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor={ACTION_COLORS.blocked} stopOpacity={0.3} />
                          <stop offset="95%" stopColor={ACTION_COLORS.blocked} stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="ipGradLogged" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor={ACTION_COLORS.logged} stopOpacity={0.3} />
                          <stop offset="95%" stopColor={ACTION_COLORS.logged} stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e275c" vertical={false} />
                      <XAxis dataKey="hour" stroke="#7a8baa" fontSize={T.chartLabel} tickLine={false} axisLine={false} />
                      <YAxis stroke="#7a8baa" fontSize={T.chartLabel} tickLine={false} axisLine={false} />
                      <Tooltip {...chartTooltipStyle} />
                      <Area type="monotone" dataKey="blocked" stroke={ACTION_COLORS.blocked} fill="url(#ipGradBlocked)" strokeWidth={2} />
                      <Area type="monotone" dataKey="logged" stroke={ACTION_COLORS.logged} fill="url(#ipGradLogged)" strokeWidth={2} />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <p className="py-8 text-center text-xs text-muted-foreground">
                    No timeline data available
                  </p>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Recent Events for this IP */}
          {data.events_total > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className={T.cardTitle}>Events</CardTitle>
                <CardDescription>
                  {data.events_total.toLocaleString()} events from {data.ip} — click a row to inspect
                </CardDescription>
              </CardHeader>
              <CardContent className="p-0 overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead>Time</TableHead>
                      <TableHead>Service</TableHead>
                      <TableHead>Method</TableHead>
                      <TableHead>URI</TableHead>
                      <TableHead>Rule</TableHead>
                      <TableHead>Status</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {eventsLoading ? (
                      [...Array(5)].map((_, i) => (
                        <TableRow key={i}>
                          <TableCell colSpan={6}><Skeleton className="h-6 w-full" /></TableCell>
                        </TableRow>
                      ))
                    ) : (
                      data.recent_events.map((evt, idx) => (
                        <TableRow
                          key={evt.id || idx}
                          className="cursor-pointer"
                          onClick={() => {
                            setSelectedEvent(evt);
                            setModalOpen(true);
                          }}
                        >
                          <TableCell className="whitespace-nowrap text-xs">
                            {formatDateTime(evt.timestamp)}
                          </TableCell>
                          <TableCell className="text-xs">{evt.service}</TableCell>
                          <TableCell>
                            <Badge variant="outline" className={T.badgeMono}>
                              {evt.method}
                            </Badge>
                          </TableCell>
                          <TableCell className="max-w-[200px] truncate text-xs font-mono" title={evt.uri}>
                            {evt.uri}
                          </TableCell>
                          <TableCell>
                            {evt.rule_id ? (
                              <Badge variant="outline" className={T.badgeMono}>
                                {evt.rule_id}
                              </Badge>
                            ) : (
                              <span className="text-xs text-muted-foreground">-</span>
                            )}
                          </TableCell>
                          <TableCell>
                            <EventTypeBadge eventType={evt.event_type} />
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
                <TablePagination
                  page={eventsPage}
                  totalPages={Math.max(1, Math.ceil(data.events_total / IP_EVENTS_PAGE_SIZE))}
                  onPageChange={handleEventsPageChange}
                  totalItems={data.events_total}
                />
              </CardContent>
            </Card>
          )}

          {/* Event Detail Modal */}
          <EventDetailModal event={selectedEvent} open={modalOpen} onOpenChange={setModalOpen} />
        </div>
      )}

      {!data && !loading && !error && (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16">
            <Search className="mb-3 h-8 w-8 text-muted-foreground/50" />
            <p className="text-sm text-muted-foreground">
              Enter an IP address above to view its WAF event history
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

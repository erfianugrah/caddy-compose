import { useState, useEffect, useMemo, useRef, useCallback } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  ReferenceArea,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import {
  Shield,
  ShieldAlert,
  ShieldBan,
  ShieldCheck,
  Ban,
  Users,
  Server,
  Bug,
  Radar,
  ChevronDown,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  ChevronLeft,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  fetchSummary,
  fetchEvents,
  getExclusions,
  type SummaryData,
  type WAFEvent,
  type EventsResponse,
  type TimeRangeParams,
  type SummaryParams,
} from "@/lib/api";
import { formatNumber, formatTime, formatDate, countryFlag } from "@/lib/format";
import { EventTypeBadge } from "./EventTypeBadge";
import { EventDetailModal } from "./EventDetailModal";
import DashboardFilterBar, {
  parseFiltersFromURL,
  filtersToSummaryParams,
  filtersToEventsParams,
  type DashboardFilter,
} from "./DashboardFilterBar";
import TimeRangePicker, { rangeToParams, type TimeRange } from "@/components/TimeRangePicker";
import { ACTION_COLORS, ACTION_LABELS, CHART_TOOLTIP_STYLE } from "@/lib/utils";
import { T } from "@/lib/typography";
import { TopBlockedIPsPanel, TopTargetedURIsPanel, TopCountriesPanel } from "./AnalyticsDashboard";

// ─── Helpers ────────────────────────────────────────────────────────

function formatHourTick(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return ts;
  }
}

function formatTooltipLabel(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    });
  } catch {
    return ts;
  }
}

/** Custom Y-axis tick renderer that wraps the label in a clickable link. */
function LinkTickRenderer({
  x,
  y,
  payload,
  buildHref,
}: {
  x: number;
  y: number;
  payload: { value: string };
  buildHref: (value: string) => string;
}) {
  return (
    <a href={buildHref(payload.value)}>
      <text
        x={x}
        y={y}
        dy={4}
        textAnchor="end"
        fill="#7a8baa"
        fontSize={T.chartLabel}
        className="hover:fill-neon-green cursor-pointer"
        style={{ textDecoration: "none" }}
      >
        {payload.value}
      </text>
    </a>
  );
}

// ─── Count-up animation hook ────────────────────────────────────────

function useCountUp(target: number, duration = 800): number {
  const [current, setCurrent] = useState(0);
  const rafRef = useRef<number>(0);

  useEffect(() => {
    if (target === 0) {
      setCurrent(0);
      return;
    }
    const startTime = performance.now();
    const startVal = 0;

    const animate = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setCurrent(Math.round(startVal + (target - startVal) * eased));
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(animate);
      }
    };

    rafRef.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(rafRef.current);
  }, [target, duration]);

  return current;
}

// ─── Stat Card ──────────────────────────────────────────────────────

function StatCard({
  title,
  value,
  icon: Icon,
  color,
  loading,
  href,
}: {
  title: string;
  value: number;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
  loading: boolean;
  href?: string;
}) {
  const animatedValue = useCountUp(loading ? 0 : value);

  const colorMap: Record<string, string> = {
    green: "text-neon-green bg-neon-green/10",
    pink: "text-neon-pink bg-neon-pink/10",
    cyan: "text-neon-cyan bg-neon-cyan/10",
    yellow: "text-yellow-400 bg-yellow-400/10",
    purple: "text-purple-400 bg-purple-400/10",
    orange: "text-orange-400 bg-orange-400/10",
    red: "text-red-400 bg-red-400/10",
  };
  const textColorMap: Record<string, string> = {
    green: "text-neon-green",
    pink: "text-neon-pink",
    cyan: "text-neon-cyan",
    yellow: "text-yellow-400",
    purple: "text-purple-400",
    orange: "text-orange-400",
    red: "text-red-400",
  };

  const card = (
    <Card className={href ? "cursor-pointer hover:ring-1 hover:ring-neon-green/30 transition-all" : undefined}>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardDescription className={T.statLabelUpper}>
          {title}
        </CardDescription>
        <div className={`rounded-md p-2 ${colorMap[color]}`}>
          <Icon className="h-4 w-4" />
        </div>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-8 w-24" />
        ) : (
          <div className={`${T.statValue} ${textColorMap[color]}`}>
            {formatNumber(animatedValue)}
          </div>
        )}
      </CardContent>
    </Card>
  );

  if (href) {
    return <a href={href} className="block no-underline">{card}</a>;
  }
  return card;
}

// ─── Chart config ───────────────────────────────────────────────────

const chartTooltipStyle = CHART_TOOLTIP_STYLE;

const DONUT_COLOR_MAP: Record<string, string> = {
  [ACTION_LABELS.blocked]:      ACTION_COLORS.blocked,
  [ACTION_LABELS.logged]:       ACTION_COLORS.logged,
  [ACTION_LABELS.rate_limited]: ACTION_COLORS.rate_limited,
  [ACTION_LABELS.ipsum]:        ACTION_COLORS.ipsum,
  [ACTION_LABELS.honeypot]:     ACTION_COLORS.honeypot,
  [ACTION_LABELS.scanner]:      ACTION_COLORS.scanner,
  [ACTION_LABELS.policy]:       ACTION_COLORS.policy,
};

// ─── Main Component ─────────────────────────────────────────────────

export default function OverviewDashboard() {
  const [data, setData] = useState<SummaryData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState<TimeRange>({
    type: "relative",
    hours: 24,
    label: "Last 24 hours",
  });

  // ── Dashboard filters (read from URL after hydration) ──
  const [filters, setFilters] = useState<DashboardFilter[]>([]);
  const filtersInitRef = useRef(false);

  // Read URL params in useEffect (client-only) to avoid SSR/hydration mismatch.
  useEffect(() => {
    if (filtersInitRef.current) return;
    filtersInitRef.current = true;
    const parsed = parseFiltersFromURL(window.location.search);
    if (parsed.length > 0) {
      setFilters(parsed);
      window.history.replaceState({}, "", window.location.pathname);
    }
  }, []);

  // ── Rule names for filter bar autocomplete ──
  const [ruleNames, setRuleNames] = useState<string[]>([]);
  useEffect(() => {
    getExclusions()
      .then((excl) => setRuleNames(excl.map((e) => e.name).filter(Boolean)))
      .catch(() => {}); // Non-critical
  }, []);

  // ── Events table state ──
  const [events, setEvents] = useState<WAFEvent[]>([]);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventsTotal, setEventsTotal] = useState(0);
  const [eventsPage, setEventsPage] = useState(1);
  const eventsPerPage = 20;

  // ── Event detail modal state ──
  const [selectedEvent, setSelectedEvent] = useState<WAFEvent | null>(null);
  const [modalOpen, setModalOpen] = useState(false);

  // ── Click-drag zoom state ──
  // User clicks and drags on the chart to select a time window.
  const [refAreaLeft, setRefAreaLeft] = useState<string | null>(null);
  const [refAreaRight, setRefAreaRight] = useState<string | null>(null);
  const [zoomLeft, setZoomLeft] = useState<string | null>(null);
  const [zoomRight, setZoomRight] = useState<string | null>(null);

  // ── Collapsible analytics section ──
  const [analyticsOpen, setAnalyticsOpen] = useState(true);
  const analyticsHours = rangeToParams(timeRange).hours;
  const [analyticsRefreshKey, setAnalyticsRefreshKey] = useState(0);

  // ── Data loading ──
  const loadData = useCallback(() => {
    setLoading(true);
    setError(null);
    const summaryParams: SummaryParams = {
      ...rangeToParams(timeRange),
      ...filtersToSummaryParams(filters),
    };
    fetchSummary(summaryParams)
      .then(setData)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [timeRange, filters]);

  useEffect(() => {
    loadData();
    setAnalyticsRefreshKey((k) => k + 1);
  }, [loadData]);

  // Reset zoom and events page when time range or filters change
  useEffect(() => {
    setZoomLeft(null);
    setZoomRight(null);
    setEventsPage(1);
  }, [timeRange, filters]);

  // ── Compute the zoom time window for event fetching ──
  const zoomTimeParams = useMemo<TimeRangeParams | null>(() => {
    if (!zoomLeft || !zoomRight) return null;
    const endDate = new Date(zoomRight);
    endDate.setHours(endDate.getHours() + 1);
    return {
      start: new Date(zoomLeft).toISOString(),
      end: endDate.toISOString(),
    };
  }, [zoomLeft, zoomRight]);

  // ── Zoomed timeline data (only show selected window) ──
  const displayTimeline = useMemo(() => {
    const timeline = data?.timeline ?? [];
    if (!zoomLeft || !zoomRight) return timeline;
    return timeline.filter((d) => d.hour >= zoomLeft && d.hour <= zoomRight);
  }, [data?.timeline, zoomLeft, zoomRight]);

  // ── Fetch events (responds to page, timeRange, zoomTimeParams, filters changes) ──
  const loadEvents = useCallback(() => {
    setEventsLoading(true);
    const baseParams = zoomTimeParams ?? rangeToParams(timeRange);
    fetchEvents({
      page: eventsPage,
      per_page: eventsPerPage,
      ...filtersToEventsParams(filters),
      ...baseParams,
    })
      .then((resp) => {
        setEvents(resp.events);
        setEventsTotal(resp.total);
      })
      .catch(() => {
        setEvents([]);
        setEventsTotal(0);
      })
      .finally(() => setEventsLoading(false));
  }, [eventsPage, timeRange, zoomTimeParams, filters]);

  useEffect(() => {
    loadEvents();
  }, [loadEvents]);

  // Reset page when zoom changes
  useEffect(() => {
    setEventsPage(1);
  }, [zoomTimeParams]);

  const totalEventsPages = Math.max(1, Math.ceil(eventsTotal / eventsPerPage));

  // ── Click-drag zoom handlers ──
  const handleMouseDown = useCallback(
    (e: { activeLabel?: string }) => {
      if (e?.activeLabel) {
        setRefAreaLeft(e.activeLabel);
        setRefAreaRight(null);
      }
    },
    [],
  );

  const handleMouseMove = useCallback(
    (e: { activeLabel?: string }) => {
      if (refAreaLeft && e?.activeLabel) {
        setRefAreaRight(e.activeLabel);
      }
    },
    [refAreaLeft],
  );

  const handleMouseUp = useCallback(() => {
    if (refAreaLeft && refAreaRight) {
      // Ensure left < right
      const [left, right] = refAreaLeft < refAreaRight
        ? [refAreaLeft, refAreaRight]
        : [refAreaRight, refAreaLeft];
      setZoomLeft(left);
      setZoomRight(right);
    }
    setRefAreaLeft(null);
    setRefAreaRight(null);
  }, [refAreaLeft, refAreaRight]);

  const resetZoom = useCallback(() => {
    setZoomLeft(null);
    setZoomRight(null);
  }, []);

  // ── Donut data ──
  const wafBlocked = Math.max(
    (data?.blocked ?? 0) - (data?.honeypot_events ?? 0) - (data?.scanner_events ?? 0),
    0,
  );
  const donutData =
    data && (data.blocked > 0 || data.logged > 0 || data.rate_limited > 0 || data.ipsum_blocked > 0 || data.policy_events > 0)
      ? [
          ...(wafBlocked > 0 ? [{ name: "WAF Blocked", value: wafBlocked }] : []),
          ...(data.logged > 0 ? [{ name: "Logged", value: data.logged }] : []),
          ...(data.rate_limited > 0 ? [{ name: "Rate Limited", value: data.rate_limited }] : []),
          ...(data.ipsum_blocked > 0 ? [{ name: "IPsum", value: data.ipsum_blocked }] : []),
          ...(data.honeypot_events > 0 ? [{ name: "Honeypot", value: data.honeypot_events }] : []),
          ...(data.scanner_events > 0 ? [{ name: "Scanner", value: data.scanner_events }] : []),
          ...(data.policy_events > 0 ? [{ name: "Policy", value: data.policy_events }] : []),
        ]
      : [];

  const serviceBreakdown = useMemo(
    () => data?.service_breakdown ?? data?.top_services ?? [],
    [data],
  );
  const serviceNames = useMemo(
    () => serviceBreakdown.map((s) => s.service),
    [serviceBreakdown],
  );

  if (error) {
    return (
      <div className="flex items-center justify-center py-20">
        <Card className="max-w-md">
          <CardHeader>
            <CardTitle className="text-neon-pink">Connection Error</CardTitle>
            <CardDescription>
              Could not reach the WAF API. Make sure the API sidecar is running.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <pre className="rounded-md bg-navy-950 p-3 text-xs text-muted-foreground">
              {error}
            </pre>
            <Button variant="outline" size="sm" className="mt-3" onClick={loadData}>
              Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header with time range */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className={T.pageTitle}>Security Overview</h2>
          <p className={T.pageDescription}>
            WAF event summary and real-time event feed
          </p>
        </div>
        <TimeRangePicker value={timeRange} onChange={setTimeRange} onRefresh={loadData} />
      </div>

      {/* ── Dashboard Filter Bar ── */}
      <DashboardFilterBar filters={filters} onChange={setFilters} services={serviceNames} ruleNames={ruleNames} />

      {/* ── Stat Cards ── */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-7">
        <StatCard title="Total Events" value={data?.total_events ?? 0} icon={Shield} color="green" loading={loading} href="/events" />
        <StatCard title="Blocked" value={data?.blocked ?? 0} icon={ShieldAlert} color="pink" loading={loading} href="/events?type=blocked" />
        <StatCard title="Rate Limited" value={data?.rate_limited ?? 0} icon={ShieldBan} color="yellow" loading={loading} href="/events?type=rate_limited" />
        <StatCard title="IPsum Blocked" value={data?.ipsum_blocked ?? 0} icon={Ban} color="purple" loading={loading} href="/events?type=ipsum_blocked" />
        <StatCard title="Honeypot" value={data?.honeypot_events ?? 0} icon={Bug} color="orange" loading={loading} href="/events?type=honeypot" />
        <StatCard title="Scanner" value={data?.scanner_events ?? 0} icon={Radar} color="red" loading={loading} href="/events?type=scanner" />
        <StatCard title="Policy" value={data?.policy_events ?? 0} icon={ShieldCheck} color="green" loading={loading} href="/events?type=policy_skip" />
      </div>

      {/* ── Timeline Chart with Click-Drag Zoom ── */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className={T.cardTitle}>Event Timeline</CardTitle>
              <CardDescription>
                {zoomTimeParams
                  ? "Zoomed in — events table below is filtered to this window"
                  : "Click and drag on the chart to zoom into a time window"}
              </CardDescription>
            </div>
            {zoomTimeParams && (
              <Button
                variant="ghost"
                size="xs"
                className="text-xs text-muted-foreground hover:text-foreground"
                onClick={resetZoom}
              >
                Reset zoom
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <Skeleton className="h-[300px] w-full" />
          ) : (
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart
                data={displayTimeline}
                margin={{ top: 5, right: 10, left: 0, bottom: 0 }}
                onMouseDown={handleMouseDown}
                onMouseMove={handleMouseMove}
                onMouseUp={handleMouseUp}
              >
                <defs>
                  <linearGradient id="gradBlocked" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={ACTION_COLORS.blocked} stopOpacity={0.3} />
                    <stop offset="95%" stopColor={ACTION_COLORS.blocked} stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gradLogged" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={ACTION_COLORS.logged} stopOpacity={0.3} />
                    <stop offset="95%" stopColor={ACTION_COLORS.logged} stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gradRateLimited" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={ACTION_COLORS.rate_limited} stopOpacity={0.3} />
                    <stop offset="95%" stopColor={ACTION_COLORS.rate_limited} stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gradIpsumBlocked" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={ACTION_COLORS.ipsum} stopOpacity={0.3} />
                    <stop offset="95%" stopColor={ACTION_COLORS.ipsum} stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gradHoneypot" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={ACTION_COLORS.honeypot} stopOpacity={0.3} />
                    <stop offset="95%" stopColor={ACTION_COLORS.honeypot} stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gradScanner" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={ACTION_COLORS.scanner} stopOpacity={0.3} />
                    <stop offset="95%" stopColor={ACTION_COLORS.scanner} stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gradPolicy" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={ACTION_COLORS.policy} stopOpacity={0.3} />
                    <stop offset="95%" stopColor={ACTION_COLORS.policy} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e275c" vertical={false} />
                <XAxis
                  dataKey="hour"
                  stroke="#7a8baa"
                  fontSize={T.chartLabel}
                  tickLine={false}
                  axisLine={false}
                  tickFormatter={formatHourTick}
                />
                <YAxis
                  stroke="#7a8baa"
                  fontSize={T.chartLabel}
                  tickLine={false}
                  axisLine={false}
                  tickFormatter={formatNumber}
                />
                <Tooltip {...chartTooltipStyle} labelFormatter={formatTooltipLabel} />
                <Legend
                  verticalAlign="top"
                  height={28}
                  iconType="square"
                  iconSize={10}
                  wrapperStyle={{ fontSize: `${T.chartLabel}px`, color: "#7a8baa" }}
                />
                <Area type="monotone" dataKey="logged" stroke={ACTION_COLORS.logged} fill="url(#gradLogged)" strokeWidth={2} />
                <Area type="monotone" dataKey="ipsum_blocked" stroke={ACTION_COLORS.ipsum} fill="url(#gradIpsumBlocked)" strokeWidth={2} name="IPsum Blocked" />
                <Area type="monotone" dataKey="rate_limited" stroke={ACTION_COLORS.rate_limited} fill="url(#gradRateLimited)" strokeWidth={2} />
                <Area type="monotone" dataKey="blocked" stroke={ACTION_COLORS.blocked} fill="url(#gradBlocked)" strokeWidth={2} />
                <Area type="monotone" dataKey="honeypot" stroke={ACTION_COLORS.honeypot} fill="url(#gradHoneypot)" strokeWidth={2} name="Honeypot" />
                <Area type="monotone" dataKey="scanner" stroke={ACTION_COLORS.scanner} fill="url(#gradScanner)" strokeWidth={2} name="Scanner" />
                <Area type="monotone" dataKey="policy" stroke={ACTION_COLORS.policy} fill="url(#gradPolicy)" strokeWidth={2} name="Policy" />
                {/* Selection overlay while dragging */}
                {refAreaLeft && refAreaRight && (
                  <ReferenceArea
                    x1={refAreaLeft}
                    x2={refAreaRight}
                    strokeOpacity={0.3}
                    fill="#7a8baa"
                    fillOpacity={0.15}
                  />
                )}
              </AreaChart>
            </ResponsiveContainer>
          )}
        </CardContent>
      </Card>

      {/* ── Analytics Section (collapsible) — above events ── */}
      <div className="space-y-4">
        <button
          onClick={() => setAnalyticsOpen(!analyticsOpen)}
          className="flex items-center gap-2 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
        >
          {analyticsOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          Analytics Breakdown
        </button>

        {analyticsOpen && (
          <>
            {/* Row: Donut + Stats row */}
            <div className="grid gap-4 lg:grid-cols-3">
              {/* Donut */}
              <Card>
                <CardHeader>
                  <CardTitle className={T.cardTitle}>Action Breakdown</CardTitle>
                  <CardDescription>Events by action type</CardDescription>
                </CardHeader>
                <CardContent className="flex flex-col items-center justify-center">
                  {loading ? (
                    <Skeleton className="h-[220px] w-[220px] rounded-full" />
                  ) : donutData.length > 0 ? (
                    <>
                      <ResponsiveContainer width="100%" height={200}>
                        <PieChart>
                          <Pie
                            data={donutData}
                            cx="50%"
                            cy="50%"
                            innerRadius={55}
                            outerRadius={80}
                            paddingAngle={4}
                            dataKey="value"
                            stroke="none"
                          >
                            {donutData.map((entry, idx) => (
                              <Cell key={`cell-${idx}`} fill={DONUT_COLOR_MAP[entry.name] ?? "#7a8baa"} />
                            ))}
                          </Pie>
                          <Tooltip {...chartTooltipStyle} />
                        </PieChart>
                      </ResponsiveContainer>
                      <div className="mt-2 flex flex-wrap items-center gap-3 text-xs">
                        {donutData.map((entry) => (
                          <div key={entry.name} className="flex items-center gap-1.5">
                            <div
                              className="h-2.5 w-2.5 rounded-full"
                              style={{ backgroundColor: DONUT_COLOR_MAP[entry.name] ?? "#7a8baa" }}
                            />
                            <span className="text-muted-foreground">
                              {entry.name} ({entry.value.toLocaleString()})
                            </span>
                          </div>
                        ))}
                      </div>
                    </>
                  ) : (
                    <p className="py-8 text-xs text-muted-foreground">No event data yet</p>
                  )}
                </CardContent>
              </Card>

              {/* Unique Clients + Services compact cards */}
              <div className="flex flex-col gap-4">
                <StatCard title="Unique Clients" value={data?.unique_clients ?? 0} icon={Users} color="cyan" loading={loading} />
                <StatCard title="Unique Services" value={data?.unique_services ?? 0} icon={Server} color="cyan" loading={loading} href="/services" />
              </div>

              {/* Top Clients chart */}
              <Card>
                <CardHeader>
                  <CardTitle className={T.cardTitle}>Top Clients</CardTitle>
                  <CardDescription>By total event count</CardDescription>
                </CardHeader>
                <CardContent>
                  {loading ? (
                    <div className="space-y-3">
                      {[...Array(5)].map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}
                    </div>
                  ) : (data?.top_clients ?? []).length > 0 ? (
                    <ResponsiveContainer width="100%" height={Math.max((data?.top_clients ?? []).slice(0, 8).length * 36 + 36, 160)}>
                      <BarChart
                        data={(data?.top_clients ?? []).slice(0, 8).map((c) => ({
                          ...c,
                          label: c.client_ip,
                          logged: Math.max(c.total - c.blocked - c.rate_limited - c.ipsum_blocked - c.honeypot - c.scanner - c.policy, 0),
                        }))}
                        layout="vertical"
                        margin={{ top: 0, right: 10, left: 0, bottom: 0 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" stroke="#1e275c" horizontal={false} />
                        <XAxis type="number" stroke="#7a8baa" fontSize={T.chartLabel} tickLine={false} axisLine={false} tickFormatter={formatNumber} />
                        <YAxis
                          type="category"
                          dataKey="label"
                          stroke="#7a8baa"
                          fontSize={T.chartLabel}
                          tickLine={false}
                          axisLine={false}
                          width={100}
                          tick={(props: Record<string, unknown>) => (
                            <LinkTickRenderer
                              x={props.x as number}
                              y={props.y as number}
                              payload={props.payload as { value: string }}
                              buildHref={(ip) => `/analytics?q=${encodeURIComponent(ip)}`}
                            />
                          )}
                        />
                        <Tooltip
                          {...chartTooltipStyle}
                          labelFormatter={(label: string) => {
                            const client = (data?.top_clients ?? []).find((c) => c.client_ip === label);
                            return client?.country && client.country !== "XX" ? `${label} (${client.country})` : label;
                          }}
                        />
                        <Bar dataKey="blocked" name="Blocked" fill={ACTION_COLORS.blocked} stackId="a" />
                        <Bar dataKey="rate_limited" name="Rate Limited" fill={ACTION_COLORS.rate_limited} stackId="a" />
                        <Bar dataKey="ipsum_blocked" name="IPsum" fill={ACTION_COLORS.ipsum} stackId="a" />
                        <Bar dataKey="honeypot" name="Honeypot" fill={ACTION_COLORS.honeypot} stackId="a" />
                        <Bar dataKey="scanner" name="Scanner" fill={ACTION_COLORS.scanner} stackId="a" />
                        <Bar dataKey="policy" name="Policy" fill={ACTION_COLORS.policy} stackId="a" />
                        <Bar dataKey="logged" name="Logged" fill={ACTION_COLORS.logged} stackId="a" opacity={0.7} radius={[0, 4, 4, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  ) : (
                    <p className="py-8 text-center text-xs text-muted-foreground">No client data yet</p>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* Events by Service */}
            <Card>
              <CardHeader>
                <CardTitle className={T.cardTitle}>Events by Service</CardTitle>
                <CardDescription>Event breakdown per service</CardDescription>
              </CardHeader>
              <CardContent>
                {loading ? (
                  <div className="space-y-3">
                    {[...Array(5)].map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}
                  </div>
                ) : serviceBreakdown.length > 0 ? (
                  <ResponsiveContainer width="100%" height={Math.max(serviceBreakdown.slice(0, 10).length * 40 + 40, 180)}>
                    <BarChart
                      data={serviceBreakdown.slice(0, 10)}
                      layout="vertical"
                      margin={{ top: 0, right: 10, left: 0, bottom: 0 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e275c" horizontal={false} />
                      <XAxis type="number" stroke="#7a8baa" fontSize={T.chartLabel} tickLine={false} axisLine={false} tickFormatter={formatNumber} />
                      <YAxis
                        type="category"
                        dataKey="service"
                        stroke="#7a8baa"
                        fontSize={T.chartLabel}
                        tickLine={false}
                        axisLine={false}
                        width={110}
                        tick={(props: Record<string, unknown>) => (
                          <LinkTickRenderer
                            x={props.x as number}
                            y={props.y as number}
                            payload={props.payload as { value: string }}
                            buildHref={(svc) => `/events?service=${encodeURIComponent(svc)}`}
                          />
                        )}
                      />
                      <Tooltip {...chartTooltipStyle} />
                      <Legend verticalAlign="top" height={28} iconType="square" iconSize={10} wrapperStyle={{ fontSize: `${T.chartLabel}px`, color: "#7a8baa" }} />
                      <Bar dataKey="blocked" name="Blocked" fill={ACTION_COLORS.blocked} stackId="a" />
                      <Bar dataKey="rate_limited" name="Rate Limited" fill={ACTION_COLORS.rate_limited} stackId="a" />
                      <Bar dataKey="ipsum_blocked" name="IPsum" fill={ACTION_COLORS.ipsum} stackId="a" />
                      <Bar dataKey="honeypot" name="Honeypot" fill={ACTION_COLORS.honeypot} stackId="a" />
                      <Bar dataKey="scanner" name="Scanner" fill={ACTION_COLORS.scanner} stackId="a" />
                      <Bar dataKey="policy" name="Policy" fill={ACTION_COLORS.policy} stackId="a" />
                      <Bar dataKey="logged" name="Logged" fill={ACTION_COLORS.logged} stackId="a" opacity={0.7} radius={[0, 4, 4, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <p className="py-8 text-center text-xs text-muted-foreground">No service data yet</p>
                )}
              </CardContent>
            </Card>

            {/* Top Blocked IPs / Top URIs / Top Countries */}
            <TopBlockedIPsPanel hours={analyticsHours} refreshKey={analyticsRefreshKey} />
            <div className="grid gap-4 lg:grid-cols-2">
              <TopTargetedURIsPanel hours={analyticsHours} refreshKey={analyticsRefreshKey} />
              <TopCountriesPanel hours={analyticsHours} refreshKey={analyticsRefreshKey} />
            </div>
          </>
        )}
      </div>

      {/* ── Events Feed (filtered by zoom) ── */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className={T.cardTitle}>Events</CardTitle>
              <CardDescription>
                {zoomTimeParams
                  ? `Showing ${eventsTotal.toLocaleString()} events in selected time window`
                  : `${eventsTotal.toLocaleString()} events — click a row to inspect`}
              </CardDescription>
            </div>
            <a href="/events">
              <Button variant="ghost" size="xs" className="text-xs text-muted-foreground hover:text-foreground">
                Open Event Log
              </Button>
            </a>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead>Time</TableHead>
                <TableHead>Service</TableHead>
                <TableHead>Method</TableHead>
                <TableHead className="max-w-[250px]">URI</TableHead>
                <TableHead>Client IP</TableHead>
                <TableHead>Country</TableHead>
                <TableHead>Type</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(loading || eventsLoading) &&
                [...Array(8)].map((_, i) => (
                  <TableRow key={i}>
                    {[...Array(7)].map((_, j) => (
                      <TableCell key={j}>
                        <Skeleton className="h-4 w-full" />
                      </TableCell>
                    ))}
                  </TableRow>
                ))}

              {!loading && !eventsLoading && events.length > 0 &&
                events.map((evt) => (
                  <TableRow
                    key={evt.id}
                    className="cursor-pointer"
                    onClick={() => {
                      setSelectedEvent(evt);
                      setModalOpen(true);
                    }}
                  >
                    <TableCell className="whitespace-nowrap text-xs">
                      <div className="text-foreground">{formatTime(evt.timestamp)}</div>
                      <div className="text-muted-foreground">{formatDate(evt.timestamp)}</div>
                    </TableCell>
                    <TableCell className="text-xs">{evt.service}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs font-mono px-1.5 py-0">
                        {evt.method}
                      </Badge>
                    </TableCell>
                    <TableCell className="max-w-[250px] truncate text-xs font-mono">
                      {evt.uri}
                    </TableCell>
                    <TableCell className="text-xs font-mono">{evt.client_ip}</TableCell>
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
                    <TableCell>
                      <EventTypeBadge eventType={evt.event_type} blocked={evt.blocked} />
                    </TableCell>
                  </TableRow>
                ))}

              {!loading && !eventsLoading && events.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="py-8 text-center text-muted-foreground">
                    No events in this time range
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>

        {/* Pagination */}
        {totalEventsPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-navy-800">
            <span className="text-xs text-muted-foreground">
              Page {eventsPage} of {totalEventsPages}
            </span>
            <div className="flex items-center gap-1">
              <Button variant="outline" size="icon" className="h-7 w-7" onClick={() => setEventsPage(1)} disabled={eventsPage <= 1}>
                <ChevronsLeft className="h-3.5 w-3.5" />
              </Button>
              <Button variant="outline" size="icon" className="h-7 w-7" onClick={() => setEventsPage((p) => Math.max(1, p - 1))} disabled={eventsPage <= 1}>
                <ChevronLeft className="h-3.5 w-3.5" />
              </Button>
              <Button variant="outline" size="icon" className="h-7 w-7" onClick={() => setEventsPage((p) => Math.min(totalEventsPages, p + 1))} disabled={eventsPage >= totalEventsPages}>
                <ChevronRight className="h-3.5 w-3.5" />
              </Button>
              <Button variant="outline" size="icon" className="h-7 w-7" onClick={() => setEventsPage(totalEventsPages)} disabled={eventsPage >= totalEventsPages}>
                <ChevronsRight className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
        )}
      </Card>

      {/* ── Event Detail Modal ── */}
      <EventDetailModal event={selectedEvent} open={modalOpen} onOpenChange={setModalOpen} />
    </div>
  );
}

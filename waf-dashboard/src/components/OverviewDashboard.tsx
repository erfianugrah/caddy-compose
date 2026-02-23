import { Fragment, useState, useEffect, useRef, useCallback } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { Shield, ShieldAlert, ShieldBan, ShieldCheck, Ban, Users, Server, Clock, ChevronDown, ChevronRight, Bug, Radar } from "lucide-react";
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
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { fetchSummary, type SummaryData, type WAFEvent } from "@/lib/api";
import { EventDetailPanel } from "@/components/EventsTable";
import TimeRangePicker, { rangeToParams, type TimeRange } from "@/components/TimeRangePicker";
import { ACTION_COLORS, ACTION_LABELS, ACTION_BADGE_CLASSES, CHART_TOOLTIP_STYLE } from "@/lib/utils";

// ─── Helpers ────────────────────────────────────────────────────────

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

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
    return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
  } catch {
    return "";
  }
}

/** Format ISO timestamp to HH:MM for chart X-axis ticks */
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

/** Format ISO timestamp to readable date+time for chart tooltips */
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
      // ease-out cubic
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
}: {
  title: string;
  value: number;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
  loading: boolean;
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

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardDescription className="text-xs font-medium uppercase tracking-wider">
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
          <div className={`text-2xl font-bold tabular-nums ${textColorMap[color]}`}>
            {formatNumber(animatedValue)}
          </div>
        )}
      </CardContent>
    </Card>
  );
}


// ─── Chart config ───────────────────────────────────────────────────

const chartTooltipStyle = CHART_TOOLTIP_STYLE;

// Donut color map — keyed by human-readable label, backed by ACTION_COLORS
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
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const toggleExpand = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const loadData = useCallback(() => {
    setLoading(true);
    setError(null);
    fetchSummary(rangeToParams(timeRange))
      .then(setData)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [timeRange]);

  useEffect(() => {
    loadData();
  }, [loadData]);

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
            <Button
              variant="outline"
              size="sm"
              className="mt-3"
              onClick={loadData}
            >
              Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Build donut data — split "Blocked" into sub-categories so each action type
  // gets its own slice. WAF Blocked = blocked - honeypot - scanner (pure CRS/direct blocks).
  const wafBlocked = Math.max((data?.blocked ?? 0) - (data?.honeypot_events ?? 0) - (data?.scanner_events ?? 0), 0);
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

  // Build service breakdown bar data
  const serviceBreakdown = data?.service_breakdown ?? data?.top_services ?? [];

  return (
    <div className="space-y-6">
      {/* Header with time range */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-lg font-semibold">Overview</h2>
          <p className="text-sm text-muted-foreground">
            WAF event summary
          </p>
        </div>
        <TimeRangePicker
          value={timeRange}
          onChange={setTimeRange}
          onRefresh={loadData}
        />
      </div>

      {/* Stat Cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-7">
        <StatCard
          title="Total Events"
          value={data?.total_events ?? 0}
          icon={Shield}
          color="green"
          loading={loading}
        />
        <StatCard
          title="Blocked"
          value={data?.blocked ?? 0}
          icon={ShieldAlert}
          color="pink"
          loading={loading}
        />
        <StatCard
          title="Rate Limited"
          value={data?.rate_limited ?? 0}
          icon={ShieldBan}
          color="yellow"
          loading={loading}
        />
        <StatCard
          title="IPsum Blocked"
          value={data?.ipsum_blocked ?? 0}
          icon={Ban}
          color="purple"
          loading={loading}
        />
        <StatCard
          title="Honeypot"
          value={data?.honeypot_events ?? 0}
          icon={Bug}
          color="orange"
          loading={loading}
        />
        <StatCard
          title="Scanner"
          value={data?.scanner_events ?? 0}
          icon={Radar}
          color="red"
          loading={loading}
        />
        <StatCard
          title="Policy Matched"
          value={data?.policy_events ?? 0}
          icon={ShieldCheck}
          color="green"
          loading={loading}
        />
        <StatCard
          title="Unique Clients"
          value={data?.unique_clients ?? 0}
          icon={Users}
          color="cyan"
          loading={loading}
        />
        <StatCard
          title="Unique Services"
          value={data?.unique_services ?? 0}
          icon={Server}
          color="cyan"
          loading={loading}
        />
      </div>

      {/* Row: Timeline + Donut */}
      <div className="grid gap-4 lg:grid-cols-3">
        {/* Timeline Chart — takes 2/3 */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-sm">Event Timeline</CardTitle>
            <CardDescription>
              Blocked, rate limited, and logged events over time
            </CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <Skeleton className="h-[300px] w-full" />
            ) : (
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart
                  data={data?.timeline ?? []}
                  margin={{ top: 5, right: 10, left: 0, bottom: 0 }}
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
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="#1e275c"
                    vertical={false}
                  />
                  <XAxis
                    dataKey="hour"
                    stroke="#7a8baa"
                    fontSize={11}
                    tickLine={false}
                    axisLine={false}
                    tickFormatter={formatHourTick}
                  />
                  <YAxis
                    stroke="#7a8baa"
                    fontSize={11}
                    tickLine={false}
                    axisLine={false}
                    tickFormatter={formatNumber}
                  />
                  <Tooltip
                    {...chartTooltipStyle}
                    labelFormatter={formatTooltipLabel}
                  />
                  {/* Independent (non-stacked) areas — each plotted from 0 so smaller series remain visible at any scale. */}
                  <Area
                    type="monotone"
                    dataKey="logged"
                    stroke={ACTION_COLORS.logged}
                    fill="url(#gradLogged)"
                    strokeWidth={2}
                  />
                  <Area
                    type="monotone"
                    dataKey="ipsum_blocked"
                    stroke={ACTION_COLORS.ipsum}
                    fill="url(#gradIpsumBlocked)"
                    strokeWidth={2}
                    name="IPsum Blocked"
                  />
                  <Area
                    type="monotone"
                    dataKey="rate_limited"
                    stroke={ACTION_COLORS.rate_limited}
                    fill="url(#gradRateLimited)"
                    strokeWidth={2}
                  />
                  <Area
                    type="monotone"
                    dataKey="blocked"
                    stroke={ACTION_COLORS.blocked}
                    fill="url(#gradBlocked)"
                    strokeWidth={2}
                  />
                  <Area
                    type="monotone"
                    dataKey="honeypot"
                    stroke={ACTION_COLORS.honeypot}
                    fill="url(#gradHoneypot)"
                    strokeWidth={2}
                    name="Honeypot"
                  />
                  <Area
                    type="monotone"
                    dataKey="scanner"
                    stroke={ACTION_COLORS.scanner}
                    fill="url(#gradScanner)"
                    strokeWidth={2}
                    name="Scanner"
                  />
                  <Area
                    type="monotone"
                    dataKey="policy"
                    stroke={ACTION_COLORS.policy}
                    fill="url(#gradPolicy)"
                    strokeWidth={2}
                    name="Policy"
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        {/* Blocked vs Logged Donut — 1/3 */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Action Breakdown</CardTitle>
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
                        <Cell
                          key={`cell-${idx}`}
                          fill={DONUT_COLOR_MAP[entry.name] ?? "#7a8baa"}
                        />
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
              <p className="py-8 text-xs text-muted-foreground">
                No event data yet
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Row: Events by Service + Top Clients */}
      <div className="grid gap-4 lg:grid-cols-2">
        {/* Events by Service — Horizontal Bar */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Events by Service</CardTitle>
            <CardDescription>Event breakdown per service</CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="space-y-3">
                {[...Array(5)].map((_, i) => (
                  <Skeleton key={i} className="h-8 w-full" />
                ))}
              </div>
            ) : serviceBreakdown.length > 0 ? (
              <ResponsiveContainer width="100%" height={Math.max(serviceBreakdown.slice(0, 10).length * 40 + 40, 180)}>
                <BarChart
                  data={serviceBreakdown.slice(0, 10)}
                  layout="vertical"
                  margin={{ top: 0, right: 10, left: 0, bottom: 0 }}
                >
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="#1e275c"
                    horizontal={false}
                  />
                  <XAxis
                    type="number"
                    stroke="#7a8baa"
                    fontSize={11}
                    tickLine={false}
                    axisLine={false}
                    tickFormatter={formatNumber}
                  />
                  <YAxis
                    type="category"
                    dataKey="service"
                    stroke="#7a8baa"
                    fontSize={10}
                    tickLine={false}
                    axisLine={false}
                    width={110}
                  />
                  <Tooltip {...chartTooltipStyle} />
                  <Legend
                    verticalAlign="top"
                    height={28}
                    iconType="square"
                    iconSize={10}
                    wrapperStyle={{ fontSize: "11px", color: "#7a8baa" }}
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
              <p className="py-8 text-center text-xs text-muted-foreground">
                No service data yet
              </p>
            )}
          </CardContent>
        </Card>

        {/* Top Clients */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Top Clients</CardTitle>
            <CardDescription>By total event count</CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="space-y-3">
                {[...Array(5)].map((_, i) => (
                  <Skeleton key={i} className="h-8 w-full" />
                ))}
              </div>
            ) : (data?.top_clients ?? []).length > 0 ? (
              <ResponsiveContainer width="100%" height={Math.max((data?.top_clients ?? []).slice(0, 10).length * 40 + 40, 180)}>
                <BarChart
                  data={(data?.top_clients ?? []).slice(0, 10).map((c) => ({
                    ...c,
                    label: c.client_ip,
                    logged: Math.max(c.total - c.blocked - c.rate_limited - c.ipsum_blocked - c.honeypot - c.scanner - c.policy, 0),
                  }))}
                  layout="vertical"
                  margin={{ top: 0, right: 10, left: 0, bottom: 0 }}
                >
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="#1e275c"
                    horizontal={false}
                  />
                  <XAxis
                    type="number"
                    stroke="#7a8baa"
                    fontSize={11}
                    tickLine={false}
                    axisLine={false}
                    tickFormatter={formatNumber}
                  />
                  <YAxis
                    type="category"
                    dataKey="label"
                    stroke="#7a8baa"
                    fontSize={10}
                    tickLine={false}
                    axisLine={false}
                    width={110}
                  />
                  <Tooltip
                    {...chartTooltipStyle}
                    labelFormatter={(label: string) => {
                      const client = (data?.top_clients ?? []).find((c) => c.client_ip === label);
                      return client?.country && client.country !== "XX"
                        ? `${label} (${client.country})`
                        : label;
                    }}
                  />
                  <Legend
                    verticalAlign="top"
                    height={28}
                    iconType="square"
                    iconSize={10}
                    wrapperStyle={{ fontSize: "11px", color: "#7a8baa" }}
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
              <p className="py-8 text-center text-xs text-muted-foreground">
                No client data yet
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Recent Events Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Clock className="h-4 w-4 text-neon-cyan" />
            <CardTitle className="text-sm">Recent Events</CardTitle>
          </div>
          <CardDescription>Last 10 WAF, rate limit, and IPsum events</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="space-y-2 p-4">
              {[...Array(5)].map((_, i) => (
                <Skeleton key={i} className="h-8 w-full" />
              ))}
            </div>
          ) : (data?.recent_events ?? []).length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-8"></TableHead>
                  <TableHead>Time</TableHead>
                  <TableHead>Service</TableHead>
                  <TableHead>Method</TableHead>
                  <TableHead className="max-w-[250px]">URI</TableHead>
                  <TableHead>Client IP</TableHead>
                  <TableHead>Type</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(data?.recent_events ?? []).slice(0, 10).map((evt, idx) => (
                  <Fragment key={evt.id || idx}>
                    <TableRow className="cursor-pointer" onClick={() => toggleExpand(evt.id || String(idx))}>
                      <TableCell className="w-8 px-2">
                        {expanded.has(evt.id || String(idx)) ? (
                          <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
                        ) : (
                          <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
                        )}
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-xs">
                        <div className="text-foreground">{formatTime(evt.timestamp)}</div>
                        <div className="text-muted-foreground">{formatDate(evt.timestamp)}</div>
                      </TableCell>
                      <TableCell className="text-xs">{evt.service}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-[10px] font-mono px-1.5 py-0">
                          {evt.method}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-[250px] truncate text-xs font-mono">
                        {evt.uri}
                      </TableCell>
                      <TableCell className="text-xs font-mono">{evt.client_ip}</TableCell>
                      <TableCell>
                        {evt.event_type === "honeypot" ? (
                          <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${ACTION_BADGE_CLASSES.honeypot}`}>
                            HONEYPOT
                          </Badge>
                        ) : evt.event_type === "scanner" ? (
                          <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${ACTION_BADGE_CLASSES.scanner}`}>
                            SCANNER
                          </Badge>
                        ) : evt.event_type === "ipsum_blocked" ? (
                          <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${ACTION_BADGE_CLASSES.ipsum_blocked}`}>
                            IPSUM
                          </Badge>
                        ) : evt.event_type === "rate_limited" ? (
                          <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${ACTION_BADGE_CLASSES.rate_limited}`}>
                            RATE LIMITED
                          </Badge>
                        ) : evt.event_type === "policy_skip" ? (
                          <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${ACTION_BADGE_CLASSES.policy_skip}`}>
                            SKIPPED
                          </Badge>
                        ) : evt.event_type === "policy_allow" ? (
                          <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${ACTION_BADGE_CLASSES.policy_allow}`}>
                            ALLOWED
                          </Badge>
                        ) : evt.event_type === "policy_block" ? (
                          <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${ACTION_BADGE_CLASSES.policy_block}`}>
                            POLICY BLOCK
                          </Badge>
                        ) : evt.event_type === "blocked" ? (
                          <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${ACTION_BADGE_CLASSES.blocked}`}>
                            BLOCKED
                          </Badge>
                        ) : (
                          <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${ACTION_BADGE_CLASSES.logged}`}>
                            LOGGED
                          </Badge>
                        )}
                      </TableCell>
                    </TableRow>
                    {expanded.has(evt.id || String(idx)) && (
                      <TableRow className="hover:bg-transparent">
                        <TableCell colSpan={7} className="bg-navy-950/50 p-0">
                          <EventDetailPanel event={evt} />
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="py-8 text-center text-xs text-muted-foreground">
              No events in this time range
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

import { useState, useEffect, useRef, useCallback } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { Shield, ShieldAlert, Users, Server, Clock } from "lucide-react";
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
import { fetchSummary, type SummaryData } from "@/lib/api";

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
    amber: "text-neon-amber bg-neon-amber/10",
  };
  const textColorMap: Record<string, string> = {
    green: "text-neon-green",
    pink: "text-neon-pink",
    cyan: "text-neon-cyan",
    amber: "text-neon-amber",
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

// ─── Time Range Selector ────────────────────────────────────────────

const TIME_RANGES = [
  { label: "1h", hours: 1 },
  { label: "6h", hours: 6 },
  { label: "24h", hours: 24 },
  { label: "3d", hours: 72 },
  { label: "7d", hours: 168 },
] as const;

function TimeRangeSelector({
  value,
  onChange,
}: {
  value: number;
  onChange: (hours: number) => void;
}) {
  return (
    <div className="flex items-center gap-1 rounded-lg bg-muted p-1">
      {TIME_RANGES.map((range) => (
        <Button
          key={range.hours}
          variant={value === range.hours ? "default" : "ghost"}
          size="sm"
          className={`h-7 px-3 text-xs ${
            value === range.hours
              ? "bg-neon-green/20 text-neon-green hover:bg-neon-green/30"
              : "text-muted-foreground hover:text-foreground"
          }`}
          onClick={() => onChange(range.hours)}
        >
          {range.label}
        </Button>
      ))}
    </div>
  );
}

// ─── Chart config ───────────────────────────────────────────────────

const chartTooltipStyle = {
  contentStyle: {
    backgroundColor: "#0f1538",
    border: "1px solid #1e275c",
    borderRadius: "8px",
    fontSize: "12px",
    color: "#e0e6f0",
  },
  itemStyle: { color: "#e0e6f0" },
  labelStyle: { color: "#7a8baa" },
};

const DONUT_COLORS = ["#ff006e", "#00ff41"];

// ─── Main Component ─────────────────────────────────────────────────

export default function OverviewDashboard() {
  const [data, setData] = useState<SummaryData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [hours, setHours] = useState(24);

  const loadData = useCallback((h: number) => {
    setLoading(true);
    setError(null);
    fetchSummary(h)
      .then(setData)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    loadData(hours);
  }, [hours, loadData]);

  const handleTimeChange = (h: number) => {
    setHours(h);
  };

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
              onClick={() => loadData(hours)}
            >
              Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Build donut data
  const donutData =
    data && (data.blocked > 0 || data.logged > 0)
      ? [
          { name: "Blocked", value: data.blocked },
          { name: "Logged", value: data.logged },
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
            WAF event summary for the last {TIME_RANGES.find((r) => r.hours === hours)?.label ?? `${hours}h`}
          </p>
        </div>
        <TimeRangeSelector value={hours} onChange={handleTimeChange} />
      </div>

      {/* Stat Cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
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
          color="amber"
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
              Blocked vs logged events over time
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
                      <stop offset="5%" stopColor="#ff006e" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#ff006e" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gradLogged" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00ff41" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#00ff41" stopOpacity={0} />
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
                  />
                  <YAxis
                    stroke="#7a8baa"
                    fontSize={11}
                    tickLine={false}
                    axisLine={false}
                    tickFormatter={formatNumber}
                  />
                  <Tooltip {...chartTooltipStyle} />
                  <Area
                    type="monotone"
                    dataKey="blocked"
                    stackId="1"
                    stroke="#ff006e"
                    fill="url(#gradBlocked)"
                    strokeWidth={2}
                  />
                  <Area
                    type="monotone"
                    dataKey="logged"
                    stackId="1"
                    stroke="#00ff41"
                    fill="url(#gradLogged)"
                    strokeWidth={2}
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        {/* Blocked vs Logged Donut — 1/3 */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Blocked vs Logged</CardTitle>
            <CardDescription>Event action breakdown</CardDescription>
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
                      {donutData.map((_, idx) => (
                        <Cell
                          key={`cell-${idx}`}
                          fill={DONUT_COLORS[idx % DONUT_COLORS.length]}
                        />
                      ))}
                    </Pie>
                    <Tooltip {...chartTooltipStyle} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="mt-2 flex items-center gap-4 text-xs">
                  <div className="flex items-center gap-1.5">
                    <div className="h-2.5 w-2.5 rounded-full bg-neon-pink" />
                    <span className="text-muted-foreground">
                      Blocked ({data?.blocked.toLocaleString()})
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <div className="h-2.5 w-2.5 rounded-full bg-neon-green" />
                    <span className="text-muted-foreground">
                      Logged ({data?.logged.toLocaleString()})
                    </span>
                  </div>
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
            <CardDescription>Blocked and total events per service</CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="space-y-3">
                {[...Array(5)].map((_, i) => (
                  <Skeleton key={i} className="h-8 w-full" />
                ))}
              </div>
            ) : serviceBreakdown.length > 0 ? (
              <ResponsiveContainer width="100%" height={Math.max(serviceBreakdown.length * 36, 140)}>
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
                  <Bar dataKey="blocked" fill="#ff006e" stackId="a" radius={[0, 0, 0, 0]} />
                  <Bar dataKey="logged" fill="#00ff41" stackId="a" radius={[0, 4, 4, 0]} opacity={0.7} />
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
              <ResponsiveContainer width="100%" height={200}>
                <BarChart
                  data={(data?.top_clients ?? []).slice(0, 10)}
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
                    dataKey="client_ip"
                    stroke="#7a8baa"
                    fontSize={10}
                    tickLine={false}
                    axisLine={false}
                    width={110}
                  />
                  <Tooltip {...chartTooltipStyle} />
                  <Bar
                    dataKey="blocked"
                    stackId="a"
                    fill="#ff006e"
                    radius={[0, 0, 0, 0]}
                  />
                  <Bar
                    dataKey="total"
                    stackId="b"
                    fill="#00d4ff"
                    radius={[0, 4, 4, 0]}
                    opacity={0.6}
                  />
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

      {/* Recent Blocks Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Clock className="h-4 w-4 text-neon-pink" />
            <CardTitle className="text-sm">Recent Blocks</CardTitle>
          </div>
          <CardDescription>Last 10 blocked requests</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="space-y-2 p-4">
              {[...Array(5)].map((_, i) => (
                <Skeleton key={i} className="h-8 w-full" />
              ))}
            </div>
          ) : (data?.recent_blocks ?? []).length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Time</TableHead>
                  <TableHead>Service</TableHead>
                  <TableHead>Method</TableHead>
                  <TableHead className="max-w-[250px]">URI</TableHead>
                  <TableHead>Client IP</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(data?.recent_blocks ?? []).slice(0, 10).map((evt, idx) => (
                  <TableRow key={evt.id || idx}>
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
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="py-8 text-center text-xs text-muted-foreground">
              No blocked events in this time range
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

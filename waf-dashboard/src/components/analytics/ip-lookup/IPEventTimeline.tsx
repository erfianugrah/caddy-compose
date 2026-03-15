import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { ACTION_COLORS, CHART_TOOLTIP_STYLE } from "@/lib/utils";
import { T } from "@/lib/typography";

const chartTooltipStyle = CHART_TOOLTIP_STYLE;

interface TimelinePoint {
  hour: string;
  total_blocked: number;
  logged: number;
}

function formatIPTimelineTick(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
  } catch {
    return ts;
  }
}

function formatIPTimelineTooltip(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleString("en-US", {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false,
    });
  } catch {
    return ts;
  }
}

export function IPEventTimeline({ timeline }: { timeline: TimelinePoint[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className={T.cardTitle}>Event Timeline</CardTitle>
        <CardDescription>Events from this IP over time</CardDescription>
      </CardHeader>
      <CardContent>
        {timeline.length > 0 ? (
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart
              data={timeline}
              margin={{ top: 5, right: 10, left: 0, bottom: 0 }}
            >
              <defs>
                <linearGradient id="ipGradBlocked" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={ACTION_COLORS.total_blocked} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={ACTION_COLORS.total_blocked} stopOpacity={0} />
                </linearGradient>
                <linearGradient id="ipGradLogged" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={ACTION_COLORS.logged} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={ACTION_COLORS.logged} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#414457" vertical={false} />
              <XAxis dataKey="hour" stroke="#bdbdc1" fontSize={T.chartAxisTick} tickLine={false} axisLine={false} tickFormatter={formatIPTimelineTick} interval="preserveStartEnd" />
              <YAxis stroke="#bdbdc1" fontSize={T.chartAxisTick} tickLine={false} axisLine={false} />
              <Tooltip {...chartTooltipStyle} labelFormatter={formatIPTimelineTooltip} />
              <Area type="monotone" dataKey="total_blocked" stroke={ACTION_COLORS.total_blocked} fill="url(#ipGradBlocked)" strokeWidth={2} name="Total Blocked" />
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
  );
}

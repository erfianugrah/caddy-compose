import { useCountUp } from "@/hooks/useCountUp";
import { Card, CardContent, CardDescription, CardHeader } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { formatNumber } from "@/lib/format";
import { T } from "@/lib/typography";

// ─── Stat Card ──────────────────────────────────────────────────────

export function StatCard({
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
    green: "text-lv-green bg-lv-green/15",
    pink: "text-lv-red bg-lv-red/15",
    cyan: "text-lv-cyan bg-lv-cyan/15",
    yellow: "text-lv-peach bg-lv-peach/15",
    purple: "text-lv-purple bg-lv-purple/15",
    orange: "text-lv-peach-bright bg-lv-peach-bright/15",
    red: "text-lv-red-bright bg-lv-red-bright/15",
    blue: "text-lv-blue bg-lv-blue/15",
  };
  const textColorMap: Record<string, string> = {
    green: "text-lv-green",
    pink: "text-lv-red",
    cyan: "text-lv-cyan",
    yellow: "text-lv-peach",
    purple: "text-lv-purple",
    orange: "text-lv-peach-bright",
    red: "text-lv-red-bright",
    blue: "text-lv-blue",
  };

  const card = (
    <Card className={href ? "cursor-pointer hover:ring-1 hover:ring-lv-purple/30 transition-all" : undefined}>
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

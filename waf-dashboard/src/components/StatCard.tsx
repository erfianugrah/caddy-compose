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

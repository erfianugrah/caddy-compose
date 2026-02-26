import { Badge } from "@/components/ui/badge";
import type {
  ClientClassification,
  HistogramBin,
  ImpactPoint,
  TimeOfDayBaseline,
} from "@/lib/api";

// ─── Classification Badge ───────────────────────────────────────────

export function ClassificationBadge({ classification }: { classification: ClientClassification }) {
  switch (classification) {
    case "abusive":
      return (
        <Badge variant="outline" className="text-[9px] px-1 py-0 font-mono bg-red-500/10 text-red-400 border-red-500/30">
          Abusive
        </Badge>
      );
    case "suspicious":
      return (
        <Badge variant="outline" className="text-[9px] px-1 py-0 font-mono bg-neon-amber/10 text-neon-amber border-neon-amber/30">
          Suspicious
        </Badge>
      );
    default:
      return (
        <Badge variant="outline" className="text-[9px] px-1 py-0 font-mono bg-neon-green/10 text-neon-green border-neon-green/30">
          Normal
        </Badge>
      );
  }
}

// ─── Confidence Badge ───────────────────────────────────────────────

export function ConfidenceBadge({ confidence }: { confidence: string }) {
  const cls = confidence === "high"
    ? "bg-neon-green/10 text-neon-green border-neon-green/30"
    : confidence === "medium"
      ? "bg-neon-amber/10 text-neon-amber border-neon-amber/30"
      : "bg-muted text-muted-foreground border-border";
  return (
    <Badge variant="outline" className={`text-[9px] px-1.5 py-0 font-mono ${cls}`}>
      {confidence}
    </Badge>
  );
}

// ─── SVG Distribution Histogram ─────────────────────────────────────

export function DistributionHistogram({
  histogram,
  threshold,
  width = 600,
  height = 120,
}: {
  histogram: HistogramBin[];
  threshold: number;
  width?: number;
  height?: number;
}) {
  if (!histogram || histogram.length === 0) return null;
  const maxCount = Math.max(...histogram.map((b) => b.count), 1);
  const barW = (width - 40) / histogram.length;
  const chartH = height - 24;

  return (
    <svg width={width} height={height} className="w-full" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="xMidYMid meet">
      {histogram.map((bin, i) => {
        const x = 30 + i * barW;
        const barH = (bin.count / maxCount) * chartH;
        const midpoint = (bin.min + bin.max) / 2;
        const isAbove = midpoint >= threshold;
        return (
          <g key={i}>
            <rect
              x={x + 1}
              y={chartH - barH}
              width={Math.max(barW - 2, 1)}
              height={Math.max(barH, 0)}
              fill={isAbove ? "rgba(239,68,68,0.6)" : "rgba(34,211,238,0.35)"}
              rx={1}
            />
            {/* X-axis label every few bins */}
            {(i === 0 || i === histogram.length - 1 || i % Math.max(1, Math.floor(histogram.length / 6)) === 0) && (
              <text x={x + barW / 2} y={height - 2} textAnchor="middle" className="fill-muted-foreground" fontSize={9}>
                {bin.min}
              </text>
            )}
            {/* Count label on top of bars with data */}
            {bin.count > 0 && barH > 12 && (
              <text x={x + barW / 2} y={chartH - barH + 10} textAnchor="middle" className="fill-foreground" fontSize={8} fontFamily="monospace">
                {bin.count}
              </text>
            )}
          </g>
        );
      })}
      {/* Threshold line */}
      {(() => {
        // Find x position for threshold.
        const idx = histogram.findIndex((b) => threshold >= b.min && threshold < b.max);
        if (idx < 0) return null;
        const bin = histogram[idx];
        const frac = bin.max > bin.min ? (threshold - bin.min) / (bin.max - bin.min) : 0.5;
        const x = 30 + idx * barW + frac * barW;
        return (
          <line x1={x} y1={0} x2={x} y2={chartH} stroke="#eab308" strokeWidth={1.5} strokeDasharray="4,3" opacity={0.8} />
        );
      })()}
      {/* Y-axis label */}
      <text x={2} y={12} className="fill-muted-foreground" fontSize={8}>clients</text>
      {/* X-axis label */}
      <text x={width / 2} y={height - 2} textAnchor="middle" className="fill-muted-foreground" fontSize={8}>
        requests / window
      </text>
    </svg>
  );
}

// ─── SVG Impact Curve ───────────────────────────────────────────────

export function ImpactCurve({
  curve,
  threshold,
  width = 300,
  height = 100,
}: {
  curve: ImpactPoint[];
  threshold: number;
  width?: number;
  height?: number;
}) {
  if (!curve || curve.length < 2) return null;
  const chartW = width - 40;
  const chartH = height - 20;
  const minT = curve[0].threshold;
  const maxT = curve[curve.length - 1].threshold;
  const range = maxT - minT || 1;

  const clientLine = curve.map((p, i) => {
    const x = 30 + ((p.threshold - minT) / range) * chartW;
    const y = 4 + (1 - p.client_pct) * chartH;
    return `${i === 0 ? "M" : "L"}${x},${y}`;
  }).join(" ");

  const requestLine = curve.map((p, i) => {
    const x = 30 + ((p.threshold - minT) / range) * chartW;
    const y = 4 + (1 - p.request_pct) * chartH;
    return `${i === 0 ? "M" : "L"}${x},${y}`;
  }).join(" ");

  const thresholdX = 30 + ((threshold - minT) / range) * chartW;

  return (
    <svg width={width} height={height} className="w-full" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="xMidYMid meet">
      <path d={clientLine} fill="none" stroke="#22d3ee" strokeWidth={1.5} opacity={0.8} />
      <path d={requestLine} fill="none" stroke="#f472b6" strokeWidth={1.5} opacity={0.8} strokeDasharray="4,2" />
      {/* Threshold line */}
      <line x1={thresholdX} y1={0} x2={thresholdX} y2={chartH + 4} stroke="#eab308" strokeWidth={1} strokeDasharray="3,2" opacity={0.7} />
      {/* Y-axis labels */}
      <text x={2} y={10} className="fill-muted-foreground" fontSize={8}>100%</text>
      <text x={2} y={chartH + 4} className="fill-muted-foreground" fontSize={8}>0%</text>
      {/* Legend */}
      <line x1={width - 110} y1={height - 6} x2={width - 98} y2={height - 6} stroke="#22d3ee" strokeWidth={1.5} />
      <text x={width - 95} y={height - 2} className="fill-muted-foreground" fontSize={7}>Clients</text>
      <line x1={width - 60} y1={height - 6} x2={width - 48} y2={height - 6} stroke="#f472b6" strokeWidth={1.5} strokeDasharray="3,2" />
      <text x={width - 45} y={height - 2} className="fill-muted-foreground" fontSize={7}>Requests</text>
    </svg>
  );
}

// ─── SVG Time-of-Day Baseline Chart ─────────────────────────────────

export function TimeOfDayChart({
  baselines,
  width = 400,
  height = 100,
}: {
  baselines: TimeOfDayBaseline[];
  width?: number;
  height?: number;
}) {
  if (!baselines || baselines.length < 2) return null;
  const chartW = width - 40;
  const chartH = height - 24;
  const maxRPS = Math.max(...baselines.map((b) => b.p95_rps), 0.001);

  const barW = chartW / 24;

  return (
    <svg width={width} height={height} className="w-full" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="xMidYMid meet">
      {/* Draw bars for all 24 hours, empty for hours with no data */}
      {Array.from({ length: 24 }, (_, hour) => {
        const baseline = baselines.find((b) => b.hour === hour);
        const x = 30 + hour * barW;
        if (!baseline) {
          return (
            <g key={hour}>
              <rect x={x + 1} y={chartH} width={Math.max(barW - 2, 1)} height={0} fill="transparent" />
              {hour % 4 === 0 && (
                <text x={x + barW / 2} y={height - 2} textAnchor="middle" className="fill-muted-foreground/40" fontSize={8}>
                  {String(hour).padStart(2, "0")}
                </text>
              )}
            </g>
          );
        }
        const medH = (baseline.median_rps / maxRPS) * chartH;
        const p95H = (baseline.p95_rps / maxRPS) * chartH;
        return (
          <g key={hour}>
            {/* P95 bar (light) */}
            <rect
              x={x + 1}
              y={chartH - p95H}
              width={Math.max(barW - 2, 1)}
              height={Math.max(p95H, 0)}
              fill="rgba(34,211,238,0.15)"
              rx={1}
            />
            {/* Median bar (solid) */}
            <rect
              x={x + 1}
              y={chartH - medH}
              width={Math.max(barW - 2, 1)}
              height={Math.max(medH, 0)}
              fill="rgba(34,211,238,0.5)"
              rx={1}
            />
            {/* Hour label every 4 hours */}
            {hour % 4 === 0 && (
              <text x={x + barW / 2} y={height - 2} textAnchor="middle" className="fill-muted-foreground" fontSize={8}>
                {String(hour).padStart(2, "0")}
              </text>
            )}
          </g>
        );
      })}
      {/* Y-axis */}
      <text x={2} y={10} className="fill-muted-foreground" fontSize={7}>{maxRPS.toFixed(2)}</text>
      <text x={2} y={chartH} className="fill-muted-foreground" fontSize={7}>0</text>
      <text x={2} y={chartH / 2 + 3} className="fill-muted-foreground" fontSize={7}>rps</text>
    </svg>
  );
}

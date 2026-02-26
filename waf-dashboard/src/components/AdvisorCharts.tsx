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
        <Badge variant="outline" className="text-xs px-1.5 py-0.5 font-mono bg-red-500/10 text-red-400 border-red-500/30">
          Abusive
        </Badge>
      );
    case "suspicious":
      return (
        <Badge variant="outline" className="text-xs px-1.5 py-0.5 font-mono bg-neon-amber/10 text-neon-amber border-neon-amber/30">
          Suspicious
        </Badge>
      );
    case "elevated":
      return (
        <Badge variant="outline" className="text-xs px-1.5 py-0.5 font-mono bg-neon-yellow/10 text-neon-yellow border-neon-yellow/30">
          Elevated
        </Badge>
      );
    default:
      return (
        <Badge variant="outline" className="text-xs px-1.5 py-0.5 font-mono bg-neon-green/10 text-neon-green border-neon-green/30">
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
    <Badge variant="outline" className={`text-xs px-1.5 py-0.5 font-mono ${cls}`}>
      {confidence}
    </Badge>
  );
}

// ─── SVG Distribution Histogram ─────────────────────────────────────

export function DistributionHistogram({
  histogram,
  threshold,
  width = 700,
  height = 200,
}: {
  histogram: HistogramBin[];
  threshold: number;
  width?: number;
  height?: number;
}) {
  if (!histogram || histogram.length === 0) return null;

  // Filter to only bins that have data or are adjacent to bins with data,
  // plus keep first/last for axis context. This avoids huge empty gaps.
  const nonEmpty = histogram.filter((b) => b.count > 0);
  if (nonEmpty.length === 0) return null;

  // Find the range that matters: from first non-empty bin to last, with 1 bin padding
  const firstIdx = histogram.indexOf(nonEmpty[0]);
  const lastIdx = histogram.indexOf(nonEmpty[nonEmpty.length - 1]);
  const startIdx = Math.max(0, firstIdx - 1);
  const endIdx = Math.min(histogram.length - 1, lastIdx + 1);
  const visibleBins = histogram.slice(startIdx, endIdx + 1);

  const maxCount = Math.max(...visibleBins.map((b) => b.count), 1);
  const padLeft = 45;
  const padBottom = 32;
  const padTop = 8;
  const chartW = width - padLeft - 10;
  const chartH = height - padBottom - padTop;
  const barW = chartW / visibleBins.length;

  return (
    <svg width={width} height={height} className="w-full" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="xMidYMid meet">
      {/* Y-axis gridlines */}
      {[0.25, 0.5, 0.75, 1].map((frac) => {
        const y = padTop + chartH - frac * chartH;
        return (
          <g key={frac}>
            <line x1={padLeft} y1={y} x2={width - 10} y2={y} stroke="currentColor" strokeOpacity={0.06} />
            <text x={padLeft - 6} y={y + 3} textAnchor="end" className="fill-muted-foreground" fontSize={10}>
              {Math.round(maxCount * frac)}
            </text>
          </g>
        );
      })}

      {/* Bars */}
      {visibleBins.map((bin, i) => {
        const x = padLeft + i * barW;
        const barH = (bin.count / maxCount) * chartH;
        const midpoint = (bin.min + bin.max) / 2;
        const isAbove = midpoint >= threshold;
        return (
          <g key={i}>
            <rect
              x={x + 2}
              y={padTop + chartH - barH}
              width={Math.max(barW - 4, 2)}
              height={Math.max(barH, 0)}
              fill={isAbove ? "rgba(239,68,68,0.6)" : "rgba(34,211,238,0.4)"}
              rx={2}
            />
            {/* Count label on top of bars */}
            {bin.count > 0 && barH > 18 && (
              <text x={x + barW / 2} y={padTop + chartH - barH + 14} textAnchor="middle" className="fill-foreground" fontSize={11} fontFamily="monospace" fontWeight={500}>
                {bin.count}
              </text>
            )}
            {bin.count > 0 && barH > 0 && barH <= 18 && (
              <text x={x + barW / 2} y={padTop + chartH - barH - 4} textAnchor="middle" className="fill-foreground" fontSize={10} fontFamily="monospace">
                {bin.count}
              </text>
            )}
            {/* X-axis label: show for every bin if few, or every Nth */}
            {(visibleBins.length <= 12 || i % Math.max(1, Math.floor(visibleBins.length / 8)) === 0 || i === visibleBins.length - 1) && (
              <text x={x + barW / 2} y={height - padBottom + 16} textAnchor="middle" className="fill-muted-foreground" fontSize={10} fontFamily="monospace">
                {bin.min}
              </text>
            )}
          </g>
        );
      })}

      {/* Threshold line */}
      {(() => {
        const idx = visibleBins.findIndex((b) => threshold >= b.min && threshold < b.max);
        if (idx < 0) {
          // Threshold is beyond visible range — check if it's past the last bin
          const lastBin = visibleBins[visibleBins.length - 1];
          if (threshold >= lastBin.min) {
            const x = padLeft + chartW;
            return <line x1={x} y1={padTop} x2={x} y2={padTop + chartH} stroke="#eab308" strokeWidth={2} strokeDasharray="6,4" opacity={0.9} />;
          }
          return null;
        }
        const bin = visibleBins[idx];
        const frac = bin.max > bin.min ? (threshold - bin.min) / (bin.max - bin.min) : 0.5;
        const x = padLeft + idx * barW + frac * barW;
        return (
          <line x1={x} y1={padTop} x2={x} y2={padTop + chartH} stroke="#eab308" strokeWidth={2} strokeDasharray="6,4" opacity={0.9} />
        );
      })()}

      {/* Y-axis label */}
      <text x={4} y={padTop + chartH / 2} className="fill-muted-foreground" fontSize={11} transform={`rotate(-90, 10, ${padTop + chartH / 2})`} textAnchor="middle">
        clients
      </text>
      {/* X-axis label */}
      <text x={padLeft + chartW / 2} y={height - 4} textAnchor="middle" className="fill-muted-foreground" fontSize={11}>
        requests / window
      </text>
      {/* Baseline */}
      <line x1={padLeft} y1={padTop + chartH} x2={padLeft + chartW} y2={padTop + chartH} stroke="currentColor" strokeOpacity={0.15} />
    </svg>
  );
}

// ─── SVG Impact Curve ───────────────────────────────────────────────

export function ImpactCurve({
  curve,
  threshold,
  width = 340,
  height = 200,
}: {
  curve: ImpactPoint[];
  threshold: number;
  width?: number;
  height?: number;
}) {
  if (!curve || curve.length < 2) return null;
  const padLeft = 36;
  const padRight = 10;
  const padTop = 8;
  const padBottom = 28;
  const chartW = width - padLeft - padRight;
  const chartH = height - padTop - padBottom;
  const minT = curve[0].threshold;
  const maxT = curve[curve.length - 1].threshold;
  const range = maxT - minT || 1;

  const clientLine = curve.map((p, i) => {
    const x = padLeft + ((p.threshold - minT) / range) * chartW;
    const y = padTop + (1 - p.client_pct) * chartH;
    return `${i === 0 ? "M" : "L"}${x},${y}`;
  }).join(" ");

  const requestLine = curve.map((p, i) => {
    const x = padLeft + ((p.threshold - minT) / range) * chartW;
    const y = padTop + (1 - p.request_pct) * chartH;
    return `${i === 0 ? "M" : "L"}${x},${y}`;
  }).join(" ");

  const thresholdX = padLeft + ((threshold - minT) / range) * chartW;

  return (
    <svg width={width} height={height} className="w-full" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="xMidYMid meet">
      {/* Gridlines */}
      {[0.25, 0.5, 0.75].map((frac) => {
        const y = padTop + (1 - frac) * chartH;
        return <line key={frac} x1={padLeft} y1={y} x2={padLeft + chartW} y2={y} stroke="currentColor" strokeOpacity={0.06} />;
      })}

      <path d={clientLine} fill="none" stroke="#22d3ee" strokeWidth={2} opacity={0.9} />
      <path d={requestLine} fill="none" stroke="#f472b6" strokeWidth={2} opacity={0.9} strokeDasharray="5,3" />

      {/* Threshold line */}
      <line x1={thresholdX} y1={padTop} x2={thresholdX} y2={padTop + chartH} stroke="#eab308" strokeWidth={1.5} strokeDasharray="4,3" opacity={0.8} />

      {/* Y-axis labels */}
      <text x={padLeft - 4} y={padTop + 4} textAnchor="end" className="fill-muted-foreground" fontSize={10}>100%</text>
      <text x={padLeft - 4} y={padTop + chartH / 2 + 3} textAnchor="end" className="fill-muted-foreground" fontSize={10}>50%</text>
      <text x={padLeft - 4} y={padTop + chartH + 4} textAnchor="end" className="fill-muted-foreground" fontSize={10}>0%</text>

      {/* Legend */}
      <line x1={padLeft + 8} y1={height - 8} x2={padLeft + 22} y2={height - 8} stroke="#22d3ee" strokeWidth={2} />
      <text x={padLeft + 26} y={height - 4} className="fill-muted-foreground" fontSize={10}>Clients</text>
      <line x1={padLeft + 80} y1={height - 8} x2={padLeft + 94} y2={height - 8} stroke="#f472b6" strokeWidth={2} strokeDasharray="4,2" />
      <text x={padLeft + 98} y={height - 4} className="fill-muted-foreground" fontSize={10}>Requests</text>
    </svg>
  );
}

// ─── SVG Time-of-Day Baseline Chart ─────────────────────────────────

export function TimeOfDayChart({
  baselines,
  width = 700,
  height = 160,
}: {
  baselines: TimeOfDayBaseline[];
  width?: number;
  height?: number;
}) {
  if (!baselines || baselines.length < 2) return null;
  const padLeft = 45;
  const padBottom = 28;
  const padTop = 8;
  const chartW = width - padLeft - 10;
  const chartH = height - padBottom - padTop;
  const maxRPS = Math.max(...baselines.map((b) => b.p95_rps), 0.001);
  const barW = chartW / 24;

  return (
    <svg width={width} height={height} className="w-full" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="xMidYMid meet">
      {/* Y-axis gridlines */}
      {[0.25, 0.5, 0.75, 1].map((frac) => {
        const y = padTop + chartH - frac * chartH;
        return (
          <g key={frac}>
            <line x1={padLeft} y1={y} x2={width - 10} y2={y} stroke="currentColor" strokeOpacity={0.06} />
            <text x={padLeft - 6} y={y + 3} textAnchor="end" className="fill-muted-foreground" fontSize={10}>
              {(maxRPS * frac).toFixed(2)}
            </text>
          </g>
        );
      })}

      {/* Bars for all 24 hours */}
      {Array.from({ length: 24 }, (_, hour) => {
        const baseline = baselines.find((b) => b.hour === hour);
        const x = padLeft + hour * barW;
        if (!baseline) {
          return (
            <g key={hour}>
              {hour % 3 === 0 && (
                <text x={x + barW / 2} y={height - padBottom + 16} textAnchor="middle" className="fill-muted-foreground/40" fontSize={10}>
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
              x={x + 2}
              y={padTop + chartH - p95H}
              width={Math.max(barW - 4, 2)}
              height={Math.max(p95H, 0)}
              fill="rgba(34,211,238,0.15)"
              rx={2}
            />
            {/* Median bar (solid) */}
            <rect
              x={x + 2}
              y={padTop + chartH - medH}
              width={Math.max(barW - 4, 2)}
              height={Math.max(medH, 0)}
              fill="rgba(34,211,238,0.5)"
              rx={2}
            />
            {/* Hour label every 3 hours */}
            {hour % 3 === 0 && (
              <text x={x + barW / 2} y={height - padBottom + 16} textAnchor="middle" className="fill-muted-foreground" fontSize={10}>
                {String(hour).padStart(2, "0")}
              </text>
            )}
          </g>
        );
      })}

      {/* Baseline */}
      <line x1={padLeft} y1={padTop + chartH} x2={padLeft + chartW} y2={padTop + chartH} stroke="currentColor" strokeOpacity={0.15} />

      {/* Y-axis label */}
      <text x={4} y={padTop + chartH / 2} className="fill-muted-foreground" fontSize={11} transform={`rotate(-90, 10, ${padTop + chartH / 2})`} textAnchor="middle">
        req/s
      </text>
      <text x={padLeft - 6} y={padTop + chartH + 4} textAnchor="end" className="fill-muted-foreground" fontSize={10}>0</text>
    </svg>
  );
}

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

// ─── Nice Y-axis Ticks ──────────────────────────────────────────────

/** Compute distinct, round Y-axis tick values. Avoids duplicate integers. */
function niceYTicks(maxVal: number, maxTicks = 4): number[] {
  if (maxVal <= 0) return [];
  const ceil = Math.ceil(maxVal);
  if (ceil <= maxTicks) {
    // Small values: just use 1, 2, ..., ceil
    return Array.from({ length: ceil }, (_, i) => i + 1);
  }
  const rawStep = maxVal / maxTicks;
  const mag = Math.pow(10, Math.floor(Math.log10(rawStep)));
  const norm = rawStep / mag;
  const step = norm <= 1 ? mag : norm <= 2 ? 2 * mag : norm <= 5 ? 5 * mag : 10 * mag;
  const ticks: number[] = [];
  for (let v = step; v <= maxVal * 1.01; v += step) {
    ticks.push(Math.round(v));
  }
  if (ticks.length === 0) ticks.push(ceil);
  return [...new Set(ticks)];
}

// ─── SVG Distribution Histogram ─────────────────────────────────────

export function DistributionHistogram({
  histogram,
  threshold,
}: {
  histogram: HistogramBin[];
  threshold: number;
}) {
  if (!histogram || histogram.length === 0) return null;

  const nonEmpty = histogram.filter((b) => b.count > 0);
  if (nonEmpty.length === 0) return null;

  // Collapse to only bins with data — no empty gaps for sparse distributions
  const visibleBins = nonEmpty;

  // ViewBox dimensions (internal coordinates — SVG scales to fill container)
  const vw = 720;
  const vh = 210;
  const padLeft = 45;
  const padRight = 10;
  const padBottom = 32;
  const padTop = 10;
  const chartW = vw - padLeft - padRight;
  const chartH = vh - padBottom - padTop;
  const barW = chartW / visibleBins.length;

  const rawMax = Math.max(...visibleBins.map((b) => b.count), 1);
  const ticks = niceYTicks(rawMax);
  const niceMax = ticks.length > 0 ? ticks[ticks.length - 1] : rawMax;

  return (
    <svg viewBox={`0 0 ${vw} ${vh}`} className="w-full h-auto" preserveAspectRatio="xMidYMid meet">
      {/* Y-axis gridlines + labels */}
      {ticks.map((tick) => {
        const y = padTop + chartH - (tick / niceMax) * chartH;
        return (
          <g key={tick}>
            <line x1={padLeft} y1={y} x2={vw - padRight} y2={y} stroke="currentColor" strokeOpacity={0.08} />
            <text x={padLeft - 6} y={y + 3} textAnchor="end" className="fill-muted-foreground" fontSize={10}>
              {tick}
            </text>
          </g>
        );
      })}

      {/* Bars */}
      {visibleBins.map((bin, i) => {
        const x = padLeft + i * barW;
        const gap = Math.min(barW * 0.08, 2);
        const bw = barW - gap * 2;
        const barH = (bin.count / niceMax) * chartH;
        const midpoint = (bin.min + bin.max) / 2;
        const isAbove = midpoint >= threshold;
        return (
          <g key={i}>
            <rect
              x={x + gap}
              y={padTop + chartH - barH}
              width={Math.max(bw, 2)}
              height={Math.max(barH, 0)}
              fill={isAbove ? "rgba(239,68,68,0.6)" : "rgba(34,211,238,0.4)"}
              rx={2}
            />
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
            {(visibleBins.length <= 12 || i % Math.max(1, Math.floor(visibleBins.length / 8)) === 0 || i === visibleBins.length - 1) && (
              <text x={x + barW / 2} y={vh - padBottom + 16} textAnchor="middle" className="fill-muted-foreground" fontSize={10} fontFamily="monospace">
                {bin.min}
              </text>
            )}
          </g>
        );
      })}

      {/* Threshold line — handles collapsed (non-contiguous) bins */}
      {(() => {
        // Threshold falls within a visible bin
        const idx = visibleBins.findIndex((b) => threshold >= b.min && threshold < b.max);
        if (idx >= 0) {
          const bin = visibleBins[idx];
          const frac = bin.max > bin.min ? (threshold - bin.min) / (bin.max - bin.min) : 0.5;
          const x = padLeft + idx * barW + frac * barW;
          return <line x1={x} y1={padTop} x2={x} y2={padTop + chartH} stroke="#eab308" strokeWidth={2} strokeDasharray="6,4" opacity={0.9} />;
        }
        // Before all visible bins
        if (threshold < visibleBins[0].min) {
          return <line x1={padLeft} y1={padTop} x2={padLeft} y2={padTop + chartH} stroke="#eab308" strokeWidth={2} strokeDasharray="6,4" opacity={0.9} />;
        }
        // After all visible bins
        const lastBin = visibleBins[visibleBins.length - 1];
        if (threshold >= lastBin.max) {
          return <line x1={padLeft + chartW} y1={padTop} x2={padLeft + chartW} y2={padTop + chartH} stroke="#eab308" strokeWidth={2} strokeDasharray="6,4" opacity={0.9} />;
        }
        // Between two non-contiguous visible bins — draw at the gap boundary
        for (let i = 0; i < visibleBins.length - 1; i++) {
          if (threshold >= visibleBins[i].max && threshold < visibleBins[i + 1].min) {
            const x = padLeft + (i + 1) * barW;
            return <line x1={x} y1={padTop} x2={x} y2={padTop + chartH} stroke="#eab308" strokeWidth={2} strokeDasharray="6,4" opacity={0.9} />;
          }
        }
        return null;
      })()}

      {/* Y-axis label */}
      <text x={4} y={padTop + chartH / 2} className="fill-muted-foreground" fontSize={11} transform={`rotate(-90, 10, ${padTop + chartH / 2})`} textAnchor="middle">
        clients
      </text>
      {/* X-axis label */}
      <text x={padLeft + chartW / 2} y={vh - 4} textAnchor="middle" className="fill-muted-foreground" fontSize={11}>
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
}: {
  curve: ImpactPoint[];
  threshold: number;
}) {
  if (!curve || curve.length < 2) return null;

  const vw = 720;
  const vh = 200;
  const padLeft = 40;
  const padRight = 10;
  const padTop = 8;
  const padBottom = 32;
  const chartW = vw - padLeft - padRight;
  const chartH = vh - padTop - padBottom;
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
    <svg viewBox={`0 0 ${vw} ${vh}`} className="w-full h-auto" preserveAspectRatio="xMidYMid meet">
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

      {/* X-axis tick labels */}
      {[0, 0.25, 0.5, 0.75, 1].map((frac) => {
        const val = minT + frac * range;
        const x = padLeft + frac * chartW;
        return (
          <text key={frac} x={x} y={vh - padBottom + 16} textAnchor="middle" className="fill-muted-foreground" fontSize={10} fontFamily="monospace">
            {Math.round(val)}
          </text>
        );
      })}

      {/* Legend */}
      <line x1={padLeft + 8} y1={vh - 8} x2={padLeft + 22} y2={vh - 8} stroke="#22d3ee" strokeWidth={2} />
      <text x={padLeft + 26} y={vh - 4} className="fill-muted-foreground" fontSize={10}>Clients</text>
      <line x1={padLeft + 80} y1={vh - 8} x2={padLeft + 94} y2={vh - 8} stroke="#f472b6" strokeWidth={2} strokeDasharray="4,2" />
      <text x={padLeft + 98} y={vh - 4} className="fill-muted-foreground" fontSize={10}>Requests</text>
    </svg>
  );
}

// ─── SVG Time-of-Day Baseline Chart ─────────────────────────────────

export function TimeOfDayChart({
  baselines,
}: {
  baselines: TimeOfDayBaseline[];
}) {
  if (!baselines || baselines.length < 2) return null;

  const vw = 720;
  const vh = 180;
  const padLeft = 45;
  const padRight = 10;
  const padBottom = 28;
  const padTop = 8;
  const chartW = vw - padLeft - padRight;
  const chartH = vh - padBottom - padTop;
  const maxRPS = Math.max(...baselines.map((b) => b.p95_rps), 0.001);
  const barW = chartW / 24;

  const ticks = niceYTicks(maxRPS, 4);
  const niceMax = ticks.length > 0 ? ticks[ticks.length - 1] : maxRPS;

  return (
    <svg viewBox={`0 0 ${vw} ${vh}`} className="w-full h-auto" preserveAspectRatio="xMidYMid meet">
      {/* Y-axis gridlines */}
      {ticks.map((tick) => {
        const y = padTop + chartH - (tick / niceMax) * chartH;
        return (
          <g key={tick}>
            <line x1={padLeft} y1={y} x2={vw - padRight} y2={y} stroke="currentColor" strokeOpacity={0.06} />
            <text x={padLeft - 6} y={y + 3} textAnchor="end" className="fill-muted-foreground" fontSize={10}>
              {tick < 1 ? tick.toFixed(2) : tick.toFixed(1)}
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
                <text x={x + barW / 2} y={vh - padBottom + 16} textAnchor="middle" className="fill-muted-foreground/40" fontSize={10}>
                  {String(hour).padStart(2, "0")}
                </text>
              )}
            </g>
          );
        }
        const gap = Math.min(barW * 0.08, 2);
        const bw = barW - gap * 2;
        const medH = (baseline.median_rps / niceMax) * chartH;
        const p95H = (baseline.p95_rps / niceMax) * chartH;
        return (
          <g key={hour}>
            <rect
              x={x + gap}
              y={padTop + chartH - p95H}
              width={Math.max(bw, 2)}
              height={Math.max(p95H, 0)}
              fill="rgba(34,211,238,0.15)"
              rx={2}
            />
            <rect
              x={x + gap}
              y={padTop + chartH - medH}
              width={Math.max(bw, 2)}
              height={Math.max(medH, 0)}
              fill="rgba(34,211,238,0.5)"
              rx={2}
            />
            {hour % 3 === 0 && (
              <text x={x + barW / 2} y={vh - padBottom + 16} textAnchor="middle" className="fill-muted-foreground" fontSize={10}>
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

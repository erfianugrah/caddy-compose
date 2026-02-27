import { useState, useCallback, useId, useRef, type MouseEvent as ReactMouseEvent } from "react";
import { Badge } from "@/components/ui/badge";
import type {
  ClientClassification,
  HistogramBin,
  ImpactPoint,
  TimeOfDayBaseline,
} from "@/lib/api";
import { T } from "@/lib/typography";

// ─── SVG Drag-to-Zoom Hook ─────────────────────────────────────────

interface DragZoomState {
  /** Fractional X positions [0–1] within the chart area for the zoomed domain. null = full view */
  zoomFracLeft: number | null;
  zoomFracRight: number | null;
  /** Selection overlay fractions during drag */
  selFracLeft: number | null;
  selFracRight: number | null;
  isDragging: boolean;
}

function useSvgDragZoom(padLeft: number, chartW: number) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [state, setState] = useState<DragZoomState>({
    zoomFracLeft: null, zoomFracRight: null,
    selFracLeft: null, selFracRight: null,
    isDragging: false,
  });

  /** Convert a mouse event to a fractional X position [0–1] within the chart area */
  const toFrac = useCallback((e: ReactMouseEvent<SVGSVGElement>) => {
    const svg = svgRef.current;
    if (!svg) return 0;
    const rect = svg.getBoundingClientRect();
    // Map pixel position to SVG viewBox coordinates
    const viewBox = svg.viewBox.baseVal;
    const svgX = ((e.clientX - rect.left) / rect.width) * viewBox.width;
    return Math.max(0, Math.min(1, (svgX - padLeft) / chartW));
  }, [padLeft, chartW]);

  const onMouseDown = useCallback((e: ReactMouseEvent<SVGSVGElement>) => {
    // Only left-click
    if (e.button !== 0) return;
    const frac = toFrac(e);
    setState((s) => ({ ...s, selFracLeft: frac, selFracRight: frac, isDragging: true }));
  }, [toFrac]);

  const onMouseMove = useCallback((e: ReactMouseEvent<SVGSVGElement>) => {
    setState((s) => {
      if (!s.isDragging) return s;
      const frac = toFrac(e);
      return { ...s, selFracRight: frac };
    });
  }, [toFrac]);

  const onMouseUp = useCallback(() => {
    setState((s) => {
      if (!s.isDragging || s.selFracLeft === null || s.selFracRight === null) {
        return { ...s, isDragging: false, selFracLeft: null, selFracRight: null };
      }
      const left = Math.min(s.selFracLeft, s.selFracRight);
      const right = Math.max(s.selFracLeft, s.selFracRight);
      // Ignore tiny drags (< 2% of chart width) — treat as click
      if (right - left < 0.02) {
        return { ...s, isDragging: false, selFracLeft: null, selFracRight: null };
      }
      // If already zoomed, compose: map selection fracs through the existing zoom window
      const curLeft = s.zoomFracLeft ?? 0;
      const curRight = s.zoomFracRight ?? 1;
      const curRange = curRight - curLeft;
      return {
        zoomFracLeft: curLeft + left * curRange,
        zoomFracRight: curLeft + right * curRange,
        selFracLeft: null, selFracRight: null, isDragging: false,
      };
    });
  }, []);

  const resetZoom = useCallback(() => {
    setState({ zoomFracLeft: null, zoomFracRight: null, selFracLeft: null, selFracRight: null, isDragging: false });
  }, []);

  const onDoubleClick = useCallback(() => {
    resetZoom();
  }, [resetZoom]);

  const isZoomed = state.zoomFracLeft !== null && state.zoomFracRight !== null;

  return { svgRef, state, onMouseDown, onMouseMove, onMouseUp, onDoubleClick, resetZoom, isZoomed };
}

/** Render the blue selection overlay rectangle during drag */
function SelectionOverlay({ state, padLeft, padTop, chartW, chartH }: {
  state: DragZoomState; padLeft: number; padTop: number; chartW: number; chartH: number;
}) {
  if (!state.isDragging || state.selFracLeft === null || state.selFracRight === null) return null;
  const left = Math.min(state.selFracLeft, state.selFracRight);
  const right = Math.max(state.selFracLeft, state.selFracRight);
  const x = padLeft + left * chartW;
  const w = (right - left) * chartW;
  return <rect x={x} y={padTop} width={w} height={chartH} fill="rgba(34,211,238,0.15)" stroke="#22d3ee" strokeWidth={1} strokeOpacity={0.4} />;
}

/** HTML reset zoom button positioned outside SVG */
function ResetZoomButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="absolute top-1 right-1 px-2 py-0.5 text-[10px] font-mono text-cyan-400 bg-cyan-400/10 border border-cyan-400/30 rounded hover:bg-cyan-400/20 transition-colors cursor-pointer z-10"
    >
      Reset zoom
    </button>
  );
}

// ─── Classification Badge ───────────────────────────────────────────

export function ClassificationBadge({ classification }: { classification: ClientClassification }) {
  switch (classification) {
    case "abusive":
      return (
         <Badge variant="outline" className={`${T.badgeMono} bg-red-500/10 text-red-400 border-red-500/30`}>
          Abusive
        </Badge>
      );
    case "suspicious":
      return (
        <Badge variant="outline" className={`${T.badgeMono} bg-neon-amber/10 text-neon-amber border-neon-amber/30`}>
          Suspicious
        </Badge>
      );
    case "elevated":
      return (
        <Badge variant="outline" className={`${T.badgeMono} bg-neon-yellow/10 text-neon-yellow border-neon-yellow/30`}>
          Elevated
        </Badge>
      );
    default:
      return (
        <Badge variant="outline" className={`${T.badgeMono} bg-neon-green/10 text-neon-green border-neon-green/30`}>
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
    <Badge variant="outline" className={`${T.badgeMono} ${cls}`}>
      {confidence}
    </Badge>
  );
}

// ─── Nice Y-axis Ticks ──────────────────────────────────────────────

/** Compute distinct, round Y-axis tick values. Works for both integers and small fractions. */
function niceYTicks(maxVal: number, maxTicks = 4): number[] {
  if (maxVal <= 0) return [];

  // For fractional values (< 1), compute nice ticks using magnitude-aware stepping
  const rawStep = maxVal / maxTicks;
  const mag = Math.pow(10, Math.floor(Math.log10(rawStep)));
  const norm = rawStep / mag;
  const step = norm <= 1 ? mag : norm <= 2 ? 2 * mag : norm <= 5 ? 5 * mag : 10 * mag;

  const ticks: number[] = [];
  for (let v = step; v <= maxVal * 1.05; v += step) {
    // Round to avoid floating-point drift — use enough precision for the magnitude
    const decimals = step < 1 ? Math.max(0, -Math.floor(Math.log10(step)) + 1) : 0;
    const rounded = decimals > 0 ? parseFloat(v.toFixed(decimals)) : Math.round(v);
    ticks.push(rounded);
  }
  if (ticks.length === 0) {
    // Fallback: at least one tick at the ceiling
    const decimals = maxVal < 1 ? Math.max(1, -Math.floor(Math.log10(maxVal)) + 1) : 0;
    ticks.push(decimals > 0 ? parseFloat(maxVal.toFixed(decimals)) : Math.ceil(maxVal));
  }
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

  // Use sqrt-scaled X positioning when the bin value range is wide (>10x),
  // so the dense low-value region gets proportionally more visual space
  const globalMin = visibleBins[0].min;
  const globalMax = visibleBins[visibleBins.length - 1].max;
  const useScaledX = globalMax / Math.max(globalMin, 1) > 10;
  const xScale = (v: number) => useScaledX ? Math.sqrt(Math.max(v, 0)) : v;
  const scaledGlobalMin = xScale(globalMin);
  const scaledGlobalMax = xScale(globalMax);
  const scaledGlobalRange = scaledGlobalMax - scaledGlobalMin || 1;

  // Precompute bar positions and widths
  const barLayouts = visibleBins.map((bin) => {
    const x0 = padLeft + ((xScale(bin.min) - scaledGlobalMin) / scaledGlobalRange) * chartW;
    const x1 = padLeft + ((xScale(bin.max) - scaledGlobalMin) / scaledGlobalRange) * chartW;
    const w = Math.max(x1 - x0, 6); // minimum 6px width so tiny tail bins remain visible
    return { x: x0, w, mid: x0 + w / 2 };
  });

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
            <text x={padLeft - 6} y={y + 3} textAnchor="end" className="fill-muted-foreground" fontSize={T.chartAxisTick}>
              {tick}
            </text>
          </g>
        );
      })}

      {/* Bars */}
      {visibleBins.map((bin, i) => {
        const { x, w, mid } = barLayouts[i];
        const gap = Math.min(w * 0.06, 2);
        const bw = w - gap * 2;
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
            {bin.count > 0 && barH > 18 && bw > 14 && (
              <text x={mid} y={padTop + chartH - barH + 14} textAnchor="middle" className="fill-foreground" fontSize={T.chartLabel} fontFamily="monospace" fontWeight={500}>
                {bin.count}
              </text>
            )}
            {bin.count > 0 && ((barH > 0 && barH <= 18) || bw <= 14) && (
              <text x={mid} y={padTop + chartH - barH - 4} textAnchor="middle" className="fill-foreground" fontSize={T.chartAxisTick} fontFamily="monospace">
                {bin.count}
              </text>
            )}
            {bw > 20 && (visibleBins.length <= 12 || i % Math.max(1, Math.floor(visibleBins.length / 8)) === 0 || i === visibleBins.length - 1) && (
              <text x={mid} y={vh - padBottom + 16} textAnchor="middle" className="fill-muted-foreground" fontSize={T.chartAxisTick} fontFamily="monospace">
                {bin.min}
              </text>
            )}
          </g>
        );
      })}

      {/* Threshold line — sqrt-scaled position */}
      {(() => {
        const thresholdScaled = xScale(threshold);
        const thresholdX = padLeft + ((thresholdScaled - scaledGlobalMin) / scaledGlobalRange) * chartW;
        // Clamp to chart area
        if (threshold < globalMin) {
          return <line x1={padLeft} y1={padTop} x2={padLeft} y2={padTop + chartH} stroke="#eab308" strokeWidth={2} strokeDasharray="6,4" opacity={0.9} />;
        }
        if (threshold > globalMax) {
          return <line x1={padLeft + chartW} y1={padTop} x2={padLeft + chartW} y2={padTop + chartH} stroke="#eab308" strokeWidth={2} strokeDasharray="6,4" opacity={0.9} />;
        }
        return <line x1={thresholdX} y1={padTop} x2={thresholdX} y2={padTop + chartH} stroke="#eab308" strokeWidth={2} strokeDasharray="6,4" opacity={0.9} />;
      })()}

      {/* Y-axis label */}
      <text x={4} y={padTop + chartH / 2} className="fill-muted-foreground" fontSize={T.chartLabel} transform={`rotate(-90, 10, ${padTop + chartH / 2})`} textAnchor="middle">
        clients
      </text>
      {/* X-axis label */}
      <text x={padLeft + chartW / 2} y={vh - 4} textAnchor="middle" className="fill-muted-foreground" fontSize={T.chartLabel}>
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
  const clipId = useId();
  if (!curve || curve.length < 2) return null;

  const vw = 720;
  const vh = 240;
  const padLeft = 63;
  const padRight = 16;
  const padTop = 12;
  const padBottom = 50;
  const chartW = vw - padLeft - padRight;
  const chartH = vh - padTop - padBottom;
  const fullMinT = curve[0].threshold;
  const fullMaxT = curve[curve.length - 1].threshold;
  const fullRange = fullMaxT - fullMinT || 1;

  // Use sqrt scale when range is wide (>10x) to compress outlier tail
  const useSqrt = fullRange > 0 && fullMaxT / Math.max(fullMinT, 1) > 10;
  const toScale = (v: number) => useSqrt ? Math.sqrt(v) : v;
  const fromScale = (v: number) => useSqrt ? v * v : v;
  const scaledMin = toScale(fullMinT);
  const scaledMax = toScale(fullMaxT);
  const scaledRange = scaledMax - scaledMin || 1;

  const zoom = useSvgDragZoom(padLeft, chartW);

  // Compute zoomed domain (in scaled space)
  const zScaledMin = zoom.isZoomed ? scaledMin + zoom.state.zoomFracLeft! * scaledRange : scaledMin;
  const zScaledMax = zoom.isZoomed ? scaledMin + zoom.state.zoomFracRight! * scaledRange : scaledMax;
  const zScaledRange = zScaledMax - zScaledMin || 1;
  // Convert back to linear for filtering
  const zMinT = fromScale(zScaledMin);
  const zMaxT = fromScale(zScaledMax);

  // Filter points within zoomed domain (with a small margin for line continuity)
  const margin = (zMaxT - zMinT) * 0.02;
  const visibleCurve = curve.filter((p) => p.threshold >= zMinT - margin && p.threshold <= zMaxT + margin);

  const clientLine = visibleCurve.map((p, i) => {
    const x = padLeft + ((toScale(p.threshold) - zScaledMin) / zScaledRange) * chartW;
    const y = padTop + (1 - p.client_pct) * chartH;
    return `${i === 0 ? "M" : "L"}${x},${y}`;
  }).join(" ");

  const requestLine = visibleCurve.map((p, i) => {
    const x = padLeft + ((toScale(p.threshold) - zScaledMin) / zScaledRange) * chartW;
    const y = padTop + (1 - p.request_pct) * chartH;
    return `${i === 0 ? "M" : "L"}${x},${y}`;
  }).join(" ");

  const thresholdX = padLeft + ((toScale(threshold) - zScaledMin) / zScaledRange) * chartW;
  const showThreshold = threshold >= zMinT && threshold <= zMaxT;

  return (
    <div className="relative">
      {zoom.isZoomed && <ResetZoomButton onClick={zoom.resetZoom} />}
      <svg
        ref={zoom.svgRef}
        viewBox={`0 0 ${vw} ${vh}`}
        className="w-full h-auto select-none"
        preserveAspectRatio="xMidYMid meet"
        onMouseDown={zoom.onMouseDown}
        onMouseMove={zoom.onMouseMove}
        onMouseUp={zoom.onMouseUp}
        onMouseLeave={zoom.onMouseUp}
        onDoubleClick={zoom.onDoubleClick}
      >
        {/* Clip path for chart area */}
        <defs>
          <clipPath id={clipId}>
            <rect x={padLeft} y={padTop} width={chartW} height={chartH} />
          </clipPath>
        </defs>

        {/* Gridlines */}
        {[0.25, 0.5, 0.75].map((frac) => {
          const y = padTop + (1 - frac) * chartH;
          return <line key={frac} x1={padLeft} y1={y} x2={padLeft + chartW} y2={y} stroke="currentColor" strokeOpacity={0.06} />;
        })}

        <g clipPath={`url(#${clipId})`}>
          <path d={clientLine} fill="none" stroke="#22d3ee" strokeWidth={2} opacity={0.9} />
          <path d={requestLine} fill="none" stroke="#f472b6" strokeWidth={2} opacity={0.9} strokeDasharray="5,3" />

          {/* Threshold line */}
          {showThreshold && (
            <line x1={thresholdX} y1={padTop} x2={thresholdX} y2={padTop + chartH} stroke="#eab308" strokeWidth={1.5} strokeDasharray="4,3" opacity={0.8} />
          )}
        </g>

        {/* Selection overlay */}
        <SelectionOverlay state={zoom.state} padLeft={padLeft} padTop={padTop} chartW={chartW} chartH={chartH} />

        {/* Y-axis labels */}
        <text x={padLeft - 4} y={padTop + 4} textAnchor="end" className="fill-muted-foreground" fontSize={T.chartAxisTick}>100%</text>
        <text x={padLeft - 4} y={padTop + chartH / 2 + 3} textAnchor="end" className="fill-muted-foreground" fontSize={T.chartAxisTick}>50%</text>
        <text x={padLeft - 4} y={padTop + chartH + 4} textAnchor="end" className="fill-muted-foreground" fontSize={T.chartAxisTick}>0%</text>

        {/* X-axis tick labels — zoomed domain (sqrt-aware) */}
        {[0, 0.25, 0.5, 0.75, 1].map((frac) => {
          const scaledVal = zScaledMin + frac * zScaledRange;
          const val = fromScale(scaledVal);
          const x = padLeft + frac * chartW;
          return (
            <text key={frac} x={x} y={vh - padBottom + 16} textAnchor="middle" className="fill-muted-foreground" fontSize={T.chartAxisTick} fontFamily="monospace">
              {Math.round(val)}
            </text>
          );
        })}

        {/* Legend */}
        <line x1={padLeft + 12} y1={vh - 10} x2={padLeft + 34} y2={vh - 10} stroke="#22d3ee" strokeWidth={2} />
        <text x={padLeft + 40} y={vh - 6} className="fill-muted-foreground" fontSize={T.chartAxisTick}>Clients</text>
        <line x1={padLeft + 120} y1={vh - 10} x2={padLeft + 142} y2={vh - 10} stroke="#f472b6" strokeWidth={2} strokeDasharray="4,2" />
        <text x={padLeft + 148} y={vh - 6} className="fill-muted-foreground" fontSize={T.chartAxisTick}>Requests</text>
      </svg>
    </div>
  );
}

// ─── SVG Time-of-Day Baseline Chart ─────────────────────────────────

export function TimeOfDayChart({
  baselines,
}: {
  baselines: TimeOfDayBaseline[];
}) {
  const clipId = useId();
  if (!baselines || baselines.length < 2) return null;

  // Wide viewBox so that font-size 10 renders small relative to chart area
  const vw = 1400;
  const vh = 320;
  const padLeft = 62;
  const padRight = 14;
  const padBottom = 36;
  const padTop = 12;
  const chartW = vw - padLeft - padRight;
  const chartH = vh - padBottom - padTop;

  const zoom = useSvgDragZoom(padLeft, chartW);

  // Compute zoomed hour range [0–24]
  const zHourMin = zoom.isZoomed ? zoom.state.zoomFracLeft! * 24 : 0;
  const zHourMax = zoom.isZoomed ? zoom.state.zoomFracRight! * 24 : 24;
  const zHourRange = zHourMax - zHourMin || 24;

  // Filter baselines to visible range and recompute Y-axis from visible data
  const visibleBaselines = baselines.filter((b) => b.hour >= Math.floor(zHourMin) && b.hour < Math.ceil(zHourMax));
  const maxRPS = Math.max(...(visibleBaselines.length > 0 ? visibleBaselines : baselines).map((b) => b.p95_rps), 0.001);
  const barW = chartW / zHourRange;

  const ticks = niceYTicks(maxRPS, 4);
  const niceMax = ticks.length > 0 ? ticks[ticks.length - 1] : maxRPS;

  // Format tick: strip trailing zeros (e.g. "0.50" → "0.5", "1.0" → "1")
  const fmtTick = (v: number) => {
    if (v === 0) return "0";
    if (v >= 1 && v === Math.floor(v)) return String(v);
    // Use enough decimals, then strip trailing zeros
    const s = v < 0.01 ? v.toFixed(4) : v < 0.1 ? v.toFixed(3) : v.toFixed(2);
    return s.replace(/\.?0+$/, "");
  };

  // Determine which hours to label on X-axis (adaptive spacing)
  const visibleHours = Math.ceil(zHourMax) - Math.floor(zHourMin);
  const labelEvery = visibleHours <= 6 ? 1 : visibleHours <= 12 ? 2 : 3;

  return (
    <div className="relative">
      {zoom.isZoomed && <ResetZoomButton onClick={zoom.resetZoom} />}
      <svg
        ref={zoom.svgRef}
        viewBox={`0 0 ${vw} ${vh}`}
        className="w-full h-auto select-none"
        preserveAspectRatio="xMidYMid meet"
        onMouseDown={zoom.onMouseDown}
        onMouseMove={zoom.onMouseMove}
        onMouseUp={zoom.onMouseUp}
        onMouseLeave={zoom.onMouseUp}
        onDoubleClick={zoom.onDoubleClick}
      >
        {/* Clip path for chart area */}
        <defs>
          <clipPath id={clipId}>
          <rect x={padLeft} y={padTop} width={chartW} height={chartH} />
        </clipPath>
      </defs>

      {/* Y-axis gridlines */}
      {ticks.map((tick) => {
        const y = padTop + chartH - (tick / niceMax) * chartH;
        return (
          <g key={tick}>
            <line x1={padLeft} y1={y} x2={vw - padRight} y2={y} stroke="currentColor" strokeOpacity={0.06} />
            <text x={padLeft - 6} y={y + 3} textAnchor="end" className="fill-muted-foreground" fontSize={9} fontFamily="monospace">
              {fmtTick(tick)}
            </text>
          </g>
        );
      })}

      {/* Bars for visible hours (clipped to chart area) */}
      <g clipPath={`url(#${clipId})`}>
        {Array.from({ length: 24 }, (_, hour) => {
          const x = padLeft + ((hour - zHourMin) / zHourRange) * chartW;
          if (x + barW < padLeft || x > padLeft + chartW) return null;

          const baseline = baselines.find((b) => b.hour === hour);
          if (!baseline) return null;
          const gap = Math.min(barW * 0.08, 2);
          const bw = barW - gap * 2;
          const rawMedH = (baseline.median_rps / niceMax) * chartH;
          const rawP95H = (baseline.p95_rps / niceMax) * chartH;
          const medH = baseline.median_rps > 0 ? Math.max(rawMedH, 3) : 0;
          const p95H = baseline.p95_rps > 0 ? Math.max(rawP95H, 3) : 0;
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
            </g>
          );
        })}
      </g>

      {/* X-axis hour labels (outside clip group so they're visible) */}
      {Array.from({ length: 24 }, (_, hour) => {
        const x = padLeft + ((hour - zHourMin) / zHourRange) * chartW;
        if (x + barW < padLeft || x > padLeft + chartW) return null;
        if ((hour - Math.floor(zHourMin)) % labelEvery !== 0) return null;
        const hasData = baselines.some((b) => b.hour === hour);
        return (
          <text key={hour} x={x + barW / 2} y={vh - padBottom + 14} textAnchor="middle" className={hasData ? "fill-muted-foreground" : "fill-muted-foreground/40"} fontSize={9} fontFamily="monospace">
            {String(hour).padStart(2, "0")}
          </text>
        );
      })}

      {/* Selection overlay */}
      <SelectionOverlay state={zoom.state} padLeft={padLeft} padTop={padTop} chartW={chartW} chartH={chartH} />

      {/* Baseline */}
      <line x1={padLeft} y1={padTop + chartH} x2={padLeft + chartW} y2={padTop + chartH} stroke="currentColor" strokeOpacity={0.15} />

      {/* Y-axis label */}
      <text x={6} y={padTop + chartH / 2} className="fill-muted-foreground" fontSize={9} transform={`rotate(-90, 10, ${padTop + chartH / 2})`} textAnchor="middle">
        req/s
      </text>
      <text x={padLeft - 6} y={padTop + chartH + 4} textAnchor="end" className="fill-muted-foreground" fontSize={9} fontFamily="monospace">0</text>

    </svg>
    </div>
  );
}

// ─── Inline SVG Sparkline ────────────────────────────────────────────

export function Sparkline({ data, width = 80, height = 24, color = "#79e6f3" }: {
  data: number[];
  width?: number;
  height?: number;
  color?: string;
}) {
  if (!data || data.length === 0 || data.every((v) => v === 0)) {
    return (
      <span className="text-xs text-muted-foreground/50">—</span>
    );
  }
  const max = Math.max(...data, 1);
  const padding = 1;
  const innerW = width - padding * 2;
  const innerH = height - padding * 2;
  const step = innerW / Math.max(data.length - 1, 1);

  const points = data.map((v, i) => {
    const x = padding + i * step;
    const y = padding + innerH - (v / max) * innerH;
    return `${x},${y}`;
  });

  // Fill area path (close at bottom)
  const firstX = padding;
  const lastX = padding + (data.length - 1) * step;
  const fillPath = `M${firstX},${padding + innerH} L${points.join(" L")} L${lastX},${padding + innerH} Z`;

  return (
    <svg width={width} height={height} className="inline-block">
      <path d={fillPath} fill={color} fillOpacity={0.15} />
      <polyline
        points={points.join(" ")}
        fill="none"
        stroke={color}
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

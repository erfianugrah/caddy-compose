import { useState, useEffect, useRef, useCallback } from "react";
import { Clock, RefreshCw, ChevronDown } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";

// ─── Types ──────────────────────────────────────────────────────────

export interface RelativeRange {
  label: string;
  hours: number;
}

export interface AbsoluteRange {
  start: string; // ISO 8601
  end: string;   // ISO 8601
}

export type TimeRange =
  | { type: "relative"; hours: number; label: string }
  | { type: "absolute"; start: string; end: string };

export interface TimeRangePickerProps {
  value: TimeRange;
  onChange: (range: TimeRange) => void;
  /** Called on each auto-refresh tick and when refresh button is clicked */
  onRefresh: () => void;
}

// ─── Constants ──────────────────────────────────────────────────────

const QUICK_RANGES: RelativeRange[] = [
  { label: "Last 5 minutes", hours: 0 },   // special: 5m = 5/60 hours
  { label: "Last 15 minutes", hours: 0 },
  { label: "Last 30 minutes", hours: 0 },
  { label: "Last 1 hour", hours: 1 },
  { label: "Last 3 hours", hours: 0 },
  { label: "Last 6 hours", hours: 6 },
  { label: "Last 12 hours", hours: 0 },
  { label: "Last 24 hours", hours: 24 },
  { label: "Last 2 days", hours: 0 },
  { label: "Last 7 days", hours: 168 },
  { label: "Last 30 days", hours: 0 },
];

// Map labels to actual minutes for the API (since Go backend only supports certain hours values,
// we'll use start/end for non-standard ranges)
const RANGE_MINUTES: Record<string, number> = {
  "Last 5 minutes": 5,
  "Last 15 minutes": 15,
  "Last 30 minutes": 30,
  "Last 1 hour": 60,
  "Last 3 hours": 180,
  "Last 6 hours": 360,
  "Last 12 hours": 720,
  "Last 24 hours": 1440,
  "Last 2 days": 2880,
  "Last 7 days": 10080,
  "Last 30 days": 43200,
};

// Which ranges map cleanly to the Go backend's validHours allowlist
const VALID_HOURS: Record<number, boolean> = {
  1: true,
  6: true,
  24: true,
  72: true,
  168: true,
};

const AUTO_REFRESH_OPTIONS = [
  { label: "Off", seconds: 0 },
  { label: "5s", seconds: 5 },
  { label: "10s", seconds: 10 },
  { label: "30s", seconds: 30 },
  { label: "1m", seconds: 60 },
  { label: "5m", seconds: 300 },
  { label: "15m", seconds: 900 },
];

// ─── Helpers ────────────────────────────────────────────────────────

function formatRangeLabel(range: TimeRange): string {
  if (range.type === "relative") return range.label;
  const start = new Date(range.start);
  const end = new Date(range.end);
  const fmt = (d: Date) =>
    d.toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  return `${fmt(start)} - ${fmt(end)}`;
}

function toLocalDatetimeString(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

/** Convert a relative range into API params (hours or start/end). */
export function rangeToParams(range: TimeRange): {
  hours?: number;
  start?: string;
  end?: string;
} {
  if (range.type === "absolute") {
    return { start: range.start, end: range.end };
  }

  // Check if this maps to a valid Go backend hours value
  if (VALID_HOURS[range.hours]) {
    return { hours: range.hours };
  }

  // Otherwise compute start/end from minutes
  const minutes = RANGE_MINUTES[range.label] ?? range.hours * 60;
  const end = new Date();
  const start = new Date(end.getTime() - minutes * 60 * 1000);
  return {
    start: start.toISOString(),
    end: end.toISOString(),
  };
}

// ─── Component ──────────────────────────────────────────────────────

export default function TimeRangePicker({
  value,
  onChange,
  onRefresh,
}: TimeRangePickerProps) {
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState<"quick" | "custom">("quick");
  const [autoRefresh, setAutoRefresh] = useState(0); // seconds, 0 = off
  const [refreshMenuOpen, setRefreshMenuOpen] = useState(false);

  // Custom range inputs
  const now = new Date();
  const defaultStart = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const [customFrom, setCustomFrom] = useState(toLocalDatetimeString(defaultStart));
  const [customTo, setCustomTo] = useState(toLocalDatetimeString(now));

  // Auto-refresh timer
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    if (autoRefresh > 0) {
      intervalRef.current = setInterval(onRefresh, autoRefresh * 1000);
    }
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [autoRefresh, onRefresh]);

  const handleQuickRange = useCallback(
    (label: string) => {
      const minutes = RANGE_MINUTES[label] ?? 1440;
      const hours = minutes / 60;
      // Find the closest valid hours value or use 0 to signal start/end
      const validHour = VALID_HOURS[hours] ? hours : 0;
      onChange({
        type: "relative",
        hours: validHour || hours,
        label,
      });
      setOpen(false);
    },
    [onChange]
  );

  const handleCustomApply = useCallback(() => {
    const start = new Date(customFrom);
    const end = new Date(customTo);
    if (isNaN(start.getTime()) || isNaN(end.getTime())) return;
    if (start >= end) return;
    onChange({
      type: "absolute",
      start: start.toISOString(),
      end: end.toISOString(),
    });
    setOpen(false);
  }, [customFrom, customTo, onChange]);

  return (
    <div className="flex items-center gap-1">
      {/* Main time range popover */}
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button
            variant="outline"
            size="sm"
            className="h-8 gap-1.5 text-xs font-normal"
          >
            <Clock className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="max-w-[220px] truncate">
              {formatRangeLabel(value)}
            </span>
            <ChevronDown className="h-3 w-3 text-muted-foreground" />
          </Button>
        </PopoverTrigger>
        <PopoverContent
          align="end"
          className="w-[440px] p-0"
          sideOffset={8}
        >
          {/* Tabs */}
          <div className="flex border-b border-border">
            <button
              className={`flex-1 px-4 py-2 text-xs font-medium transition-colors ${
                tab === "quick"
                  ? "border-b-2 border-neon-cyan text-neon-cyan"
                  : "text-muted-foreground hover:text-foreground"
              }`}
              onClick={() => setTab("quick")}
            >
              Quick ranges
            </button>
            <button
              className={`flex-1 px-4 py-2 text-xs font-medium transition-colors ${
                tab === "custom"
                  ? "border-b-2 border-neon-cyan text-neon-cyan"
                  : "text-muted-foreground hover:text-foreground"
              }`}
              onClick={() => setTab("custom")}
            >
              Custom range
            </button>
          </div>

          {tab === "quick" ? (
            <div className="grid grid-cols-2 gap-0.5 p-2">
              {QUICK_RANGES.map((r) => (
                <button
                  key={r.label}
                  className={`rounded px-3 py-1.5 text-left text-xs transition-colors hover:bg-accent ${
                    value.type === "relative" && value.label === r.label
                      ? "bg-accent text-neon-cyan"
                      : "text-foreground"
                  }`}
                  onClick={() => handleQuickRange(r.label)}
                >
                  {r.label}
                </button>
              ))}
            </div>
          ) : (
            <div className="space-y-3 p-4">
              <div className="space-y-1.5">
                <Label className="text-xs text-muted-foreground">From</Label>
                <Input
                  type="datetime-local"
                  step="1"
                  value={customFrom}
                  onChange={(e) => setCustomFrom(e.target.value)}
                  className="h-8 text-xs font-mono"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs text-muted-foreground">To</Label>
                <Input
                  type="datetime-local"
                  step="1"
                  value={customTo}
                  onChange={(e) => setCustomTo(e.target.value)}
                  className="h-8 text-xs font-mono"
                />
              </div>
              <Button
                size="sm"
                className="w-full h-8 text-xs"
                onClick={handleCustomApply}
              >
                Apply time range
              </Button>
            </div>
          )}
        </PopoverContent>
      </Popover>

      {/* Refresh button */}
      <Button
        variant="outline"
        size="icon"
        className="h-8 w-8"
        onClick={onRefresh}
        title="Refresh"
      >
        <RefreshCw className={`h-3.5 w-3.5 ${autoRefresh > 0 ? "animate-spin text-neon-cyan" : ""}`} style={autoRefresh > 0 ? { animationDuration: "3s" } : undefined} />
      </Button>

      {/* Auto-refresh interval dropdown */}
      <Popover open={refreshMenuOpen} onOpenChange={setRefreshMenuOpen}>
        <PopoverTrigger asChild>
          <Button
            variant="outline"
            size="sm"
            className="h-8 gap-1 text-xs font-normal px-2"
          >
            <span className={autoRefresh > 0 ? "text-neon-cyan" : "text-muted-foreground"}>
              {autoRefresh > 0
                ? AUTO_REFRESH_OPTIONS.find((o) => o.seconds === autoRefresh)
                    ?.label ?? `${autoRefresh}s`
                : "Auto"}
            </span>
            <ChevronDown className="h-3 w-3 text-muted-foreground" />
          </Button>
        </PopoverTrigger>
        <PopoverContent align="end" className="w-28 p-1" sideOffset={8}>
          {AUTO_REFRESH_OPTIONS.map((opt) => (
            <button
              key={opt.seconds}
              className={`w-full rounded px-3 py-1.5 text-left text-xs transition-colors hover:bg-accent ${
                autoRefresh === opt.seconds
                  ? "bg-accent text-neon-cyan"
                  : "text-foreground"
              }`}
              onClick={() => {
                setAutoRefresh(opt.seconds);
                setRefreshMenuOpen(false);
              }}
            >
              {opt.label}
            </button>
          ))}
        </PopoverContent>
      </Popover>
    </div>
  );
}

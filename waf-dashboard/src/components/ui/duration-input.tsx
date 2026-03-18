import { useState, useEffect, useCallback } from "react";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

// ─── DurationInput ──────────────────────────────────────────────────
//
// Structured duration input: number + unit dropdown.
// Emits a Go-compatible duration string ("60s", "24h", "7d").
// Supports presets and a "custom" option for arbitrary values.

const UNITS = [
  { value: "s", label: "seconds" },
  { value: "m", label: "minutes" },
  { value: "h", label: "hours" },
  { value: "d", label: "days" },
  { value: "w", label: "weeks" },
] as const;

type Unit = (typeof UNITS)[number]["value"];

/** Parse a duration string like "60s", "24h", "7d" into {number, unit}. */
function parseDuration(s: string): { num: number; unit: Unit } | null {
  if (!s) return null;
  const match = s.match(/^(\d+(?:\.\d+)?)\s*(s|m|h|d|w)$/);
  if (match) {
    return { num: parseFloat(match[1]), unit: match[2] as Unit };
  }
  return null;
}

interface DurationInputProps {
  value: string;
  onChange: (value: string) => void;
  presets?: string[];
  className?: string;
}

export function DurationInput({
  value,
  onChange,
  presets,
  className,
}: DurationInputProps) {
  const parsed = parseDuration(value);
  const [num, setNum] = useState(parsed?.num ?? 60);
  const [unit, setUnit] = useState<Unit>(parsed?.unit ?? "s");
  const [isCustom, setIsCustom] = useState(!parsed);
  const [customValue, setCustomValue] = useState(!parsed ? value : "");

  // Sync from external value changes (e.g., API load)
  useEffect(() => {
    const p = parseDuration(value);
    if (p) {
      setNum(p.num);
      setUnit(p.unit);
      setIsCustom(false);
    } else if (value) {
      setIsCustom(true);
      setCustomValue(value);
    }
  }, [value]);

  const emitChange = useCallback(
    (n: number, u: Unit) => {
      // Clean: no trailing zeros for integers
      const str = Number.isInteger(n) ? `${n}${u}` : `${n}${u}`;
      onChange(str);
    },
    [onChange],
  );

  if (isCustom) {
    return (
      <div className={`flex gap-2 ${className ?? ""}`}>
        <Input
          value={customValue}
          onChange={(e) => {
            setCustomValue(e.target.value);
            onChange(e.target.value);
          }}
          placeholder="e.g. 2h30m"
          className="flex-1 font-mono text-sm"
        />
        <Select
          value="custom"
          onValueChange={(v) => {
            if (v !== "custom") {
              setIsCustom(false);
              setUnit(v as Unit);
              emitChange(num, v as Unit);
            }
          }}
        >
          <SelectTrigger className="w-[110px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {UNITS.map((u) => (
              <SelectItem key={u.value} value={u.value}>
                {u.label}
              </SelectItem>
            ))}
            <SelectItem value="custom">custom</SelectItem>
          </SelectContent>
        </Select>
      </div>
    );
  }

  return (
    <div className={`flex gap-2 ${className ?? ""}`}>
      {presets && presets.length > 0 ? (
        <Select
          value={value}
          onValueChange={(v) => {
            if (v === "__custom__") {
              setIsCustom(true);
              setCustomValue(value);
            } else {
              const p = parseDuration(v);
              if (p) {
                setNum(p.num);
                setUnit(p.unit);
              }
              onChange(v);
            }
          }}
        >
          <SelectTrigger className="flex-1">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {presets.map((p) => (
              <SelectItem key={p} value={p}>
                {p}
              </SelectItem>
            ))}
            <SelectItem value="__custom__">Custom...</SelectItem>
          </SelectContent>
        </Select>
      ) : (
        <>
          <Input
            type="number"
            min={0}
            step={1}
            value={num}
            onChange={(e) => {
              const n = parseFloat(e.target.value) || 0;
              setNum(n);
              emitChange(n, unit);
            }}
            className="flex-1 font-mono text-sm"
          />
          <Select
            value={unit}
            onValueChange={(v) => {
              if (v === "custom") {
                setIsCustom(true);
                setCustomValue(`${num}${unit}`);
              } else {
                setUnit(v as Unit);
                emitChange(num, v as Unit);
              }
            }}
          >
            <SelectTrigger className="w-[110px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {UNITS.map((u) => (
                <SelectItem key={u.value} value={u.value}>
                  {u.label}
                </SelectItem>
              ))}
              <SelectItem value="custom">custom</SelectItem>
            </SelectContent>
          </Select>
        </>
      )}
    </div>
  );
}

import { useState, useEffect, useRef } from "react";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { CSP_SOURCES, SOURCE_CATEGORY_LABELS } from "./constants";

/**
 * Tag/pill input with a dropdown of CSP source keywords + free text entry.
 * Similar to PipeTagInput but with a keyword popover.
 */
export function CSPSourceInput({
  values,
  onChange,
  placeholder,
}: {
  values: string[];
  onChange: (values: string[]) => void;
  placeholder?: string;
}) {
  const [inputValue, setInputValue] = useState("");
  const [showDropdown, setShowDropdown] = useState(false);
  const wrapperRef = useRef<HTMLDivElement>(null);

  const addValue = (raw: string) => {
    const cleaned = raw.trim();
    if (!cleaned || values.includes(cleaned)) {
      setInputValue("");
      return;
    }
    onChange([...values, cleaned]);
    setInputValue("");
  };

  const removeValue = (val: string) => {
    onChange(values.filter((v) => v !== val));
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      addValue(inputValue);
    } else if (e.key === "Backspace" && inputValue === "" && values.length > 0) {
      removeValue(values[values.length - 1]);
    } else if (e.key === "Escape") {
      setShowDropdown(false);
    }
  };

  const handlePaste = (e: React.ClipboardEvent) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData("text");
    const newVals = pasted.split(/[\s,]+/).filter(Boolean);
    const unique = [...new Set([...values, ...newVals])];
    onChange(unique);
  };

  // Close dropdown on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (wrapperRef.current && !wrapperRef.current.contains(e.target as Node)) {
        setShowDropdown(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const unusedSources = CSP_SOURCES.filter((s) => !values.includes(s.value));
  const filtered = inputValue
    ? unusedSources.filter((s) =>
        s.value.toLowerCase().includes(inputValue.toLowerCase()) ||
        s.desc.toLowerCase().includes(inputValue.toLowerCase()))
    : unusedSources;

  // Group filtered sources by category
  const grouped = (["keyword", "scheme", "special"] as const)
    .map((cat) => ({ cat, items: filtered.filter((s) => s.category === cat) }))
    .filter((g) => g.items.length > 0);

  return (
    <div ref={wrapperRef} className="relative">
      <div className="flex flex-wrap items-center gap-1.5 rounded-md border border-input bg-background px-2 py-1.5 text-sm focus-within:ring-1 focus-within:ring-ring min-h-[36px]">
        {values.map((val) => {
          const def = CSP_SOURCES.find((s) => s.value === val);
          const pill = (
            <span
              key={val}
              className="inline-flex items-center gap-1 rounded bg-lovelace-800 border border-border px-2 py-0.5 text-xs font-data text-lv-cyan"
            >
              {val}
              <button
                type="button"
                onClick={() => removeValue(val)}
                className="ml-0.5 rounded-full p-0.5 hover:bg-accent hover:text-lv-red"
              >
                <span className="sr-only">Remove</span>
                <svg className="h-2.5 w-2.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </span>
          );
          return def ? (
            <Tooltip key={val}>
              <TooltipTrigger asChild>{pill}</TooltipTrigger>
              <TooltipContent side="top" className="max-w-xs text-xs">{def.desc}</TooltipContent>
            </Tooltip>
          ) : pill;
        })}
        <input
          type="text"
          value={inputValue}
          onChange={(e) => {
            setInputValue(e.target.value);
            setShowDropdown(true);
          }}
          onFocus={() => setShowDropdown(true)}
          onKeyDown={handleKeyDown}
          onPaste={handlePaste}
          onBlur={() => {
            // Delay to allow dropdown click
            setTimeout(() => {
              if (inputValue.trim()) addValue(inputValue);
              setShowDropdown(false);
            }, 200);
          }}
          placeholder={values.length === 0 ? (placeholder ?? "Add source...") : ""}
          className="flex-1 min-w-[100px] bg-transparent text-xs font-data outline-none placeholder:text-muted-foreground"
        />
      </div>
      {showDropdown && grouped.length > 0 && (
        <div className="absolute z-50 mt-1 max-h-64 w-full overflow-auto rounded-md border border-border bg-lovelace-950 shadow-lg">
          {grouped.map(({ cat, items }) => (
            <div key={cat}>
              <div className="px-3 py-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground bg-lovelace-900/50 sticky top-0">
                {SOURCE_CATEGORY_LABELS[cat]}
              </div>
              {items.map((src) => (
                <button
                  key={src.value}
                  type="button"
                  onMouseDown={(e) => {
                    e.preventDefault();
                    addValue(src.value);
                    setShowDropdown(false);
                  }}
                  className="flex w-full items-start gap-3 px-3 py-1.5 text-xs hover:bg-accent cursor-pointer"
                >
                  <span className="font-data text-foreground shrink-0">{src.value}</span>
                  <span className="text-muted-foreground text-[10px] leading-tight">{src.desc}</span>
                </button>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

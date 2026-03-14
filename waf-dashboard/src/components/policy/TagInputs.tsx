import { useState, useEffect, useRef } from "react";
import { Plus, X, Check, Copy, Sparkles, ChevronDown } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { VALID_TRANSFORMS } from "@/lib/api";

// ─── Copy Button ────────────────────────────────────────────────────

export function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => { if (timerRef.current) clearTimeout(timerRef.current); }, []);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
    }
    setCopied(true);
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Button variant="ghost" size="sm" onClick={handleCopy}>
      {copied ? (
        <Check className="h-3.5 w-3.5 text-lv-green" />
      ) : (
        <Copy className="h-3.5 w-3.5" />
      )}
      <span className="text-xs">{copied ? "Copied" : label ?? "Copy"}</span>
    </Button>
  );
}

// ─── Rule ID Helpers ────────────────────────────────────────────────

/** Parse a space-separated rule ID string into an array of individual IDs. */
export function parseRuleIds(value: string): string[] {
  return value.split(/[\s,]+/).filter(Boolean);
}

/** Join rule ID array back into a space-separated string. */
export function joinRuleIds(ids: string[]): string {
  return ids.join(" ");
}

// ─── Rule ID Tag Input ──────────────────────────────────────────────

/**
 * Tag-style input for multiple rule IDs.
 * Stores value as a space-separated string (e.g. "942200 942370 920420").
 * Supports typing + Enter/comma/space to add, backspace to remove last, click X to remove individual.
 */
export function RuleIdTagInput({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}) {
  const [inputValue, setInputValue] = useState("");
  const ids = parseRuleIds(value);

  const addId = (raw: string) => {
    const cleaned = raw.trim().replace(/,/g, "");
    if (!cleaned) return;
    // Don't add duplicates
    if (ids.includes(cleaned)) {
      setInputValue("");
      return;
    }
    onChange(joinRuleIds([...ids, cleaned]));
    setInputValue("");
  };

  const removeId = (id: string) => {
    onChange(joinRuleIds(ids.filter((i) => i !== id)));
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" || e.key === "," || e.key === " ") {
      e.preventDefault();
      addId(inputValue);
    } else if (e.key === "Backspace" && inputValue === "" && ids.length > 0) {
      removeId(ids[ids.length - 1]);
    }
  };

  const handlePaste = (e: React.ClipboardEvent) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData("text");
    const newIds = pasted.split(/[\s,]+/).filter(Boolean);
    const unique = [...new Set([...ids, ...newIds])];
    onChange(joinRuleIds(unique));
  };

  return (
    <div className="flex flex-wrap items-center gap-1.5 rounded-md border border-input bg-background px-2 py-1.5 text-sm focus-within:ring-1 focus-within:ring-ring min-h-[36px]">
      {ids.map((id) => (
        <span
          key={id}
          className="inline-flex items-center gap-1 rounded bg-lovelace-800 border border-border px-2 py-0.5 text-xs font-data text-lv-cyan"
        >
          {id}
          <button
            onClick={() => removeId(id)}
            className="ml-0.5 rounded-full p-0.5 hover:bg-accent hover:text-lv-red"
          >
            <X className="h-2.5 w-2.5" />
          </button>
        </span>
      ))}
      <input
        type="text"
        value={inputValue}
        onChange={(e) => setInputValue(e.target.value)}
        onKeyDown={handleKeyDown}
        onPaste={handlePaste}
        onBlur={() => { if (inputValue.trim()) addId(inputValue); }}
        placeholder={ids.length === 0 ? (placeholder ?? "Type rule ID and press Enter") : ""}
        className="flex-1 min-w-[120px] bg-transparent text-xs font-data outline-none placeholder:text-muted-foreground"
      />
    </div>
  );
}

// ─── HTTP Method Multi-Select ───────────────────────────────────────

export const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] as const;

export function MethodMultiSelect({
  value,
  onChange,
  single = false,
}: {
  value: string;
  onChange: (value: string) => void;
  single?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const selected = value ? value.split("|").filter(Boolean) : [];

  const toggle = (method: string) => {
    if (single) {
      onChange(method);
      setOpen(false);
      return;
    }
    const next = selected.includes(method)
      ? selected.filter((m) => m !== method)
      : [...selected, method];
    const ordered = HTTP_METHODS.filter((m) => next.includes(m));
    onChange(ordered.join("|"));
  };

  const remove = (method: string) => {
    const next = selected.filter((m) => m !== method);
    onChange(next.join("|"));
  };

  const unselected = HTTP_METHODS.filter((m) => !selected.includes(m));

  return (
    <div className="flex flex-wrap items-center gap-1.5 rounded-md border border-input bg-background px-2 py-1.5 text-sm focus-within:ring-1 focus-within:ring-ring min-h-[36px] flex-1">
      {selected.map((method) => (
        <span
          key={method}
          className="inline-flex items-center gap-1 rounded bg-lovelace-800 border border-border px-2 py-0.5 text-xs font-data text-lv-cyan"
        >
          {method}
          <button
            onClick={() => remove(method)}
            className="ml-0.5 rounded-full p-0.5 hover:bg-accent hover:text-lv-red"
          >
            <X className="h-2.5 w-2.5" />
          </button>
        </span>
      ))}
      {unselected.length > 0 && (
        <Popover open={open} onOpenChange={setOpen}>
          <PopoverTrigger asChild>
            <button className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs text-muted-foreground hover:text-foreground hover:bg-accent">
              <Plus className="h-3 w-3" />
              {selected.length === 0 ? "Select methods" : "Add"}
            </button>
          </PopoverTrigger>
          <PopoverContent className="w-[160px] p-1" align="start">
            {unselected.map((method) => (
              <button
                key={method}
                onClick={() => { toggle(method); if (unselected.length <= 1) setOpen(false); }}
                className="flex w-full items-center rounded px-2 py-1.5 text-xs font-data cursor-pointer hover:bg-accent"
              >
                {method}
              </button>
            ))}
          </PopoverContent>
        </Popover>
      )}
    </div>
  );
}

// ─── Host / Service Multi-Select ────────────────────────────────────

export function HostMultiSelect({
  value,
  onChange,
  services,
}: {
  value: string;
  onChange: (value: string) => void;
  services: { service: string }[];
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const selected = value ? value.split("|").filter(Boolean) : [];
  const serviceNames = services.map((s) => s.service);

  const addHost = (host: string) => {
    if (!host || selected.includes(host)) return;
    onChange([...selected, host].join("|"));
  };

  const remove = (host: string) => {
    onChange(selected.filter((h) => h !== host).join("|"));
  };

  const addCustom = () => {
    const trimmed = search.trim();
    if (trimmed && !serviceNames.includes(trimmed)) {
      addHost(trimmed);
      setSearch("");
    }
  };

  const unselected = serviceNames.filter((s) => !selected.includes(s));
  const filtered = search
    ? unselected.filter((s) => s.toLowerCase().includes(search.toLowerCase()))
    : unselected;

  return (
    <div className="flex flex-wrap items-center gap-1.5 rounded-md border border-input bg-background px-2 py-1.5 text-sm focus-within:ring-1 focus-within:ring-ring min-h-[36px] flex-1">
      {selected.map((host) => (
        <span
          key={host}
          className="inline-flex items-center gap-1 rounded bg-lovelace-800 border border-border px-2 py-0.5 text-xs font-data text-lv-cyan"
        >
          {host}
          <button
            onClick={() => remove(host)}
            className="ml-0.5 rounded-full p-0.5 hover:bg-accent hover:text-lv-red"
          >
            <X className="h-2.5 w-2.5" />
          </button>
        </span>
      ))}
      <Popover open={open} onOpenChange={(v) => { setOpen(v); if (!v) setSearch(""); }}>
        <PopoverTrigger asChild>
          <button className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs text-muted-foreground hover:text-foreground hover:bg-accent">
            <Plus className="h-3 w-3" />
            {selected.length === 0 ? "Select hosts" : "Add"}
          </button>
        </PopoverTrigger>
        <PopoverContent className="w-[240px] p-1" align="start">
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                if (filtered.length === 1) { addHost(filtered[0]); setSearch(""); }
                else addCustom();
              }
            }}
            placeholder="Search or type custom..."
            className="w-full rounded px-2 py-1.5 mb-1 text-xs bg-transparent border border-border outline-none placeholder:text-muted-foreground focus:ring-1 focus:ring-ring"
            autoFocus
          />
          <div className="max-h-[200px] overflow-y-auto">
            {filtered.map((svc) => (
              <button
                key={svc}
                onClick={() => { addHost(svc); setSearch(""); if (unselected.length <= 1) setOpen(false); }}
                className="flex w-full items-center rounded px-2 py-1.5 text-xs font-data cursor-pointer hover:bg-accent"
              >
                {svc}
              </button>
            ))}
            {filtered.length === 0 && unselected.length > 0 && (
              <div className="px-2 py-1.5 text-xs text-muted-foreground">No matches</div>
            )}
          </div>
          {search.trim() && !serviceNames.includes(search.trim()) && (
            <>
              <div className="my-1 border-t border-border" />
              <button
                onClick={addCustom}
                className="flex w-full items-center gap-1 rounded px-2 py-1.5 text-xs cursor-pointer hover:bg-accent text-lv-cyan"
              >
                <Plus className="h-3 w-3" />
                Add &ldquo;{search.trim()}&rdquo;
              </button>
            </>
          )}
        </PopoverContent>
      </Popover>
    </div>
  );
}

// ─── Pipe-separated Tag Input ───────────────────────────────────────

export function PipeTagInput({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}) {
  const [inputValue, setInputValue] = useState("");
  const tags = value ? value.split("|").filter(Boolean) : [];

  const addTag = (raw: string) => {
    const cleaned = raw.trim().replace(/[,|]/g, "");
    if (!cleaned) return;
    if (tags.includes(cleaned)) {
      setInputValue("");
      return;
    }
    onChange([...tags, cleaned].join("|"));
    setInputValue("");
  };

  const removeTag = (tag: string) => {
    onChange(tags.filter((t) => t !== tag).join("|"));
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" || e.key === "," || e.key === "|") {
      e.preventDefault();
      addTag(inputValue);
    } else if (e.key === "Backspace" && inputValue === "" && tags.length > 0) {
      removeTag(tags[tags.length - 1]);
    }
  };

  const handlePaste = (e: React.ClipboardEvent) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData("text");
    const newTags = pasted.split(/[|,\s]+/).filter(Boolean);
    const unique = [...new Set([...tags, ...newTags])];
    onChange(unique.join("|"));
  };

  return (
    <div className="flex flex-wrap items-center gap-1.5 rounded-md border border-input bg-background px-2 py-1.5 text-sm focus-within:ring-1 focus-within:ring-ring min-h-[36px] flex-1">
      {tags.map((tag) => (
        <span
          key={tag}
          className="inline-flex items-center gap-1 rounded bg-lovelace-800 border border-border px-2 py-0.5 text-xs font-data text-lv-cyan"
        >
          {tag}
          <button
            onClick={() => removeTag(tag)}
            className="ml-0.5 rounded-full p-0.5 hover:bg-accent hover:text-lv-red"
          >
            <X className="h-2.5 w-2.5" />
          </button>
        </span>
      ))}
      <input
        type="text"
        value={inputValue}
        onChange={(e) => setInputValue(e.target.value)}
        onKeyDown={handleKeyDown}
        onPaste={handlePaste}
        onBlur={() => { if (inputValue.trim()) addTag(inputValue); }}
         placeholder={tags.length === 0 ? (placeholder ?? "Type value and press Enter") : ""}
        className="flex-1 min-w-[120px] bg-transparent text-xs font-data outline-none placeholder:text-muted-foreground"
      />
    </div>
  );
}

// ─── Transform Multi-Select ─────────────────────────────────────────

/** Transform metadata: name, description, and category grouping. */
const TRANSFORM_HINTS: Record<string, string> = {
  lowercase: "Convert to lowercase for case-insensitive matching",
  urlDecode: "Decode %XX percent-encoded sequences",
  urlDecodeUni: "Decode %uXXXX Unicode + %XX sequences",
  htmlEntityDecode: "Decode &amp; &#NN; &#xHH; HTML entities",
  normalizePath: "Collapse /../ /./ and // in paths",
  normalizePathWin: "Normalize paths + convert backslashes",
  removeNulls: "Strip null bytes (bypass evasion)",
  compressWhitespace: "Collapse runs of whitespace to single space",
  removeWhitespace: "Strip all whitespace characters",
  base64Decode: "Decode base64-encoded payloads",
  hexDecode: "Decode hex-encoded sequences (0xNN)",
  jsDecode: "Decode JavaScript escape sequences (\\uNNNN)",
  cssDecode: "Decode CSS escape sequences (\\NN)",
  utf8toUnicode: "Convert UTF-8 multibyte to \\uXXXX notation",
  removeComments: "Strip /* */ and <!-- --> comment blocks",
  trim: "Trim leading and trailing whitespace",
  length: "Replace value with its string length (numeric)",
};

/** Grouped transform layout for the popover picker. */
const TRANSFORM_GROUPS: { label: string; items: string[] }[] = [
  {
    label: "Normalization",
    items: ["lowercase", "normalizePath", "normalizePathWin", "compressWhitespace", "removeWhitespace", "removeNulls", "removeComments", "trim"],
  },
  {
    label: "Decoding",
    items: ["urlDecode", "urlDecodeUni", "htmlEntityDecode", "base64Decode", "hexDecode", "jsDecode", "cssDecode"],
  },
  {
    label: "Inspection",
    items: ["utf8toUnicode", "length"],
  },
];

/** Preset transform pipelines for common use cases. */
const TRANSFORM_PRESETS: { label: string; description: string; transforms: string[] }[] = [
  { label: "CRS Standard", description: "Common CRS decoding chain", transforms: ["lowercase", "urlDecode", "htmlEntityDecode", "removeNulls"] },
  { label: "Full Decode", description: "All decoding transforms", transforms: ["lowercase", "urlDecode", "urlDecodeUni", "htmlEntityDecode", "base64Decode", "hexDecode", "jsDecode"] },
  { label: "Normalize", description: "Whitespace + path cleanup", transforms: ["lowercase", "normalizePath", "compressWhitespace", "trim"] },
];

/** Popover contents — compact scrollable list matching Select dropdown style. */
function TransformPopoverContent({
  selected,
  onToggle,
  onApplyPreset,
}: {
  selected: string[];
  onToggle: (t: string) => void;
  onApplyPreset: (transforms: string[]) => void;
}) {
  return (
    <div className="w-[240px]">
      {/* Presets — compact row */}
      <div className="flex items-center gap-1 px-2 py-1.5 border-b border-border/30">
        {TRANSFORM_PRESETS.map((preset) => (
          <button
            key={preset.label}
            onClick={() => onApplyPreset(preset.transforms)}
            className="rounded px-2 py-0.5 text-[10px] text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
            title={preset.description}
          >
            {preset.label}
          </button>
        ))}
      </div>

      {/* Scrollable transform list */}
      <div className="max-h-[200px] overflow-y-auto py-1">
        {TRANSFORM_GROUPS.map((group) => (
          <div key={group.label}>
            <p className="text-[10px] uppercase tracking-wider text-muted-foreground/40 px-2 pt-1.5 pb-0.5">{group.label}</p>
            {group.items.map((t) => {
              const isSelected = selected.includes(t);
              return (
                <button
                  key={t}
                  onClick={() => onToggle(t)}
                  className={`flex w-full items-center justify-between px-2 py-1 text-xs cursor-pointer hover:bg-accent rounded-sm mx-1 ${
                    isSelected ? "text-lv-cyan" : "text-foreground"
                  }`}
                  style={{ width: "calc(100% - 8px)" }}
                >
                  <span className="font-data">{t}</span>
                  {isSelected && <Check className="h-3 w-3 shrink-0" />}
                </button>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * Popover-based multi-select for condition transforms.
 * Simple multi-select dropdown for transforms. Looks like the Field/Operator selects.
 */

// ─── Transform Select ──────────────────────────────────────────────

export function TransformSelect({
  value,
  onChange,
}: {
  value: string[];
  onChange: (value: string[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const selected = value ?? [];

  const toggle = (t: string) => {
    if (selected.includes(t)) {
      onChange(selected.filter((s) => s !== t));
    } else {
      onChange([...selected, t]);
    }
  };

  // Trigger text
  const label = selected.length === 0
    ? "No transforms"
    : selected.length <= 2
      ? selected.join(" → ")
      : `${selected.length} transforms`;

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          className={`inline-flex items-center justify-between gap-1 rounded-md border h-9 px-3 text-xs w-[160px] shrink-0 transition-colors ${
            selected.length > 0
              ? "border-lv-cyan/30 text-lv-cyan"
              : "border-border text-muted-foreground"
          }`}
        >
          <span className="truncate font-data">{label}</span>
          <ChevronDown className="h-3.5 w-3.5 shrink-0 opacity-50" />
        </button>
      </PopoverTrigger>
      <PopoverContent className="p-0" align="start" sideOffset={4}>
        <TransformPopoverContent selected={selected} onToggle={toggle} onApplyPreset={(t) => onChange(t)} />
      </PopoverContent>
    </Popover>
  );
}

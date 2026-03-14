import { useState, useEffect, useRef } from "react";
import { Plus, X, Check, Copy, Sparkles, GripVertical, ChevronDown } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { VALID_TRANSFORMS } from "@/lib/api";
import {
  DndContext,
  closestCenter,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent,
} from "@dnd-kit/core";
import {
  arrayMove,
  SortableContext,
  horizontalListSortingStrategy,
  useSortable,
  sortableKeyboardCoordinates,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";

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
}: {
  value: string;
  onChange: (value: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const selected = value ? value.split("|").filter(Boolean) : [];

  const toggle = (method: string) => {
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
 * Displays selected transforms as a numbered pipeline with arrows.
 * Values stored as string[] (order matters — applied left-to-right).
 */
// ─── Sortable Transform Chip ────────────────────────────────────────

function SortableTransformChip({
  id,
  index,
  onRemove,
}: {
  id: string;
  index: number;
  onRemove: (t: string) => void;
}) {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id });

  const style: React.CSSProperties = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.5 : undefined,
    zIndex: isDragging ? 10 : undefined,
  };

  return (
    <span
      ref={setNodeRef}
      style={style}
      className="inline-flex items-center gap-0.5 rounded-md border border-lv-cyan/20 bg-lv-cyan/5 px-1.5 py-0.5 text-[11px] font-data text-lv-cyan select-none"
      {...attributes}
    >
      <button
        className="cursor-grab active:cursor-grabbing p-0 text-lv-cyan/30 hover:text-lv-cyan/60 touch-none"
        {...listeners}
        tabIndex={-1}
      >
        <GripVertical className="h-2.5 w-2.5" />
      </button>
      <span className="text-lv-cyan/40 text-[9px]">{index + 1}.</span>
      {id}
      <button
        onClick={() => onRemove(id)}
        className="ml-0.5 rounded-full p-0.5 text-lv-cyan/40 hover:bg-lv-red/20 hover:text-lv-red"
      >
        <X className="h-2 w-2" />
      </button>
    </span>
  );
}

// ─── Transform Select (collapsible sub-row) ────────────────────────

export function TransformSelect({
  value,
  onChange,
}: {
  value: string[];
  onChange: (value: string[]) => void;
}) {
  const [addOpen, setAddOpen] = useState(false);
  const selected = value ?? [];

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 4 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );

  const toggle = (t: string) => {
    if (selected.includes(t)) {
      onChange(selected.filter((s) => s !== t));
    } else {
      onChange([...selected, t]);
    }
  };

  const remove = (t: string) => {
    onChange(selected.filter((s) => s !== t));
  };

  const applyPreset = (transforms: string[]) => {
    const merged = [...new Set([...selected, ...transforms])];
    const presetSet = new Set(transforms);
    const nonPreset = merged.filter((t) => !presetSet.has(t));
    onChange([...transforms, ...nonPreset]);
  };

  const handleDragEnd = (event: DragEndEvent) => {
    const { active, over } = event;
    if (over && active.id !== over.id) {
      const oldIndex = selected.indexOf(active.id as string);
      const newIndex = selected.indexOf(over.id as string);
      onChange(arrayMove(selected, oldIndex, newIndex));
    }
  };

  // Auto-expand when transforms are present
  const hasTransforms = selected.length > 0;

  return (
    <div className="pl-1">
      <div className="flex flex-wrap items-center gap-1.5">
        {/* Selected transform chips (draggable) */}
        {hasTransforms && (
          <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
            <SortableContext items={selected} strategy={horizontalListSortingStrategy}>
              {selected.map((t, i) => (
                <SortableTransformChip key={t} id={t} index={i} onRemove={remove} />
              ))}
            </SortableContext>
          </DndContext>
        )}

        {/* Add dropdown — styled to match Select triggers */}
        <Popover open={addOpen} onOpenChange={setAddOpen}>
          <PopoverTrigger asChild>
            <button className={`inline-flex items-center gap-1 rounded-md border h-7 px-2 text-[11px] transition-colors ${
              hasTransforms
                ? "border-border/50 text-muted-foreground/60 hover:text-muted-foreground hover:border-muted-foreground/50"
                : "border-dashed border-border/50 text-muted-foreground/40 hover:text-muted-foreground hover:border-muted-foreground/50"
            }`}>
              <Sparkles className="h-3 w-3" />
              {hasTransforms ? <Plus className="h-2.5 w-2.5" /> : "Transforms"}
              <ChevronDown className="h-3 w-3 opacity-50" />
            </button>
          </PopoverTrigger>
          <PopoverContent className="p-0" align="start" side="bottom" sideOffset={4}>
            <TransformPopoverContent selected={selected} onToggle={toggle} onApplyPreset={applyPreset} />
          </PopoverContent>
        </Popover>
      </div>
    </div>
  );
}

import { useState } from "react";
import { Plus, X, Check, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";

// ─── Copy Button ────────────────────────────────────────────────────

export function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);

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
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Button variant="ghost" size="sm" onClick={handleCopy}>
      {copied ? (
        <Check className="h-3.5 w-3.5 text-neon-green" />
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
          className="inline-flex items-center gap-1 rounded bg-navy-800 border border-border px-2 py-0.5 text-xs font-mono text-neon-cyan"
        >
          {id}
          <button
            onClick={() => removeId(id)}
            className="ml-0.5 rounded-full p-0.5 hover:bg-accent hover:text-neon-pink"
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
        className="flex-1 min-w-[120px] bg-transparent text-xs font-mono outline-none placeholder:text-muted-foreground"
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
          className="inline-flex items-center gap-1 rounded bg-navy-800 border border-border px-2 py-0.5 text-xs font-mono text-neon-cyan"
        >
          {method}
          <button
            onClick={() => remove(method)}
            className="ml-0.5 rounded-full p-0.5 hover:bg-accent hover:text-neon-pink"
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
                className="flex w-full items-center rounded px-2 py-1.5 text-xs font-mono cursor-pointer hover:bg-accent"
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
          className="inline-flex items-center gap-1 rounded bg-navy-800 border border-border px-2 py-0.5 text-xs font-mono text-neon-cyan"
        >
          {tag}
          <button
            onClick={() => removeTag(tag)}
            className="ml-0.5 rounded-full p-0.5 hover:bg-accent hover:text-neon-pink"
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
        className="flex-1 min-w-[120px] bg-transparent text-xs font-mono outline-none placeholder:text-muted-foreground"
      />
    </div>
  );
}

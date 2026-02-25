import { useState, useCallback, useEffect, useRef, useMemo } from "react";
import { X, Plus, Filter, Search, ChevronRight } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import type { SummaryParams, EventsParams, EventType, FilterOp } from "@/lib/api";

// ─── Types ──────────────────────────────────────────────────────────

export type FilterField = "service" | "client" | "event_type" | "method" | "rule_name";

export interface DashboardFilter {
  field: FilterField;
  operator: FilterOp;
  value: string;
}

// ─── Operator metadata ──────────────────────────────────────────────

interface OpMeta {
  label: string;
  /** Short display label for chips */
  chip: string;
}

const OP_META: Record<FilterOp, OpMeta> = {
  eq:       { label: "equals",          chip: "=" },
  neq:      { label: "not equals",      chip: "≠" },
  contains: { label: "contains",        chip: "~" },
  in:       { label: "is in",           chip: "in" },
  regex:    { label: "matches regex",   chip: "re" },
};

/** Operators available per field. Order matters — first is default. */
const FIELD_OPERATORS: Record<FilterField, FilterOp[]> = {
  service:    ["eq", "neq", "contains", "in", "regex"],
  client:     ["eq", "neq", "in"],
  event_type: ["eq", "in"],
  method:     ["eq", "in"],
  rule_name:  ["eq", "contains", "regex"],
};

// ─── Field metadata ─────────────────────────────────────────────────

interface FieldMeta {
  label: string;
  placeholder: string;
  /** If present, show a selection list instead of free text */
  options?: { value: string; label: string }[];
  /** If true, the field supports dynamic options (e.g. services from API) + free text */
  dynamic?: boolean;
}

const EVENT_TYPE_OPTIONS: { value: string; label: string }[] = [
  { value: "blocked", label: "Blocked" },
  { value: "logged", label: "Logged" },
  { value: "rate_limited", label: "Rate Limited" },
  { value: "ipsum_blocked", label: "IPsum Blocked" },
  { value: "honeypot", label: "Honeypot" },
  { value: "scanner", label: "Scanner" },
  { value: "policy_skip", label: "Policy Skip" },
  { value: "policy_allow", label: "Policy Allow" },
  { value: "policy_block", label: "Policy Block" },
];

const METHOD_OPTIONS: { value: string; label: string }[] = [
  { value: "GET", label: "GET" },
  { value: "POST", label: "POST" },
  { value: "PUT", label: "PUT" },
  { value: "DELETE", label: "DELETE" },
  { value: "PATCH", label: "PATCH" },
  { value: "HEAD", label: "HEAD" },
  { value: "OPTIONS", label: "OPTIONS" },
];

export const FILTER_FIELDS: Record<FilterField, FieldMeta> = {
  service: { label: "Service", placeholder: "Search services...", dynamic: true },
  client: { label: "Client IP", placeholder: "e.g. 192.168.1.100" },
  event_type: { label: "Event Type", placeholder: "Select type", options: EVENT_TYPE_OPTIONS },
  method: { label: "Method", placeholder: "Select method", options: METHOD_OPTIONS },
  rule_name: { label: "Policy Rule", placeholder: "e.g. Allow Static Assets" },
};

const FIELD_ORDER: FilterField[] = ["service", "client", "event_type", "method", "rule_name"];

// ─── Pure logic functions (exported for testing) ────────────────────

/**
 * Parse filter state from URL search params.
 * Recognized params: service, client (also ip), event_type (also type),
 * method, rule_name. Each can have a companion _op param.
 */
export function parseFiltersFromURL(search: string): DashboardFilter[] {
  const params = new URLSearchParams(search);
  const filters: DashboardFilter[] = [];

  const fieldMap: { key: string; alias?: string; field: FilterField }[] = [
    { key: "service", field: "service" },
    { key: "client", alias: "ip", field: "client" },
    { key: "event_type", alias: "type", field: "event_type" },
    { key: "method", field: "method" },
    { key: "rule_name", field: "rule_name" },
  ];

  for (const { key, alias, field } of fieldMap) {
    const value = params.get(key) || (alias ? params.get(alias) : null);
    if (value) {
      const op = (params.get(`${key}_op`) || "eq") as FilterOp;
      const validOps = FIELD_OPERATORS[field];
      filters.push({
        field,
        operator: validOps.includes(op) ? op : validOps[0],
        value,
      });
    }
  }

  return filters;
}

/** Convert filter array to SummaryParams (excluding time range). */
export function filtersToSummaryParams(filters: DashboardFilter[]): Partial<SummaryParams> {
  const params: Partial<SummaryParams> = {};
  for (const f of filters) {
    switch (f.field) {
      case "service":    params.service = f.value;    params.service_op = f.operator;    break;
      case "client":     params.client = f.value;     params.client_op = f.operator;     break;
      case "event_type": params.event_type = f.value; params.event_type_op = f.operator; break;
      case "method":     params.method = f.value;     params.method_op = f.operator;     break;
      case "rule_name":  params.rule_name = f.value;  params.rule_name_op = f.operator;  break;
    }
  }
  return params;
}

/** Convert filter array to EventsParams (excluding pagination and time range). */
export function filtersToEventsParams(filters: DashboardFilter[]): Partial<EventsParams> {
  const params: Partial<EventsParams> = {};
  for (const f of filters) {
    switch (f.field) {
      case "service":    params.service = f.value;                         params.service_op = f.operator;    break;
      case "client":     params.client = f.value;                          params.client_op = f.operator;     break;
      case "event_type": params.event_type = f.value as EventType;         params.event_type_op = f.operator; break;
      case "method":     params.method = f.value;                          params.method_op = f.operator;     break;
      case "rule_name":  params.rule_name = f.value;                       params.rule_name_op = f.operator;  break;
    }
  }
  return params;
}

/** Get a display label for a filter value. */
export function filterDisplayValue(field: FilterField, value: string): string {
  const meta = FILTER_FIELDS[field];
  if (meta.options) {
    // For "in" operator, resolve each comma-separated value
    if (value.includes(",")) {
      return value.split(",").map((v) => {
        const opt = meta.options!.find((o) => o.value === v.trim());
        return opt ? opt.label : v.trim();
      }).join(", ");
    }
    const opt = meta.options.find((o) => o.value === value);
    if (opt) return opt.label;
  }
  return value;
}

/** Get the operator chip label. */
export function operatorChip(op: FilterOp): string {
  return OP_META[op]?.chip ?? "=";
}

// ─── Component ──────────────────────────────────────────────────────

interface DashboardFilterBarProps {
  filters: DashboardFilter[];
  onChange: (filters: DashboardFilter[]) => void;
  /** Known service names for autocomplete (from fetchServices or summary data). */
  services?: string[];
}

export default function DashboardFilterBar({ filters, onChange, services }: DashboardFilterBarProps) {
  const [popoverOpen, setPopoverOpen] = useState(false);
  const [selectedField, setSelectedField] = useState<FilterField | null>(null);
  const [selectedOp, setSelectedOp] = useState<FilterOp | null>(null);
  const [inputValue, setInputValue] = useState("");
  // For "in" operator with fixed options, track selected values
  const [inValues, setInValues] = useState<string[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);

  // Focus input when we reach the value step
  useEffect(() => {
    if (selectedField && selectedOp) {
      const meta = FILTER_FIELDS[selectedField];
      // Focus for free text or dynamic fields
      if (!meta.options || meta.dynamic || selectedOp === "in" || selectedOp === "regex" || selectedOp === "contains") {
        const t = setTimeout(() => inputRef.current?.focus(), 50);
        return () => clearTimeout(t);
      }
    }
  }, [selectedField, selectedOp]);

  // Build dynamic service options from prop
  const serviceOptions = useMemo(() => {
    if (!services || services.length === 0) return [];
    return services.map((s) => ({ value: s, label: s }));
  }, [services]);

  // Fields already in use (only allow one filter per field)
  const usedFields = new Set(filters.map((f) => f.field));
  const availableFields = FIELD_ORDER.filter((f) => !usedFields.has(f));

  const resetPopover = useCallback(() => {
    setSelectedField(null);
    setSelectedOp(null);
    setInputValue("");
    setInValues([]);
  }, []);

  const addFilter = useCallback(
    (field: FilterField, op: FilterOp, value: string) => {
      const trimmed = value.trim();
      if (!trimmed) return;
      const updated = filters.filter((f) => f.field !== field);
      updated.push({ field, operator: op, value: trimmed });
      onChange(updated);
      setPopoverOpen(false);
      resetPopover();
    },
    [filters, onChange, resetPopover],
  );

  const removeFilter = useCallback(
    (field: FilterField) => {
      onChange(filters.filter((f) => f.field !== field));
    },
    [filters, onChange],
  );

  const clearAll = useCallback(() => {
    onChange([]);
  }, [onChange]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter" && selectedField && selectedOp && inputValue.trim()) {
        e.preventDefault();
        addFilter(selectedField, selectedOp, inputValue);
      }
      if (e.key === "Escape") {
        setPopoverOpen(false);
        resetPopover();
      }
    },
    [selectedField, selectedOp, inputValue, addFilter, resetPopover],
  );

  function renderPopoverContent() {
    // Step 1: Pick a field
    if (!selectedField) {
      return (
        <div className="space-y-1">
          <p className="px-2 py-1 text-xs font-medium text-muted-foreground">Filter by</p>
          {availableFields.map((field) => (
            <button
              key={field}
              className="flex w-full items-center justify-between rounded-sm px-2 py-1.5 text-sm hover:bg-accent hover:text-accent-foreground transition-colors cursor-pointer"
              onClick={() => {
                setSelectedField(field);
                // If only one operator available, skip step 2
                const ops = FIELD_OPERATORS[field];
                if (ops.length === 1) setSelectedOp(ops[0]);
              }}
            >
              <span>{FILTER_FIELDS[field].label}</span>
              <ChevronRight className="h-3 w-3 text-muted-foreground" />
            </button>
          ))}
          {availableFields.length === 0 && (
            <p className="px-2 py-2 text-xs text-muted-foreground">All fields have active filters</p>
          )}
        </div>
      );
    }

    // Step 2: Pick an operator
    if (!selectedOp) {
      const ops = FIELD_OPERATORS[selectedField];
      return (
        <div className="space-y-1">
          <button
            className="flex items-center gap-1 px-2 py-1 text-xs text-muted-foreground hover:text-foreground cursor-pointer"
            onClick={() => { setSelectedField(null); }}
          >
            &larr; Back
          </button>
          <p className="px-2 py-1 text-xs font-medium text-muted-foreground">
            {FILTER_FIELDS[selectedField].label} &mdash; operator
          </p>
          {ops.map((op) => (
            <button
              key={op}
              className="flex w-full items-center justify-between rounded-sm px-2 py-1.5 text-sm hover:bg-accent hover:text-accent-foreground transition-colors cursor-pointer"
              onClick={() => setSelectedOp(op)}
            >
              <span>{OP_META[op].label}</span>
              <span className="text-xs font-mono text-muted-foreground">{OP_META[op].chip}</span>
            </button>
          ))}
        </div>
      );
    }

    const meta = FILTER_FIELDS[selectedField];

    // Step 3: Enter value

    // For "in" operator with options (fixed or dynamic) — multi-select checkboxes + custom text
    const inOptions = meta.options
      ? meta.options
      : (meta.dynamic && selectedField === "service" ? serviceOptions : []);

    if (selectedOp === "in" && inOptions.length > 0) {
      const filteredInOptions = inputValue
        ? inOptions.filter((o) => o.label.toLowerCase().includes(inputValue.toLowerCase()))
        : inOptions;

      return (
        <div className="space-y-1.5">
          <button
            className="flex items-center gap-1 px-2 py-1 text-xs text-muted-foreground hover:text-foreground cursor-pointer"
            onClick={() => { setSelectedOp(null); setInValues([]); setInputValue(""); }}
          >
            &larr; {FILTER_FIELDS[selectedField].label} &middot; {OP_META[selectedOp].label}
          </button>
          {/* Search box for dynamic fields */}
          {meta.dynamic && (
            <div className="relative">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                ref={inputRef}
                placeholder="Search or type custom..."
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && inputValue.trim()) {
                    e.preventDefault();
                    // Add custom value to inValues if not already present
                    const val = inputValue.trim();
                    if (!inValues.includes(val)) {
                      setInValues((prev) => [...prev, val]);
                    }
                    setInputValue("");
                  }
                  if (e.key === "Escape") {
                    setPopoverOpen(false);
                    resetPopover();
                  }
                }}
                className="h-8 text-sm pl-7"
              />
            </div>
          )}
          {/* Selected custom values (not in known options) */}
          {inValues.filter((v) => !inOptions.some((o) => o.value === v)).length > 0 && (
            <div className="flex flex-wrap gap-1 px-1">
              {inValues.filter((v) => !inOptions.some((o) => o.value === v)).map((v) => (
                <span
                  key={v}
                  className="inline-flex items-center gap-1 rounded bg-neon-cyan/10 px-1.5 py-0.5 text-[11px] font-mono text-neon-cyan"
                >
                  {v}
                  <button
                    className="hover:text-destructive cursor-pointer"
                    onClick={() => setInValues((prev) => prev.filter((x) => x !== v))}
                  >
                    <X className="h-2.5 w-2.5" />
                  </button>
                </span>
              ))}
            </div>
          )}
          <div className="max-h-48 overflow-y-auto">
            {filteredInOptions.map((opt) => {
              const checked = inValues.includes(opt.value);
              return (
                <button
                  key={opt.value}
                  className={`flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-sm transition-colors cursor-pointer ${
                    checked ? "bg-neon-cyan/10 text-neon-cyan" : "hover:bg-accent hover:text-accent-foreground"
                  }`}
                  onClick={() => {
                    setInValues((prev) =>
                      checked ? prev.filter((v) => v !== opt.value) : [...prev, opt.value]
                    );
                  }}
                >
                  <div className={`h-3.5 w-3.5 rounded border flex items-center justify-center text-[10px] ${
                    checked ? "border-neon-cyan bg-neon-cyan/20 text-neon-cyan" : "border-muted-foreground"
                  }`}>
                    {checked && "✓"}
                  </div>
                  <span className={meta.dynamic ? "font-mono" : ""}>{opt.label}</span>
                </button>
              );
            })}
            {meta.dynamic && inputValue.trim() && filteredInOptions.length === 0 && (
              <button
                className="flex w-full items-center rounded-sm px-2 py-1.5 text-sm hover:bg-accent hover:text-accent-foreground transition-colors cursor-pointer"
                onClick={() => {
                  const val = inputValue.trim();
                  if (!inValues.includes(val)) setInValues((prev) => [...prev, val]);
                  setInputValue("");
                }}
              >
                Add &quot;{inputValue.trim()}&quot;
              </button>
            )}
          </div>
          <Button
            size="sm"
            className="h-7 w-full text-xs"
            disabled={inValues.length === 0}
            onClick={() => addFilter(selectedField, "in", inValues.join(","))}
          >
            Apply ({inValues.length} selected)
          </Button>
        </div>
      );
    }

    // For eq/neq with fixed options — single-select list
    if ((selectedOp === "eq" || selectedOp === "neq") && meta.options) {
      return (
        <div className="space-y-1">
          <button
            className="flex items-center gap-1 px-2 py-1 text-xs text-muted-foreground hover:text-foreground cursor-pointer"
            onClick={() => setSelectedOp(null)}
          >
            &larr; {FILTER_FIELDS[selectedField].label} &middot; {OP_META[selectedOp].label}
          </button>
          {meta.options.map((opt) => (
            <button
              key={opt.value}
              className="flex w-full items-center rounded-sm px-2 py-1.5 text-sm hover:bg-accent hover:text-accent-foreground transition-colors cursor-pointer"
              onClick={() => addFilter(selectedField, selectedOp, opt.value)}
            >
              {opt.label}
            </button>
          ))}
        </div>
      );
    }

    // Dynamic field (searchable list + free text, e.g. service) — for eq/neq
    if (meta.dynamic && (selectedOp === "eq" || selectedOp === "neq")) {
      const options = selectedField === "service" ? serviceOptions : [];
      const filtered = inputValue
        ? options.filter((o) => o.label.toLowerCase().includes(inputValue.toLowerCase()))
        : options;

      return (
        <div className="space-y-1.5">
          <button
            className="flex items-center gap-1 px-2 py-1 text-xs text-muted-foreground hover:text-foreground cursor-pointer"
            onClick={() => { setSelectedOp(null); setInputValue(""); }}
          >
            &larr; {FILTER_FIELDS[selectedField].label} &middot; {OP_META[selectedOp].label}
          </button>
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              ref={inputRef}
              placeholder={meta.placeholder}
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={handleKeyDown}
              className="h-8 text-sm pl-7"
            />
          </div>
          <div className="max-h-48 overflow-y-auto">
            {filtered.length > 0 ? (
              filtered.map((opt) => (
                <button
                  key={opt.value}
                  className="flex w-full items-center rounded-sm px-2 py-1.5 text-sm font-mono hover:bg-accent hover:text-accent-foreground transition-colors cursor-pointer"
                  onClick={() => addFilter(selectedField, selectedOp, opt.value)}
                >
                  {opt.label}
                </button>
              ))
            ) : inputValue.trim() ? (
              <button
                className="flex w-full items-center rounded-sm px-2 py-1.5 text-sm hover:bg-accent hover:text-accent-foreground transition-colors cursor-pointer"
                onClick={() => addFilter(selectedField, selectedOp, inputValue)}
              >
                Use &quot;{inputValue}&quot;
              </button>
            ) : options.length === 0 ? (
              <p className="px-2 py-2 text-xs text-muted-foreground">Type a value...</p>
            ) : null}
          </div>
        </div>
      );
    }

    // Free text input for all other combos (contains, regex, in for free-text fields, etc.)
    const placeholder = selectedOp === "in"
      ? "Comma-separated values"
      : selectedOp === "regex"
        ? "e.g. ^cdn\\..*\\.io$"
        : meta.placeholder;

    return (
      <div className="space-y-2">
        <button
          className="flex items-center gap-1 px-2 py-1 text-xs text-muted-foreground hover:text-foreground cursor-pointer"
          onClick={() => { setSelectedOp(null); setInputValue(""); }}
        >
          &larr; {FILTER_FIELDS[selectedField].label} &middot; {OP_META[selectedOp].label}
        </button>
        {selectedOp === "regex" && (
          <p className="px-1 text-[10px] text-neon-cyan/60 font-mono">
            Go regexp syntax (RE2)
          </p>
        )}
        {selectedOp === "in" && (
          <p className="px-1 text-[10px] text-muted-foreground">
            Separate values with commas
          </p>
        )}
        <Input
          ref={inputRef}
          placeholder={placeholder}
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          onKeyDown={handleKeyDown}
          className={`h-8 text-sm ${selectedOp === "regex" ? "font-mono" : ""}`}
        />
        <Button
          size="sm"
          className="h-7 w-full text-xs"
          disabled={!inputValue.trim()}
          onClick={() => addFilter(selectedField, selectedOp, inputValue)}
        >
          Apply
        </Button>
      </div>
    );
  }

  if (filters.length === 0 && availableFields.length === FIELD_ORDER.length) {
    // No filters active — just show a minimal "Add filter" button
    return (
      <div className="flex items-center gap-2">
        <Popover open={popoverOpen} onOpenChange={(open) => {
          setPopoverOpen(open);
          if (!open) resetPopover();
        }}>
          <PopoverTrigger asChild>
            <Button variant="outline" size="sm" className="h-7 gap-1.5 text-xs text-muted-foreground">
              <Plus className="h-3 w-3" />
              Add filter
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-64 p-2" align="start">
            {renderPopoverContent()}
          </PopoverContent>
        </Popover>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2 rounded-lg border border-neon-cyan/20 bg-neon-cyan/5 px-3 py-2">
      <Filter className="h-3.5 w-3.5 text-neon-cyan shrink-0" />
      <div className="flex flex-wrap items-center gap-1.5 flex-1 min-w-0">
        {filters.map((f) => (
          <Badge
            key={f.field}
            variant="secondary"
            className="gap-1 pl-2 pr-1 py-0.5 text-xs font-normal bg-neon-cyan/10 border-neon-cyan/20 hover:bg-neon-cyan/20 transition-colors"
          >
            <span className="text-muted-foreground font-medium">{FILTER_FIELDS[f.field].label}</span>
            <span className="text-neon-cyan/70 font-mono text-[10px]">{operatorChip(f.operator)}</span>
            <span className="font-mono">{filterDisplayValue(f.field, f.value)}</span>
            <button
              className="ml-0.5 rounded-sm p-0.5 hover:bg-neon-cyan/30 transition-colors cursor-pointer"
              onClick={() => removeFilter(f.field)}
              title={`Remove ${FILTER_FIELDS[f.field].label} filter`}
            >
              <X className="h-3 w-3" />
            </button>
          </Badge>
        ))}

        {availableFields.length > 0 && (
          <Popover open={popoverOpen} onOpenChange={(open) => {
            setPopoverOpen(open);
            if (!open) resetPopover();
          }}>
            <PopoverTrigger asChild>
              <button className="flex items-center gap-1 rounded-sm px-1.5 py-0.5 text-xs text-muted-foreground hover:text-foreground hover:bg-accent/50 transition-colors cursor-pointer">
                <Plus className="h-3 w-3" />
                Add
              </button>
            </PopoverTrigger>
            <PopoverContent className="w-64 p-2" align="start">
              {renderPopoverContent()}
            </PopoverContent>
          </Popover>
        )}
      </div>

      {filters.length > 1 && (
        <Button
          variant="ghost"
          size="sm"
          className="h-6 px-2 text-xs text-muted-foreground hover:text-foreground shrink-0"
          onClick={clearAll}
        >
          Clear all
        </Button>
      )}

      {filters.length === 1 && (
        <Button
          variant="ghost"
          size="icon-sm"
          className="text-muted-foreground hover:text-foreground shrink-0"
          onClick={clearAll}
          title="Clear filter"
        >
          <X className="h-3.5 w-3.5" />
        </Button>
      )}
    </div>
  );
}

import { useState, useEffect } from "react";
import { X, ChevronDown, List } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { Condition, ConditionField, ConditionOperator, ServiceDetail } from "@/lib/api";
import { fetchManagedLists, compatibleKinds, type ManagedList } from "@/lib/api";
import { CONDITION_FIELDS, getFieldDef, type FieldDef } from "./constants";
import { MethodMultiSelect, PipeTagInput, TransformSelect } from "./TagInputs";

// ─── Host Value Input ───────────────────────────────────────────────

export function HostValueInput({
  value,
  services,
  onChange,
}: {
  value: string;
  services: ServiceDetail[];
  onChange: (value: string) => void;
}) {
  const serviceHosts = services.map((s) => s.service);
  const isKnownHost = value === "*" || serviceHosts.includes(value);
  const [customMode, setCustomMode] = useState(!isKnownHost && value !== "");

  // If the user typed a custom value and then switches back to select mode,
  // reset to empty so the select shows its placeholder.
  const handleSelectChange = (v: string) => {
    if (v === "__custom__") {
      setCustomMode(true);
      onChange("");
    } else {
      setCustomMode(false);
      onChange(v);
    }
  };

  if (customMode) {
    return (
      <div className="flex flex-1 gap-1.5">
        <Input
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder="e.g., radarr.erfi.io"
          className="flex-1"
          autoFocus
        />
        <Button
          variant="ghost"
          size="icon"
          className="shrink-0 text-muted-foreground"
          title="Switch to dropdown"
          onClick={() => { setCustomMode(false); onChange(""); }}
        >
          <ChevronDown className="h-4 w-4" />
        </Button>
      </div>
    );
  }

  return (
    <Select value={value || undefined} onValueChange={handleSelectChange}>
      <SelectTrigger className="flex-1">
        <SelectValue placeholder="Select host..." />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="*">All Services</SelectItem>
        {services.map((s) => (
          <SelectItem key={s.service} value={s.service}>{s.service}</SelectItem>
        ))}
        <SelectItem value="__custom__">Custom...</SelectItem>
      </SelectContent>
    </Select>
  );
}

// ─── List Value Select ──────────────────────────────────────────────

/** Dropdown to pick a managed list name, filtered by field-kind compatibility. */
export function ListValueSelect({
  value,
  field,
  onChange,
}: {
  value: string;
  field: ConditionField;
  onChange: (value: string) => void;
}) {
  const [lists, setLists] = useState<ManagedList[]>([]);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    fetchManagedLists()
      .then(setLists)
      .catch(() => setLists([]))
      .finally(() => setLoaded(true));
  }, []);

  // Filter lists by field-kind compatibility.
  const kinds = compatibleKinds(field);
  const compatible = lists.filter((l) => kinds.includes(l.kind));

  return (
    <div className="flex flex-1 gap-1.5">
      <Select value={value || undefined} onValueChange={onChange}>
        <SelectTrigger className="flex-1">
          <div className="flex items-center gap-1.5">
            <List className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
            <SelectValue placeholder={loaded ? "Select list..." : "Loading..."} />
          </div>
        </SelectTrigger>
        <SelectContent>
          {compatible.length === 0 ? (
            <div className="px-2 py-1.5 text-xs text-muted-foreground">
              {loaded ? "No compatible lists found" : "Loading..."}
            </div>
          ) : (
            compatible.map((l) => (
              <SelectItem key={l.name} value={l.name}>
                <div className="flex items-center gap-2">
                  <span>{l.name}</span>
                  <span className="text-[10px] text-muted-foreground">
                    {l.kind} &middot; {l.item_count.toLocaleString()} items
                  </span>
                </div>
              </SelectItem>
            ))
          )}
        </SelectContent>
      </Select>
      {value && (
        <a
          href="/lists"
          className="flex items-center shrink-0 text-xs text-muted-foreground hover:text-lv-cyan"
          title="Manage lists"
        >
          <List className="h-3.5 w-3.5" />
        </a>
      )}
    </div>
  );
}

// ─── Condition Row ──────────────────────────────────────────────────

export function ConditionRow({
  condition,
  index,
  onChange,
  onRemove,
  services,
  fields,
}: {
  condition: Condition;
  index: number;
  onChange: (index: number, condition: Condition) => void;
  onRemove: (index: number) => void;
  services: ServiceDetail[];
  fields?: FieldDef[];
}) {
  const availableFields = fields ?? CONDITION_FIELDS;
  const fieldDef = getFieldDef(condition.field);
  const operators = fieldDef.operators;

  const isListOp = condition.operator === "in_list" || condition.operator === "not_in_list";

  return (
    <div className="flex items-start gap-2">
      {/* Field selector */}
      <Select
        value={condition.field}
        onValueChange={(v) => {
          const newField = v as ConditionField;
          const newFieldDef = getFieldDef(newField);
          onChange(index, {
            field: newField,
            operator: newFieldDef.operators[0].value,
            value: "",
            transforms: condition.transforms,
          });
        }}
      >
        <SelectTrigger className="w-[160px] shrink-0">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {availableFields.map((f) => (
            <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>
          ))}
        </SelectContent>
      </Select>

      {/* Operator selector */}
      <Select
        value={condition.operator}
        onValueChange={(v) => {
          const newOp = v as ConditionOperator;
          // When switching to phrase_match, move any existing pipe-separated value into list_items
          if (newOp === "phrase_match") {
            const items = condition.value ? condition.value.split("|").filter(Boolean) : [];
            onChange(index, { ...condition, operator: newOp, value: "", list_items: items.length > 0 ? items : undefined });
          } else {
            // When switching away from phrase_match, move list_items back to pipe value for "in" or clear
            const fromPhraseMatch = condition.operator === "phrase_match" && condition.list_items?.length;
            const newValue = fromPhraseMatch && newOp === "in" ? condition.list_items!.join("|") : "";
            onChange(index, { ...condition, operator: newOp, value: newValue, list_items: undefined });
          }
        }}
      >
        <SelectTrigger className="w-[160px] shrink-0">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {operators.map((op) => (
            <SelectItem key={op.value} value={op.value}>{op.label}</SelectItem>
          ))}
        </SelectContent>
      </Select>

      {/* Value input — specialized inputs for specific field/operator combos */}
      <div className="flex flex-1 flex-col gap-1">
        {condition.operator === "exists" ? (
          <span className="flex items-center h-9 px-3 text-xs text-muted-foreground italic">field exists (no value needed)</span>
        ) : isListOp ? (
          <ListValueSelect
            value={condition.value}
            field={condition.field}
            onChange={(v) => onChange(index, { ...condition, value: v })}
          />
        ) : condition.field === "host" ? (
          <HostValueInput
            value={condition.value}
            services={services}
            onChange={(v) => onChange(index, { ...condition, value: v })}
          />
        ) : condition.field === "method" && condition.operator === "in" ? (
          <MethodMultiSelect
            value={condition.value}
            onChange={(v) => onChange(index, { ...condition, value: v })}
          />
        ) : condition.operator === "phrase_match" ? (
          <PipeTagInput
            value={(condition.list_items ?? []).join("|")}
            onChange={(v) => {
              const items = v ? v.split("|").filter(Boolean) : [];
              onChange(index, { ...condition, value: "", list_items: items.length > 0 ? items : undefined });
            }}
            placeholder="e.g., select|union|insert|drop"
          />
        ) : condition.operator === "in" ? (
          <PipeTagInput
            value={condition.value}
            onChange={(v) => onChange(index, { ...condition, value: v })}
            placeholder={fieldDef.placeholder}
          />
        ) : (
          <Input
            value={condition.value}
            onChange={(e) => onChange(index, { ...condition, value: e.target.value })}
            placeholder={fieldDef.placeholder}
            className="flex-1"
          />
        )}
        {fieldDef.hint && !isListOp && condition.operator !== "exists" && (
          <p className="text-[11px] leading-tight text-muted-foreground/70 px-1">{fieldDef.hint}</p>
        )}
        {/* Transform selection — applied left-to-right before operator evaluation */}
        <TransformSelect
          value={condition.transforms ?? []}
          onChange={(transforms) => onChange(index, { ...condition, transforms: transforms.length > 0 ? transforms : undefined })}
        />
      </div>

      {/* Remove button */}
      <Button
        variant="ghost"
        size="icon"
        className="shrink-0 text-muted-foreground hover:text-lv-red"
        onClick={() => onRemove(index)}
      >
        <X className="h-4 w-4" />
      </Button>
    </div>
  );
}

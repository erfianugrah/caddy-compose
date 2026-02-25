import { useState } from "react";
import { X, ChevronDown } from "lucide-react";
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
import { CONDITION_FIELDS, getFieldDef } from "./constants";
import { MethodMultiSelect, PipeTagInput } from "./TagInputs";

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

// ─── Condition Row ──────────────────────────────────────────────────

export function ConditionRow({
  condition,
  index,
  onChange,
  onRemove,
  services,
}: {
  condition: Condition;
  index: number;
  onChange: (index: number, condition: Condition) => void;
  onRemove: (index: number) => void;
  services: ServiceDetail[];
}) {
  const fieldDef = getFieldDef(condition.field);
  const operators = fieldDef.operators;

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
          });
        }}
      >
        <SelectTrigger className="w-[160px] shrink-0">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {CONDITION_FIELDS.map((f) => (
            <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>
          ))}
        </SelectContent>
      </Select>

      {/* Operator selector */}
      <Select
        value={condition.operator}
        onValueChange={(v) => onChange(index, { ...condition, operator: v as ConditionOperator })}
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
      {condition.field === "host" ? (
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

      {/* Remove button */}
      <Button
        variant="ghost"
        size="icon"
        className="shrink-0 text-muted-foreground hover:text-neon-pink"
        onClick={() => onRemove(index)}
      >
        <X className="h-4 w-4" />
      </Button>
    </div>
  );
}

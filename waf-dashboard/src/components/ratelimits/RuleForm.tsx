import { useState } from "react";
import { Plus, X, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ConditionRow } from "../policy/ConditionBuilder";
import { PipeTagInput } from "../policy/TagInputs";
import { RL_FIELD_DEFS, RL_KEY_OPTIONS, WINDOW_OPTIONS, WINDOW_VALUES } from "./constants";
import { isValidWindow } from "@/lib/format";
import type {
  RateLimitRule,
  RateLimitRuleCreateData,
  ServiceDetail,
  Condition,
  GroupOperator,
  RLRuleAction,
  RLRuleKey,
} from "@/lib/api";

// ─── Rule Form (Create / Edit) ──────────────────────────────────────

export interface RuleFormProps {
  initial?: RateLimitRule;
  services: ServiceDetail[];
  onSubmit: (data: RateLimitRuleCreateData) => void;
  onCancel?: () => void;
  submitLabel: string;
  saving?: boolean;
}

export function RuleForm({ initial, services, onSubmit, onCancel, submitLabel, saving }: RuleFormProps) {
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [service, setService] = useState(initial?.service ?? "");
  const [conditions, setConditions] = useState<Condition[]>(initial?.conditions ?? []);
  const [groupOp, setGroupOp] = useState<GroupOperator>(initial?.group_operator ?? "and");
  const [key, setKey] = useState(initial?.key ?? "client_ip");
  const [customKeyParam, setCustomKeyParam] = useState(() => {
    const k = initial?.key ?? "";
    for (const p of ["header:", "cookie:", "body_json:", "body_form:"] as const) {
      if (k.startsWith(p)) return k.slice(p.length);
    }
    return "";
  });
  const [events, setEvents] = useState(initial?.events ?? 100);
  const [window, setWindow] = useState(initial?.window ?? "1m");
  const [action, setAction] = useState<RLRuleAction>(initial?.action ?? "deny");
  const [priority, setPriority] = useState(initial?.priority ?? 0);
  const [tags, setTags] = useState<string[]>(initial?.tags ?? []);
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [error, setError] = useState<string | null>(null);

  // Is key a parameterized type?
  const paramPrefixes = ["header:", "cookie:", "body_json:", "body_form:"] as const;
  const keyBase = paramPrefixes.find((p) => key.startsWith(p)) ?? key;
  const isParameterizedKey = paramPrefixes.some((p) => p === keyBase);

  const handleKeyChange = (v: string) => {
    setKey(v as RLRuleKey);
    if (!paramPrefixes.some((p) => p === v)) {
      setCustomKeyParam("");
    }
  };

  const addCondition = () => {
    const firstField = RL_FIELD_DEFS[0];
    setConditions([...conditions, { field: firstField.value, operator: firstField.operators[0].value, value: "" }]);
  };

  const updateCondition = (index: number, condition: Condition) => {
    const next = [...conditions];
    next[index] = condition;
    setConditions(next);
  };

  const removeCondition = (index: number) => {
    setConditions(conditions.filter((_, i) => i !== index));
  };

  const handleSubmit = () => {
    setError(null);
    if (!name.trim()) { setError("Name is required"); return; }
    if (!service.trim()) { setError("Service is required"); return; }
    if (events < 1 || events > 100000) { setError("Events must be between 1 and 100,000"); return; }
    if (isParameterizedKey && !customKeyParam.trim()) {
      const keyTypeName = keyBase === "header:" ? "Header" :
        keyBase === "cookie:" ? "Cookie" :
        keyBase === "body_json:" ? "JSON dot-path" :
        keyBase === "body_form:" ? "Form field" : "Parameter";
      setError(`${keyTypeName} is required for this key type`);
      return;
    }

    const resolvedKey = (isParameterizedKey ? `${keyBase}${customKeyParam.trim()}` : key) as RLRuleKey;

    onSubmit({
      name: name.trim(),
      description: description.trim(),
      service: service.trim(),
      conditions: conditions.length > 0 ? conditions : undefined,
      group_operator: conditions.length > 1 ? groupOp : undefined,
      key: resolvedKey,
      events,
      window,
      action,
      priority,
      tags: tags.length > 0 ? tags : undefined,
      enabled,
    });
  };

  return (
    <div className="space-y-6">
      {/* Name & Description */}
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-2">
          <Label>Rule Name</Label>
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g., API rate limit" />
        </div>
        <div className="space-y-2">
          <Label>Description <span className="text-muted-foreground text-xs">(optional)</span></Label>
          <Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="e.g., Protect API from abuse" />
        </div>
      </div>

      {/* Service */}
      <div className="space-y-2">
        <Label>Service</Label>
        <Select value={service || undefined} onValueChange={setService}>
          <SelectTrigger>
            <SelectValue placeholder="Select service..." />
          </SelectTrigger>
          <SelectContent>
            {services.map((s) => (
              <SelectItem key={s.service} value={s.service}>{s.service}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <p className="text-xs text-muted-foreground">The service (site block) this rate limit rule applies to.</p>
      </div>

      {/* Conditions */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <Label>Conditions <span className="text-muted-foreground text-xs">(optional)</span></Label>
          {conditions.length > 1 && (
            <Select value={groupOp} onValueChange={(v) => setGroupOp(v as GroupOperator)}>
              <SelectTrigger className="w-[100px] h-7 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="and">AND</SelectItem>
                <SelectItem value="or">OR</SelectItem>
              </SelectContent>
            </Select>
          )}
        </div>
        {conditions.map((cond, idx) => (
          <ConditionRow
            key={idx}
            condition={cond}
            index={idx}
            onChange={updateCondition}
            onRemove={removeCondition}
            services={services}
            fields={RL_FIELD_DEFS}
          />
        ))}
        <Button variant="outline" size="sm" onClick={addCondition}>
          <Plus className="h-3.5 w-3.5" />
          Add Condition
        </Button>
        <p className="text-xs text-muted-foreground">
          Without conditions, the rule matches all requests to this service.
        </p>
      </div>

      <Separator />

      {/* Rate Limit Parameters */}
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="space-y-2">
          <Label>Key (rate by)</Label>
          <Select value={keyBase} onValueChange={handleKeyChange}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {RL_KEY_OPTIONS.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {isParameterizedKey && (
            <Input
              value={customKeyParam}
              onChange={(e) => setCustomKeyParam(e.target.value)}
              placeholder={
                keyBase === "header:" ? "e.g., X-API-Key" :
                keyBase === "cookie:" ? "e.g., session_id" :
                keyBase === "body_json:" ? "e.g., .user.api_key" :
                keyBase === "body_form:" ? "e.g., action" :
                ""
              }
              className="mt-1"
            />
          )}
        </div>
        <div className="space-y-2">
          <Label>Max Events</Label>
          <Input
            type="number"
            min={1}
            max={100000}
            value={events}
            onChange={(e) => setEvents(Number(e.target.value))}
            className="tabular-nums"
          />
        </div>
        <div className="space-y-2">
          <Label>Window</Label>
          {WINDOW_VALUES.has(window) || window === "" ? (
            <Select value={window || "1m"} onValueChange={(v) => {
              if (v === "__custom") {
                setWindow("");
              } else {
                setWindow(v);
              }
            }}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {WINDOW_OPTIONS.map((opt) => (
                  <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                ))}
                <SelectItem value="__custom">Custom...</SelectItem>
              </SelectContent>
            </Select>
          ) : (
            <div className="flex items-center gap-1.5">
              <Input
                value={window}
                onChange={(e) => setWindow(e.target.value.trim().toLowerCase())}
                placeholder="e.g. 3m, 45s, 2h"
                className="font-mono text-sm"
              />
              <Button
                variant="ghost"
                size="sm"
                className="h-9 px-2 shrink-0"
                onClick={() => setWindow("1m")}
                title="Switch to presets"
              >
                <X className="h-3.5 w-3.5" />
              </Button>
            </div>
          )}
          {window && !WINDOW_VALUES.has(window) && !isValidWindow(window) && (
            <p className="text-xs text-red-400">Invalid format. Use number + s/m/h (e.g. 3m, 45s, 2h)</p>
          )}
        </div>
      </div>

      {/* Action & Priority */}
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="space-y-2">
          <Label>Action</Label>
          <Select value={action} onValueChange={(v) => setAction(v as RLRuleAction)}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="deny">Deny (429)</SelectItem>
              <SelectItem value="log_only">Monitor Only</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label>Priority <span className="text-muted-foreground text-xs">(higher = first)</span></Label>
          <Input
            type="number"
            min={0}
            max={1000}
            value={priority}
            onChange={(e) => setPriority(Number(e.target.value))}
            className="tabular-nums"
          />
        </div>
        <div className="flex items-end pb-2">
          <div className="flex items-center gap-2">
            <Switch checked={enabled} onCheckedChange={setEnabled} />
            <Label className="text-sm">{enabled ? "Enabled" : "Disabled"}</Label>
          </div>
        </div>
      </div>

      {/* Tags */}
      <div className="space-y-1.5">
        <Label className="text-sm">Tags <span className="text-muted-foreground text-xs">(optional)</span></Label>
        <PipeTagInput
          value={tags.join("|")}
          onChange={(v) => setTags(v ? v.split("|").filter(Boolean) : [])}
          placeholder="e.g., api, auth, brute-force (Enter to add)"
        />
        <p className="text-xs text-muted-foreground">
          Optional labels for organizing rules and classifying rate-limited events
        </p>
      </div>

      {/* Quick Presets */}
      <div className="space-y-2">
        <Label className="text-xs text-muted-foreground">Quick Presets</Label>
        <div className="flex flex-wrap gap-2">
          {[
            { label: "Admin (100/min)", events: 100, window: "1m" },
            { label: "Auth (200/min)", events: 200, window: "1m" },
            { label: "Standard (300/min)", events: 300, window: "1m" },
            { label: "Media (1000/min)", events: 1000, window: "1m" },
            { label: "Burst (50/10s)", events: 50, window: "10s" },
            { label: "API (60/min)", events: 60, window: "1m" },
          ].map((preset) => (
            <Button
              key={preset.label}
              variant="outline"
              size="sm"
              className="text-xs"
              onClick={() => { setEvents(preset.events); setWindow(preset.window); }}
            >
              {preset.label}
            </Button>
          ))}
        </div>
      </div>

      {error && <p className="text-xs text-destructive">{error}</p>}

      {/* Submit */}
      <div className="flex items-center justify-end gap-2">
        {onCancel && (
          <Button variant="outline" onClick={onCancel} disabled={saving}>Cancel</Button>
        )}
        <Button onClick={handleSubmit} disabled={saving}>
          {saving && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
          {saving ? "Saving..." : submitLabel}
        </Button>
      </div>
    </div>
  );
}

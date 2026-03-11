import { useState, useEffect } from "react";
import {
  Shield,
  ShieldCheck,
  ShieldBan,
  ShieldAlert,
  SkipForward,
  Plus,
  X,
  ChevronDown,
  Check,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Popover, PopoverTrigger, PopoverContent } from "@/components/ui/popover";
import type {
  Condition,
  ExclusionCreateData,
  ExclusionType,
  GroupOperator,
  ServiceDetail,
  CRSRule,
  CRSAutocompleteResponse,
} from "@/lib/api";
import SecRuleEditor from "../SecRuleEditor";
import {
  type QuickActionType,
  QUICK_ACTIONS,
  ALL_EXCLUSION_TYPES,
  RULE_TAGS,
  isById,
  isByTag,
  isTargetType,
  isRuntimeType,
  type AdvancedFormState,
  emptyAdvancedForm,
} from "./constants";
import type { EventPrefill } from "./eventPrefill";
import { RuleIdTagInput, PipeTagInput } from "./TagInputs";
import { ConditionRow } from "./ConditionBuilder";
import { CRSRulePicker } from "./CRSRulePicker";
import { T } from "@/lib/typography";

// ─── Icon map (avoids passing component refs through constants) ─────

const QUICK_ACTION_ICONS: Record<string, typeof Shield> = {
  ShieldCheck,
  ShieldBan,
  ShieldAlert,
  SkipForward,
};

// ─── Exclusion Type Picker (Popover-based, no Radix Select scroll) ──

function ExclusionTypePicker({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const [open, setOpen] = useState(false);
  const selected = ALL_EXCLUSION_TYPES.find((t) => t.value === value);

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          type="button"
          className="flex h-auto w-full items-center justify-between gap-2 rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-sm ring-offset-background transition-all duration-150 ease-out hover:border-accent-foreground/20 hover:bg-accent/50 focus:outline-none focus:ring-1 focus:ring-ring"
        >
          {selected ? (
            <div className="flex flex-col gap-0.5 text-left">
              <span className="font-medium text-sm">{selected.label}</span>
              <span className="text-xs leading-tight text-muted-foreground">{selected.description}</span>
            </div>
          ) : (
            <span className="text-muted-foreground">Select type...</span>
          )}
          <ChevronDown className="h-4 w-4 shrink-0 opacity-50" />
        </button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-[var(--radix-popover-trigger-width)] p-0">
        <div className="max-h-80 overflow-y-auto p-1">
          {(["quick", "advanced", "runtime"] as const).map((group, gi) => {
            const items = ALL_EXCLUSION_TYPES.filter((t) => t.group === group);
            if (items.length === 0) return null;
            const groupLabel = group === "quick" ? "Quick Actions" : group === "advanced" ? "Global Exclusions" : "Conditional Exclusions";
            return (
              <div key={group}>
                {gi > 0 && <div className="-mx-1 my-1 h-px bg-muted" />}
                <div className="px-2 py-1.5 text-xs font-semibold uppercase tracking-widest text-muted-foreground/60">
                  {groupLabel}
                </div>
                {items.map((t) => (
                  <button
                    key={t.value}
                    type="button"
                    onClick={() => { onChange(t.value); setOpen(false); }}
                    className={cn(
                      "flex w-full cursor-default select-none items-center rounded-sm px-2 py-2 text-left outline-none transition-colors hover:bg-accent hover:text-accent-foreground",
                      t.value === value && "bg-accent text-accent-foreground",
                    )}
                  >
                    <div className="flex flex-col gap-0.5">
                      <span className="font-medium text-sm">{t.label}</span>
                      <span className="text-xs leading-tight text-muted-foreground">{t.description}</span>
                    </div>
                    {t.value === value && <Check className="ml-auto h-4 w-4 shrink-0" />}
                  </button>
                ))}
              </div>
            );
          })}
        </div>
      </PopoverContent>
    </Popover>
  );
}

// ─── Quick Actions Form ─────────────────────────────────────────────

export function QuickActionsForm({
  services,
  crsRules,
  crsCategories,
  onSubmit,
  prefill,
  onPrefillConsumed,
}: {
  services: ServiceDetail[];
  crsRules: CRSRule[];
  crsCategories: { id: string; name: string }[];
  onSubmit: (data: ExclusionCreateData) => void;
  prefill?: EventPrefill | null;
  onPrefillConsumed?: () => void;
}) {
  const [actionType, setActionType] = useState<QuickActionType>("allow");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [conditions, setConditions] = useState<Condition[]>([
    { field: "ip", operator: "ip_match", value: "" },
  ]);
  const [groupOp, setGroupOp] = useState<GroupOperator>("and");
  const [ruleId, setRuleId] = useState("");
  const [ruleTag, setRuleTag] = useState("");
  const [skipMode, setSkipMode] = useState<"id" | "tag">("id");
  const [anomalyScore, setAnomalyScore] = useState(3);
  const [anomalyPL, setAnomalyPL] = useState(1);
  const [enabled, setEnabled] = useState(true);
  const [showPrefillBanner, setShowPrefillBanner] = useState(false);

  // Apply prefill when it arrives (async from useEffect in parent)
  useEffect(() => {
    if (!prefill) return;
    setActionType(prefill.action);
    setName(prefill.name);
    setDescription(prefill.description);
    if (prefill.conditions && prefill.conditions.length > 0) {
      setConditions(prefill.conditions);
    }
    if (prefill.ruleIds) {
      setRuleId(prefill.ruleIds);
      setSkipMode("id");
    }
    setShowPrefillBanner(true);
  }, [prefill]);

  const resetForm = () => {
    setName("");
    setDescription("");
    setConditions([{ field: "ip", operator: "ip_match", value: "" }]);
    setGroupOp("and");
    setRuleId("");
    setRuleTag("");
    setSkipMode("id");
    setAnomalyScore(3);
    setAnomalyPL(1);
    setEnabled(true);
    setShowPrefillBanner(false);
    onPrefillConsumed?.();
  };

  const updateCondition = (index: number, condition: Condition) => {
    setConditions((prev) => prev.map((c, i) => (i === index ? condition : c)));
  };

  const removeCondition = (index: number) => {
    setConditions((prev) => prev.filter((_, i) => i !== index));
  };

  const addCondition = () => {
    setConditions((prev) => [...prev, { field: "path", operator: "eq", value: "" }]);
  };

  const handleSubmit = () => {
    const validConditions = conditions.filter((c) => c.value.trim() !== "");
    const data: ExclusionCreateData = {
      name: name || `${actionType} rule`,
      description,
      type: actionType,
      conditions: validConditions,
      group_operator: groupOp,
      enabled,
    };

    if (actionType === "skip_rule") {
      if (skipMode === "id" && ruleId) data.rule_id = ruleId;
      if (skipMode === "tag" && ruleTag) data.rule_tag = ruleTag;
    }

    if (actionType === "anomaly") {
      data.anomaly_score = anomalyScore;
      data.anomaly_paranoia_level = anomalyPL;
    }

    onSubmit(data);
    resetForm();
  };

  const validConditions = conditions.filter((c) => c.value.trim() !== "");
  const isValid = (() => {
    if (!name.trim()) return false;
    if (validConditions.length === 0) return false;
    if (actionType === "skip_rule") {
      return !!(skipMode === "id" ? ruleId : ruleTag);
    }
    return true;
  })();

  const selectedAction = QUICK_ACTIONS.find((a) => a.value === actionType);
  const SelectedIcon = selectedAction ? (QUICK_ACTION_ICONS[selectedAction.iconName] ?? Shield) : Shield;

  return (
    <div className="space-y-4">
      {/* Prefill banner when created from an event */}
      {showPrefillBanner && prefill && (
        <Alert>
          <ShieldCheck className="h-4 w-4" />
          <AlertTitle>Pre-filled from event</AlertTitle>
          <AlertDescription className="flex items-center justify-between">
            <span className="text-xs">
              {prefill.sourceEvent.rule_msg
                ? `${prefill.sourceEvent.method} ${prefill.sourceEvent.uri?.split("?")[0]} — ${prefill.sourceEvent.rule_msg}`
                : `${prefill.sourceEvent.method} ${prefill.sourceEvent.uri}`}
            </span>
            <Button
              variant="ghost"
              size="xs"
              className="text-muted-foreground hover:text-foreground shrink-0 ml-2"
              onClick={resetForm}
            >
              <X className="h-3 w-3 mr-1" />
              Clear
            </Button>
          </AlertDescription>
        </Alert>
      )}

      {/* Action Type Selector */}
      <div className="grid gap-3 sm:grid-cols-3">
        {QUICK_ACTIONS.map((action) => {
          const Icon = QUICK_ACTION_ICONS[action.iconName] ?? Shield;
          const isActive = actionType === action.value;
          // Color-code by action intent: green=allow, red=block, peach=anomaly, purple=skip
          const colorMap: Record<string, { active: string; icon: string; text: string }> = {
            allow: { active: "border-lv-green/40 bg-lv-green/5", icon: "text-lv-green", text: "text-lv-green" },
            block: { active: "border-lv-red/40 bg-lv-red/5", icon: "text-lv-red", text: "text-lv-red" },
            anomaly: { active: "border-lv-peach/40 bg-lv-peach/5", icon: "text-lv-peach", text: "text-lv-peach" },
            skip_rule: { active: "border-lv-purple/40 bg-lv-purple/5", icon: "text-lv-purple", text: "text-lv-purple" },
          };
          const colors = colorMap[action.value] ?? colorMap.skip_rule;
          return (
            <button
              key={action.value}
              className={`flex flex-col gap-1 rounded-lg border p-3 text-left transition-colors ${
                isActive
                  ? colors.active
                  : "border-border hover:border-muted-foreground/50"
              }`}
              onClick={() => setActionType(action.value)}
            >
              <div className="flex items-center gap-2">
                <Icon className={`h-4 w-4 ${isActive ? colors.icon : "text-muted-foreground"}`} />
                <span className={`text-sm font-medium ${isActive ? colors.text : ""}`}>
                  {action.label}
                </span>
              </div>
              <p className="text-xs text-muted-foreground">{action.description}</p>
            </button>
          );
        })}
      </div>

      <Separator />

      {/* Name & Description */}
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label className={T.formLabel}>Name</Label>
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={
              actionType === "allow" ? "e.g., Allow admin IP"
              : actionType === "block" ? "e.g., Block bad actor"
              : "e.g., Skip SQLi for API"
            }
          />
        </div>
        <div className="space-y-1.5">
          <Label className={T.formLabel}>Description</Label>
          <Input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Optional description"
          />
        </div>
      </div>

      {/* Condition Builder */}
      <div className="space-y-3">
        <Label className={T.formLabel}>
          When incoming requests match...
        </Label>

        <div className={`space-y-2 rounded-md border p-3 ${
          conditions.length > 1
            ? groupOp === "and"
              ? "border-lv-cyan/30 bg-lv-cyan/5"
              : "border-lv-peach/30 bg-lv-peach/5"
            : "border-border bg-lovelace-950/30"
        }`}>
          {conditions.map((c, i) => (
            <div key={i}>
              {i > 0 && conditions.length > 1 && (
                <div className="flex items-center gap-2 py-1.5">
                  <div className="h-px flex-1 bg-border/50" />
                  <div className="flex items-center gap-0.5 rounded-full border border-border/50 bg-lovelace-950/50 p-0.5">
                    <button
                      type="button"
                      onClick={() => setGroupOp("and")}
                      className={`rounded-full px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide transition-colors ${
                        groupOp === "and"
                          ? "bg-lv-cyan/20 text-lv-cyan border border-lv-cyan/30"
                          : "text-muted-foreground hover:text-foreground border border-transparent"
                      }`}
                    >
                      AND
                    </button>
                    <button
                      type="button"
                      onClick={() => setGroupOp("or")}
                      className={`rounded-full px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide transition-colors ${
                        groupOp === "or"
                          ? "bg-lv-peach/20 text-lv-peach border border-lv-peach/30"
                          : "text-muted-foreground hover:text-foreground border border-transparent"
                      }`}
                    >
                      OR
                    </button>
                  </div>
                  <div className="h-px flex-1 bg-border/50" />
                </div>
              )}
              <ConditionRow
                condition={c}
                index={i}
                onChange={updateCondition}
                onRemove={removeCondition}
                services={services}
              />
            </div>
          ))}

          <Button variant="outline" size="sm" onClick={addCondition} className="mt-1">
            <Plus className="h-3.5 w-3.5" />
            Add condition
          </Button>
        </div>
      </div>

      {/* Skip/Bypass: CRS Rule Picker */}
      {actionType === "skip_rule" && (
        <div className="space-y-3">
          <div className="flex items-center gap-4">
            <Label className={T.formLabel}>Skip by:</Label>
            <div className="flex gap-2">
              <Button
                variant={skipMode === "id" ? "default" : "outline"}
                size="sm"
                onClick={() => setSkipMode("id")}
              >
                Rule ID
              </Button>
              <Button
                variant={skipMode === "tag" ? "default" : "outline"}
                size="sm"
                onClick={() => setSkipMode("tag")}
              >
                Rule Tag
              </Button>
            </div>
          </div>

          {skipMode === "id" ? (
            <CRSRulePicker
              rules={crsRules}
              categories={crsCategories}
              selectedRuleIds={ruleId}
              onSelect={setRuleId}
            />
          ) : (
            <div className="space-y-1.5">
              <Label className={T.formLabel}>
                Rule Tag
              </Label>
              <Select value={ruleTag} onValueChange={setRuleTag}>
                <SelectTrigger>
                  <SelectValue placeholder="Select a tag category" />
                </SelectTrigger>
                <SelectContent>
                  {RULE_TAGS.map((tag) => (
                    <SelectItem key={tag} value={tag}>{tag}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
        </div>
      )}

      {/* Anomaly: Score and Paranoia Level */}
      {actionType === "anomaly" && (
        <div className="space-y-3">
          <div className="rounded-lg border border-border/50 bg-muted/30 p-3 text-xs text-muted-foreground">
            <p className="font-medium text-foreground">Anomaly Scoring</p>
            <p className="mt-1">
              Adds anomaly score points to matching requests instead of blocking outright. Multiple heuristic
              signals stack — a request that triggers several low-score rules may cross the blocking threshold.
            </p>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label className={T.formLabel}>Score Points (1-10)</Label>
              <Input
                type="number"
                min={1}
                max={10}
                value={anomalyScore}
                onChange={(e) => setAnomalyScore(Math.min(10, Math.max(1, parseInt(e.target.value) || 1)))}
              />
              <p className="text-xs text-muted-foreground">+1 minor signal, +3 moderate, +5 strong, +10 critical</p>
            </div>
            <div className="space-y-1.5">
              <Label className={T.formLabel}>Paranoia Level</Label>
              <Select value={String(anomalyPL)} onValueChange={(v) => setAnomalyPL(parseInt(v))}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">PL 1 (default)</SelectItem>
                  <SelectItem value="2">PL 2</SelectItem>
                  <SelectItem value="3">PL 3</SelectItem>
                  <SelectItem value="4">PL 4</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">Which paranoia level score bucket to increment</p>
            </div>
          </div>
        </div>
      )}

      {/* Enabled + Submit */}
      <div className="flex items-center gap-4 pt-2">
        <Button onClick={handleSubmit} disabled={!isValid}>
          <SelectedIcon className="h-4 w-4" />
          {actionType === "allow" ? "Add Allow Rule" : actionType === "block" ? "Add Block Rule" : actionType === "anomaly" ? "Add Anomaly Rule" : "Add Skip Rule"}
        </Button>
        <div className="flex items-center gap-2">
          <Switch checked={enabled} onCheckedChange={setEnabled} id="qa-enabled" />
          <Label htmlFor="qa-enabled" className="text-sm">
            {enabled ? "Enabled" : "Disabled"}
          </Label>
        </div>
      </div>
    </div>
  );
}

// ─── Advanced Builder Form ──────────────────────────────────────────

export function AdvancedBuilderForm({
  initial,
  services,
  onSubmit,
  onCancel,
  submitLabel,
}: {
  initial?: AdvancedFormState;
  services: ServiceDetail[];
  onSubmit: (data: ExclusionCreateData) => void;
  onCancel?: () => void;
  submitLabel: string;
}) {
  const [form, setForm] = useState<AdvancedFormState>(initial ?? emptyAdvancedForm);

  const update = (field: keyof AdvancedFormState, value: string | number | boolean | Condition[] | GroupOperator | string[]) => {
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  const isQuickAction = ["allow", "block", "skip_rule", "anomaly"].includes(form.type);
  const needsRuleId = isById(form.type) || form.type === "skip_rule";
  const needsRuleTag = isByTag(form.type) || form.type === "skip_rule";
  const needsVariable = isTargetType(form.type);
  const needsConditions = isRuntimeType(form.type) || isQuickAction;
  const needsAnomalyFields = form.type === "anomaly";

  // Condition management for runtime types
  const updateCondition = (index: number, condition: Condition) => {
    const next = form.conditions.map((c, i) => (i === index ? condition : c));
    update("conditions", next);
  };

  const removeCondition = (index: number) => {
    update("conditions", form.conditions.filter((_, i) => i !== index));
  };

  const addCondition = () => {
    update("conditions", [...form.conditions, { field: "path", operator: "eq", value: "" }]);
  };

  // When switching to a type that needs conditions, ensure at least one exists
  const handleTypeChange = (v: string) => {
    const newType = v as ExclusionType;
    const willNeedConditions = isRuntimeType(newType) || ["allow", "block", "skip_rule", "anomaly"].includes(newType);
    const willNeedRuleId = isById(newType) || newType === "skip_rule";
    const willNeedRuleTag = isByTag(newType) || newType === "skip_rule";
    const willNeedVariable = isTargetType(newType);
    const hadConditions = form.conditions.length > 0;
    setForm((prev) => ({
      ...prev,
      type: newType,
      // Clear fields that the new type doesn't use
      rule_id: willNeedRuleId ? prev.rule_id : "",
      rule_tag: willNeedRuleTag ? prev.rule_tag : "",
      variable: willNeedVariable ? prev.variable : "",
      conditions: willNeedConditions
        ? (hadConditions ? prev.conditions : [{ field: "path", operator: "eq", value: "" }])
        : [],
    }));
  };

  const handleSubmit = () => {
    const validConditions = form.conditions.filter((c) => c.value.trim() !== "");
    const data: ExclusionCreateData = {
      name: form.name || `${form.type} exclusion`,
      description: form.description,
      type: form.type,
      enabled: form.enabled,
    };
    if (needsRuleId && form.rule_id) data.rule_id = form.rule_id;
    if (needsRuleTag && form.rule_tag) data.rule_tag = form.rule_tag;
    if (needsVariable && form.variable) data.variable = form.variable;
    if (needsAnomalyFields) {
      data.anomaly_score = form.anomaly_score;
      data.anomaly_paranoia_level = form.anomaly_paranoia_level;
    }
    if (needsConditions && validConditions.length > 0) {
      data.conditions = validConditions;
      data.group_operator = form.group_operator;
    }
    if (form.tags && form.tags.length > 0) data.tags = form.tags;
    onSubmit(data);
  };

  const isValid = (() => {
    if (form.name.trim() === "") return false;
    // skip_rule needs either rule_id or rule_tag
    if (form.type === "skip_rule") {
      if (form.rule_id.trim() === "" && form.rule_tag.trim() === "") return false;
    } else {
      // configure-time types: ById needs rule_id, ByTag needs rule_tag
      if (isById(form.type) && form.rule_id.trim() === "") return false;
      if (isByTag(form.type) && form.rule_tag.trim() === "") return false;
    }
    // Types that need conditions (runtime ctl: + quick actions)
    if (needsConditions) {
      const validConds = form.conditions.filter((c) => c.value.trim() !== "");
      if (validConds.length === 0) return false;
    }
    return true;
  })();

  return (
    <div className="space-y-3">
      {/* Name & Description */}
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label className={T.formLabel}>Name</Label>
          <Input value={form.name} onChange={(e) => update("name", e.target.value)} placeholder="e.g., Allow WordPress admin" />
        </div>
        <div className="space-y-1.5">
          <Label className={T.formLabel}>Description</Label>
          <Input value={form.description} onChange={(e) => update("description", e.target.value)} placeholder="Optional description" />
        </div>
      </div>

      {/* Exclusion Type */}
      <div className="space-y-1">
        <div className="flex items-center gap-2">
          <Label className={T.formLabel}>Exclusion Type</Label>
          {/* Color-coded intent indicator */}
          {form.type === "allow" && <span className="inline-flex items-center rounded bg-lv-green/20 border border-lv-green/30 px-1.5 py-0 text-[10px] font-semibold uppercase text-lv-green">Allow</span>}
          {form.type === "block" && <span className="inline-flex items-center rounded bg-lv-red/20 border border-lv-red/30 px-1.5 py-0 text-[10px] font-semibold uppercase text-lv-red">Block</span>}
          {form.type === "anomaly" && <span className="inline-flex items-center rounded bg-lv-peach/20 border border-lv-peach/30 px-1.5 py-0 text-[10px] font-semibold uppercase text-lv-peach">Anomaly</span>}
          {form.type === "skip_rule" && <span className="inline-flex items-center rounded bg-lv-purple/20 border border-lv-purple/30 px-1.5 py-0 text-[10px] font-semibold uppercase text-lv-purple">Skip</span>}
          {form.type === "raw" && <span className="inline-flex items-center rounded bg-lv-blue/20 border border-lv-blue/30 px-1.5 py-0 text-[10px] font-semibold uppercase text-lv-blue">Raw</span>}
          {isRuntimeType(form.type) && <span className="inline-flex items-center rounded bg-lv-cyan/20 border border-lv-cyan/30 px-1.5 py-0 text-[10px] font-semibold uppercase text-lv-cyan">Runtime</span>}
          {(form.type.startsWith("SecRule") && !isRuntimeType(form.type)) && <span className="inline-flex items-center rounded bg-lovelace-600/30 border border-lovelace-600/50 px-1.5 py-0 text-[10px] font-semibold uppercase text-muted-foreground">Config-time</span>}
        </div>
        <ExclusionTypePicker value={form.type} onChange={handleTypeChange} />
      </div>

      {/* Rule ID / Tag / Variable fields */}
      {(needsRuleId || needsRuleTag || needsVariable) && (
        <div className="grid gap-3 sm:grid-cols-2">
          {needsRuleId && (
            <div className="space-y-1.5">
              <Label className={T.formLabel}>Rule ID / Range</Label>
              <RuleIdTagInput
                value={form.rule_id}
                onChange={(v) => update("rule_id", v)}
                placeholder="e.g., 941100, 942000-942999 (Enter to add)"
              />
            </div>
          )}
          {needsRuleTag && (
            <div className="space-y-1.5">
              <Label className={T.formLabel}>Rule Tag</Label>
              <Select value={form.rule_tag} onValueChange={(v) => update("rule_tag", v)}>
                <SelectTrigger>
                  <SelectValue placeholder="Select a tag" />
                </SelectTrigger>
                <SelectContent>
                  {RULE_TAGS.map((tag) => (
                    <SelectItem key={tag} value={tag}>{tag}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
          {needsVariable && (
            <div className="space-y-1.5">
              <Label className={T.formLabel}>Variable</Label>
              <Input value={form.variable} onChange={(e) => update("variable", e.target.value)} placeholder='e.g., ARGS:wp_post, REQUEST_COOKIES:/^uid_.*/' />
            </div>
          )}
        </div>
      )}

      {/* Anomaly score fields */}
      {needsAnomalyFields && (
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label className={T.formLabel}>Score Points (1-10)</Label>
            <Input
              type="number"
              min={1}
              max={10}
              value={form.anomaly_score}
              onChange={(e) => update("anomaly_score", Math.min(10, Math.max(1, parseInt(e.target.value) || 1)))}
            />
          </div>
          <div className="space-y-1.5">
            <Label className={T.formLabel}>Paranoia Level</Label>
            <Select value={String(form.anomaly_paranoia_level)} onValueChange={(v) => update("anomaly_paranoia_level", parseInt(v))}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="1">PL 1 (default)</SelectItem>
                <SelectItem value="2">PL 2</SelectItem>
                <SelectItem value="3">PL 3</SelectItem>
                <SelectItem value="4">PL 4</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      )}

      {/* Condition builder for runtime ctl: types */}
      {needsConditions && (
        <div className="space-y-3">
          <Label className={T.formLabel}>
            Apply when requests match...
          </Label>

          <div className={`space-y-2 rounded-md border p-3 ${
            form.conditions.length > 1
              ? form.group_operator === "and"
                ? "border-lv-cyan/30 bg-lv-cyan/5"
                : "border-lv-peach/30 bg-lv-peach/5"
              : "border-border bg-lovelace-950/30"
          }`}>
            {form.conditions.map((c, i) => (
              <div key={i}>
                {i > 0 && form.conditions.length > 1 && (
                  <div className="flex items-center gap-2 py-1.5">
                    <div className="h-px flex-1 bg-border/50" />
                    <div className="flex items-center gap-0.5 rounded-full border border-border/50 bg-lovelace-950/50 p-0.5">
                      <button
                        type="button"
                        onClick={() => update("group_operator", "and" as GroupOperator)}
                        className={`rounded-full px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide transition-colors ${
                          form.group_operator === "and"
                            ? "bg-lv-cyan/20 text-lv-cyan border border-lv-cyan/30"
                            : "text-muted-foreground hover:text-foreground border border-transparent"
                        }`}
                      >
                        AND
                      </button>
                      <button
                        type="button"
                        onClick={() => update("group_operator", "or" as GroupOperator)}
                        className={`rounded-full px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide transition-colors ${
                          form.group_operator === "or"
                            ? "bg-lv-peach/20 text-lv-peach border border-lv-peach/30"
                            : "text-muted-foreground hover:text-foreground border border-transparent"
                        }`}
                      >
                        OR
                      </button>
                    </div>
                    <div className="h-px flex-1 bg-border/50" />
                  </div>
                )}
                <ConditionRow
                  condition={c}
                  index={i}
                  onChange={updateCondition}
                  onRemove={removeCondition}
                  services={services}
                />
              </div>
            ))}

            <Button variant="outline" size="sm" onClick={addCondition} className="mt-1">
              <Plus className="h-3.5 w-3.5" />
              Add condition
            </Button>
          </div>
        </div>
      )}

      {/* Tags */}
      <div className="space-y-1.5">
        <Label className={T.formLabel}>Tags</Label>
        <PipeTagInput
          value={form.tags.join("|")}
          onChange={(v) => update("tags", v ? v.split("|").filter(Boolean) : [])}
          placeholder="e.g., scanner, bot-detection, temporary (Enter to add)"
        />
        <p className="text-xs text-muted-foreground">
          Optional labels for organizing rules and classifying events
        </p>
      </div>

      {/* Enabled */}
      <div className="flex items-center gap-2">
        <Switch checked={form.enabled} onCheckedChange={(v) => update("enabled", v)} id="adv-enabled" />
        <Label htmlFor="adv-enabled" className="text-sm">{form.enabled ? "Enabled" : "Disabled"}</Label>
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2 pt-2">
        <Button onClick={handleSubmit} disabled={!isValid}>
          <Plus className="h-4 w-4" />
          {submitLabel}
        </Button>
        {onCancel && (
          <Button variant="outline" onClick={onCancel}>Cancel</Button>
        )}
      </div>
    </div>
  );
}

// ─── Raw Editor Form ────────────────────────────────────────────────

export function RawEditorForm({
  autocompleteData,
  crsRules,
  onSubmit,
}: {
  autocompleteData: CRSAutocompleteResponse | null;
  crsRules: CRSRule[];
  onSubmit: (data: ExclusionCreateData) => void;
}) {
  const [name, setName] = useState("");
  const [rawRule, setRawRule] = useState("");

  const handleSubmit = () => {
    if (!name.trim() || !rawRule.trim()) return;
    onSubmit({
      name,
      description: "Raw SecRule expression",
      type: "raw",
      enabled: true,
      raw_rule: rawRule,
    });
    setName("");
    setRawRule("");
  };

  return (
    <div className="space-y-4">
      <div className="space-y-1.5">
        <Label className={T.formLabel}>Name</Label>
        <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Exclusion name" />
      </div>

      <div className="space-y-1.5">
        <Label className={T.formLabel}>
          SecRule Directive
        </Label>
        <p className="text-xs text-muted-foreground mb-2">
          Type @ for operators, uppercase for variables, digits for CRS rule IDs. Ctrl+Space for completions.
        </p>
        <SecRuleEditor
          value={rawRule}
          onChange={setRawRule}
          autocompleteData={autocompleteData}
          crsRules={crsRules}
          minHeight="250px"
          placeholder={`SecRule REQUEST_URI "@streq /api/upload" \\
    "id:10001,\\
    phase:1,\\
    pass,\\
    t:none,\\
    nolog,\\
    ctl:ruleRemoveById=942100"`}
        />
      </div>

      <Button onClick={handleSubmit} disabled={!name.trim() || !rawRule.trim()}>
        <Plus className="h-4 w-4" />
        Add Raw Rule
      </Button>
    </div>
  );
}



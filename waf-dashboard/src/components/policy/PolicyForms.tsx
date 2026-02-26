import { useState, useEffect } from "react";
import {
  Shield,
  ShieldCheck,
  ShieldBan,
  SkipForward,
  Plus,
  X,
} from "lucide-react";
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
import { RuleIdTagInput } from "./TagInputs";
import { ConditionRow } from "./ConditionBuilder";
import { CRSRulePicker } from "./CRSRulePicker";
import { T } from "@/lib/typography";

// ─── Icon map (avoids passing component refs through constants) ─────

const QUICK_ACTION_ICONS: Record<string, typeof Shield> = {
  ShieldCheck,
  ShieldBan,
  SkipForward,
};

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
          return (
            <button
              key={action.value}
              className={`flex flex-col gap-1 rounded-lg border p-3 text-left transition-colors ${
                isActive
                  ? "border-neon-cyan bg-neon-cyan/5"
                  : "border-border hover:border-muted-foreground/50"
              }`}
              onClick={() => setActionType(action.value)}
            >
              <div className="flex items-center gap-2">
                <Icon className={`h-4 w-4 ${isActive ? "text-neon-cyan" : "text-muted-foreground"}`} />
                <span className={`text-sm font-medium ${isActive ? "text-neon-cyan" : ""}`}>
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
        <div className="flex items-center justify-between">
          <Label className={T.formLabel}>
            When incoming requests match...
          </Label>
          {conditions.length > 1 && (
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">Match:</span>
              <Select value={groupOp} onValueChange={(v) => setGroupOp(v as GroupOperator)}>
                <SelectTrigger className="h-7 w-[90px] text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="and">All (AND)</SelectItem>
                  <SelectItem value="or">Any (OR)</SelectItem>
                </SelectContent>
              </Select>
            </div>
          )}
        </div>

        <div className="space-y-2 rounded-md border border-border bg-navy-950/30 p-3">
          {conditions.map((c, i) => (
            <div key={i}>
              {i > 0 && (
                <div className="flex items-center gap-2 py-1">
                  <div className="h-px flex-1 bg-border" />
                  <span className="text-xs font-medium uppercase text-muted-foreground">
                    {groupOp}
                  </span>
                  <div className="h-px flex-1 bg-border" />
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

      {/* Enabled + Submit */}
      <div className="flex items-center gap-4 pt-2">
        <Button onClick={handleSubmit} disabled={!isValid}>
          <SelectedIcon className="h-4 w-4" />
          {actionType === "allow" ? "Add Allow Rule" : actionType === "block" ? "Add Block Rule" : "Add Skip Rule"}
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

  const update = (field: keyof AdvancedFormState, value: string | boolean | Condition[] | GroupOperator) => {
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  const isQuickAction = ["allow", "block", "skip_rule"].includes(form.type);
  const needsRuleId = isById(form.type) || form.type === "skip_rule";
  const needsRuleTag = isByTag(form.type) || form.type === "skip_rule";
  const needsVariable = isTargetType(form.type);
  const needsConditions = isRuntimeType(form.type) || isQuickAction;

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
    const willNeedConditions = isRuntimeType(newType) || ["allow", "block", "skip_rule"].includes(newType);
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
    if (needsConditions && validConditions.length > 0) {
      data.conditions = validConditions;
      data.group_operator = form.group_operator;
    }
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
    <div className="space-y-4">
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
      <div className="space-y-1.5">
        <Label className={T.formLabel}>Exclusion Type</Label>
        <Select value={form.type} onValueChange={handleTypeChange}>
          <SelectTrigger className="h-auto py-2">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {(["quick", "advanced", "runtime"] as const).map((group, gi) => {
              const items = ALL_EXCLUSION_TYPES.filter((t) => t.group === group);
              if (items.length === 0) return null;
              const groupLabel = group === "quick" ? "Quick Actions" : group === "advanced" ? "Configure-time" : "Runtime (per-request)";
              return [
                gi > 0 ? <SelectSeparator key={`sep-${group}`} /> : null,
                <SelectGroup key={`group-${group}`}>
                  <SelectLabel className="text-xs uppercase tracking-widest text-muted-foreground/60">
                    {groupLabel}
                  </SelectLabel>
                  {items.map((t) => (
                    <SelectItem key={t.value} value={t.value} textValue={t.label} className="py-2">
                      <div className="flex flex-col gap-0.5">
                        <span className="font-medium text-sm">{t.label}</span>
                        <span className="text-xs leading-tight text-muted-foreground">{t.description}</span>
                      </div>
                    </SelectItem>
                  ))}
                </SelectGroup>,
              ];
            })}
          </SelectContent>
        </Select>
      </div>

      {/* Rule ID / Tag / Variable fields */}
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

      {/* Condition builder for runtime ctl: types */}
      {needsConditions && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <Label className={T.formLabel}>
              Apply when requests match...
            </Label>
            {form.conditions.length > 1 && (
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">Match:</span>
                <Select value={form.group_operator} onValueChange={(v) => update("group_operator", v as GroupOperator)}>
                  <SelectTrigger className="h-7 w-[90px] text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="and">All (AND)</SelectItem>
                    <SelectItem value="or">Any (OR)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}
          </div>

          <div className="space-y-2 rounded-md border border-border bg-navy-950/30 p-3">
            {form.conditions.map((c, i) => (
              <div key={i}>
                {i > 0 && (
                  <div className="flex items-center gap-2 py-1">
                    <div className="h-px flex-1 bg-border" />
                    <span className="text-xs font-medium uppercase text-muted-foreground">
                      {form.group_operator}
                    </span>
                    <div className="h-px flex-1 bg-border" />
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

// ─── Honeypot Form ──────────────────────────────────────────────────

export function HoneypotForm({ onSubmit }: { onSubmit: (data: ExclusionCreateData) => void }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [pathsText, setPathsText] = useState("");
  const [enabled, setEnabled] = useState(true);

  const resetForm = () => {
    setName("");
    setDescription("");
    setPathsText("");
    setEnabled(true);
  };

  const handleSubmit = () => {
    // Parse paths: one per line, trim whitespace, remove empty lines and comments
    const paths = pathsText
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#"));

    if (paths.length === 0) return;

    const data: ExclusionCreateData = {
      name: name || "Honeypot paths",
      description,
      type: "honeypot",
      conditions: [{ field: "path", operator: "in", value: paths.join(" ") }],
      enabled,
    };

    onSubmit(data);
    resetForm();
  };

  const pathCount = pathsText
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#")).length;

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-border/50 bg-muted/30 p-3 text-xs text-muted-foreground">
        <p className="font-medium text-foreground">Dynamic Honeypot Paths</p>
        <p className="mt-1">
          Add path fragments that should never appear in legitimate traffic (e.g., WordPress,
          PHP admin panels, dotfiles). Requests matching these paths are instantly blocked
          with 403 and tagged as honeypot events. Matched via substring (Aho-Corasick).
        </p>
        <p className="mt-1">
          All honeypot paths are managed here. Paths are consolidated into a single
          high-performance rule and deployed to the WAF.
        </p>
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        <div className="space-y-1.5">
          <label className="text-xs font-medium">Group Name</label>
          <Input
            placeholder="e.g., Custom WordPress paths"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <div className="space-y-1.5">
          <label className="text-xs font-medium">Description (optional)</label>
          <Input
            placeholder="e.g., Additional WP paths not in the default list"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>
      </div>

      <div className="space-y-1.5">
        <label className="text-xs font-medium">
          Paths (one per line, # for comments)
          {pathCount > 0 && (
            <span className="ml-2 text-muted-foreground">({pathCount} paths)</span>
          )}
        </label>
        <textarea
          className="flex min-h-[200px] w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          placeholder={"# WordPress\n/wp-login.php\n/wp-admin/\n/xmlrpc.php\n\n# PHP admin panels\n/phpmyadmin\n/adminer\n\n# Dotfiles\n/.env\n/.git/\n/.aws/"}
          value={pathsText}
          onChange={(e) => setPathsText(e.target.value)}
        />
      </div>

      <div className="flex items-center gap-2">
        <input
          type="checkbox"
          id="honeypot-enabled"
          checked={enabled}
          onChange={(e) => setEnabled(e.target.checked)}
          className="h-4 w-4 rounded border-gray-300"
        />
        <label htmlFor="honeypot-enabled" className="text-xs">Enabled</label>
      </div>

      <Button onClick={handleSubmit} disabled={pathCount === 0}>
        <Plus className="h-4 w-4" />
        Add Honeypot Group
      </Button>
    </div>
  );
}

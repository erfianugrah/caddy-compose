import { useState, useEffect } from "react";
import {
  Shield,
  ShieldCheck,
  ShieldBan,
  ShieldQuestion,
  ShieldMinus,
  ShieldAlert,
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
  SelectItem,
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
  SkipTargets,
} from "@/lib/api";
import {
  type QuickActionType,
  QUICK_ACTIONS,
  ALL_EXCLUSION_TYPES,
  type AdvancedFormState,
  emptyAdvancedForm,
  INBOUND_FIELD_DEFS,
  OUTBOUND_FIELD_DEFS,
} from "./constants";
import type { EventPrefill } from "./eventPrefill";
import { PipeTagInput, RuleIdTagInput, parseRuleIds } from "./TagInputs";
import { ConditionRow } from "./ConditionBuilder";
import { T } from "@/lib/typography";

// ─── Icon map (avoids passing component refs through constants) ─────

const QUICK_ACTION_ICONS: Record<string, typeof Shield> = {
  ShieldCheck,
  ShieldBan,
  ShieldQuestion,
  ShieldMinus,
  ShieldAlert,
};

// ─── Detect severity options ────────────────────────────────────────

const SEVERITY_OPTIONS = [
  { value: "NOTICE", label: "Notice", description: "Low severity — informational signal" },
  { value: "WARNING", label: "Warning", description: "Medium severity — suspicious activity" },
  { value: "ERROR", label: "Error", description: "High severity — likely malicious" },
  { value: "CRITICAL", label: "Critical", description: "Highest severity — definite attack" },
];

// ─── Skip target phase options ──────────────────────────────────────

const SKIP_PHASES = [
  { value: "detect", label: "Detect", description: "Skip all CRS/anomaly detection rules" },
  { value: "rate_limit", label: "Rate Limit", description: "Skip all rate limiting rules" },
  { value: "block", label: "Block", description: "Skip all block rules" },
];

// ─── Skip Targets Form ─────────────────────────────────────────────

function SkipTargetsForm({
  value,
  onChange,
}: {
  value: SkipTargets;
  onChange: (targets: SkipTargets) => void;
}) {
  const ruleIds = (value.rules ?? []).join(" ");
  const phases = value.phases ?? [];
  const allRemaining = value.all_remaining ?? false;

  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-border/50 bg-muted/30 p-3 text-xs text-muted-foreground">
        <p className="font-medium text-foreground">Skip Rule</p>
        <p className="mt-1">
          Selectively bypass specific rules or entire evaluation phases for matching requests.
          Unlike Allow (which terminates evaluation), Skip accumulates targets and later phases
          check the skip list before evaluating.
        </p>
      </div>

      {/* All Remaining toggle */}
      <div className="flex items-center gap-2">
        <Switch
          id="skip-all-remaining"
          checked={allRemaining}
          onCheckedChange={(checked) => {
            onChange({
              ...value,
              all_remaining: checked,
              // Clear specific targets when all_remaining is toggled on
              ...(checked ? { rules: undefined, phases: undefined } : {}),
            });
          }}
        />
        <Label htmlFor="skip-all-remaining" className="text-sm font-medium">
          Skip all remaining rules
        </Label>
        <span className="text-xs text-muted-foreground">(bypass all block, detect, and rate limit rules)</span>
      </div>

      {!allRemaining && (
        <>
          {/* Phase toggles */}
          <div className="space-y-1.5">
            <Label className={T.formLabel}>Skip Phases</Label>
            <div className="flex flex-wrap gap-4">
              {SKIP_PHASES.map((phase) => {
                const checked = phases.includes(phase.value);
                return (
                  <div key={phase.value} className="flex items-center gap-2">
                    <Switch
                      id={`skip-phase-${phase.value}`}
                      checked={checked}
                      onCheckedChange={(c) => {
                        const next = c
                          ? [...phases, phase.value]
                          : phases.filter((p) => p !== phase.value);
                        onChange({ ...value, phases: next.length > 0 ? next : undefined });
                      }}
                    />
                    <Label htmlFor={`skip-phase-${phase.value}`} className="text-sm">
                      {phase.label}
                    </Label>
                  </div>
                );
              })}
            </div>
            <p className="text-xs text-muted-foreground">
              Skip all rules in the selected evaluation phases
            </p>
          </div>

          {/* Rule IDs */}
          <div className="space-y-1.5">
            <Label className={T.formLabel}>Skip Specific Rule IDs</Label>
            <RuleIdTagInput
              value={ruleIds}
              onChange={(v) => {
                const ids = parseRuleIds(v);
                onChange({ ...value, rules: ids.length > 0 ? ids : undefined });
              }}
              placeholder="Type rule IDs to skip (Enter to add)"
            />
            <p className="text-xs text-muted-foreground">
              Skip individual rules by ID — these are policy engine rule IDs from your block/detect/rate-limit rules
            </p>
          </div>
        </>
      )}
    </div>
  );
}

// ─── Response Header Form ───────────────────────────────────────────

function HeaderKeyValueSection({
  label,
  description,
  entries,
  onChange,
}: {
  label: string;
  description: string;
  entries: Record<string, string>;
  onChange: (entries: Record<string, string>) => void;
}) {
  const pairs = Object.entries(entries);
  const [newKey, setNewKey] = useState("");
  const [newValue, setNewValue] = useState("");

  const addPair = () => {
    const key = newKey.trim();
    if (!key) return;
    onChange({ ...entries, [key]: newValue });
    setNewKey("");
    setNewValue("");
  };

  const removePair = (key: string) => {
    const next = { ...entries };
    delete next[key];
    onChange(next);
  };

  return (
    <div className="space-y-2">
      <div>
        <p className="text-sm font-medium">{label}</p>
        <p className="text-xs text-muted-foreground">{description}</p>
      </div>
      {pairs.length > 0 && (
        <div className="space-y-1">
          {pairs.map(([k, v]) => (
            <div key={k} className="flex items-center gap-2">
              <code className="rounded bg-muted/50 px-1.5 py-0.5 text-xs font-mono">{k}</code>
              <span className="text-xs text-muted-foreground">:</span>
              <code className="rounded bg-muted/50 px-1.5 py-0.5 text-xs font-mono flex-1 truncate">{v}</code>
              <Button variant="ghost" size="icon-sm" onClick={() => removePair(k)} className="text-muted-foreground hover:text-lv-red shrink-0">
                <X className="h-3 w-3" />
              </Button>
            </div>
          ))}
        </div>
      )}
      <div className="flex items-center gap-2">
        <Input
          value={newKey}
          onChange={(e) => setNewKey(e.target.value)}
          placeholder="Header name"
          className="h-7 text-xs flex-1"
          onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addPair(); } }}
        />
        <Input
          value={newValue}
          onChange={(e) => setNewValue(e.target.value)}
          placeholder="Value"
          className="h-7 text-xs flex-1"
          onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addPair(); } }}
        />
        <Button variant="outline" size="sm" onClick={addPair} disabled={!newKey.trim()} className="shrink-0 h-7 text-xs">
          <Plus className="h-3 w-3" />
        </Button>
      </div>
    </div>
  );
}

function HeaderRemoveSection({
  headers,
  onChange,
}: {
  headers: string[];
  onChange: (headers: string[]) => void;
}) {
  const [newHeader, setNewHeader] = useState("");

  const addHeader = () => {
    const h = newHeader.trim();
    if (!h || headers.includes(h)) return;
    onChange([...headers, h]);
    setNewHeader("");
  };

  const removeHeader = (h: string) => {
    onChange(headers.filter((x) => x !== h));
  };

  return (
    <div className="space-y-2">
      <div>
        <p className="text-sm font-medium">Remove Headers</p>
        <p className="text-xs text-muted-foreground">Headers to strip from the response</p>
      </div>
      {headers.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {headers.map((h) => (
            <span key={h} className="inline-flex items-center gap-1 rounded bg-lv-red/10 border border-lv-red/20 px-1.5 py-0.5 text-xs font-mono">
              {h}
              <button onClick={() => removeHeader(h)} className="text-muted-foreground hover:text-lv-red">
                <X className="h-2.5 w-2.5" />
              </button>
            </span>
          ))}
        </div>
      )}
      <div className="flex items-center gap-2">
        <Input
          value={newHeader}
          onChange={(e) => setNewHeader(e.target.value)}
          placeholder="Header name to remove"
          className="h-7 text-xs flex-1"
          onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addHeader(); } }}
        />
        <Button variant="outline" size="sm" onClick={addHeader} disabled={!newHeader.trim()} className="shrink-0 h-7 text-xs">
          <Plus className="h-3 w-3" />
        </Button>
      </div>
    </div>
  );
}

function ResponseHeaderForm({
  headerSet,
  headerAdd,
  headerRemove,
  headerDefault,
  onChangeSet,
  onChangeAdd,
  onChangeRemove,
  onChangeDefault,
}: {
  headerSet: Record<string, string>;
  headerAdd: Record<string, string>;
  headerRemove: string[];
  headerDefault: Record<string, string>;
  onChangeSet: (v: Record<string, string>) => void;
  onChangeAdd: (v: Record<string, string>) => void;
  onChangeRemove: (v: string[]) => void;
  onChangeDefault: (v: Record<string, string>) => void;
}) {
  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-border/50 bg-muted/30 p-3 text-xs text-muted-foreground">
        <p className="font-medium text-foreground">Response Header Rule</p>
        <p className="mt-1">
          Modify response headers for matching requests. Set replaces existing values, Add appends
          (allows multiple values), Remove strips headers, and Default sets only if not already present.
        </p>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <HeaderKeyValueSection
          label="Set Headers"
          description="Replace or create header with this value"
          entries={headerSet}
          onChange={onChangeSet}
        />
        <HeaderKeyValueSection
          label="Add Headers"
          description="Append header (does not replace existing)"
          entries={headerAdd}
          onChange={onChangeAdd}
        />
        <HeaderRemoveSection
          headers={headerRemove}
          onChange={onChangeRemove}
        />
        <HeaderKeyValueSection
          label="Default Headers"
          description="Set only if header is not already present"
          entries={headerDefault}
          onChange={onChangeDefault}
        />
      </div>
    </div>
  );
}

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
          {ALL_EXCLUSION_TYPES.map((t) => (
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
      </PopoverContent>
    </Popover>
  );
}

// ─── Quick Actions Form ─────────────────────────────────────────────

export function QuickActionsForm({
  services,
  onSubmit,
  prefill,
  onPrefillConsumed,
}: {
  services: ServiceDetail[];
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
  const [enabled, setEnabled] = useState(true);
  const [tags, setTags] = useState<string[]>([]);
  const [showPrefillBanner, setShowPrefillBanner] = useState(false);

  // Detect-specific state
  const [severity, setSeverity] = useState("WARNING");
  const [detectPL, setDetectPL] = useState(0);

  // Skip-specific state
  const [skipTargets, setSkipTargets] = useState<SkipTargets>({});

  // Challenge-specific state
  const [challengeDifficulty, setChallengeDifficulty] = useState(4);
  const [challengeAlgorithm, setChallengeAlgorithm] = useState("fast");
  const [challengeTTL, setChallengeTTL] = useState("1h");
  const [challengeBindIP, setChallengeBindIP] = useState(true);
  const [challengeBindJA4, setChallengeBindJA4] = useState(true);

  // Apply prefill when it arrives (async from useEffect in parent)
  useEffect(() => {
    if (!prefill) return;
    setActionType(prefill.action);
    setName(prefill.name);
    setDescription(prefill.description);
    if (prefill.conditions && prefill.conditions.length > 0) {
      setConditions(prefill.conditions);
    }
    // Pre-populate skip targets from matched rule IDs so switching to Skip is seamless
    if (prefill.suggestedSkipTargets) {
      setSkipTargets(prefill.suggestedSkipTargets);
    }
    setShowPrefillBanner(true);
  }, [prefill]);

  const resetForm = () => {
    setName("");
    setDescription("");
    setConditions([{ field: "ip", operator: "ip_match", value: "" }]);
    setGroupOp("and");
    setSeverity("WARNING");
    setDetectPL(0);
    setSkipTargets({});
    setChallengeDifficulty(4);
    setChallengeAlgorithm("fast");
    setChallengeTTL("1h");
    setChallengeBindIP(true);
    setChallengeBindJA4(true);
    setEnabled(true);
    setTags([]);
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

    if (actionType === "detect") {
      data.severity = severity;
      if (detectPL > 0) data.detect_paranoia_level = detectPL;
    }
    if (actionType === "skip") {
      const hasTargets = skipTargets.all_remaining || (skipTargets.rules?.length ?? 0) > 0 || (skipTargets.phases?.length ?? 0) > 0;
      if (hasTargets) data.skip_targets = skipTargets;
    }
    if (actionType === "challenge") {
      data.challenge_difficulty = challengeDifficulty;
      data.challenge_algorithm = challengeAlgorithm as "fast" | "slow";
      data.challenge_ttl = challengeTTL;
      data.challenge_bind_ip = challengeBindIP;
      data.challenge_bind_ja4 = challengeBindJA4;
    }
    if (tags.length > 0) data.tags = tags;

    onSubmit(data);
    resetForm();
  };

  const validConditions = conditions.filter((c) => c.value.trim() !== "");
  const isValid = (() => {
    if (!name.trim()) return false;
    if (validConditions.length === 0) return false;
    if (actionType === "detect" && !severity) return false;
    if (actionType === "skip") {
      const hasTargets = skipTargets.all_remaining || (skipTargets.rules?.length ?? 0) > 0 || (skipTargets.phases?.length ?? 0) > 0;
      if (!hasTargets) return false;
    }
    return true;
  })();

  const selectedAction = QUICK_ACTIONS.find((a) => a.value === actionType);
  const SelectedIcon = selectedAction ? (QUICK_ACTION_ICONS[selectedAction.iconName] ?? Shield) : Shield;

  return (
    <div className="space-y-4">
      {/* Prefill banner when created from an event or quick-action link */}
      {showPrefillBanner && prefill && (
        <Alert>
          <ShieldCheck className="h-4 w-4" />
          <AlertTitle>{prefill.sourceEvent.id ? "Pre-filled from event" : "Pre-filled from quick action"}</AlertTitle>
          <AlertDescription className="flex items-center justify-between">
            <span className="text-xs">
              {prefill.sourceEvent.rule_msg
                ? `${prefill.sourceEvent.method} ${prefill.sourceEvent.uri?.split("?")[0]} — ${prefill.sourceEvent.rule_msg}`
                : prefill.sourceEvent.method
                  ? `${prefill.sourceEvent.method} ${prefill.sourceEvent.uri}`
                  : prefill.description}
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
      <div className="grid gap-3 sm:grid-cols-4">
        {QUICK_ACTIONS.map((action) => {
          const Icon = QUICK_ACTION_ICONS[action.iconName] ?? Shield;
          const isActive = actionType === action.value;
          const colorMap: Record<string, { active: string; icon: string; text: string }> = {
            allow: { active: "border-lv-green/40 bg-lv-green/5", icon: "text-lv-green", text: "text-lv-green" },
            block: { active: "border-lv-red/40 bg-lv-red/5", icon: "text-lv-red", text: "text-lv-red" },
            challenge: { active: "border-lv-yellow/40 bg-lv-yellow/5", icon: "text-lv-yellow", text: "text-lv-yellow" },
            skip: { active: "border-lv-cyan/40 bg-lv-cyan/5", icon: "text-lv-cyan", text: "text-lv-cyan" },
            detect: { active: "border-lv-peach/40 bg-lv-peach/5", icon: "text-lv-peach", text: "text-lv-peach" },
          };
          const colors = colorMap[action.value] ?? colorMap.detect;
          return (
            <button
              key={action.value}
              className={`flex flex-col gap-1 rounded-lg border p-3 text-left transition-colors ${
                isActive
                  ? colors.active
                  : "border-border hover:border-muted-foreground/50"
              }`}
              onClick={() => {
                setActionType(action.value);
                // Update auto-generated name to reflect new action type
                if (prefill && (name.startsWith("Allow ") || name.startsWith("Block ") || name.startsWith("Challenge ") || name.startsWith("Skip ") || name.startsWith("Detect "))) {
                  const label = action.value === "allow" ? "Allow" : action.value === "block" ? "Block" : action.value === "challenge" ? "Challenge" : action.value === "skip" ? "Skip" : "Detect";
                  setName(name.replace(/^(Allow|Block|Challenge|Skip|Detect)\b/, label));
                }
              }}
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
              : "e.g., Detect missing referer"
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
                fields={INBOUND_FIELD_DEFS}
              />
            </div>
          ))}

          <Button variant="outline" size="sm" onClick={addCondition} className="mt-1">
            <Plus className="h-3.5 w-3.5" />
            Add condition
          </Button>
        </div>
      </div>

      {/* Detect: Severity and Paranoia Level */}
      {actionType === "detect" && (
        <div className="space-y-3">
          <div className="rounded-lg border border-border/50 bg-muted/30 p-3 text-xs text-muted-foreground">
            <p className="font-medium text-foreground">Detection Rule</p>
            <p className="mt-1">
              Runs matching CRS rules at the configured severity level. Multiple detection signals
              combine via anomaly scoring — requests that trigger several rules may cross the blocking threshold.
            </p>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label className={T.formLabel}>Severity</Label>
              <Select value={severity} onValueChange={setSeverity}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SEVERITY_OPTIONS.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">Determines the anomaly score contribution</p>
            </div>
            <div className="space-y-1.5">
              <Label className={T.formLabel}>Paranoia Level</Label>
              <Select value={String(detectPL)} onValueChange={(v) => setDetectPL(parseInt(v))}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="0">All levels (default)</SelectItem>
                  <SelectItem value="1">PL 1</SelectItem>
                  <SelectItem value="2">PL 2</SelectItem>
                  <SelectItem value="3">PL 3</SelectItem>
                  <SelectItem value="4">PL 4</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">Which paranoia level this detection applies to (0 = all)</p>
            </div>
          </div>
        </div>
      )}

      {/* Skip: Target Selection */}
      {actionType === "skip" && (
        <SkipTargetsForm value={skipTargets} onChange={setSkipTargets} />
      )}

      {/* Challenge: Settings */}
      {actionType === "challenge" && (
        <div className="space-y-3 rounded-md border border-lv-border/30 bg-lv-surface/30 p-3">
          <p className="text-xs font-medium text-lv-muted">Challenge Settings</p>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-lv-muted">Difficulty (leading hex zeros)</label>
              <input type="number" min={1} max={16} value={challengeDifficulty}
                onChange={(e) => setChallengeDifficulty(parseInt(e.target.value) || 4)}
                className="mt-1 w-full rounded border border-lv-border/50 bg-lv-surface px-2 py-1 text-sm text-lv-text" />
              <p className="mt-0.5 text-[10px] text-lv-muted">4 = ~0.5s, 6 = ~5s, 8 = ~30s, 16 = extreme</p>
            </div>
            <div>
              <label className="text-xs text-lv-muted">Algorithm</label>
              <select value={challengeAlgorithm} onChange={(e) => setChallengeAlgorithm(e.target.value)}
                className="mt-1 w-full rounded border border-lv-border/50 bg-lv-surface px-2 py-1 text-sm text-lv-text">
                <option value="fast">Fast (WebCrypto)</option>
                <option value="slow">Slow (CPU-intensive)</option>
              </select>
              {challengeAlgorithm === "slow" && challengeDifficulty > 2 && (
                <p className="mt-0.5 text-[10px] text-lv-red font-medium">Warning: slow + difficulty &gt;2 takes minutes to hours. Use difficulty 1-2 with slow, or switch to fast.</p>
              )}
            </div>
            <div>
              <label className="text-xs text-lv-muted">Cookie TTL</label>
              <input type="text" value={challengeTTL} onChange={(e) => setChallengeTTL(e.target.value)}
                placeholder="1h" className="mt-1 w-full rounded border border-lv-border/50 bg-lv-surface px-2 py-1 text-sm text-lv-text" />
              <p className="mt-0.5 text-[10px] text-lv-muted">How long before re-challenge (e.g., 1h, 4h, 24h)</p>
            </div>
            <div className="flex items-center gap-2 pt-4">
              <input type="checkbox" id="quick-challenge-bind-ip" checked={challengeBindIP}
                onChange={(e) => setChallengeBindIP(e.target.checked)} className="h-4 w-4 rounded border-lv-border/50" />
              <label htmlFor="quick-challenge-bind-ip" className="text-xs text-lv-muted">Bind cookie to client IP</label>
            </div>
            <div className="flex items-center gap-2 pt-1">
              <input type="checkbox" id="quick-challenge-bind-ja4" checked={challengeBindJA4}
                onChange={(e) => setChallengeBindJA4(e.target.checked)} className="h-4 w-4 rounded border-lv-border/50" />
              <label htmlFor="quick-challenge-bind-ja4" className="text-xs text-lv-muted">Bind cookie to JA4 TLS fingerprint</label>
            </div>
          </div>
        </div>
      )}

      {/* Tags */}
      <div className="space-y-1.5">
        <Label className={T.formLabel}>Tags</Label>
        <PipeTagInput
          value={tags.join("|")}
          onChange={(v) => setTags(v ? v.split("|").filter(Boolean) : [])}
          placeholder="e.g., scanner, bot-detection, temporary (Enter to add)"
        />
        <p className="text-xs text-muted-foreground">
          Optional labels for organizing rules and classifying events
        </p>
      </div>

      {/* Enabled + Submit */}
      <div className="flex items-center gap-4 pt-2">
        <Button onClick={handleSubmit} disabled={!isValid}>
          <SelectedIcon className="h-4 w-4" />
          {actionType === "allow" ? "Add Allow Rule" : actionType === "block" ? "Add Block Rule" : actionType === "challenge" ? "Add Challenge Rule" : actionType === "skip" ? "Add Skip Rule" : "Add Detect Rule"}
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

  const update = (field: keyof AdvancedFormState, value: string | number | boolean | Condition[] | GroupOperator | string[] | SkipTargets | Record<string, string>) => {
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  const isDetect = form.type === "detect";
  const isSkip = form.type === "skip";
  const isChallenge = form.type === "challenge";
  const isResponseHeader = form.type === "response_header";
  // response_header rules are always outbound regardless of toggle state
  const effectivePhase = isResponseHeader ? "outbound" : (form.phase ?? "inbound");

  // Condition management — all 3 types need conditions
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

  // When switching types, ensure at least one condition exists
  const handleTypeChange = (v: string) => {
    const newType = v as ExclusionType;
    const hadConditions = form.conditions.length > 0;
    setForm((prev) => ({
      ...prev,
      type: newType,
      conditions: hadConditions ? prev.conditions : [{ field: "path", operator: "eq", value: "" }],
      // Reset detect-specific fields when switching away from detect
      severity: newType === "detect" ? (prev.severity || "WARNING") : "",
      detect_paranoia_level: newType === "detect" ? prev.detect_paranoia_level : 0,
      // Reset skip-specific fields when switching away from skip
      skip_targets: newType === "skip" ? prev.skip_targets : {},
      // Reset challenge-specific fields when switching away from challenge
      challenge_difficulty: newType === "challenge" ? prev.challenge_difficulty : 4,
      challenge_min_difficulty: newType === "challenge" ? prev.challenge_min_difficulty : 0,
      challenge_max_difficulty: newType === "challenge" ? prev.challenge_max_difficulty : 0,
      challenge_algorithm: newType === "challenge" ? prev.challenge_algorithm : "fast",
      challenge_ttl: newType === "challenge" ? prev.challenge_ttl : "1h",
      challenge_bind_ip: newType === "challenge" ? prev.challenge_bind_ip : true,
      challenge_bind_ja4: newType === "challenge" ? prev.challenge_bind_ja4 : true,
      // Auto-set phase to outbound for response_header
      phase: newType === "response_header" ? "outbound" : prev.phase,
      // Reset header fields when switching away from response_header
      header_set: newType === "response_header" ? prev.header_set : {},
      header_add: newType === "response_header" ? prev.header_add : {},
      header_remove: newType === "response_header" ? prev.header_remove : [],
      header_default: newType === "response_header" ? prev.header_default : {},
    }));
  };

  const handleSubmit = () => {
    const validConditions = form.conditions.filter((c) => c.value.trim() !== "");
    const data: ExclusionCreateData = {
      name: form.name || `${form.type} exclusion`,
      description: form.description,
      type: form.type,
      phase: form.phase || undefined,
      enabled: form.enabled,
    };
    if (isDetect) {
      data.severity = form.severity;
      if (form.detect_paranoia_level > 0) data.detect_paranoia_level = form.detect_paranoia_level;
    }
    if (isSkip) {
      const st = form.skip_targets;
      const hasTargets = st.all_remaining || (st.rules?.length ?? 0) > 0 || (st.phases?.length ?? 0) > 0;
      if (hasTargets) data.skip_targets = st;
    }
    if (isChallenge) {
      data.challenge_difficulty = form.challenge_difficulty;
      if (form.challenge_min_difficulty > 0) data.challenge_min_difficulty = form.challenge_min_difficulty;
      if (form.challenge_max_difficulty > 0) data.challenge_max_difficulty = form.challenge_max_difficulty;
      data.challenge_algorithm = form.challenge_algorithm as "fast" | "slow";
      data.challenge_ttl = form.challenge_ttl;
      data.challenge_bind_ip = form.challenge_bind_ip;
      data.challenge_bind_ja4 = form.challenge_bind_ja4;
    }
    if (isResponseHeader) {
      if (Object.keys(form.header_set).length > 0) data.header_set = form.header_set;
      if (Object.keys(form.header_add).length > 0) data.header_add = form.header_add;
      if (form.header_remove.length > 0) data.header_remove = form.header_remove;
      if (Object.keys(form.header_default).length > 0) data.header_default = form.header_default;
      // Force outbound phase
      data.phase = "outbound";
    }
    if (validConditions.length > 0) {
      data.conditions = validConditions;
      data.group_operator = form.group_operator;
    }
    if (form.tags && form.tags.length > 0) data.tags = form.tags;
    // Rule TTL — convert to expires_in for the backend.
    if (form.expires_in) {
      (data as Record<string, unknown>).expires_in = form.expires_in;
    }
    onSubmit(data);
  };

  const isValid = (() => {
    if (form.name.trim() === "") return false;
    // Response header rules don't strictly require conditions (they can apply globally)
    if (!isResponseHeader) {
      const validConds = form.conditions.filter((c) => c.value.trim() !== "");
      if (validConds.length === 0) return false;
    }
    // Detect needs severity
    if (isDetect && !form.severity) return false;
    // Skip needs at least one target
    if (isSkip) {
      const st = form.skip_targets;
      const hasTargets = st.all_remaining || (st.rules?.length ?? 0) > 0 || (st.phases?.length ?? 0) > 0;
      if (!hasTargets) return false;
    }
    // Response header needs at least one header action
    if (isResponseHeader) {
      const hasActions = Object.keys(form.header_set).length > 0 ||
        Object.keys(form.header_add).length > 0 ||
        form.header_remove.length > 0 ||
        Object.keys(form.header_default).length > 0;
      if (!hasActions) return false;
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
          {form.type === "allow" && <span className="inline-flex items-center rounded bg-lv-green/20 border border-lv-green/30 px-1.5 py-0 text-[10px] font-semibold uppercase text-lv-green">Allow</span>}
          {form.type === "block" && <span className="inline-flex items-center rounded bg-lv-red/20 border border-lv-red/30 px-1.5 py-0 text-[10px] font-semibold uppercase text-lv-red">Block</span>}
          {form.type === "skip" && <span className="inline-flex items-center rounded bg-lv-cyan/20 border border-lv-cyan/30 px-1.5 py-0 text-[10px] font-semibold uppercase text-lv-cyan">Skip</span>}
          {form.type === "detect" && <span className="inline-flex items-center rounded bg-lv-peach/20 border border-lv-peach/30 px-1.5 py-0 text-[10px] font-semibold uppercase text-lv-peach">Detect</span>}
          {form.type === "response_header" && <span className="inline-flex items-center rounded bg-lv-purple/20 border border-lv-purple/30 px-1.5 py-0 text-[10px] font-semibold uppercase text-lv-purple">Response Header</span>}
        </div>
        <ExclusionTypePicker value={form.type} onChange={handleTypeChange} />
      </div>

      {/* Phase (inbound/outbound) */}
      <div className="space-y-1">
        <Label className={T.formLabel}>Phase</Label>
        <div className="flex gap-2">
          {(["inbound", "outbound"] as const).map((p) => {
            const isActive = (effectivePhase === "inbound" && p === "inbound") || (effectivePhase === "outbound" && p === "outbound");
            const isDisabled = isResponseHeader && p === "inbound";
            return (
              <button
                key={p}
                type="button"
                disabled={isDisabled}
                onClick={() => !isDisabled && setForm((prev) => ({ ...prev, phase: p === "inbound" ? undefined : p }))}
                className={`rounded-md border px-3 py-1.5 text-xs font-medium transition-all ${
                  isDisabled
                    ? "border-border/30 bg-lovelace-950/50 text-muted-foreground/40 cursor-not-allowed"
                    : isActive
                      ? p === "inbound"
                        ? "border-lv-cyan/40 bg-lv-cyan/10 text-lv-cyan"
                        : "border-lv-peach/40 bg-lv-peach/10 text-lv-peach"
                      : "border-border bg-lovelace-950 text-muted-foreground hover:border-border/80"
                }`}
              >
                {p === "inbound" ? "Inbound (Request)" : "Outbound (Response)"}
              </button>
            );
          })}
        </div>
        <p className="text-[10px] text-muted-foreground">
          {isResponseHeader
            ? "Response header rules always evaluate on server response (outbound)."
            : effectivePhase === "outbound"
              ? "Evaluates on server response — can match response_status, response_header."
              : "Evaluates on incoming request (default)."}
        </p>
      </div>

      {/* Detect: Severity and Paranoia Level */}
      {isDetect && (
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label className={T.formLabel}>Severity</Label>
            <Select value={form.severity || "WARNING"} onValueChange={(v) => update("severity", v)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {SEVERITY_OPTIONS.map((opt) => (
                  <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label className={T.formLabel}>Paranoia Level</Label>
            <Select value={String(form.detect_paranoia_level)} onValueChange={(v) => update("detect_paranoia_level", parseInt(v))}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="0">All levels (default)</SelectItem>
                <SelectItem value="1">PL 1</SelectItem>
                <SelectItem value="2">PL 2</SelectItem>
                <SelectItem value="3">PL 3</SelectItem>
                <SelectItem value="4">PL 4</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      )}

      {/* Skip: Target Selection */}
      {isSkip && (
        <SkipTargetsForm
          value={form.skip_targets}
          onChange={(targets) => update("skip_targets", targets)}
        />
      )}

      {/* Challenge: PoW Settings */}
      {isChallenge && (() => {
        const adaptiveActive = form.challenge_min_difficulty > 0 && form.challenge_max_difficulty > 0;
        const effectiveMax = adaptiveActive ? form.challenge_max_difficulty : form.challenge_difficulty;
        const slowWarning = form.challenge_algorithm === "slow" && effectiveMax > 2;
        return (
        <div className="space-y-4 rounded-md border border-lv-border/30 bg-lv-surface/30 p-3">
          <p className="text-xs font-medium text-lv-muted">Challenge Settings</p>

          {/* Difficulty section */}
          <div className="space-y-2">
            <p className="text-[10px] font-medium text-lv-muted/80 uppercase tracking-wide">Difficulty</p>
            <div className="grid grid-cols-3 gap-3">
              <div className={adaptiveActive ? "opacity-40" : ""}>
                <label className="text-xs text-lv-muted">Static Difficulty (1-16)</label>
                <input
                  type="number"
                  min={1}
                  max={16}
                  value={form.challenge_difficulty}
                  onChange={(e) => update("challenge_difficulty", parseInt(e.target.value) || 4)}
                  className="mt-1 w-full rounded border border-lv-border/50 bg-lv-surface px-2 py-1 text-sm text-lv-text"
                  disabled={adaptiveActive}
                />
                <p className="mt-0.5 text-[10px] text-lv-muted">
                  {adaptiveActive ? "Overridden by adaptive range below." : "Leading hex zeros. 4 \u2248 0.5s, 6 \u2248 5s, 8 \u2248 30s. Same for all clients."}
                </p>
              </div>
              <div>
                <label className="text-xs text-lv-muted">Adaptive Min</label>
                <input
                  type="number"
                  min={0}
                  max={16}
                  value={form.challenge_min_difficulty}
                  onChange={(e) => update("challenge_min_difficulty", parseInt(e.target.value) || 0)}
                  className="mt-1 w-full rounded border border-lv-border/50 bg-lv-surface px-2 py-1 text-sm text-lv-text"
                />
                <p className="mt-0.5 text-[10px] text-lv-muted">
                  For clean browsers (good JA4 + headers). 0 = use static.
                </p>
              </div>
              <div>
                <label className="text-xs text-lv-muted">Adaptive Max</label>
                <input
                  type="number"
                  min={0}
                  max={16}
                  value={form.challenge_max_difficulty}
                  onChange={(e) => update("challenge_max_difficulty", parseInt(e.target.value) || 0)}
                  className="mt-1 w-full rounded border border-lv-border/50 bg-lv-surface px-2 py-1 text-sm text-lv-text"
                />
                <p className="mt-0.5 text-[10px] text-lv-muted">
                  For suspicious clients (no ALPN, missing headers). 0 = use static.
                </p>
              </div>
            </div>
            {adaptiveActive && (
              <p className="text-[10px] text-lv-cyan">
                Adaptive mode active: server picks difficulty {form.challenge_min_difficulty}-{form.challenge_max_difficulty} per request based on TLS/header signals. Static difficulty is ignored.
              </p>
            )}
          </div>

          {/* Algorithm + TTL */}
          <div className="space-y-2">
            <p className="text-[10px] font-medium text-lv-muted/80 uppercase tracking-wide">Solver &amp; Cookie</p>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-lv-muted">Algorithm</label>
                <select
                  value={form.challenge_algorithm}
                  onChange={(e) => update("challenge_algorithm", e.target.value)}
                  className="mt-1 w-full rounded border border-lv-border/50 bg-lv-surface px-2 py-1 text-sm text-lv-text"
                >
                  <option value="fast">Fast (WebCrypto, native speed)</option>
                  <option value="slow">Slow (10ms delay per hash, punishes bots)</option>
                </select>
                <p className="mt-0.5 text-[10px] text-lv-muted">
                  Applies to all clients regardless of difficulty. Slow penalizes CPU time without increasing hash count.
                </p>
                {slowWarning && (
                  <p className="mt-0.5 text-[10px] text-lv-red font-medium">Warning: slow + difficulty &gt;2 takes minutes to hours for real users.</p>
                )}
              </div>
              <div>
                <label className="text-xs text-lv-muted">Cookie TTL</label>
                <input
                  type="text"
                  value={form.challenge_ttl}
                  onChange={(e) => update("challenge_ttl", e.target.value)}
                  placeholder="1h"
                  className="mt-1 w-full rounded border border-lv-border/50 bg-lv-surface px-2 py-1 text-sm text-lv-text"
                />
                <p className="mt-0.5 text-[10px] text-lv-muted">
                  How long the bypass cookie lasts before re-challenge (e.g., 1h, 4h, 24h, 7d)
                </p>
              </div>
            </div>
          </div>

          {/* Cookie binding */}
          <div className="space-y-2">
            <p className="text-[10px] font-medium text-lv-muted/80 uppercase tracking-wide">Cookie Binding</p>
            <div className="grid grid-cols-2 gap-3">
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="challenge-bind-ip"
                  checked={form.challenge_bind_ip}
                  onChange={(e) => update("challenge_bind_ip", e.target.checked)}
                  className="h-4 w-4 rounded border-lv-border/50"
                />
                <div>
                  <label htmlFor="challenge-bind-ip" className="text-xs text-lv-muted">
                    Bind to client IP
                  </label>
                  <p className="text-[10px] text-lv-muted/60">Cookie invalid if IP changes. Disable for mobile/cellular users.</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="challenge-bind-ja4"
                  checked={form.challenge_bind_ja4}
                  onChange={(e) => update("challenge_bind_ja4", e.target.checked)}
                  className="h-4 w-4 rounded border-lv-border/50"
                />
                <div>
                  <label htmlFor="challenge-bind-ja4" className="text-xs text-lv-muted">
                    Bind to JA4 TLS fingerprint
                  </label>
                  <p className="text-[10px] text-lv-muted/60">Blocks cookie replay from different TLS stacks (e.g., solve in browser, replay from curl).</p>
                </div>
              </div>
            </div>
          </div>
        </div>
        );
      })()}

      {/* Response Header: Header Actions */}
      {isResponseHeader && (
        <ResponseHeaderForm
          headerSet={form.header_set}
          headerAdd={form.header_add}
          headerRemove={form.header_remove}
          headerDefault={form.header_default}
          onChangeSet={(v) => update("header_set", v)}
          onChangeAdd={(v) => update("header_add", v)}
          onChangeRemove={(v) => setForm((prev) => ({ ...prev, header_remove: v }))}
          onChangeDefault={(v) => update("header_default", v)}
        />
      )}

      {/* Condition builder */}
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
                fields={effectivePhase === "outbound" ? OUTBOUND_FIELD_DEFS : INBOUND_FIELD_DEFS}
              />
            </div>
          ))}

          <Button variant="outline" size="sm" onClick={addCondition} className="mt-1">
            <Plus className="h-3.5 w-3.5" />
            Add condition
          </Button>
        </div>
      </div>

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

      {/* Rule TTL */}
      <div className="space-y-1.5">
        <Label className={T.formLabel}>Expires after</Label>
        <Select value={form.expires_in || "never"} onValueChange={(v) => update("expires_in", v === "never" ? "" : v)}>
          <SelectTrigger className="w-[200px] h-8 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="never">Never (permanent)</SelectItem>
            <SelectItem value="1h">1 hour</SelectItem>
            <SelectItem value="6h">6 hours</SelectItem>
            <SelectItem value="24h">24 hours</SelectItem>
            <SelectItem value="7d">7 days</SelectItem>
            <SelectItem value="30d">30 days</SelectItem>
          </SelectContent>
        </Select>
        <p className="text-xs text-muted-foreground">
          Auto-delete this rule after the specified duration
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

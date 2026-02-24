import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import {
  Shield,
  ShieldCheck,
  ShieldBan,
  SkipForward,
  FileCode,
  Plus,
  Trash2,
  Pencil,
  Copy,
  Check,
  GripVertical,
  AlertTriangle,
  Code2,
  Zap,
  Rocket,
  Download,
  Upload,
  X,
  Loader2,
  Search,
  ChevronDown,
  Crosshair,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  getExclusions,
  createExclusion,
  updateExclusion,
  deleteExclusion,
  generateConfig,
  deployConfig,
  fetchServices,
  exportExclusions,
  importExclusions,
  fetchCRSRules,
  fetchCRSAutocomplete,
  type Exclusion,
  type ExclusionType,
  type ExclusionCreateData,
  type Condition,
  type ConditionField,
  type ConditionOperator,
  type GroupOperator,
  type GeneratedConfig,
  type DeployResult,
  type ServiceDetail,
  type CRSRule,
  type CRSCatalogResponse,
  type CRSAutocompleteResponse,
} from "@/lib/api";
import SecRuleEditor from "./SecRuleEditor";
import type { WAFEvent } from "@/lib/api";

// ─── Event Prefill ──────────────────────────────────────────────────

interface EventPrefill {
  action: "allow" | "block" | "skip_rule";
  name: string;
  description: string;
  ruleIds: string;        // Space-separated rule IDs
  conditions: Condition[];
  sourceEvent: WAFEvent;
}

/** Extract prefill data from a WAF event for the Quick Actions form.
 *  Populates ALL available conditions from the event JSON so the user
 *  can remove the ones they don't need via the "X" buttons. */
function extractPrefillFromEvent(event: WAFEvent): EventPrefill {
  // Collect rule IDs from matched_rules, or fall back to primary rule_id
  const ruleIds: string[] = [];
  if (event.matched_rules && event.matched_rules.length > 0) {
    for (const r of event.matched_rules) {
      if (r.id && !ruleIds.includes(String(r.id))) {
        ruleIds.push(String(r.id));
      }
    }
  } else if (event.rule_id) {
    ruleIds.push(String(event.rule_id));
  }

  // Build conditions from ALL available event context.
  // The user can remove unwanted conditions via the "X" button.
  const conditions: Condition[] = [];

  // Path condition — use the path without query string
  if (event.uri) {
    const path = event.uri.split("?")[0];
    // Use begins_with for paths that look like prefixes (e.g., /socket.io/)
    // Use eq for exact paths
    const op: ConditionOperator = path.endsWith("/") ? "begins_with" : "eq";
    conditions.push({ field: "path", operator: op, value: path });
  }

  // Host / service condition — this is the hostname the request was sent to
  if (event.service) {
    conditions.push({ field: "host", operator: "eq", value: event.service });
  }

  // Method condition
  if (event.method) {
    conditions.push({ field: "method", operator: "eq", value: event.method });
  }

  // IP condition
  if (event.client_ip) {
    conditions.push({ field: "ip", operator: "eq", value: event.client_ip });
  }

  // User agent condition
  if (event.user_agent) {
    conditions.push({ field: "user_agent", operator: "contains", value: event.user_agent });
  }

  // Country condition (GeoIP via Cf-Ipcountry header)
  if (event.country) {
    conditions.push({ field: "country", operator: "eq", value: event.country });
  }

  // Auto-generate name
  const ruleSnippet = ruleIds.length > 0
    ? ruleIds.slice(0, 3).join(", ") + (ruleIds.length > 3 ? "..." : "")
    : "";
  const pathSnippet = event.uri ? event.uri.split("?")[0] : "";
  const serviceSnippet = event.service ? `on ${event.service}` : "";
  const name = ["Skip", ruleSnippet, "for", pathSnippet, serviceSnippet].filter(Boolean).join(" ");

  // Description from the primary rule message
  const description = event.rule_msg
    ? `Auto-created from event: ${event.rule_msg}`
    : `Auto-created from event ${event.id}`;

  return {
    action: "skip_rule",
    name,
    description,
    ruleIds: ruleIds.join(" "),
    conditions,
    sourceEvent: event,
  };
}

/** Read and consume a prefill event from sessionStorage (if present). */
function consumePrefillEvent(): EventPrefill | null {
  if (typeof window === "undefined") return null;

  const params = new URLSearchParams(window.location.search);
  if (!params.has("from_event")) return null;

  const raw = sessionStorage.getItem("waf:prefill-event");
  if (!raw) return null;

  try {
    const event = JSON.parse(raw) as WAFEvent;
    sessionStorage.removeItem("waf:prefill-event");
    // Clean up URL param without reload
    const url = new URL(window.location.href);
    url.searchParams.delete("from_event");
    window.history.replaceState({}, "", url.pathname + url.search);
    return extractPrefillFromEvent(event);
  } catch {
    return null;
  }
}

// ─── Constants ──────────────────────────────────────────────────────

// Quick Action types
type QuickActionType = "allow" | "block" | "skip_rule";

const QUICK_ACTIONS: { value: QuickActionType; label: string; description: string; icon: typeof Shield }[] = [
  { value: "allow", label: "Allow", description: "Whitelist IP, path, or service — bypass WAF checks", icon: ShieldCheck },
  { value: "block", label: "Block", description: "Deny requests by IP, path, or user agent", icon: ShieldBan },
  { value: "skip_rule", label: "Skip / Bypass", description: "Skip specific CRS rules for a path or service", icon: SkipForward },
];

// All exclusion types for the Advanced tab (includes quick action types for editing)
const ALL_EXCLUSION_TYPES: { value: ExclusionType; label: string; description: string; group: "quick" | "advanced" | "runtime" }[] = [
  // Quick action types (mainly created from Quick Actions tab, but editable here)
  { value: "allow", label: "Allow", description: "Whitelist — bypass WAF checks", group: "quick" },
  { value: "block", label: "Block", description: "Deny matching requests", group: "quick" },
  { value: "skip_rule", label: "Skip / Bypass", description: "Skip specific CRS rules", group: "quick" },
  // Configure-time advanced types
  { value: "SecRuleRemoveById", label: "Remove entire rule", description: "SecRuleRemoveById — removes a rule globally", group: "advanced" },
  { value: "SecRuleRemoveByTag", label: "Remove rule category", description: "SecRuleRemoveByTag — removes all rules in a tag category", group: "advanced" },
  { value: "SecRuleUpdateTargetById", label: "Exclude variable from rule", description: "SecRuleUpdateTargetById — excludes a specific variable from a rule", group: "advanced" },
  { value: "SecRuleUpdateTargetByTag", label: "Exclude variable from category", description: "SecRuleUpdateTargetByTag — excludes a variable from all rules in a tag", group: "advanced" },
  // Runtime ctl: types
  { value: "ctl:ruleRemoveById", label: "Remove rule for URI", description: "Runtime ctl:ruleRemoveById — removes a rule only for matching requests", group: "runtime" },
  { value: "ctl:ruleRemoveByTag", label: "Remove category for URI", description: "Runtime ctl:ruleRemoveByTag — removes a tag category for matching requests", group: "runtime" },
  { value: "ctl:ruleRemoveTargetById", label: "Exclude variable for URI", description: "Runtime ctl:ruleRemoveTargetById — excludes a variable for matching requests", group: "runtime" },
];

const RULE_TAGS = [
  "attack-sqli", "attack-xss", "attack-rce", "attack-lfi", "attack-rfi",
  "attack-protocol", "attack-injection-php", "attack-injection-generic",
  "attack-reputation-ip", "attack-disclosure", "attack-fixation",
  "paranoia-level/1", "paranoia-level/2", "paranoia-level/3", "paranoia-level/4",
];

// ─── Condition builder field/operator definitions ───────────────────

interface FieldDef {
  value: ConditionField;
  label: string;
  operators: { value: ConditionOperator; label: string }[];
  placeholder: string;
}

const CONDITION_FIELDS: FieldDef[] = [
  {
    value: "ip", label: "IP Address",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "ip_match", label: "is in (CIDR)" },
      { value: "not_ip_match", label: "is not in (CIDR)" },
    ],
    placeholder: "e.g., 195.240.81.42 or 10.0.0.0/8",
  },
  {
    value: "path", label: "Path / URI",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "begins_with", label: "begins with" },
      { value: "ends_with", label: "ends with" },
      { value: "regex", label: "matches regex" },
      { value: "in", label: "is in (substring match)" },
    ],
    placeholder: "e.g., /api/v3/, /socket.io/",
  },
  {
    value: "host", label: "Host / Service",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
    ],
    placeholder: "e.g., radarr.erfi.io",
  },
  {
    value: "method", label: "HTTP Method",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "in", label: "is in" },
    ],
    placeholder: "e.g., POST or GET|POST|PUT",
  },
  {
    value: "user_agent", label: "User Agent",
    operators: [
      { value: "eq", label: "equals" },
      { value: "contains", label: "contains" },
      { value: "regex", label: "matches regex" },
    ],
    placeholder: "e.g., BadBot.*, curl/.*",
  },
  {
    value: "header", label: "Request Header",
    operators: [
      { value: "eq", label: "equals" },
      { value: "contains", label: "contains" },
      { value: "regex", label: "matches regex" },
    ],
    placeholder: "e.g., X-Custom-Header:value",
  },
  {
    value: "query", label: "Query String",
    operators: [
      { value: "contains", label: "contains" },
      { value: "regex", label: "matches regex" },
    ],
    placeholder: "e.g., debug=true",
  },
  {
    value: "country", label: "Country (GeoIP)",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "in", label: "is in" },
    ],
    placeholder: "e.g., CN or CN RU KP (ISO 3166-1 alpha-2)",
  },
  {
    value: "cookie", label: "Cookie",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "regex", label: "matches regex" },
    ],
    placeholder: "e.g., session_id:abc123 or cookie_name:value",
  },
  {
    value: "body", label: "Request Body",
    operators: [
      { value: "contains", label: "contains" },
      { value: "regex", label: "matches regex" },
    ],
    placeholder: "e.g., <script> or password=.*",
  },
  {
    value: "args", label: "Parameter (Args)",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "regex", label: "matches regex" },
    ],
    placeholder: "e.g., action:delete or param_name:value",
  },
  {
    value: "uri_path", label: "URI Path (no query)",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "begins_with", label: "begins with" },
      { value: "ends_with", label: "ends with" },
      { value: "regex", label: "matches regex" },
    ],
    placeholder: "e.g., /api/v1/upload",
  },
  {
    value: "referer", label: "Referer",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "contains", label: "contains" },
      { value: "regex", label: "matches regex" },
    ],
    placeholder: "e.g., https://example.com/page",
  },
  {
    value: "response_header", label: "Response Header",
    operators: [
      { value: "eq", label: "equals" },
      { value: "contains", label: "contains" },
      { value: "regex", label: "matches regex" },
    ],
    placeholder: "e.g., Content-Type:application/json",
  },
  {
    value: "response_status", label: "Response Status",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
      { value: "in", label: "is in" },
    ],
    placeholder: "e.g., 403 or 401 403 500",
  },
  {
    value: "http_version", label: "HTTP Version",
    operators: [
      { value: "eq", label: "equals" },
      { value: "neq", label: "does not equal" },
    ],
    placeholder: "e.g., HTTP/1.0 or HTTP/2.0",
  },
];

function getFieldDef(field: ConditionField): FieldDef {
  return CONDITION_FIELDS.find((f) => f.value === field) ?? CONDITION_FIELDS[0];
}

function isById(type: ExclusionType): boolean {
  return type.includes("ById");
}

function isByTag(type: ExclusionType): boolean {
  return type.includes("ByTag");
}

function isTargetType(type: ExclusionType): boolean {
  return type.includes("Target") || type.includes("UpdateTarget");
}

function isRuntimeType(type: ExclusionType): boolean {
  return type.startsWith("ctl:");
}

// ─── Utility Components ─────────────────────────────────────────────

function CopyButton({ text, label }: { text: string; label?: string }) {
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

function ConditionChip({
  label,
  value,
  onRemove,
}: {
  label: string;
  value: string;
  onRemove?: () => void;
}) {
  return (
    <div className="inline-flex items-center gap-1.5 rounded-full border border-border bg-navy-950 px-2.5 py-1 text-xs">
      <span className="text-muted-foreground">{label}:</span>
      <span className="font-medium text-neon-cyan">{value}</span>
      {onRemove && (
        <button
          onClick={onRemove}
          className="ml-0.5 rounded-full p-0.5 hover:bg-accent"
        >
          <X className="h-3 w-3 text-muted-foreground hover:text-neon-pink" />
        </button>
      )}
    </div>
  );
}

// ─── CRS Rule Picker (searchable dropdown) ──────────────────────────

/** Parse a space-separated rule ID string into an array of individual IDs. */
function parseRuleIds(value: string): string[] {
  return value.split(/[\s,]+/).filter(Boolean);
}

/** Join rule ID array back into a space-separated string. */
function joinRuleIds(ids: string[]): string {
  return ids.join(" ");
}

/**
 * Tag-style input for multiple rule IDs.
 * Stores value as a space-separated string (e.g. "942200 942370 920420").
 * Supports typing + Enter/comma/space to add, backspace to remove last, click X to remove individual.
 */
function RuleIdTagInput({
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

function CRSRulePicker({
  rules,
  categories,
  selectedRuleIds,
  onSelect,
}: {
  rules: CRSRule[];
  categories: { id: string; name: string }[];
  selectedRuleIds: string;
  onSelect: (ruleIds: string) => void;
}) {
  const [search, setSearch] = useState("");
  const [open, setOpen] = useState(false);
  const ids = parseRuleIds(selectedRuleIds);

  const filteredRules = useMemo(() => {
    if (!search) return rules.slice(0, 50);
    const q = search.toLowerCase();
    return rules.filter(
      (r) =>
        r.id.includes(q) ||
        r.description.toLowerCase().includes(q) ||
        r.category.toLowerCase().includes(q)
    ).slice(0, 50);
  }, [rules, search]);

  const categoryMap = useMemo(() => {
    const m: Record<string, string> = {};
    for (const c of categories) m[c.id] = c.name;
    return m;
  }, [categories]);

  const toggleRule = (ruleId: string) => {
    if (ids.includes(ruleId)) {
      onSelect(joinRuleIds(ids.filter((id) => id !== ruleId)));
    } else {
      onSelect(joinRuleIds([...ids, ruleId]));
    }
  };

  return (
    <div className="space-y-1.5">
      <Label className="text-xs uppercase tracking-wider text-muted-foreground">
        Rule ID / Range
      </Label>
      <RuleIdTagInput
        value={selectedRuleIds}
        onChange={onSelect}
        placeholder="Type rule IDs (Enter to add) or browse below"
      />
      <div className="relative">
        <button
          type="button"
          className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
          onClick={() => setOpen(!open)}
        >
          <Search className="h-3 w-3" />
          {open ? "Hide" : "Browse"} CRS rule catalog
        </button>

        {open && (
          <div className="mt-1.5 rounded-md border border-border bg-popover shadow-lg">
            <div className="p-2 border-b border-border">
              <Input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search by ID, description, or category..."
                className="h-8 text-xs"
                autoFocus
              />
            </div>
            <div className="max-h-[300px] overflow-y-auto p-1">
              {filteredRules.length > 0 ? (
                filteredRules.map((rule) => {
                  const isSelected = ids.includes(rule.id);
                  return (
                    <button
                      key={rule.id}
                      className={`flex w-full items-start gap-2 rounded px-2 py-1.5 text-left text-xs hover:bg-accent ${isSelected ? "bg-accent/50" : ""}`}
                      onClick={() => toggleRule(rule.id)}
                    >
                      <span className="shrink-0 font-mono text-neon-cyan">{rule.id}</span>
                      <div className="min-w-0 flex-1">
                        <p className="truncate">{rule.description}</p>
                        <p className="text-muted-foreground">
                          {categoryMap[rule.category] ?? rule.category}
                          {rule.severity && (
                            <Badge variant="outline" className="ml-1.5 text-[9px] px-1 py-0">
                              {rule.severity}
                            </Badge>
                          )}
                        </p>
                      </div>
                      {isSelected && (
                        <Check className="h-3.5 w-3.5 shrink-0 text-neon-green" />
                      )}
                    </button>
                  );
                })
              ) : (
                <p className="px-2 py-3 text-center text-xs text-muted-foreground">
                  No rules found
                </p>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Condition Row Component ────────────────────────────────────────

// Host value input: dropdown with service list + "All Services" + "Custom..." with text input fallback.
function HostValueInput({
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

function ConditionRow({
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

      {/* Value input — special case for host field (show service dropdown with custom option) */}
      {condition.field === "host" ? (
        <HostValueInput
          value={condition.value}
          services={services}
          onChange={(v) => onChange(index, { ...condition, value: v })}
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

// ─── Quick Actions Form ─────────────────────────────────────────────

function QuickActionsForm({
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

  const SelectedIcon = QUICK_ACTIONS.find((a) => a.value === actionType)?.icon ?? Shield;

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
          const Icon = action.icon;
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
          <Label className="text-xs uppercase tracking-wider text-muted-foreground">Name</Label>
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
          <Label className="text-xs uppercase tracking-wider text-muted-foreground">Description</Label>
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
          <Label className="text-xs uppercase tracking-wider text-muted-foreground">
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
                  <span className="text-[10px] font-medium uppercase text-muted-foreground">
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
            <Label className="text-xs uppercase tracking-wider text-muted-foreground">Skip by:</Label>
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
              <Label className="text-xs uppercase tracking-wider text-muted-foreground">
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

interface AdvancedFormState {
  name: string;
  description: string;
  type: ExclusionType;
  rule_id: string;
  rule_tag: string;
  variable: string;
  // Runtime ctl: types use conditions for URI/method/host matching
  conditions: Condition[];
  group_operator: GroupOperator;
  enabled: boolean;
}

const emptyAdvancedForm: AdvancedFormState = {
  name: "",
  description: "",
  type: "SecRuleRemoveById",
  rule_id: "",
  rule_tag: "",
  variable: "",
  conditions: [],
  group_operator: "and",
  enabled: true,
};

function AdvancedBuilderForm({
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
    const hadConditions = form.conditions.length > 0;
    setForm((prev) => ({
      ...prev,
      type: newType,
      conditions: willNeedConditions && !hadConditions
        ? [{ field: "path", operator: "eq", value: "" }]
        : prev.conditions,
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
          <Label className="text-xs uppercase tracking-wider text-muted-foreground">Name</Label>
          <Input value={form.name} onChange={(e) => update("name", e.target.value)} placeholder="e.g., Allow WordPress admin" />
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs uppercase tracking-wider text-muted-foreground">Description</Label>
          <Input value={form.description} onChange={(e) => update("description", e.target.value)} placeholder="Optional description" />
        </div>
      </div>

      {/* Exclusion Type */}
      <div className="space-y-1.5">
        <Label className="text-xs uppercase tracking-wider text-muted-foreground">Exclusion Type</Label>
        <Select value={form.type} onValueChange={handleTypeChange}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {ALL_EXCLUSION_TYPES.map((t) => (
              <SelectItem key={t.value} value={t.value} textValue={t.label}>
                <div className="flex flex-col gap-0.5">
                  <span className="font-medium">{t.label}</span>
                  <span className="text-xs text-muted-foreground">{t.description}</span>
                </div>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Rule ID / Tag / Variable fields */}
      <div className="grid gap-3 sm:grid-cols-2">
        {needsRuleId && (
          <div className="space-y-1.5">
            <Label className="text-xs uppercase tracking-wider text-muted-foreground">Rule ID / Range</Label>
            <RuleIdTagInput
              value={form.rule_id}
              onChange={(v) => update("rule_id", v)}
              placeholder="e.g., 941100, 942000-942999 (Enter to add)"
            />
          </div>
        )}
        {needsRuleTag && (
          <div className="space-y-1.5">
            <Label className="text-xs uppercase tracking-wider text-muted-foreground">Rule Tag</Label>
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
            <Label className="text-xs uppercase tracking-wider text-muted-foreground">Variable</Label>
            <Input value={form.variable} onChange={(e) => update("variable", e.target.value)} placeholder='e.g., ARGS:wp_post, REQUEST_COOKIES:/^uid_.*/' />
          </div>
        )}
      </div>

      {/* Condition builder for runtime ctl: types */}
      {needsConditions && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <Label className="text-xs uppercase tracking-wider text-muted-foreground">
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
                    <span className="text-[10px] font-medium uppercase text-muted-foreground">
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

function RawEditorForm({
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
        <Label className="text-xs uppercase tracking-wider text-muted-foreground">Name</Label>
        <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Exclusion name" />
      </div>

      <div className="space-y-1.5">
        <Label className="text-xs uppercase tracking-wider text-muted-foreground">
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

function HoneypotForm({ onSubmit }: { onSubmit: (data: ExclusionCreateData) => void }) {
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

// ─── Config Viewer ──────────────────────────────────────────────────

function ConfigViewer({ config }: { config: GeneratedConfig }) {
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm">pre-crs.conf</CardTitle>
            {config.pre_crs && <CopyButton text={config.pre_crs} />}
          </div>
          <CardDescription>Loaded before CRS rules</CardDescription>
        </CardHeader>
        <Separator />
        <CardContent className="p-0">
          <div className="relative max-h-[400px] overflow-auto">
            <pre className="p-4 text-xs leading-relaxed">
              <code className="text-neon-green/80">{config.pre_crs || "# No pre-CRS exclusions configured"}</code>
            </pre>
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm">post-crs.conf</CardTitle>
            {config.post_crs && <CopyButton text={config.post_crs} />}
          </div>
          <CardDescription>Loaded after CRS rules</CardDescription>
        </CardHeader>
        <Separator />
        <CardContent className="p-0">
          <div className="relative max-h-[400px] overflow-auto">
            <pre className="p-4 text-xs leading-relaxed">
              <code className="text-neon-cyan/80">{config.post_crs || "# No post-CRS exclusions configured"}</code>
            </pre>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Exclusion type label helper ────────────────────────────────────

function conditionsSummary(excl: Exclusion): string {
  // For honeypot rules, show path count
  if (excl.type === "honeypot" && excl.conditions && excl.conditions.length > 0) {
    const paths = excl.conditions.flatMap((c) => c.value.split(/\s+/).filter(Boolean));
    const preview = paths.slice(0, 3).join(", ");
    return paths.length > 3 ? `${preview} (+${paths.length - 3} more)` : preview;
  }
  // For raw rules, show raw_rule snippet
  if (excl.type === "raw" && excl.raw_rule) {
    return excl.raw_rule.length > 50 ? excl.raw_rule.slice(0, 50) + "..." : excl.raw_rule;
  }
  // For configure-time types without conditions, show rule_id or rule_tag
  if (excl.rule_id) return `Rule ${excl.rule_id}`;
  if (excl.rule_tag) return `Tag: ${excl.rule_tag}`;
  // Show conditions summary
  if (excl.conditions && excl.conditions.length > 0) {
    const parts = excl.conditions.map((c) => {
      const fieldLabel = CONDITION_FIELDS.find((f) => f.value === c.field)?.label ?? c.field;
      const opLabel = CONDITION_FIELDS.find((f) => f.value === c.field)
        ?.operators.find((o) => o.value === c.operator)?.label ?? c.operator;
      const val = c.value.length > 30 ? c.value.slice(0, 30) + "..." : c.value;
      return `${fieldLabel} ${opLabel} ${val}`;
    });
    const joiner = excl.group_operator === "or" ? " OR " : " AND ";
    const joined = parts.join(joiner);
    return joined.length > 80 ? joined.slice(0, 80) + "..." : joined;
  }
  return "-";
}

function exclusionTypeLabel(type: ExclusionType): string {
  switch (type) {
    case "allow": return "Allow";
    case "block": return "Block";
    case "skip_rule": return "Skip";
    case "honeypot": return "Honeypot";
    case "raw": return "Raw";
    default: return type;
  }
}

function exclusionTypeBadgeVariant(type: ExclusionType): "default" | "outline" | "secondary" | "destructive" {
  switch (type) {
    case "allow": return "default";
    case "block": return "destructive";
    case "honeypot": return "destructive";
    case "skip_rule": return "secondary";
    default: return "outline";
  }
}

// ─── Main Policy Engine Component ───────────────────────────────────

export default function PolicyEngine() {
  const [exclusions, setExclusions] = useState<Exclusion[]>([]);
  const [services, setServices] = useState<ServiceDetail[]>([]);
  const [crsData, setCrsData] = useState<CRSCatalogResponse | null>(null);
  const [autocompleteData, setAutocompleteData] = useState<CRSAutocompleteResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [generatedConfig, setGeneratedConfig] = useState<GeneratedConfig | null>(null);
  const [generating, setGenerating] = useState(false);
  const [deployStep, setDeployStep] = useState<string | null>(null);
  const [deployResult, setDeployResult] = useState<DeployResult | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Event prefill — consumed once on mount from sessionStorage.
  // Must use useEffect (not useState initializer) to avoid SSR hydration mismatch.
  const [eventPrefill, setEventPrefill] = useState<EventPrefill | null>(null);
  useEffect(() => {
    const prefill = consumePrefillEvent();
    if (prefill) setEventPrefill(prefill);
  }, []);

  // Highlight a specific exclusion when navigating from an event (e.g. /policy?rule=<name>).
  // The name is extracted from the Policy Engine rule's msg field.
  const [highlightedRule, setHighlightedRule] = useState<string | null>(null);
  const highlightedRef = useRef<HTMLTableRowElement | null>(null);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const ruleName = params.get("rule");
    if (ruleName) {
      setHighlightedRule(ruleName);
      // Clean up URL param without reload
      const url = new URL(window.location.href);
      url.searchParams.delete("rule");
      window.history.replaceState({}, "", url.pathname + url.search);
    }
  }, []);

  const loadData = useCallback(() => {
    setLoading(true);
    setError(null);
    Promise.all([
      getExclusions(),
      fetchServices(),
      fetchCRSRules().catch(() => null),
      fetchCRSAutocomplete().catch(() => null),
    ])
      .then(([excl, svcs, crs, ac]) => {
        setExclusions(excl);
        setServices(svcs);
        if (crs) setCrsData(crs);
        if (ac) setAutocompleteData(ac);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Scroll to the highlighted rule once exclusions have loaded.
  useEffect(() => {
    if (highlightedRule && !loading && highlightedRef.current) {
      highlightedRef.current.scrollIntoView({ behavior: "smooth", block: "center" });
      // Auto-clear the highlight after 4 seconds.
      const timer = setTimeout(() => setHighlightedRule(null), 4000);
      return () => clearTimeout(timer);
    }
  }, [highlightedRule, loading, exclusions]);

  const showSuccess = (msg: string) => {
    setSuccessMsg(msg);
    setTimeout(() => setSuccessMsg(null), 3000);
  };

  const handleCreate = async (data: ExclusionCreateData) => {
    try {
      const created = await createExclusion(data);
      setExclusions((prev) => [...prev, created]);
      showSuccess("Exclusion created — deploying...");

      // Auto-deploy after creating a rule so it takes effect immediately.
      try {
        setDeployStep("Writing WAF files & reloading Caddy...");
        const result = await deployConfig();
        setDeployResult(result);
        if (result.status === "deployed") {
          showSuccess("Rule created and deployed successfully");
        } else {
          showSuccess("Rule created — config files written, Caddy reload needs manual intervention");
        }
      } catch (deployErr: any) {
        setError(`Rule saved but deploy failed: ${deployErr.message}`);
      } finally {
        setDeployStep(null);
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleUpdate = async (id: string, data: ExclusionCreateData) => {
    try {
      const updated = await updateExclusion(id, data);
      setExclusions((prev) => prev.map((e) => (e.id === id ? updated : e)));
      setEditingId(null);
      showSuccess("Exclusion updated");
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteExclusion(id);
      setExclusions((prev) => prev.filter((e) => e.id !== id));
      setDeleteConfirmId(null);
      showSuccess("Exclusion deleted");
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleToggleEnabled = async (id: string, enabled: boolean) => {
    try {
      const updated = await updateExclusion(id, { enabled });
      setExclusions((prev) => prev.map((e) => (e.id === id ? updated : e)));
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleGenerateConfig = async () => {
    setGenerating(true);
    try {
      const config = await generateConfig();
      setGeneratedConfig(config);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setGenerating(false);
    }
  };

  const handleDeploy = async () => {
    setDeployResult(null);
    try {
      setDeployStep("Writing WAF files & reloading Caddy...");
      const result = await deployConfig();
      setDeployResult(result);
      if (result.status === "deployed") {
        showSuccess("Configuration deployed and Caddy reloaded");
      } else {
        showSuccess("Config files written — Caddy reload needs manual intervention");
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setDeployStep(null);
    }
  };

  const handleExport = async () => {
    try {
      const data = await exportExclusions();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "waf-exclusions.json";
      a.click();
      URL.revokeObjectURL(url);
      showSuccess("Exclusions exported");
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleImport = () => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json";
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const data = JSON.parse(text);
        const result = await importExclusions(data);
        showSuccess(`Imported ${result.imported} exclusions`);
        loadData();
      } catch (err: any) {
        setError(err.message);
      }
    };
    input.click();
  };

  // Editing: determine which tab the exclusion belongs to so we show the edit form in the right tab
  const exclusionToEdit = editingId ? exclusions.find((e) => e.id === editingId) : null;

  const editFormState: AdvancedFormState | undefined = exclusionToEdit
    ? {
        name: exclusionToEdit.name,
        description: exclusionToEdit.description,
        type: exclusionToEdit.type,
        rule_id: exclusionToEdit.rule_id ?? "",
        rule_tag: exclusionToEdit.rule_tag ?? "",
        variable: exclusionToEdit.variable ?? "",
        conditions: exclusionToEdit.conditions ?? [],
        group_operator: exclusionToEdit.group_operator ?? "and",
        enabled: exclusionToEdit.enabled,
      }
    : undefined;

  // Determine the editing tab — always route to advanced tab for edits (it supports all types now)
  const isEditingRaw = exclusionToEdit?.type === "raw";

  // Controlled tab state — switches automatically when editing starts.
  const [activeTab, setActiveTab] = useState<string>("quick");
  useEffect(() => {
    if (editingId) {
      setActiveTab(isEditingRaw ? "raw" : "advanced");
    }
  }, [editingId, isEditingRaw]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-lg font-semibold">Policy Engine</h2>
          <p className="text-sm text-muted-foreground">
            Create allow/block rules, manage CRS exclusions, or write raw SecRule directives.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={handleExport}>
            <Download className="h-3.5 w-3.5" />
            Export
          </Button>
          <Button variant="outline" size="sm" onClick={handleImport}>
            <Upload className="h-3.5 w-3.5" />
            Import
          </Button>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {successMsg && (
        <Alert variant="success">
          <Check className="h-4 w-4" />
          <AlertTitle>Success</AlertTitle>
          <AlertDescription>{successMsg}</AlertDescription>
        </Alert>
      )}

      {/* Builder Section — 3 Tabs */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-neon-green" />
            <CardTitle className="text-sm">
              {editingId ? "Edit Rule" : "Create Rule"}
            </CardTitle>
          </div>
          <CardDescription>
            Use Quick Actions for common tasks, Advanced for ModSecurity experts, or Raw Editor for full control
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="mb-4">
              <TabsTrigger value="quick" className="gap-1.5">
                <Zap className="h-3.5 w-3.5" />
                Quick Actions
              </TabsTrigger>
              <TabsTrigger value="advanced" className="gap-1.5">
                <Code2 className="h-3.5 w-3.5" />
                Advanced
              </TabsTrigger>
              <TabsTrigger value="honeypot" className="gap-1.5">
                <Crosshair className="h-3.5 w-3.5" />
                Honeypot
              </TabsTrigger>
              <TabsTrigger value="raw" className="gap-1.5">
                <FileCode className="h-3.5 w-3.5" />
                Raw Editor
              </TabsTrigger>
            </TabsList>

            <TabsContent value="quick">
              <QuickActionsForm
                services={services}
                crsRules={crsData?.rules ?? []}
                crsCategories={crsData?.categories ?? []}
                onSubmit={(data) => {
                  handleCreate(data);
                  setEventPrefill(null);
                }}
                prefill={eventPrefill}
                onPrefillConsumed={() => setEventPrefill(null)}
              />
            </TabsContent>

            <TabsContent value="advanced">
              {editingId && editFormState && !isEditingRaw ? (
                <AdvancedBuilderForm
                  key={editingId}
                  initial={editFormState}
                  services={services}
                  onSubmit={(data) => handleUpdate(editingId, data)}
                  onCancel={() => setEditingId(null)}
                  submitLabel="Update Rule"
                />
              ) : (
                <AdvancedBuilderForm
                  services={services}
                  onSubmit={handleCreate}
                  submitLabel="Add Exclusion"
                />
              )}
            </TabsContent>

            <TabsContent value="honeypot">
              <HoneypotForm onSubmit={handleCreate} />
            </TabsContent>

            <TabsContent value="raw">
              <RawEditorForm
                autocompleteData={autocompleteData}
                crsRules={crsData?.rules ?? []}
                onSubmit={handleCreate}
              />
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {/* Exclusion List */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm">Rules ({exclusions.length})</CardTitle>
              <CardDescription>Manage your WAF rules and exclusions</CardDescription>
            </div>
            <Button onClick={handleGenerateConfig} disabled={generating || exclusions.length === 0} size="sm">
              <FileCode className="h-3.5 w-3.5" />
              {generating ? "Generating..." : "Generate Config"}
            </Button>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="space-y-2 p-6">
              {[...Array(5)].map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : exclusions.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-8" />
                  <TableHead>Name</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Target / Conditions</TableHead>
                  <TableHead>Enabled</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {exclusions.map((excl) => {
                  const isHighlighted = highlightedRule !== null && excl.name === highlightedRule;
                  return (
                  <TableRow
                    key={excl.id}
                    ref={isHighlighted ? highlightedRef : undefined}
                    className={isHighlighted ? "ring-1 ring-emerald-500/60 bg-emerald-500/5 transition-all duration-700" : undefined}
                  >
                    <TableCell className="w-8">
                      <GripVertical className="h-4 w-4 cursor-grab text-muted-foreground/50" />
                    </TableCell>
                    <TableCell>
                      <div>
                        <p className="text-xs font-medium">{excl.name}</p>
                        {excl.description && (
                          <p className="text-xs text-muted-foreground truncate max-w-[200px]">{excl.description}</p>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={exclusionTypeBadgeVariant(excl.type)} className="text-[10px] px-1.5 py-0 font-mono">
                        {exclusionTypeLabel(excl.type)}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs font-mono max-w-[300px] truncate" title={conditionsSummary(excl)}>
                      {conditionsSummary(excl)}
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={excl.enabled}
                        onCheckedChange={(v) => handleToggleEnabled(excl.id, v)}
                      />
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          onClick={() => setEditingId(excl.id)}
                        >
                          <Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          className="text-muted-foreground hover:text-neon-pink"
                          onClick={() => setDeleteConfirmId(excl.id)}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          ) : (
            <div className="flex flex-col items-center justify-center py-12">
              <Shield className="mb-3 h-8 w-8 text-muted-foreground/50" />
              <p className="text-sm text-muted-foreground">No rules configured yet</p>
              <p className="text-xs text-muted-foreground/70">Use the builder above to create your first rule</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Generated Config */}
      {generatedConfig && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold">Generated Configuration</h3>
            <Button variant="default" size="sm" onClick={handleDeploy} disabled={deployStep !== null}>
              {deployStep ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Rocket className="h-3.5 w-3.5" />
              )}
              {deployStep ?? "Deploy to Caddy"}
            </Button>
          </div>
          {deployResult && (
            <Alert variant={deployResult.status === "deployed" ? "default" : "destructive"}>
              <AlertTitle>
                {deployResult.status === "deployed" ? "Deployed Successfully" : "Partial Deploy"}
              </AlertTitle>
              <AlertDescription>
                <p>{deployResult.message}</p>
                <p className="text-xs text-muted-foreground mt-1">
                  {deployResult.timestamp}
                  {!deployResult.reloaded && (
                    <span className="ml-2 text-yellow-600">
                      Caddy reload failed — run manually: docker exec caddy caddy reload --config /etc/caddy/Caddyfile
                    </span>
                  )}
                </p>
              </AlertDescription>
            </Alert>
          )}
          <ConfigViewer config={generatedConfig} />
        </div>
      )}

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteConfirmId !== null} onOpenChange={(open) => !open && setDeleteConfirmId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Rule</DialogTitle>
            <DialogDescription>Are you sure you want to delete this rule? This action cannot be undone.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteConfirmId(null)}>Cancel</Button>
            <Button variant="destructive" onClick={() => deleteConfirmId && handleDelete(deleteConfirmId)}>Delete</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

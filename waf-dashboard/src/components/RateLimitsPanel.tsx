import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { TablePagination, paginateArray } from "./TablePagination";
import {
  Shield,
  Plus,
  Trash2,
  Pencil,
  AlertTriangle,
  Download,
  Upload,
  Loader2,
  Check,
  Search,
  X,
  Settings2,
  Zap,
  BarChart3,
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
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { ConditionRow } from "./policy/ConditionBuilder";
import {
  getRLRules,
  createRLRule,
  updateRLRule,
  deleteRLRule,
  deployRLRules,
  getRLGlobal,
  updateRLGlobal,
  exportRLRules,
  importRLRules,
  getRLRuleHits,
  fetchServices,
  type RateLimitRule,
  type RateLimitRuleCreateData,
  type RateLimitGlobalConfig,
  type RLRuleHitsResponse,
  type ServiceDetail,
  type Condition,
  type ConditionField,
  type GroupOperator,
  type RLRuleAction,
} from "@/lib/api";
import type { FieldDef } from "./policy/constants";
import { CONDITION_FIELDS } from "./policy/constants";
import { RateAdvisorPanel } from "./RateAdvisorPanel";
import { isValidWindow } from "@/lib/format";
import { T } from "@/lib/typography";

// ─── RL-specific condition fields (subset of WAF fields) ────────────

const RL_CONDITION_FIELDS: ConditionField[] = [
  "ip", "path", "host", "method", "user_agent",
  "header", "query", "country", "cookie", "uri_path", "referer", "http_version",
];

const RL_FIELD_DEFS: FieldDef[] = CONDITION_FIELDS.filter(
  (f) => RL_CONDITION_FIELDS.includes(f.value)
);

// ─── Rate Limit Key Options ─────────────────────────────────────────

const RL_KEY_OPTIONS: { value: string; label: string; description: string }[] = [
  { value: "client_ip", label: "Client IP", description: "Rate limit per client IP address" },
  { value: "path", label: "Path", description: "Rate limit per request path" },
  { value: "static", label: "Static (Global)", description: "Single shared counter for all matching requests" },
  { value: "client_ip+path", label: "Client IP + Path", description: "Rate limit per IP and path combination" },
  { value: "client_ip+method", label: "Client IP + Method", description: "Rate limit per IP and HTTP method" },
  { value: "header:", label: "Header Value", description: "Rate limit per request header value (e.g., header:X-API-Key)" },
  { value: "cookie:", label: "Cookie Value", description: "Rate limit per cookie value (e.g., cookie:session_id)" },
];

// ─── Window Options ─────────────────────────────────────────────────

const WINDOW_OPTIONS = [
  { value: "10s", label: "10 seconds" },
  { value: "30s", label: "30 seconds" },
  { value: "1m", label: "1 minute" },
  { value: "2m", label: "2 minutes" },
  { value: "5m", label: "5 minutes" },
  { value: "10m", label: "10 minutes" },
  { value: "30m", label: "30 minutes" },
  { value: "1h", label: "1 hour" },
];

const WINDOW_VALUES = new Set(WINDOW_OPTIONS.map((o) => o.value));


// ─── Inline SVG Sparkline ───────────────────────────────────────────

function Sparkline({ data, width = 80, height = 24, color = "#22d3ee" }: {
  data: number[];
  width?: number;
  height?: number;
  color?: string;
}) {
  if (!data || data.length === 0 || data.every((v) => v === 0)) {
    return <span className="text-xs text-muted-foreground/50">—</span>;
  }
  const max = Math.max(...data, 1);
  const padding = 1;
  const innerW = width - padding * 2;
  const innerH = height - padding * 2;
  const step = innerW / Math.max(data.length - 1, 1);

  const points = data.map((v, i) => {
    const x = padding + i * step;
    const y = padding + innerH - (v / max) * innerH;
    return `${x},${y}`;
  });

  const firstX = padding;
  const lastX = padding + (data.length - 1) * step;
  const fillPath = `M${firstX},${padding + innerH} L${points.join(" L")} L${lastX},${padding + innerH} Z`;

  return (
    <svg width={width} height={height} className="inline-block">
      <path d={fillPath} fill={color} fillOpacity={0.15} />
      <polyline
        points={points.join(" ")}
        fill="none"
        stroke={color}
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

// ─── Action Badge ───────────────────────────────────────────────────

function ActionBadge({ action }: { action: RLRuleAction }) {
  if (action === "log_only") {
    return (
      <Badge variant="outline" className={`${T.badgeMono} bg-neon-amber/10 text-neon-amber border-neon-amber/30`}>
        Monitor
      </Badge>
    );
  }
  return (
      <Badge variant="outline" className={`${T.badgeMono} bg-neon-pink/10 text-neon-pink border-neon-pink/30`}>
      Deny
    </Badge>
  );
}

// ─── Key Display ────────────────────────────────────────────────────

function keyLabel(key: string): string {
  const found = RL_KEY_OPTIONS.find((k) => k.value === key);
  if (found) return found.label;
  if (key.startsWith("header:")) return `Header: ${key.slice(7)}`;
  if (key.startsWith("cookie:")) return `Cookie: ${key.slice(7)}`;
  return key;
}

// ─── Conditions Summary ─────────────────────────────────────────────

function rlConditionsSummary(rule: RateLimitRule): string {
  const parts: string[] = [];
  if (rule.service) parts.push(`Service: ${rule.service}`);
  if (rule.conditions && rule.conditions.length > 0) {
    const condParts = rule.conditions.map((c) => {
      const fieldDef = RL_FIELD_DEFS.find((f) => f.value === c.field);
      const fieldLabel = fieldDef?.label ?? c.field;
      const opLabel = fieldDef?.operators.find((o) => o.value === c.operator)?.label ?? c.operator;
      const val = c.value.length > 30 ? c.value.slice(0, 30) + "..." : c.value;
      return `${fieldLabel} ${opLabel} ${val}`;
    });
    const joiner = rule.group_operator === "or" ? " OR " : " AND ";
    parts.push(condParts.join(joiner));
  }
  if (parts.length === 0) return "All requests";
  const joined = parts.join(" · ");
  return joined.length > 100 ? joined.slice(0, 100) + "..." : joined;
}

// ─── Rule Form (Create / Edit) ──────────────────────────────────────

interface RuleFormProps {
  initial?: RateLimitRule;
  services: ServiceDetail[];
  onSubmit: (data: RateLimitRuleCreateData) => void;
  onCancel?: () => void;
  submitLabel: string;
  saving?: boolean;
}

function RuleForm({ initial, services, onSubmit, onCancel, submitLabel, saving }: RuleFormProps) {
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [service, setService] = useState(initial?.service ?? "");
  const [conditions, setConditions] = useState<Condition[]>(initial?.conditions ?? []);
  const [groupOp, setGroupOp] = useState<GroupOperator>(initial?.group_operator ?? "and");
  const [key, setKey] = useState(initial?.key ?? "client_ip");
  const [customKeyParam, setCustomKeyParam] = useState(() => {
    const k = initial?.key ?? "";
    if (k.startsWith("header:")) return k.slice(7);
    if (k.startsWith("cookie:")) return k.slice(7);
    return "";
  });
  const [events, setEvents] = useState(initial?.events ?? 100);
  const [window, setWindow] = useState(initial?.window ?? "1m");
  const [action, setAction] = useState<RLRuleAction>(initial?.action ?? "deny");
  const [priority, setPriority] = useState(initial?.priority ?? 0);
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [error, setError] = useState<string | null>(null);

  // Is key a parameterized type?
  const keyBase = key.startsWith("header:") ? "header:" : key.startsWith("cookie:") ? "cookie:" : key;
  const isParameterizedKey = keyBase === "header:" || keyBase === "cookie:";

  const handleKeyChange = (v: string) => {
    setKey(v);
    if (v !== "header:" && v !== "cookie:") {
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
      setError(`${keyBase === "header:" ? "Header" : "Cookie"} name is required for this key type`);
      return;
    }

    const resolvedKey = isParameterizedKey ? `${keyBase}${customKeyParam.trim()}` : key;

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
              placeholder={keyBase === "header:" ? "e.g., X-API-Key" : "e.g., session_id"}
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

// Chart components (ClassificationBadge, ConfidenceBadge, DistributionHistogram,
// ImpactCurve, TimeOfDayChart) live in AdvisorCharts.tsx.
// RateAdvisorPanel lives in RateAdvisorPanel.tsx.

interface GlobalSettingsPanelProps {
  config: RateLimitGlobalConfig;
  onChange: (config: RateLimitGlobalConfig) => void;
  onSave: () => void;
  saving: boolean;
  dirty: boolean;
}

function GlobalSettingsPanel({ config, onChange, onSave, saving, dirty }: GlobalSettingsPanelProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className={`${T.cardTitle} flex items-center gap-2`}>
          <Settings2 className="h-4 w-4" />
          Global Settings
        </CardTitle>
        <CardDescription>Shared rate limiting configuration applied to all rules.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <div className="space-y-2">
            <Label>Jitter</Label>
            <Input
              type="number"
              min={0}
              max={1}
              step={0.05}
              value={config.jitter}
              onChange={(e) => onChange({ ...config, jitter: parseFloat(e.target.value) || 0 })}
              className="tabular-nums"
            />
            <p className="text-xs text-muted-foreground">Randomization factor (0-1) to spread burst traffic.</p>
          </div>
          <div className="space-y-2">
            <Label>Sweep Interval</Label>
            <Select value={config.sweep_interval || "1m"} onValueChange={(v) => onChange({ ...config, sweep_interval: v })}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="30s">30 seconds</SelectItem>
                <SelectItem value="1m">1 minute</SelectItem>
                <SelectItem value="5m">5 minutes</SelectItem>
                <SelectItem value="10m">10 minutes</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">How often to clean up expired rate limit entries.</p>
          </div>
        </div>

        <Separator />

        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Switch
              checked={config.distributed}
              onCheckedChange={(v) => onChange({ ...config, distributed: v })}
            />
            <Label>Distributed Rate Limiting</Label>
          </div>
          <p className="text-xs text-muted-foreground">
            Enable distributed rate limiting across multiple Caddy instances using shared state.
          </p>
          {config.distributed && (
            <div className="grid gap-4 sm:grid-cols-3 pl-4 border-l-2 border-neon-cyan/20">
              <div className="space-y-2">
                <Label>Read Interval</Label>
                <Select value={config.read_interval || "5s"} onValueChange={(v) => onChange({ ...config, read_interval: v })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1s">1 second</SelectItem>
                    <SelectItem value="5s">5 seconds</SelectItem>
                    <SelectItem value="10s">10 seconds</SelectItem>
                    <SelectItem value="30s">30 seconds</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Write Interval</Label>
                <Select value={config.write_interval || "5s"} onValueChange={(v) => onChange({ ...config, write_interval: v })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1s">1 second</SelectItem>
                    <SelectItem value="5s">5 seconds</SelectItem>
                    <SelectItem value="10s">10 seconds</SelectItem>
                    <SelectItem value="30s">30 seconds</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Purge Age</Label>
                <Select value={config.purge_age || "24h"} onValueChange={(v) => onChange({ ...config, purge_age: v })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1h">1 hour</SelectItem>
                    <SelectItem value="6h">6 hours</SelectItem>
                    <SelectItem value="24h">24 hours</SelectItem>
                    <SelectItem value="72h">72 hours</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          )}
        </div>

        {dirty && (
          <div className="flex justify-end">
            <Button size="sm" onClick={onSave} disabled={saving}>
              {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
              {saving ? "Saving..." : "Save Global Settings"}
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Main Rate Limits Panel ─────────────────────────────────────────

export default function RateLimitsPanel() {
  const [rules, setRules] = useState<RateLimitRule[]>([]);
  const [services, setServices] = useState<ServiceDetail[]>([]);
  const [globalConfig, setGlobalConfig] = useState<RateLimitGlobalConfig | null>(null);
  const [initialGlobalConfig, setInitialGlobalConfig] = useState<RateLimitGlobalConfig | null>(null);
  const [hitsData, setHitsData] = useState<RLRuleHitsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [deployStep, setDeployStep] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [globalSaving, setGlobalSaving] = useState(false);
  const [saving, setSaving] = useState(false);

  // Search & filter
  const [searchQuery, setSearchQuery] = useState("");
  const [actionFilter, setActionFilter] = useState<RLRuleAction | "all">("all");
  const [rulesPage, setRulesPage] = useState(1);

  // Dialog state
  const [dialogOpen, setDialogOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<string>("rules");

  const loadData = useCallback(() => {
    setLoading(true);
    setError(null);
    Promise.all([
      getRLRules(),
      fetchServices(),
      getRLGlobal().catch(() => null),
      getRLRuleHits(24).catch(() => null),
    ])
      .then(([rlRules, svcs, gc, hits]) => {
        setRules(rlRules);
        setServices(svcs);
        if (gc) {
          setGlobalConfig(gc);
          setInitialGlobalConfig(gc);
        }
        if (hits) setHitsData(hits);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Filtered rules
  const filteredRules = useMemo(() => {
    let result = rules;
    if (actionFilter !== "all") {
      result = result.filter((r) => r.action === actionFilter);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter((r) =>
        r.name.toLowerCase().includes(q) ||
        r.description.toLowerCase().includes(q) ||
        r.service.toLowerCase().includes(q) ||
        (r.conditions && r.conditions.some((c) => c.value.toLowerCase().includes(q)))
      );
    }
    return result;
  }, [rules, searchQuery, actionFilter]);

  // Reset page when filters change
  useEffect(() => { setRulesPage(1); }, [searchQuery, actionFilter]);

  const RULES_PAGE_SIZE = 15;
  const { items: pagedRules, totalPages: rulesTotalPages } = paginateArray(filteredRules, rulesPage, RULES_PAGE_SIZE);

  // Success toast
  const successTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const showSuccess = (msg: string) => {
    if (successTimerRef.current) clearTimeout(successTimerRef.current);
    setSuccessMsg(msg);
    successTimerRef.current = setTimeout(() => setSuccessMsg(null), 4000);
  };
  useEffect(() => () => { if (successTimerRef.current) clearTimeout(successTimerRef.current); }, []);

  // Global config dirty check
  const globalDirty = globalConfig !== null && initialGlobalConfig !== null &&
    JSON.stringify(globalConfig) !== JSON.stringify(initialGlobalConfig);

  // Auto-deploy after CRUD
  const autoDeploy = async (action: string) => {
    try {
      setDeployStep("Deploying...");
      const result = await deployRLRules();
      if (result.status === "deployed") {
        showSuccess(`${action} — deployed`);
      } else {
        showSuccess(`${action} — config written, Caddy reload needs manual intervention`);
      }
    } catch (deployErr: unknown) {
      setError(`${action}, but deploy failed: ${deployErr instanceof Error ? deployErr.message : "unknown error"}`);
    } finally {
      setDeployStep(null);
    }
  };

  const handleCreate = async (data: RateLimitRuleCreateData) => {
    setError(null);
    setSaving(true);
    try {
      const created = await createRLRule(data);
      setRules((prev) => [...prev, created]);
      closeDialog();
      await autoDeploy("Rule created");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Create failed");
    } finally {
      setSaving(false);
    }
  };

  const handleUpdate = async (id: string, data: RateLimitRuleCreateData) => {
    setError(null);
    setSaving(true);
    try {
      const updated = await updateRLRule(id, data);
      setRules((prev) => prev.map((r) => (r.id === id ? updated : r)));
      setEditingId(null);
      closeDialog();
      await autoDeploy("Rule updated");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Update failed");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: string) => {
    setError(null);
    setSaving(true);
    try {
      await deleteRLRule(id);
      setRules((prev) => prev.filter((r) => r.id !== id));
      setDeleteConfirmId(null);
      await autoDeploy("Rule deleted");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Delete failed");
    } finally {
      setSaving(false);
    }
  };

  const handleToggleEnabled = async (id: string, enabled: boolean) => {
    setError(null);
    setSaving(true);
    try {
      const updated = await updateRLRule(id, { enabled });
      setRules((prev) => prev.map((r) => (r.id === id ? updated : r)));
      await autoDeploy(enabled ? "Rule enabled" : "Rule disabled");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Toggle failed");
    } finally {
      setSaving(false);
    }
  };

  const handleSaveGlobal = async () => {
    if (!globalConfig) return;
    setGlobalSaving(true);
    try {
      const updated = await updateRLGlobal(globalConfig);
      setGlobalConfig(updated);
      setInitialGlobalConfig(updated);
      await autoDeploy("Global settings updated");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Save global settings failed");
    } finally {
      setGlobalSaving(false);
    }
  };

  const handleAdvisorCreateRule = useCallback(async (data: RateLimitRuleCreateData) => {
    setError(null);
    try {
      await createRLRule(data);
      await deployRLRules();
      const updated = await getRLRules();
      setRules(updated);
      setActiveTab("rules");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to create rule");
    }
  }, []);

  const handleExport = async () => {
    try {
      const data = await exportRLRules();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "rate-limit-rules.json";
      a.click();
      URL.revokeObjectURL(url);
      showSuccess("Rules exported");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Export failed");
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
        const parsed = JSON.parse(text);
        const result = await importRLRules(parsed);
        showSuccess(`Imported ${result.imported} rules`);
        loadData();
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "Import failed");
      }
    };
    input.click();
  };

  // Dialog control
  const openCreateDialog = () => {
    setEditingId(null);
    setDialogOpen(true);
  };

  const closeDialog = () => {
    setDialogOpen(false);
    setEditingId(null);
  };

  useEffect(() => {
    if (editingId) setDialogOpen(true);
  }, [editingId]);

  const ruleToEdit = editingId ? rules.find((r) => r.id === editingId) : null;

  // Stats
  const enabledCount = rules.filter((r) => r.enabled).length;
  const disabledCount = rules.length - enabledCount;
  const denyCount = rules.filter((r) => r.action === "deny" && r.enabled).length;
  const monitorCount = rules.filter((r) => r.action === "log_only" && r.enabled).length;

  if (loading) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className={T.pageTitle}>Rate Limits</h2>
          <p className={T.pageDescription}>Condition-based rate limiting rules</p>
        </div>
        <div className="space-y-4">
          {[...Array(3)].map((_, i) => (
            <Card key={i}>
              <CardContent className="p-6">
                <Skeleton className="h-20 w-full" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className={T.pageTitle}>Rate Limits</h2>
          <p className={T.pageDescription}>
            Condition-based rate limiting rules with per-path matching, flexible keys, and auto-deploy.
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

      {/* Alerts */}
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
      {deployStep && (
        <Alert>
          <Loader2 className="h-4 w-4 animate-spin" />
          <AlertTitle>Deploying</AlertTitle>
          <AlertDescription>{deployStep}</AlertDescription>
        </Alert>
      )}

      {/* Tabs: Rules | Global Settings */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="rules" className="gap-1.5">
            <Zap className="h-3.5 w-3.5" />
            Rules ({rules.length})
          </TabsTrigger>
          <TabsTrigger value="advisor" className="gap-1.5">
            <BarChart3 className="h-3.5 w-3.5" />
            Rate Advisor
          </TabsTrigger>
          <TabsTrigger value="settings" className="gap-1.5">
            <Settings2 className="h-3.5 w-3.5" />
            Global Settings
          </TabsTrigger>
        </TabsList>

        <TabsContent value="rules" className="space-y-4 mt-4">
          {/* Summary stats */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardContent className="p-4">
                <div className={T.statLabelUpper}>Total Rules</div>
                <div className={T.statValue}>{rules.length}</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className={T.statLabelUpper}>Active</div>
                <div className={`${T.statValue} text-neon-green`}>{enabledCount}</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className={T.statLabelUpper}>Deny</div>
                <div className={`${T.statValue} text-neon-pink`}>{denyCount}</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className={T.statLabelUpper}>Monitor</div>
                <div className={`${T.statValue} text-neon-amber`}>{monitorCount}</div>
              </CardContent>
            </Card>
          </div>

          {/* Rule list card */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className={T.cardTitle}>Rate Limit Rules</CardTitle>
                  <CardDescription>Per-service rate limiting with conditions, flexible keys, and auto-deploy.</CardDescription>
                </div>
                <Button onClick={openCreateDialog} size="sm">
                  <Plus className="h-3.5 w-3.5" />
                  Create Rule
                </Button>
              </div>
              {/* Search & Filter */}
              {rules.length > 0 && (
                <div className="flex items-center gap-2 pt-2">
                  <div className="relative flex-1 max-w-xs">
                    <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                    <Input
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Search rules..."
                      className="pl-8 h-8 text-xs"
                    />
                    {searchQuery && (
                      <button
                        onClick={() => setSearchQuery("")}
                        className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                      >
                        <X className="h-3 w-3" />
                      </button>
                    )}
                  </div>
                  <Select value={actionFilter} onValueChange={(v) => setActionFilter(v as RLRuleAction | "all")}>
                    <SelectTrigger className="w-[130px] h-8 text-xs">
                      <SelectValue placeholder="All actions" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All actions</SelectItem>
                      <SelectItem value="deny">Deny</SelectItem>
                      <SelectItem value="log_only">Monitor</SelectItem>
                    </SelectContent>
                  </Select>
                  {(searchQuery || actionFilter !== "all") && (
                    <span className="text-xs text-muted-foreground">
                      {filteredRules.length} of {rules.length}
                    </span>
                  )}
                </div>
              )}
            </CardHeader>
            <CardContent className="p-0 overflow-x-auto">
              {rules.length > 0 ? (
                <>
                  <Table>
                    <TableHeader>
                      <TableRow className="hover:bg-transparent">
                        <TableHead>Name</TableHead>
                        <TableHead>Service</TableHead>
                        <TableHead>Conditions / Target</TableHead>
                        <TableHead>Rate</TableHead>
                        <TableHead>Key</TableHead>
                        <TableHead>Action</TableHead>
                        <TableHead>Hits (24h)</TableHead>
                        <TableHead>Enabled</TableHead>
                        <TableHead className="text-right">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {pagedRules.map((rule) => (
                        <TableRow key={rule.id} className={!rule.enabled ? "opacity-50" : ""}>
                          <TableCell>
                            <div>
                              <p className={T.tableRowName}>{rule.name}</p>
                              {rule.description && (
                                <p className="text-xs text-muted-foreground truncate max-w-[200px]">{rule.description}</p>
                              )}
                            </div>
                          </TableCell>
                          <TableCell className="font-mono text-xs">{rule.service}</TableCell>
                          <TableCell className="text-xs font-mono max-w-[250px] truncate" title={rlConditionsSummary(rule)}>
                            {rlConditionsSummary(rule)}
                          </TableCell>
                          <TableCell className="text-xs tabular-nums whitespace-nowrap">
                            {rule.events}/{rule.window}
                          </TableCell>
                          <TableCell className="text-xs">{keyLabel(rule.key)}</TableCell>
                          <TableCell><ActionBadge action={rule.action} /></TableCell>
                          <TableCell>
                            {(() => {
                              const hit = hitsData?.[rule.id];
                              if (!hit) return <span className="text-xs text-muted-foreground/50">—</span>;
                              if (hit.total === 0) {
                                return <Sparkline data={hit.sparkline} color="#475569" />;
                              }
                              return (
                                <div className="flex items-center gap-1.5">
                                  <Sparkline data={hit.sparkline} color="#22d3ee" />
                                  <span className="text-xs tabular-nums text-muted-foreground">
                                    {hit.total.toLocaleString()}
                                  </span>
                                </div>
                              );
                            })()}
                          </TableCell>
                          <TableCell>
                            <Switch
                              checked={rule.enabled}
                              onCheckedChange={(v) => handleToggleEnabled(rule.id, v)}
                            />
                          </TableCell>
                          <TableCell className="text-right">
                            <div className="flex items-center justify-end gap-1">
                              <Button
                                variant="ghost"
                                size="icon-sm"
                                onClick={() => setEditingId(rule.id)}
                              >
                                <Pencil className="h-3.5 w-3.5" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="icon-sm"
                                className="text-muted-foreground hover:text-neon-pink"
                                onClick={() => setDeleteConfirmId(rule.id)}
                              >
                                <Trash2 className="h-3.5 w-3.5" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                   {filteredRules.length > 0 && (
                    <TablePagination page={rulesPage} totalPages={rulesTotalPages} onPageChange={setRulesPage} totalItems={filteredRules.length} />
                  )}
                  {filteredRules.length === 0 && (
                    <div className="flex flex-col items-center justify-center py-8">
                      <Search className="mb-2 h-6 w-6 text-muted-foreground/50" />
                      <p className="text-sm text-muted-foreground">No rules match your filters</p>
                      <button
                        className="text-xs text-neon-cyan hover:underline mt-1"
                        onClick={() => { setSearchQuery(""); setActionFilter("all"); }}
                      >
                        Clear filters
                      </button>
                    </div>
                  )}
                </>
              ) : (
                <div className="flex flex-col items-center justify-center py-12">
                  <Shield className="mb-3 h-8 w-8 text-muted-foreground/50" />
                  <p className="text-sm text-muted-foreground">No rate limit rules configured yet</p>
                  <p className="text-xs text-muted-foreground/70 mt-1">
                    <button className="text-neon-cyan hover:underline" onClick={openCreateDialog}>
                      Create your first rule
                    </button>
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="advisor" className="mt-4">
          <RateAdvisorPanel
            services={services}
            onCreateRule={handleAdvisorCreateRule}
          />
        </TabsContent>

        <TabsContent value="settings" className="mt-4">
          {globalConfig && (
            <GlobalSettingsPanel
              config={globalConfig}
              onChange={setGlobalConfig}
              onSave={handleSaveGlobal}
              saving={globalSaving}
              dirty={globalDirty}
            />
          )}
        </TabsContent>
      </Tabs>

      {/* Create / Edit Dialog */}
      <Dialog open={dialogOpen} onOpenChange={(open) => { if (!open) closeDialog(); }}>
        <DialogContent className="w-[90vw] max-w-[1200px] max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Zap className="h-4 w-4 text-neon-green" />
              {editingId ? "Edit Rate Limit Rule" : "Create Rate Limit Rule"}
            </DialogTitle>
            <DialogDescription>
              {editingId
                ? "Modify the rule below. Changes are deployed automatically on save."
                : "Create a condition-based rate limiting rule. Deployed automatically on save."}
            </DialogDescription>
          </DialogHeader>

          {editingId && ruleToEdit ? (
            <RuleForm
              key={editingId}
              initial={ruleToEdit}
              services={services}
              onSubmit={(data) => handleUpdate(editingId, data)}
              onCancel={closeDialog}
              submitLabel="Save Changes"
              saving={saving}
            />
          ) : (
            <RuleForm
              services={services}
              onSubmit={(data) => handleCreate(data)}
              submitLabel="Create Rule"
              saving={saving}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <Dialog open={deleteConfirmId !== null} onOpenChange={(open) => !open && setDeleteConfirmId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Rate Limit Rule</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete this rule? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteConfirmId(null)} disabled={saving}>Cancel</Button>
            <Button variant="destructive" onClick={() => deleteConfirmId && handleDelete(deleteConfirmId)} disabled={saving}>
              {saving && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
              {saving ? "Deleting..." : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

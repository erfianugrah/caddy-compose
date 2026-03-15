import { useState, useEffect, useCallback, useRef, useMemo, useDeferredValue } from "react";
import { useTableSort } from "@/hooks/useTableSort";
import { SortableTableHead } from "@/components/SortableTableHead";
import { TablePagination, paginateArray } from "./TablePagination";
import {
  DndContext,
  closestCenter,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent,
} from "@dnd-kit/core";
import {
  arrayMove,
  SortableContext,
  sortableKeyboardCoordinates,
  verticalListSortingStrategy,
} from "@dnd-kit/sortable";
import { Sparkline } from "./Sparkline";
import { SortableTableRow } from "./SortableTableRow";
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
  ArrowUpToLine,
  ArrowDownToLine,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
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
import {
  getRLRules,
  createRLRule,
  updateRLRule,
  deleteRLRule,
  reorderRLRules,
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
  type RLRuleAction,
} from "@/lib/api";
import { RateAdvisorPanel } from "./RateAdvisorPanel";
import { T } from "@/lib/typography";
import { downloadJSON } from "@/lib/download";

// ─── Submodule imports ──────────────────────────────────────────────
import { RL_RULES_PAGE_SIZE } from "./ratelimits/constants";
import { ActionBadge, keyLabel, rlConditionsSummary } from "./ratelimits/helpers";
import { RuleForm } from "./ratelimits/RuleForm";
import { GlobalSettingsPanel } from "./ratelimits/GlobalSettingsPanel";

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

  // Guard against stale responses when rapid reloads fire concurrent requests.
  const requestGenRef = useRef(0);

  // Search & filter
  const [searchQuery, setSearchQuery] = useState("");
  const deferredSearch = useDeferredValue(searchQuery);
  const [actionFilter, setActionFilter] = useState<RLRuleAction | "all">("all");
  const [rulesPage, setRulesPage] = useState(1);

  // Bulk selection
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkBusy, setBulkBusy] = useState(false);

  // Inline position editing — click an order number to type a new position.
  const [editingPositionId, setEditingPositionId] = useState<string | null>(null);

  // Drag-and-drop reorder
  const isFilteredBase = deferredSearch.trim() !== "" || actionFilter !== "all";
  const dndSensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 5 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );

  // Dialog state
  const [dialogOpen, setDialogOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<string>("rules");

  const loadData = useCallback(() => {
    const gen = ++requestGenRef.current;
    setLoading(true);
    setError(null);
    Promise.all([
      getRLRules(),
      fetchServices(),
      getRLGlobal().catch(() => null),
      getRLRuleHits(24).catch(() => null),
    ])
      .then(([rlRules, svcs, gc, hits]) => {
        if (gen !== requestGenRef.current) return;
        setRules(rlRules);
        setServices(svcs);
        if (gc) {
          setGlobalConfig(gc);
          setInitialGlobalConfig(gc);
        }
        if (hits) setHitsData(hits);
      })
      .catch((err) => {
        if (gen !== requestGenRef.current) return;
        setError(err.message);
      })
      .finally(() => {
        if (gen !== requestGenRef.current) return;
        setLoading(false);
      });
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
    if (deferredSearch.trim()) {
      const q = deferredSearch.toLowerCase();
      result = result.filter((r) =>
        r.name.toLowerCase().includes(q) ||
        r.description.toLowerCase().includes(q) ||
        r.service.toLowerCase().includes(q) ||
        (r.conditions && r.conditions.some((c) => c.value.toLowerCase().includes(q))) ||
        (r.tags && r.tags.some((t) => t.toLowerCase().includes(q)))
      );
    }
    return result;
  }, [rules, deferredSearch, actionFilter]);

  const selectAllVisible = useCallback(() => {
    setSelected(new Set(filteredRules.map((r) => r.id)));
  }, [filteredRules]);

  // Reset page when filters change
  useEffect(() => { setRulesPage(1); }, [deferredSearch, actionFilter]);

  const rlSortComparators = useMemo(() => ({
    name: (a: RateLimitRule, b: RateLimitRule) => a.name.localeCompare(b.name),
    service: (a: RateLimitRule, b: RateLimitRule) => a.service.localeCompare(b.service),
    rate: (a: RateLimitRule, b: RateLimitRule) => a.events - b.events,
    key: (a: RateLimitRule, b: RateLimitRule) => a.key.localeCompare(b.key),
    action: (a: RateLimitRule, b: RateLimitRule) => a.action.localeCompare(b.action),
    hits: (a: RateLimitRule, b: RateLimitRule) => (hitsData?.[a.id]?.total ?? 0) - (hitsData?.[b.id]?.total ?? 0),
    enabled: (a: RateLimitRule, b: RateLimitRule) => Number(a.enabled) - Number(b.enabled),
  }), [hitsData]);
  const rlSort = useTableSort(filteredRules, rlSortComparators);
  const sortedFilteredRules = rlSort.sortedData;

  const isSorted = rlSort.sortState.key !== null;
  const isFiltered = isFilteredBase || isSorted;
  const { items: pagedRules, totalPages: rulesTotalPages } = paginateArray(sortedFilteredRules, rulesPage, RL_RULES_PAGE_SIZE);

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
  const autoDeploy = useCallback(async (action: string) => {
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
  }, []);

  const handleDragEnd = useCallback(async (event: DragEndEvent) => {
    const { active, over } = event;
    if (!over || active.id === over.id) return;

    const pageStartIdx = (rulesPage - 1) * RL_RULES_PAGE_SIZE;
    const pageIds = rules.slice(pageStartIdx, pageStartIdx + RL_RULES_PAGE_SIZE).map((r) => r.id);
    const oldIdx = pageIds.indexOf(active.id as string);
    const newIdx = pageIds.indexOf(over.id as string);
    if (oldIdx === -1 || newIdx === -1) return;

    const newRules = [...rules];
    const pageSlice = newRules.splice(pageStartIdx, pageIds.length);
    const reorderedPage = arrayMove(pageSlice, oldIdx, newIdx);
    newRules.splice(pageStartIdx, 0, ...reorderedPage);

    const prev = rules;
    setRules(newRules);
    try {
      const result = await reorderRLRules(newRules.map((r) => r.id));
      setRules(result);
      await autoDeploy("Rules reordered");
    } catch (err: unknown) {
      setRules(prev);
      setError(err instanceof Error ? err.message : "Reorder failed");
    }
  }, [rules, rulesPage, autoDeploy]);

  // ─── Move to edge (top / bottom) ───────────────────────────────────

  const handleMoveToEdge = useCallback(async (id: string, edge: "top" | "bottom") => {
    const idx = rules.findIndex((r) => r.id === id);
    if (idx === -1) return;
    if (edge === "top" && idx === 0) return;
    if (edge === "bottom" && idx === rules.length - 1) return;

    const newRules = [...rules];
    const [item] = newRules.splice(idx, 1);
    if (edge === "top") {
      newRules.unshift(item);
      setRulesPage(1);
    } else {
      newRules.push(item);
      setRulesPage(Math.ceil(newRules.length / RL_RULES_PAGE_SIZE));
    }

    const prev = rules;
    setRules(newRules);
    try {
      const result = await reorderRLRules(newRules.map((r) => r.id));
      setRules(result);
      await autoDeploy(`Rule moved to ${edge}`);
    } catch (err: unknown) {
      setRules(prev);
      setError(err instanceof Error ? err.message : "Move failed");
    }
  }, [rules, autoDeploy]);

  // ─── Move single rule to a specific position ─────────────────────

  const handleMoveToPosition = useCallback(async (id: string, targetPos: number) => {
    const fromIdx = rules.findIndex((r) => r.id === id);
    if (fromIdx === -1) return;
    const toIdx = Math.max(0, Math.min(rules.length - 1, targetPos - 1));
    if (fromIdx === toIdx) return;

    const newRules = [...rules];
    const [item] = newRules.splice(fromIdx, 1);
    newRules.splice(toIdx, 0, item);

    setRulesPage(Math.ceil((toIdx + 1) / RL_RULES_PAGE_SIZE));

    const prev = rules;
    setRules(newRules);
    try {
      const result = await reorderRLRules(newRules.map((r) => r.id));
      setRules(result);
      await autoDeploy(`Rule moved to position ${toIdx + 1}`);
    } catch (err: unknown) {
      setRules(prev);
      setError(err instanceof Error ? err.message : "Move failed");
    }
  }, [rules, autoDeploy]);

  // ─── Bulk move to position / edge ─────────────────────────────────

  const handleBulkMoveToPosition = useCallback(async (targetPos: number) => {
    if (selected.size === 0) return;
    const selectedIds = new Set(selected);
    const remaining = rules.filter((r) => !selectedIds.has(r.id));
    const moved = rules.filter((r) => selectedIds.has(r.id));
    const insertIdx = Math.max(0, Math.min(remaining.length, targetPos - 1));
    const newRules = [...remaining.slice(0, insertIdx), ...moved, ...remaining.slice(insertIdx)];

    setRulesPage(Math.ceil((insertIdx + 1) / RL_RULES_PAGE_SIZE));

    const prev = rules;
    setRules(newRules);
    try {
      const result = await reorderRLRules(newRules.map((r) => r.id));
      setRules(result);
      setSelected(new Set());
      await autoDeploy(`${moved.length} rules moved to position ${insertIdx + 1}`);
    } catch (err: unknown) {
      setRules(prev);
      setError(err instanceof Error ? err.message : "Bulk move failed");
    }
  }, [rules, selected, autoDeploy]);

  const handleBulkMoveToEdge = useCallback(async (edge: "top" | "bottom") => {
    if (selected.size === 0) return;
    const selectedIds = new Set(selected);
    const remaining = rules.filter((r) => !selectedIds.has(r.id));
    const moved = rules.filter((r) => selectedIds.has(r.id));
    const newRules = edge === "top" ? [...moved, ...remaining] : [...remaining, ...moved];

    if (edge === "top") {
      setRulesPage(1);
    } else {
      setRulesPage(Math.ceil(newRules.length / RL_RULES_PAGE_SIZE));
    }

    const prev = rules;
    setRules(newRules);
    try {
      const result = await reorderRLRules(newRules.map((r) => r.id));
      setRules(result);
      setSelected(new Set());
      await autoDeploy(`${moved.length} rules moved to ${edge}`);
    } catch (err: unknown) {
      setRules(prev);
      setError(err instanceof Error ? err.message : "Bulk move failed");
    }
  }, [rules, selected, autoDeploy]);

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
      const existing = rules.find((r) => r.id === id);
      if (!existing) {
        setError("Rule not found");
        return;
      }
      const payload = {
        name: existing.name,
        description: existing.description,
        service: existing.service,
        conditions: existing.conditions,
        group_operator: existing.group_operator,
        key: existing.key,
        events: existing.events,
        window: existing.window,
        action: existing.action,
        priority: existing.priority,
        enabled,
      };
      const updated = await updateRLRule(id, payload);
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

  // ─── Bulk actions ─────────────────────────────────────────────────

  const lastSelectedRef = useRef<number | null>(null);

  const toggleSelect = useCallback((id: string, index: number, shiftKey: boolean) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (shiftKey && lastSelectedRef.current !== null) {
        const start = Math.min(lastSelectedRef.current, index);
        const end = Math.max(lastSelectedRef.current, index);
        for (let i = start; i <= end; i++) {
          next.add(pagedRules[i].id);
        }
      } else {
        if (next.has(id)) {
          next.delete(id);
        } else {
          next.add(id);
        }
      }
      lastSelectedRef.current = index;
      return next;
    });
  }, [pagedRules]);

  const clearSelection = useCallback(() => setSelected(new Set()), []);

  const handleBulkAction = useCallback(
    async (action: "enable" | "disable" | "delete") => {
      if (selected.size === 0) return;
      const confirmMsg = action === "delete"
        ? `Delete ${selected.size} rule(s)? This cannot be undone.`
        : undefined;
      if (confirmMsg && !window.confirm(confirmMsg)) return;
      try {
        setBulkBusy(true);
        if (action === "delete") {
          for (const id of selected) {
            await deleteRLRule(id);
          }
        } else {
          for (const id of selected) {
            await updateRLRule(id, { enabled: action === "enable" });
          }
        }
        setSelected(new Set());
        loadData();
        await autoDeploy(`Bulk ${action}: ${selected.size} rules`);
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : `Bulk ${action} failed`);
      } finally {
        setBulkBusy(false);
      }
    },
    [selected, loadData, autoDeploy],
  );

  const handleExport = async () => {
    try {
      const data = await exportRLRules();
      downloadJSON(data, "rate-limit-rules.json");
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
        const imported = Array.isArray(parsed) ? parsed : parsed.rules;
        if (!Array.isArray(imported) || !imported.every((r: unknown) => typeof r === "object" && r !== null && "id" in r && "name" in r && "service" in r)) {
          throw new Error("Invalid import data: expected an array of rules with 'id', 'name', and 'service' fields");
        }
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
      {/* Export/Import buttons */}
      <div className="flex items-center justify-end gap-2">
        <Button variant="outline" size="sm" onClick={handleExport}>
          <Download className="h-3.5 w-3.5" />
          Export
        </Button>
        <Button variant="outline" size="sm" onClick={handleImport}>
          <Upload className="h-3.5 w-3.5" />
          Import
        </Button>
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

      {/* Tabs: Rules | Advisor | Global Settings */}
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
                <div className={`${T.statValue} text-lv-green`}>{enabledCount}</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className={T.statLabelUpper}>Deny</div>
                <div className={`${T.statValue} text-lv-red`}>{denyCount}</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className={T.statLabelUpper}>Monitor</div>
                <div className={`${T.statValue} text-lv-peach`}>{monitorCount}</div>
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
                        aria-label="Clear search"
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
                  {selected.size > 0 && (
                    <div className="flex items-center gap-2 px-4 py-2 border-b border-lv-cyan/30 bg-lv-cyan/5">
                      <span className="text-xs font-medium text-lv-cyan mr-2">
                        {selected.size} selected
                      </span>
                      <Button variant="outline" size="xs" onClick={() => handleBulkAction("enable")} disabled={bulkBusy}>
                        Enable
                      </Button>
                      <Button variant="outline" size="xs" onClick={() => handleBulkAction("disable")} disabled={bulkBusy}>
                        Disable
                      </Button>
                      <Button variant="outline" size="xs" className="text-lv-red hover:text-lv-red" onClick={() => handleBulkAction("delete")} disabled={bulkBusy}>
                        Delete
                      </Button>
                      {!isFiltered && (
                        <>
                          <span className="mx-1 h-4 w-px bg-border" />
                          <Button variant="outline" size="xs" onClick={() => handleBulkMoveToEdge("top")} disabled={bulkBusy}>
                            <ArrowUpToLine className="h-3 w-3 mr-1" />
                            Move to Top
                          </Button>
                          <Button variant="outline" size="xs" onClick={() => handleBulkMoveToEdge("bottom")} disabled={bulkBusy}>
                            <ArrowDownToLine className="h-3 w-3 mr-1" />
                            Move to Bottom
                          </Button>
                          <form className="inline-flex items-center gap-1 ml-1" onSubmit={(e) => {
                            e.preventDefault();
                            const input = (e.target as HTMLFormElement).elements.namedItem("bulkPos") as HTMLInputElement;
                            const pos = parseInt(input.value, 10);
                            if (!isNaN(pos) && pos >= 1) {
                              handleBulkMoveToPosition(pos);
                              input.value = "";
                            }
                          }}>
                            <span className="text-xs text-muted-foreground">Move to #</span>
                            <input
                              name="bulkPos"
                              type="number"
                              min={1}
                              max={rules.length}
                              className="w-[50px] h-6 bg-transparent border border-border rounded px-1 text-xs text-center outline-none focus:border-lv-cyan"
                              placeholder="#"
                            />
                          </form>
                        </>
                      )}
                      <div className="ml-auto flex items-center gap-2">
                        <Button variant="ghost" size="xs" onClick={selectAllVisible} className="text-xs text-muted-foreground">
                          Select All ({filteredRules.length})
                        </Button>
                        <Button variant="ghost" size="xs" onClick={clearSelection} className="text-xs text-muted-foreground">
                          Clear
                        </Button>
                      </div>
                    </div>
                  )}
                  <DndContext sensors={dndSensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
                  <Table>
                    <TableHeader>
                      <TableRow className="hover:bg-transparent">
                        <TableHead className="w-[36px] px-2">
                          <input
                            type="checkbox"
                            checked={pagedRules.length > 0 && pagedRules.every((r) => selected.has(r.id))}
                            ref={(el) => {
                              if (el) {
                                const allSelected = pagedRules.length > 0 && pagedRules.every((r) => selected.has(r.id));
                                const someSelected = pagedRules.some((r) => selected.has(r.id));
                                el.indeterminate = someSelected && !allSelected;
                              }
                            }}
                            onChange={(ev) => {
                              if (ev.target.checked) {
                                setSelected(new Set([...selected, ...pagedRules.map((r) => r.id)]));
                              } else {
                                const pageIds = new Set(pagedRules.map((r) => r.id));
                                setSelected(new Set([...selected].filter((id) => !pageIds.has(id))));
                              }
                            }}
                            className="h-3.5 w-3.5 rounded border-border"
                          />
                        </TableHead>
                        <TableHead className="w-[52px] px-1">#</TableHead>
                        <SortableTableHead sortKey="name" activeKey={rlSort.sortState.key} direction={rlSort.sortState.direction} onSort={rlSort.toggleSort}>Name</SortableTableHead>
                        <SortableTableHead sortKey="service" activeKey={rlSort.sortState.key} direction={rlSort.sortState.direction} onSort={rlSort.toggleSort}>Service</SortableTableHead>
                        <TableHead>Conditions / Target</TableHead>
                        <SortableTableHead sortKey="rate" activeKey={rlSort.sortState.key} direction={rlSort.sortState.direction} onSort={rlSort.toggleSort}>Rate</SortableTableHead>
                        <SortableTableHead sortKey="key" activeKey={rlSort.sortState.key} direction={rlSort.sortState.direction} onSort={rlSort.toggleSort}>Key</SortableTableHead>
                        <SortableTableHead sortKey="action" activeKey={rlSort.sortState.key} direction={rlSort.sortState.direction} onSort={rlSort.toggleSort}>Action</SortableTableHead>
                        <SortableTableHead sortKey="hits" activeKey={rlSort.sortState.key} direction={rlSort.sortState.direction} onSort={rlSort.toggleSort}>Hits (24h)</SortableTableHead>
                        <SortableTableHead sortKey="enabled" activeKey={rlSort.sortState.key} direction={rlSort.sortState.direction} onSort={rlSort.toggleSort}>Enabled</SortableTableHead>
                        <TableHead className="text-right">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <SortableContext items={pagedRules.map((r) => r.id)} strategy={verticalListSortingStrategy}>
                    <TableBody>
                      {pagedRules.map((rule, pageIdx) => {
                        const globalIdx = (rulesPage - 1) * RL_RULES_PAGE_SIZE + pageIdx + 1;
                        return (
                        <SortableTableRow
                          key={rule.id}
                          id={rule.id}
                          disabled={isFiltered}
                          className={`${!rule.enabled ? "opacity-50" : ""}${selected.has(rule.id) ? " bg-lv-purple/10" : ""}`}
                        >
                          <TableCell className="px-2" onClick={(e) => e.stopPropagation()}>
                            <input
                              type="checkbox"
                              checked={selected.has(rule.id)}
                              onChange={(e) => toggleSelect(rule.id, pageIdx, (e.nativeEvent as MouseEvent).shiftKey)}
                              className="h-3.5 w-3.5 rounded border-border accent-lv-purple cursor-pointer"
                            />
                          </TableCell>
                          <TableCell className="text-xs tabular-nums text-muted-foreground/60" title={`Rule ${globalIdx} of ${filteredRules.length} — click to move`}>
                            {editingPositionId === rule.id ? (
                              <input
                                type="number"
                                min={1}
                                max={rules.length}
                                defaultValue={globalIdx}
                                autoFocus
                                className="w-[40px] bg-transparent border border-lv-cyan/50 rounded px-1 py-0 text-xs text-center text-lv-cyan outline-none"
                                onBlur={(e) => {
                                  setEditingPositionId(null);
                                  const v = parseInt(e.target.value, 10);
                                  if (!isNaN(v) && v !== globalIdx) handleMoveToPosition(rule.id, v);
                                }}
                                onKeyDown={(e) => {
                                  if (e.key === "Enter") {
                                    (e.target as HTMLInputElement).blur();
                                  } else if (e.key === "Escape") {
                                    setEditingPositionId(null);
                                  }
                                }}
                              />
                            ) : (
                              <button
                                onClick={() => !isFiltered && setEditingPositionId(rule.id)}
                                className={`${isFiltered ? "cursor-default" : "cursor-pointer hover:text-lv-cyan hover:bg-lv-cyan/10 rounded px-1"} transition-colors`}
                                disabled={isFiltered}
                              >
                                {globalIdx}
                              </button>
                            )}
                          </TableCell>
                          <TableCell>
                            <div>
                              <p className={T.tableRowName}>{rule.name}</p>
                              {rule.description && (
                                <p className="text-xs text-muted-foreground truncate max-w-[200px]">{rule.description}</p>
                              )}
                              {rule.tags && rule.tags.length > 0 && (
                                <div className="flex flex-wrap gap-1 mt-1">
                                  {rule.tags.map((tag) => (
                                    <span key={tag} className="inline-flex items-center rounded bg-lovelace-800 border border-border px-1.5 py-0 text-[10px] font-data text-lv-cyan">
                                      {tag}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          </TableCell>
                          <TableCell className="font-data text-xs">{rule.service}</TableCell>
                          <TableCell className="text-xs font-data max-w-[250px] truncate" title={rlConditionsSummary(rule)}>
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
                                return <Sparkline data={hit.sparkline} color="#606270" />;
                              }
                              return (
                                <div className="flex items-center gap-1.5">
                                  <Sparkline data={hit.sparkline} color="#79e6f3" />
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
                              {!isFiltered && (
                                <>
                                  <Button
                                    aria-label={`Move rule ${rule.name} to top`}
                                    variant="ghost"
                                    size="icon-sm"
                                    className="text-muted-foreground/50 hover:text-lv-cyan"
                                    onClick={() => handleMoveToEdge(rule.id, "top")}
                                    disabled={globalIdx === 1}
                                  >
                                    <ArrowUpToLine className="h-3.5 w-3.5" />
                                  </Button>
                                  <Button
                                    aria-label={`Move rule ${rule.name} to bottom`}
                                    variant="ghost"
                                    size="icon-sm"
                                    className="text-muted-foreground/50 hover:text-lv-cyan"
                                    onClick={() => handleMoveToEdge(rule.id, "bottom")}
                                    disabled={globalIdx === filteredRules.length}
                                  >
                                    <ArrowDownToLine className="h-3.5 w-3.5" />
                                  </Button>
                                </>
                              )}
                              <Button
                                aria-label={`Edit rule ${rule.name}`}
                                variant="ghost"
                                size="icon-sm"
                                onClick={() => setEditingId(rule.id)}
                              >
                                <Pencil className="h-3.5 w-3.5" />
                              </Button>
                              <Button
                                aria-label={`Delete rule ${rule.name}`}
                                variant="ghost"
                                size="icon-sm"
                                className="text-muted-foreground hover:text-lv-red"
                                onClick={() => setDeleteConfirmId(rule.id)}
                              >
                                <Trash2 className="h-3.5 w-3.5" />
                              </Button>
                            </div>
                          </TableCell>
                        </SortableTableRow>
                        );
                      })}
                    </TableBody>
                    </SortableContext>
                  </Table>
                  </DndContext>
                   {filteredRules.length > 0 && (
                    <TablePagination page={rulesPage} totalPages={rulesTotalPages} onPageChange={setRulesPage} totalItems={filteredRules.length} pageSize={RL_RULES_PAGE_SIZE} />
                  )}
                  {filteredRules.length === 0 && (
                    <div className="flex flex-col items-center justify-center py-8">
                      <Search className="mb-2 h-6 w-6 text-muted-foreground/50" />
                      <p className="text-sm text-muted-foreground">No rules match your filters</p>
                      <button
                        className="text-xs text-lv-cyan hover:underline mt-1"
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
                    <button className="text-lv-cyan hover:underline" onClick={openCreateDialog}>
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
              <Zap className="h-4 w-4 text-lv-green" />
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

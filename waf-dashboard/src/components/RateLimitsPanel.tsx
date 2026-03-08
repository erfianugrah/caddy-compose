import { useState, useEffect, useCallback, useRef, useMemo } from "react";
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

  // Search & filter
  const [searchQuery, setSearchQuery] = useState("");
  const [actionFilter, setActionFilter] = useState<RLRuleAction | "all">("all");
  const [rulesPage, setRulesPage] = useState(1);

  // Drag-and-drop reorder
  const isFilteredBase = searchQuery.trim() !== "" || actionFilter !== "all";
  const dndSensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 5 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );

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
  }, [rules, rulesPage]);

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
                  <DndContext sensors={dndSensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
                  <Table>
                    <TableHeader>
                      <TableRow className="hover:bg-transparent">
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
                          className={!rule.enabled ? "opacity-50" : ""}
                        >
                          <TableCell className="text-xs tabular-nums text-muted-foreground/60">
                            {globalIdx}
                          </TableCell>
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
                                className="text-muted-foreground hover:text-neon-pink"
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

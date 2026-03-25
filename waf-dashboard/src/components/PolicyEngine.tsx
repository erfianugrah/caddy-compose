import { useState, useEffect, useCallback, useRef, useMemo, useDeferredValue } from "react";
import { useTableSort } from "@/hooks/useTableSort";
import { useRuleReorder } from "@/hooks/useRuleReorder";
import { useRuleSelection } from "@/hooks/useRuleSelection";
import { SortableTableHead } from "@/components/SortableTableHead";
import { TablePagination, paginateArray } from "./TablePagination";
import { StatusAlerts, BulkActionsBar, InlinePositionEditor, DeleteConfirmDialog } from "./rules";
import {
  DndContext,
  closestCenter,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
} from "@dnd-kit/core";
import {
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
  Code2,
  Zap,
  Loader2,
  Search,
  X,
  ArrowUpToLine,
  ArrowDownToLine,
  LayoutTemplate,
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  getExclusions,
  createExclusion,
  updateExclusion,
  deleteExclusion,
  reorderExclusions,
  deployConfig,
  fetchServices,
  exportExclusions,
  importExclusions,
  fetchExclusionHits,
  bulkUpdateExclusions,
  listTemplates,
  applyTemplate,
  type Exclusion,
  type ExclusionType,
  type ExclusionCreateData,
  type ServiceDetail,
  type ExclusionHitsResponse,
  type BulkExclusionAction,
  type RuleTemplate,
} from "@/lib/api";

import { T } from "@/lib/typography";
import { downloadJSON } from "@/lib/download";
import type { AdvancedFormState } from "./policy/constants";
import type { EventPrefill } from "./policy/eventPrefill";
import { consumePrefillEvent, consumeURLPrefill } from "./policy/eventPrefill";
import { conditionsSummary, exclusionTypeLabel, exclusionTypeBadgeVariant } from "./policy/exclusionHelpers";
import { QuickActionsForm, AdvancedBuilderForm } from "./policy/PolicyForms";
import { RuleForm } from "./ratelimits/RuleForm";
import { updateRLRule, type RateLimitRule, type RateLimitRuleCreateData, type RLRuleKey, type RLRuleAction } from "@/lib/api";

const RULES_PAGE_SIZE = 25;

// ─── Main Policy Engine Component ───────────────────────────────────

export default function PolicyEngine() {
  const [exclusions, setExclusions] = useState<Exclusion[]>([]);
  const [services, setServices] = useState<ServiceDetail[]>([]);
  const [hitsData, setHitsData] = useState<ExclusionHitsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);

  // Search & filter state
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<ExclusionType | "all">("all");
  const [rulesPage, setRulesPage] = useState(1);

  // Bulk selection (shared via useRuleSelection — wired up after filteredExclusions)
  const [bulkBusy, setBulkBusy] = useState(false);

  // Inline position editing — click an order number to type a new position.
  const [editingPositionId, setEditingPositionId] = useState<string | null>(null);

  const [deployStep, setDeployStep] = useState<string | null>(null);

  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Event prefill — consumed once on mount from sessionStorage or URL params.
  // Must use useEffect (not useState initializer) to avoid SSR hydration mismatch.
  const [eventPrefill, setEventPrefill] = useState<EventPrefill | null>(null);
  const [cameFromEvents, setCameFromEvents] = useState(false);
  useEffect(() => {
    // Try sessionStorage-based prefill first (from Events page), then URL params
    // (from Challenge Analytics quick-actions: Endpoint Discovery, Reputation).
    const prefill = consumePrefillEvent() || consumeURLPrefill();
    if (prefill) {
      setEventPrefill(prefill);
      setCameFromEvents(true);
    }
  }, []);

  // Guard against stale responses when rapid reloads fire concurrent requests.
  const requestGenRef = useRef(0);

  // Drag-and-drop reorder state
  const deferredSearch = useDeferredValue(searchQuery);
  const isFilteredBase = deferredSearch.trim() !== "" || typeFilter !== "all";
  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 5 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );

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
    const gen = ++requestGenRef.current;
    setLoading(true);
    setError(null);
    Promise.all([
      getExclusions(),
      fetchServices(),
      fetchExclusionHits(24).catch(() => null),
    ])
      .then(([excl, svcs, hits]) => {
        if (gen !== requestGenRef.current) return;
        setExclusions(excl);
        setServices(svcs);
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

  // Filtered exclusions for search + type filter
  const filteredExclusions = useMemo(() => {
    let result = exclusions;
    if (typeFilter !== "all") {
      result = result.filter((e) => e.type === typeFilter);
    }
    if (deferredSearch.trim()) {
      const q = deferredSearch.toLowerCase();
      result = result.filter((e) =>
        e.name.toLowerCase().includes(q) ||
        e.description.toLowerCase().includes(q) ||
        (e.conditions && e.conditions.some((c) => c.value.toLowerCase().includes(q)))
      );
    }
    return result;
  }, [exclusions, deferredSearch, typeFilter]);

  // Reset page when filters change
  useEffect(() => { setRulesPage(1); }, [deferredSearch, typeFilter]);

  const exclSortComparators = useMemo(() => ({
    name: (a: Exclusion, b: Exclusion) => a.name.localeCompare(b.name),
    type: (a: Exclusion, b: Exclusion) => a.type.localeCompare(b.type),
    hits: (a: Exclusion, b: Exclusion) => (hitsData?.hits?.[a.name]?.total ?? 0) - (hitsData?.hits?.[b.name]?.total ?? 0),
    enabled: (a: Exclusion, b: Exclusion) => Number(a.enabled) - Number(b.enabled),
  }), [hitsData]);
  const exclSort = useTableSort(filteredExclusions, exclSortComparators);
  const sortedFilteredExclusions = exclSort.sortedData;

  const isSorted = exclSort.sortState.key !== null;
  const isFiltered = isFilteredBase || isSorted;
  const { items: pagedExclusions, totalPages: rulesTotalPages } = paginateArray(sortedFilteredExclusions, rulesPage, RULES_PAGE_SIZE);

  // Selection hook — wired after pagedExclusions/filteredExclusions are defined.
  const { selected, setSelected, toggleSelect, selectAllVisible, clearSelection } =
    useRuleSelection(pagedExclusions, filteredExclusions);

  // All possible exclusion types for the filter dropdown
  const allExclusionTypes: ExclusionType[] = ["allow", "block", "skip", "detect", "response_header"];

  // Scroll to the highlighted rule once exclusions have loaded.
  useEffect(() => {
    if (highlightedRule && !loading && highlightedRef.current) {
      highlightedRef.current.scrollIntoView({ behavior: "smooth", block: "center" });
      // Auto-clear the highlight after 4 seconds.
      const timer = setTimeout(() => setHighlightedRule(null), 4000);
      return () => clearTimeout(timer);
    }
  }, [highlightedRule, loading, exclusions]);

  const successTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const showSuccess = (msg: string) => {
    if (successTimerRef.current) clearTimeout(successTimerRef.current);
    setSuccessMsg(msg);
    successTimerRef.current = setTimeout(() => setSuccessMsg(null), 3000);
  };
  useEffect(() => () => { if (successTimerRef.current) clearTimeout(successTimerRef.current); }, []);

  const autoDeploy = useCallback(async (action: string) => {
    try {
      setDeployStep("Deploying...");
      const result = await deployConfig();
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

  // Reorder hook — handles drag, move-to-edge, move-to-position, bulk move.
  const { handleDragEnd, handleMoveToEdge, handleMoveToPosition, handleBulkMoveToPosition } =
    useRuleReorder({
      items: exclusions,
      setItems: setExclusions,
      getId: (e) => e.id,
      reorderApi: reorderExclusions,
      pageSize: RULES_PAGE_SIZE,
      page: rulesPage,
      setPage: setRulesPage,
      setError,
      autoDeploy,
      selected,
      setSelected,
    });

  const handleCreate = async (data: ExclusionCreateData) => {
    try {
      const created = await createExclusion(data);
      setExclusions((prev) => [...prev, created]);
      await autoDeploy("Rule created");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Operation failed");
    }
  };

  const handleUpdate = async (id: string, data: ExclusionCreateData) => {
    try {
      const updated = await updateExclusion(id, data);
      setExclusions((prev) => prev.map((e) => (e.id === id ? updated : e)));
      setEditingId(null);
      await autoDeploy("Rule updated");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Update failed");
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteExclusion(id);
      setExclusions((prev) => prev.filter((e) => e.id !== id));
      setDeleteConfirmId(null);
      await autoDeploy("Rule deleted");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Delete failed");
    }
  };

  const handleToggleEnabled = async (id: string, enabled: boolean) => {
    try {
      const updated = await updateExclusion(id, { enabled });
      setExclusions((prev) => prev.map((e) => (e.id === id ? updated : e)));
      await autoDeploy(enabled ? "Rule enabled" : "Rule disabled");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Toggle failed");
    }
  };

  const handleExport = async () => {
    try {
      const data = await exportExclusions();
      downloadJSON(data, "waf-exclusions.json");
      showSuccess("Exclusions exported");
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
        // Support both array format and { exclusions: [...] } export format.
        const exclusions = Array.isArray(parsed) ? parsed : parsed.exclusions;
        if (!Array.isArray(exclusions)) {
          throw new Error("Invalid import file: expected an array of exclusions or { exclusions: [...] }");
        }
        if (!exclusions.every((e: unknown) => typeof e === "object" && e !== null && "id" in e && "type" in e)) {
          throw new Error("Invalid import data: each exclusion must have 'id' and 'type' fields");
        }
        const result = await importExclusions(exclusions as Exclusion[]);
        showSuccess(`Imported ${result.imported} exclusions`);
        loadData();
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "Import failed");
      }
    };
    input.click();
  };

  // ─── Bulk actions ─────────────────────────────────────────────────

  const handleBulkAction = useCallback(
    async (action: BulkExclusionAction) => {
      if (selected.size === 0) return;
      const confirmMsg = action === "delete"
        ? `Delete ${selected.size} rule(s)? This cannot be undone.`
        : undefined;
      if (confirmMsg && !window.confirm(confirmMsg)) return;
      try {
        setBulkBusy(true);
        await bulkUpdateExclusions([...selected], action);
        setSelected(new Set());
        await loadData();
        await autoDeploy(`Bulk ${action}: ${selected.size} rules`);
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : `Bulk ${action} failed`);
      } finally {
        setBulkBusy(false);
      }
    },
    [selected, loadData, autoDeploy],
  );

  // ─── Templates ─────────────────────────────────────────────────────
  const [templates, setTemplates] = useState<RuleTemplate[]>([]);
  const [templatesLoading, setTemplatesLoading] = useState(false);
  const [templateApplying, setTemplateApplying] = useState<string | null>(null);

  const loadTemplates = useCallback(async () => {
    setTemplatesLoading(true);
    try {
      const t = await listTemplates();
      setTemplates(t);
    } catch {
      // Templates are optional — fail silently
      setTemplates([]);
    } finally {
      setTemplatesLoading(false);
    }
  }, []);

  // ─── Dialog state for create/edit ──────────────────────────────────
  const [dialogOpen, setDialogOpen] = useState(false);

  const handleApplyTemplate = useCallback(async (templateId: string) => {
    try {
      setTemplateApplying(templateId);
      const result = await applyTemplate(templateId);
      await autoDeploy(`Template applied: ${result.template} (${result.created} rules)`);
      loadData();
      setDialogOpen(false);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to apply template");
    } finally {
      setTemplateApplying(null);
    }
  }, [autoDeploy, loadData]);

  // Editing: determine which tab the exclusion belongs to so we show the edit form in the right tab
  const exclusionToEdit = editingId ? exclusions.find((e) => e.id === editingId) : null;

  const isEditingRateLimit = exclusionToEdit?.type === "rate_limit";

  const editFormState: AdvancedFormState | undefined = exclusionToEdit && !isEditingRateLimit
    ? {
        name: exclusionToEdit.name,
        description: exclusionToEdit.description,
        type: exclusionToEdit.type,
        phase: exclusionToEdit.phase,
        severity: exclusionToEdit.severity ?? "",
        detect_paranoia_level: exclusionToEdit.detect_paranoia_level ?? 0,
        skip_targets: exclusionToEdit.skip_targets ?? {},
        conditions: exclusionToEdit.conditions ?? [],
        group_operator: exclusionToEdit.group_operator ?? "and",
        tags: exclusionToEdit.tags ?? [],
        enabled: exclusionToEdit.enabled,
        challenge_difficulty: exclusionToEdit.challenge_difficulty ?? 4,
        challenge_min_difficulty: exclusionToEdit.challenge_min_difficulty ?? 0,
        challenge_max_difficulty: exclusionToEdit.challenge_max_difficulty ?? 0,
        challenge_algorithm: exclusionToEdit.challenge_algorithm ?? "fast",
        challenge_ttl: exclusionToEdit.challenge_ttl ?? "1h",
        challenge_bind_ip: exclusionToEdit.challenge_bind_ip ?? true,
        challenge_bind_ja4: exclusionToEdit.challenge_bind_ja4 ?? true,
        header_set: exclusionToEdit.header_set ?? {},
        header_add: exclusionToEdit.header_add ?? {},
        header_remove: exclusionToEdit.header_remove ?? [],
        header_default: exclusionToEdit.header_default ?? {},
      }
    : undefined;

  // Convert Exclusion → RateLimitRule for the rate limit form
  const rlRuleToEdit: RateLimitRule | undefined = exclusionToEdit && isEditingRateLimit
    ? {
        id: exclusionToEdit.id,
        name: exclusionToEdit.name,
        description: exclusionToEdit.description,
        service: exclusionToEdit.service ?? "*",
        conditions: exclusionToEdit.conditions ?? [],
        group_operator: exclusionToEdit.group_operator ?? "and",
        key: (exclusionToEdit.rate_limit_key ?? "client_ip") as RLRuleKey,
        events: exclusionToEdit.rate_limit_events ?? 0,
        window: exclusionToEdit.rate_limit_window ?? "1m",
        action: (exclusionToEdit.rate_limit_action ?? "deny") as RLRuleAction,
        priority: exclusionToEdit.priority ?? 0,
        tags: exclusionToEdit.tags ?? [],
        enabled: exclusionToEdit.enabled,
        created_at: exclusionToEdit.created_at,
        updated_at: exclusionToEdit.updated_at,
      }
    : undefined;

  const handleRLUpdate = async (id: string, data: RateLimitRuleCreateData) => {
    try {
      const updated = await updateRLRule(id, data);
      // Refresh the full list since updateRLRule returns a RateLimitRule, not an Exclusion
      const fresh = await getExclusions();
      setExclusions(fresh);
      setEditingId(null);
      await autoDeploy("Rate limit rule updated");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Update failed");
    }
  };

  // Controlled tab state — switches automatically when editing starts.
  const [activeTab, setActiveTab] = useState<string>("quick");
  useEffect(() => {
    if (editingId) {
      setActiveTab("advanced");
      setDialogOpen(true);
    }
  }, [editingId]);

  // Open create dialog
  const openCreateDialog = () => {
    setEditingId(null);
    setActiveTab("quick");
    setDialogOpen(true);
    loadTemplates();
  };

  // Close dialog and reset edit state
  const closeDialog = () => {
    setDialogOpen(false);
    setEditingId(null);
    setEventPrefill(null);
  };

  // Open dialog with prefill from event
  useEffect(() => {
    if (eventPrefill) {
      setActiveTab("quick");
      setDialogOpen(true);
    }
  }, [eventPrefill]);

  return (
    <div className="space-y-6">
      <StatusAlerts
        error={error}
        successMsg={successMsg}
        deployStep={deployStep}
        successExtra={cameFromEvents ? (
          <a href="/events" className="inline-flex items-center gap-1 text-xs font-medium text-lv-cyan hover:underline ml-2">
            Back to Events
          </a>
        ) : undefined}
      />

      {/* Exclusion List */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className={T.cardTitle}>Rules ({exclusions.length})</CardTitle>
              <CardDescription>Manage your WAF rules and exclusions</CardDescription>
            </div>
            <Button onClick={openCreateDialog} size="sm">
              <Plus className="h-3.5 w-3.5" />
              Create Rule
            </Button>
          </div>
          {/* Search & Filter bar */}
          {exclusions.length > 0 && (
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
              <Select value={typeFilter} onValueChange={(v) => setTypeFilter(v as ExclusionType | "all")}>
                <SelectTrigger className="w-[160px] h-8 text-xs">
                  <SelectValue placeholder="All types" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All types</SelectItem>
                  {allExclusionTypes.map((type) => (
                    <SelectItem key={type} value={type}>{exclusionTypeLabel(type)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {(searchQuery || typeFilter !== "all") && (
                <span className="text-xs text-muted-foreground">
                  {filteredExclusions.length} of {exclusions.length}
                </span>
              )}
            </div>
          )}
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="space-y-2 p-6">
              {[...Array(5)].map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : exclusions.length > 0 ? (
            <>
            {selected.size > 0 && (
              <BulkActionsBar
                selectedCount={selected.size}
                filteredCount={filteredExclusions.length}
                totalCount={exclusions.length}
                isFiltered={isFiltered}
                bulkBusy={bulkBusy}
                onEnable={() => handleBulkAction("enable")}
                onDisable={() => handleBulkAction("disable")}
                onDelete={() => handleBulkAction("delete")}
                onBulkMoveToPosition={handleBulkMoveToPosition}
                onSelectAll={selectAllVisible}
                onClear={clearSelection}
              />
            )}
            <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-[52px] px-1" />
                  <TableHead className="w-[36px] px-2">
                    <input
                      type="checkbox"
                      checked={pagedExclusions.length > 0 && pagedExclusions.every((e) => selected.has(e.id))}
                      ref={(el) => {
                        if (el) {
                          const allSelected = pagedExclusions.length > 0 && pagedExclusions.every((e) => selected.has(e.id));
                          const someSelected = pagedExclusions.some((e) => selected.has(e.id));
                          el.indeterminate = someSelected && !allSelected;
                        }
                      }}
                      onChange={(ev) => {
                        if (ev.target.checked) {
                          setSelected(new Set([...selected, ...pagedExclusions.map((e) => e.id)]));
                        } else {
                          const pageIds = new Set(pagedExclusions.map((e) => e.id));
                          setSelected(new Set([...selected].filter((id) => !pageIds.has(id))));
                        }
                      }}
                      className="h-3.5 w-3.5 rounded border-border"
                    />
                  </TableHead>
                  <TableHead className="w-[52px] px-1">#</TableHead>
                  <SortableTableHead sortKey="name" activeKey={exclSort.sortState.key} direction={exclSort.sortState.direction} onSort={exclSort.toggleSort}>Name</SortableTableHead>
                  <SortableTableHead sortKey="type" activeKey={exclSort.sortState.key} direction={exclSort.sortState.direction} onSort={exclSort.toggleSort}>Type</SortableTableHead>
                  <TableHead>Target / Conditions</TableHead>
                  <TableHead>Tags</TableHead>
                  <SortableTableHead sortKey="hits" activeKey={exclSort.sortState.key} direction={exclSort.sortState.direction} onSort={exclSort.toggleSort}>Hits (24h)</SortableTableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <SortableContext items={pagedExclusions.map((e) => e.id)} strategy={verticalListSortingStrategy}>
              <TableBody>
                {pagedExclusions.map((excl, pageIdx) => {
                  const isHighlighted = highlightedRule !== null && excl.name === highlightedRule;
                  const globalIdx = (rulesPage - 1) * RULES_PAGE_SIZE + pageIdx + 1;
                  return (
                  <SortableTableRow
                    key={excl.id}
                    id={excl.id}
                    disabled={isFiltered}
                    rowRef={isHighlighted ? highlightedRef : undefined}
                    className={`cursor-pointer ${isHighlighted ? "ring-1 ring-emerald-500/60 bg-lv-green/5 transition-all duration-700" : ""}${selected.has(excl.id) ? " bg-lv-purple/10" : ""}`}
                    onClick={() => setEditingId(excl.id)}
                  >
                    <TableCell className="px-2" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={selected.has(excl.id)}
                        onChange={(e) => toggleSelect(excl.id, pageIdx, (e.nativeEvent as MouseEvent).shiftKey)}
                        className="h-3.5 w-3.5 rounded border-border accent-lv-purple cursor-pointer"
                      />
                    </TableCell>
                    <TableCell className="text-xs tabular-nums text-muted-foreground/60 w-[52px] px-1" title={`Rule ${globalIdx} of ${filteredExclusions.length} — click to move`} onClick={(e) => e.stopPropagation()}>
                      <InlinePositionEditor
                        globalIndex={globalIdx}
                        totalItems={exclusions.length}
                        isEditing={editingPositionId === excl.id}
                        isFiltered={isFiltered}
                        onStartEdit={() => setEditingPositionId(excl.id)}
                        onMove={(pos) => handleMoveToPosition(excl.id, pos)}
                        onCancel={() => setEditingPositionId(null)}
                      />
                    </TableCell>
                    <TableCell>
                      <div>
                        <p className={T.tableRowName}>{excl.name}</p>
                        {excl.description && (
                          <p className="text-xs text-muted-foreground truncate max-w-[200px]">{excl.description}</p>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={exclusionTypeBadgeVariant(excl.type)} className={T.badgeMono}>
                        {exclusionTypeLabel(excl.type)}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs font-data max-w-[300px] truncate" title={conditionsSummary(excl)}>
                      {conditionsSummary(excl)}
                    </TableCell>
                    <TableCell>
                      {excl.tags && excl.tags.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {excl.tags.slice(0, 3).map((tag) => (
                            <span key={tag} className="inline-block rounded bg-muted/50 px-1.5 py-0 text-[10px] text-muted-foreground font-data">
                              {tag}
                            </span>
                          ))}
                          {excl.tags.length > 3 && (
                            <span className="text-[10px] text-muted-foreground/50">+{excl.tags.length - 3}</span>
                          )}
                        </div>
                      ) : (
                        <span className="text-xs text-muted-foreground/30">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {(() => {
                        const hit = hitsData?.hits?.[excl.name];
                        if (!hit) return <span className="text-xs text-muted-foreground/50">—</span>;
                        if (hit.total === 0) {
                          return (
                            <div className="flex items-center gap-1.5">
                              <Sparkline data={hit.sparkline} color="#606270" />
                            </div>
                          );
                        }
                        return (
                          <a
                            href={`/?rule_name=${encodeURIComponent(excl.name)}`}
                            className="flex items-center gap-1.5 group no-underline rounded px-1.5 py-0.5 -mx-1.5 -my-0.5 hover:bg-lv-cyan/10 hover:shadow-[0_0_8px_rgba(121,230,243,0.15)] transition-all"
                            title={`View ${hit.total} events for "${excl.name}" on Overview`}
                          >
                            <Sparkline data={hit.sparkline} color="#79e6f3" />
                            <span className="text-xs tabular-nums text-muted-foreground group-hover:text-lv-cyan transition-colors">
                              {hit.total.toLocaleString()}
                            </span>
                          </a>
                        );
                      })()}
                    </TableCell>
                    <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1">
                        <Switch
                          checked={excl.enabled}
                          onCheckedChange={(v) => handleToggleEnabled(excl.id, v)}
                        />
                        {!isFiltered && (
                          <>
                            <Button
                              aria-label={`Move rule ${excl.name} to top`}
                              variant="ghost"
                              size="icon-sm"
                              className="text-muted-foreground/50 hover:text-lv-cyan"
                              onClick={() => handleMoveToEdge(excl.id, "top")}
                              disabled={globalIdx === 1}
                            >
                              <ArrowUpToLine className="h-3.5 w-3.5" />
                            </Button>
                            <Button
                              aria-label={`Move rule ${excl.name} to bottom`}
                              variant="ghost"
                              size="icon-sm"
                              className="text-muted-foreground/50 hover:text-lv-cyan"
                              onClick={() => handleMoveToEdge(excl.id, "bottom")}
                              disabled={globalIdx === filteredExclusions.length}
                            >
                              <ArrowDownToLine className="h-3.5 w-3.5" />
                            </Button>
                          </>
                        )}
                        <Button
                          aria-label={`Edit rule ${excl.name}`}
                          variant="ghost"
                          size="icon-sm"
                          onClick={() => setEditingId(excl.id)}
                        >
                          <Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          aria-label={`Delete rule ${excl.name}`}
                          variant="ghost"
                          size="icon-sm"
                          className="text-muted-foreground hover:text-lv-red"
                          onClick={() => setDeleteConfirmId(excl.id)}
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
            <TablePagination page={rulesPage} totalPages={rulesTotalPages} onPageChange={setRulesPage} totalItems={filteredExclusions.length} pageSize={RULES_PAGE_SIZE} />
            {filteredExclusions.length === 0 && (
              <div className="flex flex-col items-center justify-center py-8">
                <Search className="mb-2 h-6 w-6 text-muted-foreground/50" />
                <p className="text-sm text-muted-foreground">No rules match your filters</p>
                <button
                  className="text-xs text-lv-cyan hover:underline mt-1"
                  onClick={() => { setSearchQuery(""); setTypeFilter("all"); }}
                >
                  Clear filters
                </button>
              </div>
            )}
            </>
          ) : (
            <div className="flex flex-col items-center justify-center py-12">
              <Shield className="mb-3 h-8 w-8 text-muted-foreground/50" />
              <p className="text-sm text-muted-foreground">No rules configured yet</p>
              <p className="text-xs text-muted-foreground/70 mt-1">
                <button className="text-lv-cyan hover:underline" onClick={openCreateDialog}>
                  Create your first rule
                </button>
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create / Edit Rule Dialog */}
      <Dialog open={dialogOpen} onOpenChange={(open) => { if (!open) closeDialog(); }}>
        <DialogContent className="w-[95vw] max-w-5xl max-h-[90vh] overflow-y-auto">
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <DialogHeader className="space-y-3">
              <div className="flex items-center justify-between">
                <DialogTitle className="text-base">
                  {editingId && isEditingRateLimit ? "Edit Rate Limit Rule" : editingId ? "Edit Rule" : "Create Rule"}
                </DialogTitle>
                {!editingId && (
                  <TabsList className="h-8">
                    <TabsTrigger value="quick" className="gap-1.5 text-xs px-3 h-7">
                      <Zap className="h-3 w-3" />
                      Quick
                    </TabsTrigger>
                    <TabsTrigger value="advanced" className="gap-1.5 text-xs px-3 h-7">
                      <Code2 className="h-3 w-3" />
                      Advanced
                    </TabsTrigger>
                    <TabsTrigger value="templates" className="gap-1.5 text-xs px-3 h-7">
                      <LayoutTemplate className="h-3 w-3" />
                      Templates
                    </TabsTrigger>
                  </TabsList>
                )}
              </div>
              <DialogDescription className="text-xs">
                {editingId
                  ? "Modify the rule below. Changes are deployed automatically on save."
                  : activeTab === "quick"
                    ? "Pick an action type, define conditions, and deploy."
                    : "Full control over rule type, conditions, and metadata."}
              </DialogDescription>
            </DialogHeader>

            <TabsContent value="quick" className="mt-4">
              <QuickActionsForm
                services={services}
                onSubmit={(data) => {
                  handleCreate(data);
                  closeDialog();
                  setEventPrefill(null);
                }}
                prefill={eventPrefill}
                onPrefillConsumed={() => setEventPrefill(null)}
              />
            </TabsContent>

            <TabsContent value="advanced" className="mt-4">
              {editingId && isEditingRateLimit && rlRuleToEdit ? (
                <RuleForm
                  key={editingId}
                  initial={rlRuleToEdit}
                  services={services}
                  onSubmit={(data) => { handleRLUpdate(editingId!, data); closeDialog(); }}
                  onCancel={closeDialog}
                  submitLabel="Save Changes"
                />
              ) : editingId && editFormState ? (
                <AdvancedBuilderForm
                  key={editingId}
                  initial={editFormState}
                  services={services}
                  onSubmit={(data) => { handleUpdate(editingId!, data); closeDialog(); }}
                  onCancel={closeDialog}
                  submitLabel="Save Changes"
                />
              ) : (
                <AdvancedBuilderForm
                  services={services}
                  onSubmit={(data) => { handleCreate(data); closeDialog(); }}
                  submitLabel="Add Exclusion"
                />
              )}
            </TabsContent>

            {!editingId && (
              <TabsContent value="templates" className="mt-4">
                {templatesLoading ? (
                  <div className="flex items-center justify-center py-8">
                    <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
                  </div>
                ) : templates.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-8">
                    <LayoutTemplate className="mb-2 h-6 w-6 text-muted-foreground/50" />
                    <p className="text-sm text-muted-foreground">No templates available</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <p className="text-xs text-muted-foreground">
                      Apply a pre-built rule template. This creates all rules in the template and deploys automatically.
                    </p>
                    <div className="grid gap-3 sm:grid-cols-2">
                      {templates.map((tpl) => (
                        <button
                          key={tpl.id}
                          onClick={() => handleApplyTemplate(tpl.id)}
                          disabled={templateApplying !== null}
                          className="flex flex-col gap-1.5 rounded-lg border border-border p-4 text-left transition-all hover:border-lv-cyan/40 hover:bg-lv-cyan/5 disabled:opacity-50"
                        >
                          <div className="flex items-center justify-between">
                            <span className="text-sm font-medium">{tpl.name}</span>
                            {templateApplying === tpl.id ? (
                              <Loader2 className="h-3.5 w-3.5 animate-spin text-lv-cyan" />
                            ) : (
                              <Badge variant="outline" className="text-[10px]">{tpl.category}</Badge>
                            )}
                          </div>
                          <p className="text-xs text-muted-foreground">{tpl.description}</p>
                          <p className="text-[10px] text-muted-foreground/70">
                            {tpl.rules.length} rule{tpl.rules.length !== 1 ? "s" : ""}
                          </p>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </TabsContent>
            )}
          </Tabs>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <DeleteConfirmDialog
        open={deleteConfirmId !== null}
        onOpenChange={(open) => !open && setDeleteConfirmId(null)}
        onConfirm={() => deleteConfirmId && handleDelete(deleteConfirmId)}
      />
    </div>
  );
}

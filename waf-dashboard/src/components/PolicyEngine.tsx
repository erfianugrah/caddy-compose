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
  Code2,
  Zap,
  Download,
  Upload,
  Loader2,
  Check,
  Search,
  X,
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
  reorderExclusions,
  deployConfig,
  fetchServices,
  exportExclusions,
  importExclusions,
  fetchExclusionHits,
  bulkUpdateExclusions,
  type Exclusion,
  type ExclusionType,
  type ExclusionCreateData,
  type ServiceDetail,
  type ExclusionHitsResponse,
  type BulkExclusionAction,
} from "@/lib/api";

import { T } from "@/lib/typography";
import { downloadJSON } from "@/lib/download";
import type { AdvancedFormState } from "./policy/constants";
import type { EventPrefill } from "./policy/eventPrefill";
import { consumePrefillEvent } from "./policy/eventPrefill";
import { conditionsSummary, exclusionTypeLabel, exclusionTypeBadgeVariant } from "./policy/exclusionHelpers";
import { QuickActionsForm, AdvancedBuilderForm } from "./policy/PolicyForms";

const RULES_PAGE_SIZE = 15;

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

  // Bulk selection
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkBusy, setBulkBusy] = useState(false);

  const [deployStep, setDeployStep] = useState<string | null>(null);

  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Event prefill — consumed once on mount from sessionStorage.
  // Must use useEffect (not useState initializer) to avoid SSR hydration mismatch.
  const [eventPrefill, setEventPrefill] = useState<EventPrefill | null>(null);
  useEffect(() => {
    const prefill = consumePrefillEvent();
    if (prefill) setEventPrefill(prefill);
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

  const selectAllVisible = useCallback(() => {
    setSelected(new Set(filteredExclusions.map((e) => e.id)));
  }, [filteredExclusions]);

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

  // All possible exclusion types for the filter dropdown
  const allExclusionTypes: ExclusionType[] = ["allow", "block", "detect"];

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

  const handleDragEnd = useCallback(async (event: DragEndEvent) => {
    const { active, over } = event;
    if (!over || active.id === over.id) return;

    // Compute reordered array for the current page
    const pageStartIdx = (rulesPage - 1) * RULES_PAGE_SIZE;
    const pageIds = exclusions.slice(pageStartIdx, pageStartIdx + RULES_PAGE_SIZE).map((e) => e.id);
    const oldIdx = pageIds.indexOf(active.id as string);
    const newIdx = pageIds.indexOf(over.id as string);
    if (oldIdx === -1 || newIdx === -1) return;

    // Reorder the full array: splice the page portion, reorder it, put it back
    const newExclusions = [...exclusions];
    const pageSlice = newExclusions.splice(pageStartIdx, pageIds.length);
    const reorderedPage = arrayMove(pageSlice, oldIdx, newIdx);
    newExclusions.splice(pageStartIdx, 0, ...reorderedPage);

    // Optimistic update
    const prev = exclusions;
    setExclusions(newExclusions);
    try {
      const result = await reorderExclusions(newExclusions.map((e) => e.id));
      setExclusions(result);
      await autoDeploy("Rules reordered");
    } catch (err: unknown) {
      setExclusions(prev); // rollback
      setError(err instanceof Error ? err.message : "Reorder failed");
    }
  }, [exclusions, rulesPage, autoDeploy]);

  const handleMoveToEdge = useCallback(async (id: string, edge: "top" | "bottom") => {
    const idx = exclusions.findIndex((e) => e.id === id);
    if (idx === -1) return;
    if (edge === "top" && idx === 0) return;
    if (edge === "bottom" && idx === exclusions.length - 1) return;

    const newExclusions = [...exclusions];
    const [item] = newExclusions.splice(idx, 1);
    if (edge === "top") {
      newExclusions.unshift(item);
      setRulesPage(1); // jump to first page so user sees the moved rule
    } else {
      newExclusions.push(item);
      setRulesPage(Math.ceil(newExclusions.length / RULES_PAGE_SIZE)); // jump to last page
    }

    const prev = exclusions;
    setExclusions(newExclusions);
    try {
      const result = await reorderExclusions(newExclusions.map((e) => e.id));
      setExclusions(result);
      await autoDeploy(`Rule moved to ${edge}`);
    } catch (err: unknown) {
      setExclusions(prev);
      setError(err instanceof Error ? err.message : "Move failed");
    }
  }, [exclusions, autoDeploy]);

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

  const toggleSelect = useCallback((id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const clearSelection = useCallback(() => setSelected(new Set()), []);

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

  // ─── Dialog state for create/edit ──────────────────────────────────
  const [dialogOpen, setDialogOpen] = useState(false);

  // Editing: determine which tab the exclusion belongs to so we show the edit form in the right tab
  const exclusionToEdit = editingId ? exclusions.find((e) => e.id === editingId) : null;

  const editFormState: AdvancedFormState | undefined = exclusionToEdit
    ? {
        name: exclusionToEdit.name,
        description: exclusionToEdit.description,
        type: exclusionToEdit.type,
        severity: exclusionToEdit.severity ?? "",
        detect_paranoia_level: exclusionToEdit.detect_paranoia_level ?? 0,
        skip_targets: exclusionToEdit.skip_targets ?? {},
        conditions: exclusionToEdit.conditions ?? [],
        group_operator: exclusionToEdit.group_operator ?? "and",
        tags: exclusionToEdit.tags ?? [],
        enabled: exclusionToEdit.enabled,
      }
    : undefined;

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
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className={T.pageTitle}>Policy Engine</h2>
          <p className={T.pageDescription}>
            Create allow/block/detect rules to control WAF behavior.
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

      {deployStep && (
        <Alert>
          <Loader2 className="h-4 w-4 animate-spin" />
          <AlertTitle>Deploying</AlertTitle>
          <AlertDescription>{deployStep}</AlertDescription>
        </Alert>
      )}

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
                <div className="ml-auto flex items-center gap-2">
                  <Button variant="ghost" size="xs" onClick={selectAllVisible} className="text-xs text-muted-foreground">
                    Select All ({filteredExclusions.length})
                  </Button>
                  <Button variant="ghost" size="xs" onClick={clearSelection} className="text-xs text-muted-foreground">
                    Clear
                  </Button>
                </div>
              </div>
            )}
            <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-[36px] px-2" />
                  <TableHead className="w-[52px] px-1">#</TableHead>
                  <SortableTableHead sortKey="name" activeKey={exclSort.sortState.key} direction={exclSort.sortState.direction} onSort={exclSort.toggleSort}>Name</SortableTableHead>
                  <SortableTableHead sortKey="type" activeKey={exclSort.sortState.key} direction={exclSort.sortState.direction} onSort={exclSort.toggleSort}>Type</SortableTableHead>
                  <TableHead>Target / Conditions</TableHead>
                  <SortableTableHead sortKey="hits" activeKey={exclSort.sortState.key} direction={exclSort.sortState.direction} onSort={exclSort.toggleSort}>Hits (24h)</SortableTableHead>
                  <SortableTableHead sortKey="enabled" activeKey={exclSort.sortState.key} direction={exclSort.sortState.direction} onSort={exclSort.toggleSort}>Enabled</SortableTableHead>
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
                    className={`${isHighlighted ? "ring-1 ring-emerald-500/60 bg-lv-green/5 transition-all duration-700" : ""}${selected.has(excl.id) ? " bg-lv-purple/10" : ""}`}
                  >
                    <TableCell className="px-2" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={selected.has(excl.id)}
                        onChange={() => toggleSelect(excl.id)}
                        className="h-3.5 w-3.5 rounded border-border accent-lv-purple cursor-pointer"
                      />
                    </TableCell>
                    <TableCell className="text-xs tabular-nums text-muted-foreground/60" title={`Rule ${globalIdx} of ${filteredExclusions.length}`}>
                      {globalIdx}
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
                    <TableCell>
                      <Switch
                        checked={excl.enabled}
                        onCheckedChange={(v) => handleToggleEnabled(excl.id, v)}
                      />
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
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
            <TablePagination page={rulesPage} totalPages={rulesTotalPages} onPageChange={setRulesPage} totalItems={filteredExclusions.length} />
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
                  {editingId ? "Edit Rule" : "Create Rule"}
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
              {editingId && editFormState ? (
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
          </Tabs>
        </DialogContent>
      </Dialog>

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

import { useState, useEffect, useCallback, useRef, useMemo } from "react";
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
  useSortable,
  verticalListSortingStrategy,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
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
  FileCode,
  Crosshair,
  Search,
  X,
  GripVertical,
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
  fetchCRSRules,
  fetchCRSAutocomplete,
  fetchExclusionHits,
  type Exclusion,
  type ExclusionType,
  type ExclusionCreateData,
  type ServiceDetail,
  type CRSCatalogResponse,
  type CRSAutocompleteResponse,
  type ExclusionHitsResponse,
} from "@/lib/api";

import { T } from "@/lib/typography";
import type { AdvancedFormState } from "./policy/constants";
import type { EventPrefill } from "./policy/eventPrefill";
import { consumePrefillEvent } from "./policy/eventPrefill";
import { conditionsSummary, exclusionTypeLabel, exclusionTypeBadgeVariant } from "./policy/exclusionHelpers";
import { QuickActionsForm, AdvancedBuilderForm, RawEditorForm, HoneypotForm } from "./policy/PolicyForms";

// ─── Inline SVG Sparkline ────────────────────────────────────────────

function Sparkline({ data, width = 80, height = 24, color = "#22d3ee" }: {
  data: number[];
  width?: number;
  height?: number;
  color?: string;
}) {
  if (!data || data.length === 0 || data.every((v) => v === 0)) {
    return (
      <span className="text-xs text-muted-foreground/50">—</span>
    );
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

  // Fill area path (close at bottom)
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

// ─── Sortable Table Row ─────────────────────────────────────────────

function SortableTableRow({
  id,
  disabled,
  children,
  className,
  rowRef,
}: {
  id: string;
  disabled?: boolean;
  children: React.ReactNode;
  className?: string;
  rowRef?: React.Ref<HTMLTableRowElement>;
}) {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id, disabled });

  const style: React.CSSProperties = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.5 : undefined,
    position: "relative",
    zIndex: isDragging ? 10 : undefined,
  };

  // Merge refs if rowRef is provided
  const mergedRef = useCallback(
    (node: HTMLTableRowElement | null) => {
      setNodeRef(node);
      if (typeof rowRef === "function") rowRef(node);
      else if (rowRef && "current" in rowRef) (rowRef as React.MutableRefObject<HTMLTableRowElement | null>).current = node;
    },
    [setNodeRef, rowRef],
  );

  return (
    <TableRow ref={mergedRef} style={style} className={className} {...attributes}>
      <TableCell className="w-[52px] px-1">
        <div className="flex items-center gap-0.5">
          {!disabled ? (
            <button
              className="cursor-grab active:cursor-grabbing p-0.5 text-muted-foreground/50 hover:text-muted-foreground touch-none"
              {...listeners}
              tabIndex={-1}
            >
              <GripVertical className="h-3.5 w-3.5" />
            </button>
          ) : (
            <span className="p-0.5 w-[18px]" />
          )}
        </div>
      </TableCell>
      {children}
    </TableRow>
  );
}

const RULES_PAGE_SIZE = 15;

// ─── Main Policy Engine Component ───────────────────────────────────

export default function PolicyEngine() {
  const [exclusions, setExclusions] = useState<Exclusion[]>([]);
  const [services, setServices] = useState<ServiceDetail[]>([]);
  const [crsData, setCrsData] = useState<CRSCatalogResponse | null>(null);
  const [autocompleteData, setAutocompleteData] = useState<CRSAutocompleteResponse | null>(null);
  const [hitsData, setHitsData] = useState<ExclusionHitsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);

  // Search & filter state
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<ExclusionType | "all">("all");
  const [rulesPage, setRulesPage] = useState(1);

  const [deployStep, setDeployStep] = useState<string | null>(null);

  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Event prefill — consumed once on mount from sessionStorage.
  // Must use useEffect (not useState initializer) to avoid SSR hydration mismatch.
  const [eventPrefill, setEventPrefill] = useState<EventPrefill | null>(null);
  useEffect(() => {
    const prefill = consumePrefillEvent();
    if (prefill) setEventPrefill(prefill);
  }, []);

  // Drag-and-drop reorder state
  const isFiltered = searchQuery.trim() !== "" || typeFilter !== "all";
  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 5 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );

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
    } catch (err: unknown) {
      setExclusions(prev); // rollback
      setError(err instanceof Error ? err.message : "Reorder failed");
    }
  }, [exclusions, rulesPage]);

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
      fetchExclusionHits(24).catch(() => null),
    ])
      .then(([excl, svcs, crs, ac, hits]) => {
        setExclusions(excl);
        setServices(svcs);
        if (crs) setCrsData(crs);
        if (ac) setAutocompleteData(ac);
        if (hits) setHitsData(hits);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
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
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter((e) =>
        e.name.toLowerCase().includes(q) ||
        e.description.toLowerCase().includes(q) ||
        (e.rule_id && e.rule_id.toLowerCase().includes(q)) ||
        (e.rule_tag && e.rule_tag.toLowerCase().includes(q)) ||
        (e.conditions && e.conditions.some((c) => c.value.toLowerCase().includes(q)))
      );
    }
    return result;
  }, [exclusions, searchQuery, typeFilter]);

  // Reset page when filters change
  useEffect(() => { setRulesPage(1); }, [searchQuery, typeFilter]);

  const { items: pagedExclusions, totalPages: rulesTotalPages } = paginateArray(filteredExclusions, rulesPage, RULES_PAGE_SIZE);

  // All possible exclusion types for the filter dropdown (ordered logically)
  const allExclusionTypes: ExclusionType[] = [
    "allow", "block", "skip_rule", "honeypot", "raw",
    "SecRuleRemoveById", "SecRuleRemoveByTag",
    "SecRuleUpdateTargetById", "SecRuleUpdateTargetByTag",
    "ctl:ruleRemoveById", "ctl:ruleRemoveByTag",
    "ctl:ruleRemoveTargetById", "ctl:ruleRemoveTargetByTag",
  ];

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

  const handleCreate = async (data: ExclusionCreateData) => {
    try {
      const created = await createExclusion(data);
      setExclusions((prev) => [...prev, created]);
      await autoDeploy("Rule created");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Operation failed");
    }
  };

  const autoDeploy = async (action: string) => {
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
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "waf-exclusions.json";
      a.click();
      URL.revokeObjectURL(url);
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
        const result = await importExclusions(exclusions);
        showSuccess(`Imported ${result.imported} exclusions`);
        loadData();
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "Import failed");
      }
    };
    input.click();
  };

  // ─── Dialog state for create/edit ──────────────────────────────────
  const [dialogOpen, setDialogOpen] = useState(false);

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
      setDialogOpen(true);
    }
  }, [editingId, isEditingRaw]);

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
            <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-[52px] px-1">#</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Target / Conditions</TableHead>
                  <TableHead>Hits (24h)</TableHead>
                  <TableHead>Enabled</TableHead>
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
                    className={isHighlighted ? "ring-1 ring-emerald-500/60 bg-emerald-500/5 transition-all duration-700" : undefined}
                  >
                    <TableCell className="text-xs tabular-nums text-muted-foreground/60">
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
                    <TableCell className="text-xs font-mono max-w-[300px] truncate" title={conditionsSummary(excl)}>
                      {conditionsSummary(excl)}
                    </TableCell>
                    <TableCell>
                      {(() => {
                        const hit = hitsData?.hits?.[excl.name];
                        if (!hit) return <span className="text-xs text-muted-foreground/50">—</span>;
                        if (hit.total === 0) {
                          return (
                            <div className="flex items-center gap-1.5">
                              <Sparkline data={hit.sparkline} color="#475569" />
                            </div>
                          );
                        }
                        return (
                          <a
                            href={`/?rule_name=${encodeURIComponent(excl.name)}`}
                            className="flex items-center gap-1.5 group no-underline rounded px-1.5 py-0.5 -mx-1.5 -my-0.5 hover:bg-neon-cyan/10 hover:shadow-[0_0_8px_rgba(34,211,238,0.15)] transition-all"
                            title={`View ${hit.total} events for "${excl.name}" on Overview`}
                          >
                            <Sparkline data={hit.sparkline} color="#22d3ee" />
                            <span className="text-xs tabular-nums text-muted-foreground group-hover:text-neon-cyan transition-colors">
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
                  className="text-xs text-neon-cyan hover:underline mt-1"
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
                <button className="text-neon-cyan hover:underline" onClick={openCreateDialog}>
                  Create your first rule
                </button>
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create / Edit Rule Dialog */}
      <Dialog open={dialogOpen} onOpenChange={(open) => { if (!open) closeDialog(); }}>
        <DialogContent className="w-[90vw] max-w-[1800px] max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-neon-green" />
              {editingId ? "Edit Rule" : "Create Rule"}
            </DialogTitle>
            <DialogDescription>
              {editingId
                ? "Modify the rule below. Changes are deployed automatically on save."
                : "Use Quick Actions for common tasks, Advanced for ModSecurity experts, or Raw Editor for full control."}
            </DialogDescription>
          </DialogHeader>

          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="mb-4">
              <TabsTrigger value="quick" className="gap-1.5" disabled={!!editingId}>
                <Zap className="h-3.5 w-3.5" />
                Quick Actions
              </TabsTrigger>
              <TabsTrigger value="advanced" className="gap-1.5">
                <Code2 className="h-3.5 w-3.5" />
                Advanced
              </TabsTrigger>
              <TabsTrigger value="honeypot" className="gap-1.5" disabled={!!editingId}>
                <Crosshair className="h-3.5 w-3.5" />
                Honeypot
              </TabsTrigger>
              <TabsTrigger value="raw" className="gap-1.5" disabled={!!editingId && !isEditingRaw}>
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
                  closeDialog();
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

            <TabsContent value="honeypot">
              <HoneypotForm onSubmit={(data) => { handleCreate(data); closeDialog(); }} />
            </TabsContent>

            <TabsContent value="raw">
              <RawEditorForm
                autocompleteData={autocompleteData}
                crsRules={crsData?.rules ?? []}
                onSubmit={(data) => { handleCreate(data); closeDialog(); }}
              />
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

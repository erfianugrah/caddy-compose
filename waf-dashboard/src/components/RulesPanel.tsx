import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { T } from "@/lib/typography";
import { cn } from "@/lib/utils";
import {
  type DefaultRule,
  type RuleSeverity,
  CRS_CATEGORIES,
  getCategoryForRule,
  listDefaultRules,
  overrideDefaultRule,
  resetDefaultRule,
} from "@/lib/api";
import { postJSON } from "@/lib/api/shared";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
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
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { SortableTableHead } from "./SortableTableHead";
import { useTableSort } from "@/hooks/useTableSort";
import { ArrowLeft, ChevronDown, ChevronRight } from "lucide-react";

// ─── Constants ──────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "bg-rose-500/20 text-rose-400 border-rose-500/30",
  ERROR: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  WARNING: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  NOTICE: "bg-sky-500/20 text-sky-400 border-sky-500/30",
};

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 4,
  ERROR: 3,
  WARNING: 2,
  NOTICE: 1,
};

type RuleSortKey = "id" | "severity" | "category";

const RULE_COMPARATORS: Record<RuleSortKey, (a: DefaultRule, b: DefaultRule) => number> = {
  id: (a, b) => (parseInt(a.id, 10) || 0) - (parseInt(b.id, 10) || 0),
  severity: (a, b) => (SEVERITY_ORDER[a.severity ?? ""] ?? 0) - (SEVERITY_ORDER[b.severity ?? ""] ?? 0),
  category: (a, b) => {
    const ca = getCategoryForRule(a.id)?.shortName ?? "ZZZ";
    const cb = getCategoryForRule(b.id)?.shortName ?? "ZZZ";
    return ca.localeCompare(cb);
  },
};

// ─── Component ──────────────────────────────────────────────────────

export default function RulesPanel() {
  const [rules, setRules] = useState<DefaultRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deploying, setDeploying] = useState(false);
  const [deployMsg, setDeployMsg] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);

  // Filters
  const [search, setSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");

  // Collapsed PL sections
  const [collapsedPLs, setCollapsedPLs] = useState<Set<number>>(new Set());

  // Detail dialog
  const [detailRule, setDetailRule] = useState<DefaultRule | null>(null);

  // ── Load ────────────────────────────────────────────────────────

  const load = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await listDefaultRules();
      setRules(data);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  // ── Mutations ───────────────────────────────────────────────────

  const handleToggle = useCallback(
    async (rule: DefaultRule) => {
      try {
        const updated = await overrideDefaultRule(rule.id, {
          enabled: !rule.enabled,
        });
        setRules((prev) => prev.map((r) => (r.id === rule.id ? updated : r)));
        setDirty(true);
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : String(e));
      }
    },
    [],
  );

  const handleSeverityChange = useCallback(
    async (rule: DefaultRule, severity: RuleSeverity) => {
      try {
        const updated = await overrideDefaultRule(rule.id, { severity });
        setRules((prev) => prev.map((r) => (r.id === rule.id ? updated : r)));
        setDirty(true);
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : String(e));
      }
    },
    [],
  );

  const handlePLChange = useCallback(
    async (rule: DefaultRule, paranoia_level: number) => {
      try {
        const updated = await overrideDefaultRule(rule.id, { paranoia_level });
        setRules((prev) => prev.map((r) => (r.id === rule.id ? updated : r)));
        setDirty(true);
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : String(e));
      }
    },
    [],
  );

  const handleReset = useCallback(async (rule: DefaultRule) => {
    try {
      const updated = await resetDefaultRule(rule.id);
      setRules((prev) => prev.map((r) => (r.id === rule.id ? updated : r)));
      setDirty(true);
      setDetailRule(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  const deployTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => { if (deployTimerRef.current) clearTimeout(deployTimerRef.current); }, []);

  const handleDeploy = useCallback(async () => {
    try {
      setDeploying(true);
      setDeployMsg(null);
      await postJSON("/api/config/deploy", {});
      setDeployMsg("Deployed successfully");
      setDirty(false);
      if (deployTimerRef.current) clearTimeout(deployTimerRef.current);
      deployTimerRef.current = setTimeout(() => setDeployMsg(null), 3000);
    } catch (e: unknown) {
      setDeployMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setDeploying(false);
    }
  }, []);

  // ── PL section toggle ───────────────────────────────────────────

  const togglePL = useCallback((pl: number) => {
    setCollapsedPLs((prev) => {
      const next = new Set(prev);
      if (next.has(pl)) next.delete(pl);
      else next.add(pl);
      return next;
    });
  }, []);

  // ── Filtering ───────────────────────────────────────────────────

  const filtered = useMemo(() => {
    let result = rules;

    if (search) {
      const q = search.toLowerCase();
      result = result.filter(
        (r) =>
          r.id.includes(q) ||
          r.name.toLowerCase().includes(q) ||
          (r.description?.toLowerCase().includes(q) ?? false) ||
          (r.tags?.some((t) => t.toLowerCase().includes(q)) ?? false),
      );
    }

    if (categoryFilter !== "all") {
      result = result.filter((r) => {
        const cat = getCategoryForRule(r.id);
        return cat?.prefix === categoryFilter;
      });
    }

    if (severityFilter !== "all") {
      result = result.filter((r) => r.severity === severityFilter);
    }

    if (statusFilter === "enabled") {
      result = result.filter((r) => r.enabled);
    } else if (statusFilter === "disabled") {
      result = result.filter((r) => !r.enabled);
    } else if (statusFilter === "overridden") {
      result = result.filter((r) => r.has_override);
    }

    return result;
  }, [rules, search, categoryFilter, severityFilter, statusFilter]);

  // ── Group by PL ─────────────────────────────────────────────────

  const plGroups = useMemo(() => {
    const groups: Record<number, DefaultRule[]> = {};
    for (const r of filtered) {
      const pl = r.paranoia_level ?? 1;
      if (!groups[pl]) groups[pl] = [];
      groups[pl].push(r);
    }
    return groups;
  }, [filtered]);

  // ── Category stats ──────────────────────────────────────────────

  const categoryStats = useMemo(() => {
    const stats = new Map<string, { total: number; enabled: number }>();
    for (const r of rules) {
      const cat = getCategoryForRule(r.id);
      const prefix = cat?.prefix ?? "other";
      const s = stats.get(prefix) ?? { total: 0, enabled: 0 };
      s.total++;
      if (r.enabled) s.enabled++;
      stats.set(prefix, s);
    }
    return stats;
  }, [rules]);

  // ── Summary stats ───────────────────────────────────────────────

  const totalEnabled = rules.filter((r) => r.enabled).length;
  const totalOverridden = rules.filter((r) => r.has_override).length;

  // ── Render ──────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="p-6">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-muted rounded w-48" />
          <div className="h-10 bg-muted rounded" />
          <div className="h-64 bg-muted rounded" />
        </div>
      </div>
    );
  }

  return (
    <TooltipProvider delayDuration={300}>
      <div className="space-y-6">
        {/* Back link + Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <a
              href="/rules"
              className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              <ArrowLeft className="h-4 w-4" />
              Rules
            </a>
            <div>
              <h1 className={T.pageTitle}>OWASP CRS 4.24.1</h1>
              <p className={T.pageDescription}>
                {rules.length} rules ({totalEnabled} enabled
                {totalOverridden > 0 && `, ${totalOverridden} overridden`})
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {deployMsg && (
              <span
                className={cn(
                  "text-xs px-2 py-1 rounded",
                  deployMsg.includes("success")
                    ? "bg-emerald-500/20 text-emerald-400"
                    : "bg-rose-500/20 text-rose-400",
                )}
              >
                {deployMsg}
              </span>
            )}
            <Button
              variant="default"
              size="sm"
              onClick={handleDeploy}
              disabled={deploying}
              className={cn(
                dirty &&
                  "ring-2 ring-lv-cyan ring-offset-2 ring-offset-background",
              )}
            >
              {deploying ? "Deploying..." : "Save & Deploy"}
            </Button>
          </div>
        </div>

        {error && (
          <div className="bg-rose-500/10 border border-rose-500/30 rounded-lg p-3 text-sm text-rose-400">
            {error}
          </div>
        )}

        {/* Category pills */}
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => setCategoryFilter("all")}
            className={cn(
              "px-3 py-1.5 rounded-lg text-xs font-medium transition-colors border",
              categoryFilter === "all"
                ? "bg-lv-purple/20 text-lv-purple border-lv-purple/40"
                : "bg-card text-muted-foreground border-border hover:border-muted-foreground/40",
            )}
          >
            All ({rules.length})
          </button>
          {CRS_CATEGORIES.map((cat) => {
            const s = categoryStats.get(cat.prefix);
            if (!s) return null;
            return (
              <button
                key={cat.prefix}
                onClick={() =>
                  setCategoryFilter(
                    categoryFilter === cat.prefix ? "all" : cat.prefix,
                  )
                }
                className={cn(
                  "px-3 py-1.5 rounded-lg text-xs font-medium transition-colors border",
                  categoryFilter === cat.prefix
                    ? "bg-lv-purple/20 text-lv-purple border-lv-purple/40"
                    : "bg-card text-muted-foreground border-border hover:border-muted-foreground/40",
                )}
              >
                {cat.shortName} ({s.enabled}/{s.total})
              </button>
            );
          })}
        </div>

        {/* Filters row */}
        <div className="flex items-center gap-3">
          <Input
            placeholder="Search rules by ID, name, description, or tag..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="max-w-sm"
          />
          <Select value={severityFilter} onValueChange={setSeverityFilter}>
            <SelectTrigger className="w-[120px]">
              <SelectValue placeholder="Severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Severity</SelectItem>
              <SelectItem value="CRITICAL">Critical</SelectItem>
              <SelectItem value="ERROR">Error</SelectItem>
              <SelectItem value="WARNING">Warning</SelectItem>
              <SelectItem value="NOTICE">Notice</SelectItem>
            </SelectContent>
          </Select>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-[120px]">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="enabled">Enabled</SelectItem>
              <SelectItem value="disabled">Disabled</SelectItem>
              <SelectItem value="overridden">Overridden</SelectItem>
            </SelectContent>
          </Select>
          <span className="text-xs text-muted-foreground ml-auto">
            {filtered.length} rules shown
          </span>
        </div>

        {/* PL Sections */}
        {[1, 2, 3, 4].map((pl) => {
          const group = plGroups[pl];
          if (!group || group.length === 0) return null;
          const isCollapsed = collapsedPLs.has(pl);
          const enabledCount = group.filter((r) => r.enabled).length;

          return (
            <PLSection
              key={pl}
              pl={pl}
              rules={group}
              enabledCount={enabledCount}
              isCollapsed={isCollapsed}
              onToggleCollapse={() => togglePL(pl)}
              onToggleRule={handleToggle}
              onSeverityChange={handleSeverityChange}
              onPLChange={handlePLChange}
              onDetail={setDetailRule}
            />
          );
        })}

        {filtered.length === 0 && (
          <div className="text-center text-muted-foreground py-12">
            No rules match the current filters.
          </div>
        )}

        {/* Detail dialog */}
        {detailRule && (
          <RuleDetailDialog
            rule={detailRule}
            onClose={() => setDetailRule(null)}
            onToggle={handleToggle}
            onSeverityChange={handleSeverityChange}
            onPLChange={handlePLChange}
            onReset={handleReset}
          />
        )}
      </div>
    </TooltipProvider>
  );
}

// ─── PL Section with Sortable Table ─────────────────────────────────

const PL_DESCRIPTIONS: Record<number, string> = {
  1: "Core rules with minimal false positives",
  2: "Additional rules, some tuning may be needed",
  3: "Aggressive rules, expect false positives",
  4: "Maximum paranoia, extensive tuning required",
};

interface PLSectionProps {
  pl: number;
  rules: DefaultRule[];
  enabledCount: number;
  isCollapsed: boolean;
  onToggleCollapse: () => void;
  onToggleRule: (rule: DefaultRule) => void;
  onSeverityChange: (rule: DefaultRule, severity: RuleSeverity) => void;
  onPLChange: (rule: DefaultRule, pl: number) => void;
  onDetail: (rule: DefaultRule) => void;
}

function PLSection({
  pl,
  rules,
  enabledCount,
  isCollapsed,
  onToggleCollapse,
  onToggleRule,
  onSeverityChange,
  onPLChange,
  onDetail,
}: PLSectionProps) {
  const { sortState, toggleSort, sortedData } = useTableSort<DefaultRule, RuleSortKey>(
    rules,
    RULE_COMPARATORS,
    { defaultDirection: "asc" },
  );

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      {/* Section header */}
      <button
        onClick={onToggleCollapse}
        className="flex w-full items-center justify-between px-4 py-3 bg-lovelace-950 hover:bg-lovelace-900/50 transition-colors"
      >
        <div className="flex items-center gap-3">
          {isCollapsed ? (
            <ChevronRight className="h-4 w-4 text-muted-foreground" />
          ) : (
            <ChevronDown className="h-4 w-4 text-muted-foreground" />
          )}
          <span className="text-sm font-semibold">PL{pl}</span>
          <Badge variant="outline" className="text-xs">
            {enabledCount}/{rules.length} enabled
          </Badge>
          <span className="text-xs text-muted-foreground hidden sm:inline">
            {PL_DESCRIPTIONS[pl]}
          </span>
        </div>
      </button>

      {/* Table */}
      {!isCollapsed && (
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="w-[60px]">Status</TableHead>
              <SortableTableHead<RuleSortKey>
                sortKey="id"
                activeKey={sortState.key}
                direction={sortState.direction}
                onSort={toggleSort}
                className="w-[80px]"
              >
                ID
              </SortableTableHead>
              <TableHead>Rule</TableHead>
              <SortableTableHead<RuleSortKey>
                sortKey="severity"
                activeKey={sortState.key}
                direction={sortState.direction}
                onSort={toggleSort}
                className="w-[90px]"
              >
                Severity
              </SortableTableHead>
              <TableHead className="w-[60px]">PL</TableHead>
              <SortableTableHead<RuleSortKey>
                sortKey="category"
                activeKey={sortState.key}
                direction={sortState.direction}
                onSort={toggleSort}
                className="w-[90px]"
              >
                Category
              </SortableTableHead>
              <TableHead className="w-[40px]" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {sortedData.map((rule) => (
              <RuleRow
                key={rule.id}
                rule={rule}
                onToggle={onToggleRule}
                onSeverityChange={onSeverityChange}
                onPLChange={onPLChange}
                onDetail={onDetail}
              />
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}

// ─── Rule Row ───────────────────────────────────────────────────────

interface RuleRowProps {
  rule: DefaultRule;
  onToggle: (rule: DefaultRule) => void;
  onSeverityChange: (rule: DefaultRule, severity: RuleSeverity) => void;
  onPLChange: (rule: DefaultRule, pl: number) => void;
  onDetail: (rule: DefaultRule) => void;
}

function RuleRow({
  rule,
  onToggle,
  onSeverityChange,
  onPLChange,
  onDetail,
}: RuleRowProps) {
  const category = getCategoryForRule(rule.id);

  return (
    <TableRow
      className={cn(
        "group cursor-pointer",
        !rule.enabled && "opacity-50",
        rule.has_override && "bg-lv-cyan/5",
      )}
      onClick={() => onDetail(rule)}
    >
      <TableCell onClick={(e) => e.stopPropagation()}>
        <Switch
          checked={rule.enabled}
          onCheckedChange={() => onToggle(rule)}
          className="scale-75"
        />
      </TableCell>
      <TableCell className="font-mono text-xs">{rule.id}</TableCell>
      <TableCell>
        <div className="flex flex-col gap-0.5">
          <span className="text-sm font-medium leading-tight">
            {rule.name}
            {rule.has_override && (
              <span className="ml-1.5 text-[10px] text-lv-cyan font-normal">
                MODIFIED
              </span>
            )}
          </span>
          {rule.description && (
            <span className="text-xs text-muted-foreground truncate max-w-[500px]">
              {rule.description}
            </span>
          )}
        </div>
      </TableCell>
      <TableCell onClick={(e) => e.stopPropagation()}>
        {rule.severity && rule.type === "detect" ? (
          <Select
            value={rule.severity}
            onValueChange={(v) =>
              onSeverityChange(rule, v as RuleSeverity)
            }
          >
            <SelectTrigger className="h-6 w-[80px] text-xs border-0 bg-transparent p-0">
              <SeverityBadge severity={rule.severity} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="CRITICAL">Critical (+5)</SelectItem>
              <SelectItem value="ERROR">Error (+4)</SelectItem>
              <SelectItem value="WARNING">Warning (+3)</SelectItem>
              <SelectItem value="NOTICE">Notice (+2)</SelectItem>
            </SelectContent>
          </Select>
        ) : (
          <Badge variant="outline" className="text-xs">
            {rule.type}
          </Badge>
        )}
      </TableCell>
      <TableCell onClick={(e) => e.stopPropagation()}>
        {rule.type === "detect" ? (
          <Select
            value={String(rule.paranoia_level ?? 1)}
            onValueChange={(v) => onPLChange(rule, parseInt(v, 10))}
          >
            <SelectTrigger className="h-6 w-[55px] text-xs border-0 bg-transparent p-0">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="1">PL1</SelectItem>
              <SelectItem value="2">PL2</SelectItem>
              <SelectItem value="3">PL3</SelectItem>
              <SelectItem value="4">PL4</SelectItem>
            </SelectContent>
          </Select>
        ) : (
          <span className="text-xs text-muted-foreground">--</span>
        )}
      </TableCell>
      <TableCell>
        {category && (
          <span className="text-xs text-muted-foreground">
            {category.shortName}
          </span>
        )}
      </TableCell>
      <TableCell>
        <svg
          className="h-4 w-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
        >
          <polyline points="9 18 15 12 9 6" />
        </svg>
      </TableCell>
    </TableRow>
  );
}

// ─── Severity Badge ─────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const colors = SEVERITY_COLORS[severity] ?? "bg-muted text-muted-foreground";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase border",
        colors,
      )}
    >
      {severity}
    </span>
  );
}

// ─── Rule Detail Dialog ─────────────────────────────────────────────

interface RuleDetailDialogProps {
  rule: DefaultRule;
  onClose: () => void;
  onToggle: (rule: DefaultRule) => void;
  onSeverityChange: (rule: DefaultRule, severity: RuleSeverity) => void;
  onPLChange: (rule: DefaultRule, pl: number) => void;
  onReset: (rule: DefaultRule) => void;
}

function RuleDetailDialog({
  rule,
  onClose,
  onToggle,
  onSeverityChange,
  onPLChange,
  onReset,
}: RuleDetailDialogProps) {
  const category = getCategoryForRule(rule.id);

  return (
    <Dialog open onOpenChange={() => onClose()}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-3 font-mono">
            <span className="text-muted-foreground">{rule.id}</span>
            <span>{rule.name}</span>
          </DialogTitle>
          {rule.description && (
            <DialogDescription>{rule.description}</DialogDescription>
          )}
        </DialogHeader>

        <div className="space-y-4 py-2">
          {/* Status + controls */}
          <div className="grid grid-cols-3 gap-4">
            <div className="space-y-1">
              <label className={T.sectionLabel}>Status</label>
              <div className="flex items-center gap-2">
                <Switch
                  checked={rule.enabled}
                  onCheckedChange={() => onToggle(rule)}
                />
                <span className="text-sm">
                  {rule.enabled ? "Enabled" : "Disabled"}
                </span>
              </div>
            </div>
            {rule.type === "detect" && rule.severity && (
              <div className="space-y-1">
                <label className={T.sectionLabel}>Severity</label>
                <Select
                  value={rule.severity}
                  onValueChange={(v) =>
                    onSeverityChange(rule, v as RuleSeverity)
                  }
                >
                  <SelectTrigger className="h-8">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="CRITICAL">Critical (+5)</SelectItem>
                    <SelectItem value="ERROR">Error (+4)</SelectItem>
                    <SelectItem value="WARNING">Warning (+3)</SelectItem>
                    <SelectItem value="NOTICE">Notice (+2)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}
            {rule.type === "detect" && (
              <div className="space-y-1">
                <label className={T.sectionLabel}>Paranoia Level</label>
                <Select
                  value={String(rule.paranoia_level ?? 1)}
                  onValueChange={(v) => onPLChange(rule, parseInt(v, 10))}
                >
                  <SelectTrigger className="h-8">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1">PL1 - Basic</SelectItem>
                    <SelectItem value="2">PL2 - Moderate</SelectItem>
                    <SelectItem value="3">PL3 - Strict</SelectItem>
                    <SelectItem value="4">PL4 - Paranoid</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}
          </div>

          {/* Metadata */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <label className={T.sectionLabel}>Type</label>
              <p className="text-sm">{rule.type}</p>
            </div>
            <div className="space-y-1">
              <label className={T.sectionLabel}>Category</label>
              <p className="text-sm">{category?.name ?? "Other"}</p>
            </div>
          </div>

          {/* Tags */}
          {rule.tags && rule.tags.length > 0 && (
            <div className="space-y-1">
              <label className={T.sectionLabel}>Tags</label>
              <div className="flex flex-wrap gap-1">
                {rule.tags.map((tag) => (
                  <Badge key={tag} variant="outline" className="text-xs">
                    {tag}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* Conditions */}
          {rule.conditions && rule.conditions.length > 0 && (
            <div className="space-y-1">
              <label className={T.sectionLabel}>
                Conditions ({rule.group_op.toUpperCase()})
              </label>
              <div className="space-y-1">
                {rule.conditions.map((cond, i) => (
                  <div
                    key={i}
                    className="font-mono text-xs bg-muted/50 rounded px-3 py-2 border border-border"
                  >
                    <span className="text-emerald-400">{cond.field}</span>
                    {cond.negate && (
                      <span className="text-rose-400 ml-1">NOT</span>
                    )}
                    <span className="text-amber-400 ml-1">{cond.operator}</span>
                    {cond.value && (
                      <span className="text-muted-foreground ml-1 break-all">
                        {cond.value.length > 200
                          ? cond.value.slice(0, 200) + "..."
                          : cond.value}
                      </span>
                    )}
                    {cond.list_items && (
                      <span className="text-muted-foreground ml-1">
                        [{cond.list_items.length} items]
                      </span>
                    )}
                    {cond.transforms && cond.transforms.length > 0 && (
                      <span className="text-sky-400 ml-2">
                        t:{cond.transforms.join(",")}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Override info */}
          {rule.has_override && (
            <div className="bg-lv-cyan/10 border border-lv-cyan/30 rounded-lg p-3">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-sm font-medium text-lv-cyan">
                    This rule has been modified
                  </span>
                  {rule.override_fields && (
                    <p className="text-xs text-muted-foreground mt-0.5">
                      Changed fields: {rule.override_fields.join(", ")}
                    </p>
                  )}
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => onReset(rule)}
                  className="text-xs"
                >
                  Reset to Default
                </Button>
              </div>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

import { useState, useEffect, useCallback, useRef } from "react";
import {
  List, Plus, RefreshCw, Trash2, Pencil, Download, Upload,
  Globe, Database, ExternalLink, Copy, Check, Search, Shield,
  Network, Server, Type, Hash, Loader2, AlertTriangle,
} from "lucide-react";
import {
  Card, CardContent, CardDescription, CardHeader, CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import {
  fetchManagedLists, getManagedList, createManagedList, updateManagedList,
  deleteManagedList, refreshManagedList, exportManagedLists, importManagedLists,
  type ManagedList, type ManagedListCreate, type ManagedListUpdate,
  getBlocklistStats, checkBlocklistIP, refreshBlocklist,
  type BlocklistStats, type BlocklistCheckResult, type BlocklistRefreshResult,
} from "@/lib/api";
import { T } from "@/lib/typography";
import { downloadJSON } from "@/lib/download";

// ─── Kind / Source Badge Colors ─────────────────────────────────────

const KIND_COLORS: Record<string, string> = {
  ip: "bg-lv-red/10 text-lv-red border-lv-red/20",
  hostname: "bg-lv-cyan/10 text-lv-cyan border-lv-cyan/20",
  string: "bg-lv-green/10 text-lv-green border-lv-green/20",
  asn: "bg-amber-500/10 text-lv-peach border-amber-500/20",
};

const SOURCE_ICONS: Record<string, typeof Database> = {
  manual: Database,
  url: Globe,
  ipsum: ExternalLink,
};

// ─── List Card ──────────────────────────────────────────────────────

function ListCard({
  list,
  onEdit,
  onDelete,
  onRefresh,
}: {
  list: ManagedList;
  onEdit: () => void;
  onDelete: () => void;
  onRefresh: () => void;
}) {
  const SourceIcon = SOURCE_ICONS[list.source] ?? Database;
  const isReadOnly = list.source === "ipsum";

  return (
    <Card className="group">
      <CardContent className="pt-4 pb-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-medium font-data truncate">{list.name}</h3>
              <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${KIND_COLORS[list.kind] ?? ""}`}>
                {list.kind}
              </Badge>
              <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                <SourceIcon className="mr-1 h-2.5 w-2.5" />
                {list.source}
              </Badge>
            </div>
            {list.description && (
              <p className="mt-1 text-xs text-muted-foreground truncate">{list.description}</p>
            )}
            <div className="mt-2 flex items-center gap-3 text-[11px] text-muted-foreground">
              <span>{list.item_count.toLocaleString()} items</span>
              {list.url && (
                <span className="truncate max-w-[200px]" title={list.url}>{list.url}</span>
              )}
              <span>Updated {new Date(list.updated_at).toLocaleDateString()}</span>
            </div>
          </div>
          <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
            {list.source === "url" && (
              <Button variant="ghost" size="icon" className="h-7 w-7" onClick={onRefresh} title="Refresh from URL">
                <RefreshCw className="h-3.5 w-3.5" />
              </Button>
            )}
            {!isReadOnly && (
              <>
                <Button variant="ghost" size="icon" className="h-7 w-7" onClick={onEdit} title="Edit">
                  <Pencil className="h-3.5 w-3.5" />
                </Button>
                <Button variant="ghost" size="icon" className="h-7 w-7 text-muted-foreground hover:text-lv-red" onClick={onDelete} title="Delete">
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Create / Edit Dialog ───────────────────────────────────────────

interface FormState {
  name: string;
  description: string;
  kind: ManagedList["kind"];
  source: ManagedList["source"];
  url: string;
  itemsText: string;
}

const emptyForm: FormState = {
  name: "", description: "", kind: "ip", source: "manual", url: "", itemsText: "",
};

const KIND_META: Record<ManagedList["kind"], { icon: typeof Network; label: string; desc: string; hint: string; placeholder: string }> = {
  ip:       { icon: Network, label: "IP Addresses", desc: "IPv4/IPv6 addresses and CIDR ranges", hint: "Enter IPs or CIDR ranges (e.g. 10.0.0.0/8, 2001:db8::1)", placeholder: "10.0.0.1\n192.168.0.0/24\n2001:db8::/32" },
  hostname: { icon: Server,  label: "Hostnames",    desc: "Domain names and subdomains",         hint: "Enter fully qualified domain names",                      placeholder: "evil.com\nmalware.example.net" },
  string:   { icon: Type,    label: "Strings",      desc: "Free-form text values (paths, countries, etc.)", hint: "Enter one value per line",                      placeholder: "/admin\n/wp-login.php\nblocked-value" },
  asn:      { icon: Hash,    label: "ASN Numbers",  desc: "Autonomous System Numbers",           hint: "Enter ASNs in AS##### format",                            placeholder: "AS13335\nAS15169\nAS32934" },
};

/** Validate an IPv4 address (4 octets, each 0-255). */
function isValidIPv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    if (!/^\d{1,3}$/.test(p)) return false;
    const n = parseInt(p, 10);
    return n >= 0 && n <= 255;
  });
}

/** Validate an IPv6 address (simplified — allows hex groups and ::). */
function isValidIPv6(ip: string): boolean {
  // Must contain at least one colon and only hex digits, colons, dots (for mapped v4)
  if (!ip.includes(":")) return false;
  if (!/^[0-9a-fA-F:.]+$/.test(ip)) return false;
  // Reject multiple consecutive :: groups
  if ((ip.match(/::/g) || []).length > 1) return false;
  return true;
}

/** Validate an IP address or CIDR range. */
function isValidIPOrCIDR(value: string): boolean {
  const [ip, prefix, ...rest] = value.split("/");
  if (rest.length > 0) return false; // multiple slashes
  const isV4 = isValidIPv4(ip);
  const isV6 = isValidIPv6(ip);
  if (!isV4 && !isV6) return false;
  if (prefix !== undefined) {
    if (!/^\d{1,3}$/.test(prefix)) return false;
    const n = parseInt(prefix, 10);
    const max = isV4 ? 32 : 128;
    if (n < 0 || n > max) return false;
  }
  return true;
}

/** Simple line-level validation for item entries. */
function validateItems(kind: ManagedList["kind"], text: string): string[] {
  const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
  const errors: string[] = [];
  for (const line of lines) {
    if (kind === "ip") {
      if (!isValidIPOrCIDR(line)) errors.push(line);
    } else if (kind === "asn") {
      if (!/^AS\d+$/i.test(line)) errors.push(line);
    }
    // hostname and string are too freeform to validate strictly
  }
  return errors;
}

function ListFormDialog({
  open,
  onOpenChange,
  editing,
  onSave,
  saving,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editing: ManagedList | null;
  onSave: (form: FormState) => void;
  saving: boolean;
}) {
  const [form, setForm] = useState<FormState>(emptyForm);

  useEffect(() => {
    if (open && editing) {
      setForm({
        name: editing.name,
        description: editing.description ?? "",
        kind: editing.kind,
        source: editing.source,
        url: editing.url ?? "",
        itemsText: editing.items.join("\n"),
      });
    } else if (open) {
      setForm(emptyForm);
    }
  }, [open, editing]);

  const isEdit = !!editing;
  const nameValid = /^[a-z0-9][a-z0-9_-]*$/.test(form.name);
  const itemLines = form.itemsText.split("\n").filter((l) => l.trim());
  const itemErrors = validateItems(form.kind, form.itemsText);
  const kindMeta = KIND_META[form.kind];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {isEdit ? "Edit List" : "Create List"}
            {isEdit && (
              <Badge variant="outline" className={`ml-1 text-[10px] ${KIND_COLORS[form.kind] || ""}`}>
                {KIND_META[form.kind].label}
              </Badge>
            )}
          </DialogTitle>
          <DialogDescription>
            {isEdit
              ? "Update the list name, description, or items."
              : "Create a reusable list for use in policy conditions and rate limit rules."}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* ── Metadata Section ─────────────────────────────── */}

          <div className="grid grid-cols-2 gap-3">
            {/* Name */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium">Name</label>
              <Input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="e.g., bad-ips, blocked-countries"
                disabled={isEdit}
                className="font-data"
              />
              {form.name && !nameValid && (
                <p className="text-[11px] text-lv-red">Lowercase alphanumeric, hyphens, underscores. Must start with letter/number.</p>
              )}
            </div>
            {/* Description */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium">Description</label>
              <Input
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                placeholder="Optional description"
              />
            </div>
          </div>

          {/* Kind + Source row (create only) */}
          {!isEdit && (
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label className="text-xs font-medium">Kind</label>
                <Select value={form.kind} onValueChange={(v) => setForm({ ...form, kind: v as ManagedList["kind"] })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {(Object.entries(KIND_META) as [ManagedList["kind"], typeof kindMeta][]).map(([k, m]) => {
                      const Icon = m.icon;
                      return (
                        <SelectItem key={k} value={k}>
                          <div className="flex items-center gap-2">
                            <Icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                            <div>
                              <span>{m.label}</span>
                              <span className="ml-1.5 text-[10px] text-muted-foreground">{m.desc}</span>
                            </div>
                          </div>
                        </SelectItem>
                      );
                    })}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-medium">Source</label>
                <Select value={form.source} onValueChange={(v) => setForm({ ...form, source: v as ManagedList["source"] })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="manual">
                      <div className="flex items-center gap-2">
                        <Database className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                        <div>
                          <span>Manual</span>
                          <span className="ml-1.5 text-[10px] text-muted-foreground">Enter items directly</span>
                        </div>
                      </div>
                    </SelectItem>
                    <SelectItem value="url">
                      <div className="flex items-center gap-2">
                        <Globe className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                        <div>
                          <span>URL</span>
                          <span className="ml-1.5 text-[10px] text-muted-foreground">Fetch from remote source</span>
                        </div>
                      </div>
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          )}

          {/* URL (for url source) */}
          {form.source === "url" && (
            <div className="space-y-1.5">
              <label className="text-xs font-medium">Source URL</label>
              <Input
                value={form.url}
                onChange={(e) => setForm({ ...form, url: e.target.value })}
                placeholder="https://example.com/blocklist.txt"
                className="font-data text-xs"
              />
              <p className="text-[11px] text-muted-foreground">One item per line. Lines starting with # are ignored.</p>
            </div>
          )}

          <Separator />

          {/* ── Items Section ────────────────────────────────── */}

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-medium flex items-center gap-1.5">
                Items
                <Badge variant="outline" className="ml-1 text-[10px] font-normal tabular-nums">
                  {itemLines.length}
                </Badge>
              </label>
              {itemErrors.length > 0 && (
                <span className="flex items-center gap-1 text-[11px] text-lv-peach">
                  <AlertTriangle className="h-3 w-3" />
                  {itemErrors.length} invalid {itemErrors.length === 1 ? "entry" : "entries"}
                </span>
              )}
            </div>

            <div className="rounded-md border border-border bg-lovelace-950/30 p-3 space-y-2">
              <textarea
                value={form.itemsText}
                onChange={(e) => setForm({ ...form, itemsText: e.target.value })}
                placeholder={kindMeta.placeholder}
                rows={8}
                className="w-full rounded-md border border-border bg-lovelace-950 px-3 py-2 text-xs font-data text-foreground placeholder:text-muted-foreground focus:border-lv-cyan focus:outline-none focus:ring-1 focus:ring-lv-cyan/50 resize-y"
              />
              <p className="text-[11px] text-muted-foreground/70 px-1">{kindMeta.hint}</p>
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" size="sm" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button
            size="sm"
            onClick={() => onSave(form)}
            disabled={saving || !form.name || (!isEdit && !nameValid)}
          >
            {saving ? (
              <>
                <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                Saving...
              </>
            ) : isEdit ? "Update" : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Delete Confirm Dialog ──────────────────────────────────────────

function DeleteConfirmDialog({
  open,
  onOpenChange,
  list,
  onConfirm,
  deleting,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  list: ManagedList | null;
  onConfirm: () => void;
  deleting: boolean;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>Delete List</DialogTitle>
          <DialogDescription>
            Are you sure you want to delete <span className="font-data font-medium">{list?.name}</span>?
            Any policy rules or rate limit conditions referencing this list will stop matching.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" size="sm" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button variant="destructive" size="sm" onClick={onConfirm} disabled={deleting}>
            {deleting ? "Deleting..." : "Delete"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── IPsum Blocklist Section ────────────────────────────────────────

function IpsumSection({
  lists,
  onRefreshDone,
}: {
  lists: ManagedList[];
  onRefreshDone: () => void;
}) {
  const [stats, setStats] = useState<BlocklistStats | null>(null);
  const [checkIP, setCheckIP] = useState("");
  const [checkResult, setCheckResult] = useState<BlocklistCheckResult | null>(null);
  const [checking, setChecking] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshResult, setRefreshResult] = useState<BlocklistRefreshResult | null>(null);

  useEffect(() => {
    getBlocklistStats().then(setStats).catch((err) => { console.error("Failed to load blocklist stats:", err); });
  }, []);

  // Clear refresh result after 10s
  useEffect(() => {
    if (!refreshResult) return;
    const t = setTimeout(() => setRefreshResult(null), 10_000);
    return () => clearTimeout(t);
  }, [refreshResult]);

  const ipsumLists = lists.filter((l) => l.source === "ipsum");
  const totalIPs = ipsumLists.reduce((s, l) => s + l.item_count, 0);

  const handleCheck = async () => {
    const trimmed = checkIP.trim();
    if (!trimmed) return;
    // Basic IP validation
    if (!/^[\d.:a-fA-F]+$/.test(trimmed)) return;
    setChecking(true);
    setCheckResult(null);
    try {
      const result = await checkBlocklistIP(trimmed);
      setCheckResult(result);
    } catch (err) {
      console.error("Blocklist IP check failed:", err);
      setCheckResult(null);
    } finally {
      setChecking(false);
    }
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    setRefreshResult(null);
    try {
      const result = await refreshBlocklist();
      setRefreshResult(result);
      // Reload stats and parent list
      getBlocklistStats().then(setStats).catch((err) => { console.error("Failed to reload blocklist stats:", err); });
      onRefreshDone();
    } catch {
      setRefreshResult({ status: "error", message: "Refresh request failed", blocked_ips: 0, min_score: 1, last_updated: "", reloaded: false });
    } finally {
      setRefreshing(false);
    }
  };

  return (
    <Card className="border-lv-red/20">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-lv-red" />
            <CardTitle className={T.cardTitle}>IPsum Threat Intelligence</CardTitle>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            disabled={refreshing}
          >
            <RefreshCw className={`mr-2 h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
            {refreshing ? "Updating..." : "Update Now"}
          </Button>
        </div>
        <CardDescription className="text-xs">
          Aggregated threat intelligence from multiple public blocklists. Blocking via policy engine.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Stats row */}
        <div className="grid gap-3 sm:grid-cols-3">
          <div className="rounded-md border border-border/50 bg-lovelace-950 px-3 py-2">
            <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Blocked IPs</p>
            <p className="text-lg font-semibold font-data">{(stats?.blocked_ips ?? totalIPs).toLocaleString()}</p>
          </div>
          <div className="rounded-md border border-border/50 bg-lovelace-950 px-3 py-2">
            <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Threat Levels</p>
            <p className="text-lg font-semibold">{ipsumLists.length}</p>
          </div>
          <div className="rounded-md border border-border/50 bg-lovelace-950 px-3 py-2">
            <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Last Updated</p>
            <p className="text-sm font-data text-muted-foreground">
              {stats?.last_updated ? new Date(stats.last_updated).toLocaleDateString() : "—"}
            </p>
          </div>
        </div>

        {/* Refresh result */}
        {refreshResult && (
          <Alert
            variant={refreshResult.status === "error" ? "destructive" : "default"}
            className={refreshResult.status !== "error" ? "border-lv-green/30 bg-lv-green/5" : ""}
          >
            <AlertDescription className="text-xs">{refreshResult.message}</AlertDescription>
          </Alert>
        )}

        {/* Check IP */}
        <div className="space-y-2">
          <label className="text-xs font-medium text-muted-foreground">Check IP</label>
          <div className="flex gap-2">
            <Input
              value={checkIP}
              onChange={(e) => { setCheckIP(e.target.value); setCheckResult(null); }}
              onKeyDown={(e) => e.key === "Enter" && handleCheck()}
              placeholder="Enter IP address to check"
              className="font-data text-xs max-w-xs"
            />
            <Button
              variant="outline"
              size="sm"
              onClick={handleCheck}
              disabled={checking || !checkIP.trim()}
            >
              <Search className="mr-1.5 h-3 w-3" />
              {checking ? "..." : "Check"}
            </Button>
          </div>
          {checkResult && (
            <div className={`flex items-center gap-2 text-xs ${checkResult.blocked ? "text-lv-red" : "text-lv-green"}`}>
              <Badge variant="outline" className={checkResult.blocked
                ? "bg-lv-red/10 text-lv-red border-lv-red/20"
                : "bg-lv-green/10 text-lv-green border-lv-green/20"
              }>
                {checkResult.blocked ? "BLOCKED" : "CLEAN"}
              </Badge>
              <span className="font-data">{checkResult.ip}</span>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Main Component ─────────────────────────────────────────────────

export default function ManagedListsPanel() {
  const [lists, setLists] = useState<ManagedList[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Dialog state
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<ManagedList | null>(null);
  const [saving, setSaving] = useState(false);

  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<ManagedList | null>(null);
  const [deleting, setDeleting] = useState(false);

  // Feedback
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; message: string } | null>(null);

  // Guard against stale responses when rapid reloads fire concurrent requests.
  const requestGenRef = useRef(0);

  const loadLists = useCallback(() => {
    const gen = ++requestGenRef.current;
    setLoading(true);
    setError(null);
    fetchManagedLists()
      .then((data) => {
        if (gen !== requestGenRef.current) return;
        setLists(data);
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

  useEffect(() => { loadLists(); }, [loadLists]);

  // Auto-dismiss feedback after 8s
  useEffect(() => {
    if (!feedback) return;
    const t = setTimeout(() => setFeedback(null), 8_000);
    return () => clearTimeout(t);
  }, [feedback]);

  const handleSave = useCallback(async (form: FormState) => {
    setSaving(true);
    try {
      const items = form.itemsText.split("\n").map((l) => l.trim()).filter(Boolean);
      if (editing) {
        const updates: ManagedListUpdate = {
          description: form.description,
          items,
        };
        if (form.url) updates.url = form.url;
        await updateManagedList(editing.id, updates);
        setFeedback({ type: "success", message: `List "${form.name}" updated.` });
      } else {
        const create: ManagedListCreate = {
          name: form.name,
          description: form.description || undefined,
          kind: form.kind,
          source: form.source,
          url: form.url || undefined,
          items,
        };
        await createManagedList(create);
        setFeedback({ type: "success", message: `List "${form.name}" created.` });
      }
      setFormOpen(false);
      setEditing(null);
      loadLists();
    } catch (err: unknown) {
      setFeedback({ type: "error", message: err instanceof Error ? err.message : "Save failed" });
    } finally {
      setSaving(false);
    }
  }, [editing, loadLists]);

  const handleDelete = useCallback(async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await deleteManagedList(deleteTarget.id);
      setFeedback({ type: "success", message: `List "${deleteTarget.name}" deleted.` });
      setDeleteOpen(false);
      setDeleteTarget(null);
      loadLists();
    } catch (err: unknown) {
      setFeedback({ type: "error", message: err instanceof Error ? err.message : "Delete failed" });
    } finally {
      setDeleting(false);
    }
  }, [deleteTarget, loadLists]);

  const handleRefresh = useCallback(async (list: ManagedList) => {
    try {
      await refreshManagedList(list.id);
      setFeedback({ type: "success", message: `List "${list.name}" refreshed from URL.` });
      loadLists();
    } catch (err: unknown) {
      setFeedback({ type: "error", message: err instanceof Error ? err.message : "Refresh failed" });
    }
  }, [loadLists]);

  const handleEdit = useCallback(async (list: ManagedList) => {
    // Fetch full list (includes items) before editing.
    try {
      const full = await getManagedList(list.id);
      setEditing(full);
      setFormOpen(true);
    } catch (err: unknown) {
      setFeedback({ type: "error", message: err instanceof Error ? err.message : "Failed to load list" });
    }
  }, []);

  const handleExport = useCallback(async () => {
    try {
      const data = await exportManagedLists();
      downloadJSON(data, `managed-lists-export-${new Date().toISOString().slice(0, 10)}.json`);
    } catch (err: unknown) {
      setFeedback({ type: "error", message: err instanceof Error ? err.message : "Export failed" });
    }
  }, []);

  const handleImport = useCallback(() => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json";
    input.onchange = async () => {
      const file = input.files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const data = JSON.parse(text);
        const items = Array.isArray(data) ? data : data.lists;
        if (!Array.isArray(items) || !items.every((l: unknown) => typeof l === "object" && l !== null && "id" in l && "name" in l && "type" in l)) {
          throw new Error("Invalid import data: expected an array of lists with 'id', 'name', and 'type' fields");
        }
        const result = await importManagedLists(data);
        setFeedback({ type: "success", message: `Imported ${result.imported} list(s).` });
        loadLists();
      } catch (err: unknown) {
        setFeedback({ type: "error", message: err instanceof Error ? err.message : "Import failed" });
      }
    };
    input.click();
  }, [loadLists]);

  if (error) {
    return (
      <div className="flex items-center justify-center py-20">
        <Card className="max-w-md">
          <CardHeader>
            <CardTitle className="text-lv-red">Connection Error</CardTitle>
            <CardDescription>Could not reach the WAF API.</CardDescription>
          </CardHeader>
          <CardContent>
            <pre className="max-h-32 overflow-auto whitespace-pre-wrap break-all rounded-md bg-lovelace-950 p-3 text-xs text-muted-foreground">{error}</pre>
            <Button variant="outline" size="sm" className="mt-3" onClick={loadLists}>Retry</Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className={T.pageTitle}>Managed Lists ({lists.length})</h2>
          <p className={T.pageDescription}>
            Reusable IP, hostname, and string lists for policy conditions and rate limit rules
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={handleImport}>
            <Upload className="mr-2 h-3.5 w-3.5" /> Import
          </Button>
          <Button variant="outline" size="sm" onClick={handleExport} disabled={lists.length === 0}>
            <Download className="mr-2 h-3.5 w-3.5" /> Export
          </Button>
          <Button variant="outline" size="sm" onClick={loadLists} disabled={loading}>
            <RefreshCw className={`mr-2 h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} /> Refresh
          </Button>
          <Button size="sm" onClick={() => { setEditing(null); setFormOpen(true); }}>
            <Plus className="mr-2 h-3.5 w-3.5" /> New List
          </Button>
        </div>
      </div>

      {/* Feedback */}
      {feedback && (
        <Alert
          variant={feedback.type === "error" ? "destructive" : "default"}
          className={feedback.type === "success" ? "border-lv-green/30 bg-lv-green/5" : ""}
        >
          <AlertTitle className="text-xs font-medium">
            {feedback.type === "success" ? "Success" : "Error"}
          </AlertTitle>
          <AlertDescription className="text-xs">{feedback.message}</AlertDescription>
        </Alert>
      )}

      {/* IPsum section */}
      {!loading && lists.some((l) => l.source === "ipsum") && (
        <IpsumSection lists={lists} onRefreshDone={loadLists} />
      )}

      {/* Summary stats */}
      {!loading && lists.length > 0 && (
        <div className="grid gap-4 sm:grid-cols-4">
          <Card className="border-l-2 border-l-lv-cyan">
            <CardContent className="pt-3 pb-3">
              <p className="text-[11px] uppercase tracking-wider text-muted-foreground">Total Lists</p>
              <p className="text-lg font-semibold">{lists.length}</p>
            </CardContent>
          </Card>
          <Card className="border-l-2 border-l-lv-red">
            <CardContent className="pt-3 pb-3">
              <p className="text-[11px] uppercase tracking-wider text-muted-foreground">IP Lists</p>
              <p className="text-lg font-semibold">{lists.filter((l) => l.kind === "ip").length}</p>
            </CardContent>
          </Card>
          <Card className="border-l-2 border-l-lv-green">
            <CardContent className="pt-3 pb-3">
              <p className="text-[11px] uppercase tracking-wider text-muted-foreground">Total Items</p>
              <p className="text-lg font-semibold">{lists.reduce((s, l) => s + l.item_count, 0).toLocaleString()}</p>
            </CardContent>
          </Card>
          <Card className="border-l-2 border-l-amber-500">
            <CardContent className="pt-3 pb-3">
              <p className="text-[11px] uppercase tracking-wider text-muted-foreground">URL Sources</p>
              <p className="text-lg font-semibold">{lists.filter((l) => l.source === "url").length}</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Lists */}
      {loading ? (
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <Card key={i}><CardContent className="pt-4 pb-4"><Skeleton className="h-12 w-full" /></CardContent></Card>
          ))}
        </div>
      ) : lists.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <List className="mx-auto h-10 w-10 text-muted-foreground/30" />
            <p className="mt-3 text-sm text-muted-foreground">No managed lists yet.</p>
            <p className="mt-1 text-xs text-muted-foreground">
              Create a list to use with <span className="font-data text-lv-cyan">in_list</span> / <span className="font-data text-lv-cyan">not_in_list</span> operators in policy conditions and rate limit rules.
            </p>
            <Button size="sm" className="mt-4" onClick={() => { setEditing(null); setFormOpen(true); }}>
              <Plus className="mr-2 h-3.5 w-3.5" /> Create First List
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {lists.map((list) => (
            <ListCard
              key={list.id}
              list={list}
              onEdit={() => handleEdit(list)}
              onDelete={() => { setDeleteTarget(list); setDeleteOpen(true); }}
              onRefresh={() => handleRefresh(list)}
            />
          ))}
        </div>
      )}

      {/* About card */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Database className="h-4 w-4 text-muted-foreground" />
            <CardTitle className={T.cardTitle}>About Managed Lists</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="space-y-2 text-xs text-muted-foreground">
          <p>
            Managed lists are reusable collections of IPs, hostnames, strings, or ASNs.
            Reference them in policy engine conditions or rate limit rules using the
            <span className="font-data text-lv-cyan mx-1">is in list</span> and
            <span className="font-data text-lv-cyan mx-1">is not in list</span> operators.
          </p>
          <p>
            IP lists support CIDR notation and use hash-set lookups for O(1) matching.
            Lists with URL sources can be refreshed on-demand to pull updated entries.
          </p>
        </CardContent>
      </Card>

      {/* Dialogs */}
      <ListFormDialog
        open={formOpen}
        onOpenChange={setFormOpen}
        editing={editing}
        onSave={handleSave}
        saving={saving}
      />
      <DeleteConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        list={deleteTarget}
        onConfirm={handleDelete}
        deleting={deleting}
      />
    </div>
  );
}

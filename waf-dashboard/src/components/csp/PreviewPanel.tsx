import { useState } from "react";
import {
  Check,
  ChevronDown,
  ChevronRight,
  Eye,
  Copy,
  Trash2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { T } from "@/lib/typography";
import type { CSPServiceConfig, CSPPreviewResponse } from "@/lib/api";
import { DirectiveEditor } from "./DirectiveEditor";

// ─── Service Config Card ────────────────────────────────────────────

export function ServiceCard({
  name,
  config,
  onChange,
  onRemove,
  previewHeader,
}: {
  name: string;
  config: CSPServiceConfig;
  onChange: (cfg: CSPServiceConfig) => void;
  onRemove: () => void;
  previewHeader?: string;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 cursor-pointer" onClick={() => setExpanded(!expanded)}>
            {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            <CardTitle className={T.cardTitle}>{name}</CardTitle>
            <Badge variant="outline" className="text-[10px]">{config.mode}</Badge>
            {config.report_only && <Badge variant="outline" className="text-[10px] text-lv-peach">report-only</Badge>}
            {config.inherit && <Badge variant="outline" className="text-[10px] text-lv-cyan">inherit</Badge>}
          </div>
          <div className="flex items-center gap-1">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="sm" onClick={onRemove}>
                  <Trash2 className="h-3.5 w-3.5 text-muted-foreground hover:text-lv-red" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Remove service override</TooltipContent>
            </Tooltip>
          </div>
        </div>
        {/* Inline preview */}
        {previewHeader && config.mode !== "none" && (
          <p className="mt-1 text-[10px] font-data text-muted-foreground truncate max-w-full" title={previewHeader}>
            {previewHeader}
          </p>
        )}
      </CardHeader>
      {expanded && (
        <CardContent className="space-y-4 pt-0">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="space-y-1">
              <Label className={T.formLabel}>Mode</Label>
              <Select value={config.mode} onValueChange={(v) => onChange({ ...config, mode: v as CSPServiceConfig["mode"] })}>
                <SelectTrigger className="h-8 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="set">set (overwrite upstream)</SelectItem>
                  <SelectItem value="default">default (only if missing)</SelectItem>
                  <SelectItem value="none">none (no CSP)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center gap-2">
              <Switch
                id={`ro-${name}`}
                checked={config.report_only}
                onCheckedChange={(checked) => onChange({ ...config, report_only: checked })}
              />
              <Label htmlFor={`ro-${name}`} className="text-xs">Report-Only</Label>
            </div>
            <div className="flex items-center gap-2">
              <Switch
                id={`inh-${name}`}
                checked={config.inherit}
                onCheckedChange={(checked) => onChange({ ...config, inherit: checked })}
              />
              <Label htmlFor={`inh-${name}`} className="text-xs">Inherit Global</Label>
            </div>
          </div>

          {config.mode !== "none" && (
            <>
              <Separator />
              <DirectiveEditor
                policy={config.policy}
                onChange={(policy) => onChange({ ...config, policy })}
                compact
              />
            </>
          )}
        </CardContent>
      )}
    </Card>
  );
}

// ─── CSP Header Formatter ───────────────────────────────────────────

/** Split a raw CSP header string into colored directive segments */
function CSPHeaderFormatted({ header }: { header: string }) {
  const parts = header.split(";").map((p) => p.trim()).filter(Boolean);
  return (
    <span className="text-[10px] font-data leading-relaxed">
      {parts.map((part, i) => {
        const spaceIdx = part.indexOf(" ");
        const directive = spaceIdx > 0 ? part.slice(0, spaceIdx) : part;
        const values = spaceIdx > 0 ? part.slice(spaceIdx) : "";
        return (
          <span key={i}>
            {i > 0 && <span className="text-muted-foreground/40">; </span>}
            <span className="text-lv-cyan">{directive}</span>
            <span className="text-muted-foreground">{values}</span>
          </span>
        );
      })}
    </span>
  );
}

// ─── Preview Panel ──────────────────────────────────────────────────

const PREVIEW_PAGE_SIZE = 10;

export function PreviewPanel({ preview }: { preview: CSPPreviewResponse | null }) {
  const [copied, setCopied] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [filter, setFilter] = useState("");
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());

  if (!preview || Object.keys(preview.services).length === 0) {
    return (
      <Card>
        <CardContent className="p-6">
          <p className={T.muted}>No services configured. Add a service override or configure global defaults to see previews.</p>
        </CardContent>
      </Card>
    );
  }

  const copyHeader = (service: string, header: string) => {
    navigator.clipboard.writeText(header).catch(() => {});
    setCopied(service);
    setTimeout(() => setCopied(null), 2000);
  };

  const toggleRow = (service: string) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(service)) next.delete(service);
      else next.add(service);
      return next;
    });
  };

  const allEntries = Object.entries(preview.services)
    .sort(([a], [b]) => a.localeCompare(b));
  const filtered = filter
    ? allEntries.filter(([name]) => name.toLowerCase().includes(filter.toLowerCase()))
    : allEntries;
  const totalPages = Math.ceil(filtered.length / PREVIEW_PAGE_SIZE);
  const paged = filtered.slice(page * PREVIEW_PAGE_SIZE, (page + 1) * PREVIEW_PAGE_SIZE);

  // Reset page if filter changes and page is out of bounds
  if (page >= totalPages && totalPages > 0) setPage(0);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Eye className="h-4 w-4 text-lv-cyan" />
            <CardTitle className={T.cardTitle}>CSP Header Preview</CardTitle>
            <Badge variant="outline" className="text-[10px]">{filtered.length} service{filtered.length !== 1 ? "s" : ""}</Badge>
          </div>
          {allEntries.length > PREVIEW_PAGE_SIZE && (
            <Input
              value={filter}
              onChange={(e) => { setFilter(e.target.value); setPage(0); }}
              placeholder="Filter services..."
              className="h-7 w-48 text-xs"
            />
          )}
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div className="divide-y divide-border">
          {paged.map(([service, entry]) => {
            const isExpanded = expandedRows.has(service);
            return (
              <div key={service} className="group">
                <div className="flex items-center gap-3 px-4 py-2 hover:bg-accent/30 transition-colors">
                  {/* Service name + badges */}
                  <div className="flex items-center gap-2 min-w-[180px] shrink-0">
                    <span className="text-xs font-medium font-data">{service}</span>
                    <Badge
                      variant="outline"
                      className={`text-[9px] ${entry.mode === "none" ? "text-muted-foreground" : entry.mode === "default" ? "text-lv-peach" : "text-lv-green"}`}
                    >
                      {entry.mode}
                    </Badge>
                    {entry.report_only && (
                      <Badge variant="outline" className="text-[9px] text-lv-peach">RO</Badge>
                    )}
                  </div>

                  {/* Header preview (truncated) */}
                  <div className="flex-1 min-w-0">
                    {entry.header ? (
                      <button
                        type="button"
                        onClick={() => toggleRow(service)}
                        className={`text-left w-full ${isExpanded ? "" : "truncate"} block`}
                      >
                        <CSPHeaderFormatted header={entry.header} />
                      </button>
                    ) : (
                      <span className="text-[10px] text-muted-foreground/60 italic">
                        {entry.mode === "none" ? "CSP disabled" : "Empty policy"}
                      </span>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-1 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                    {entry.header && (
                      <>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => toggleRow(service)}
                              className="h-6 w-6 p-0"
                            >
                              {isExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>{isExpanded ? "Collapse" : "Expand full header"}</TooltipContent>
                        </Tooltip>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyHeader(service, entry.header)}
                              className="h-6 w-6 p-0"
                            >
                              {copied === service ? (
                                <Check className="h-3 w-3 text-lv-green" />
                              ) : (
                                <Copy className="h-3 w-3" />
                              )}
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>Copy header</TooltipContent>
                        </Tooltip>
                      </>
                    )}
                  </div>
                </div>

                {/* Expanded: full header with directive breakdown */}
                {isExpanded && entry.header && (
                  <div className="px-4 pb-3 bg-lovelace-950/50">
                    <div className="rounded border border-border p-3 space-y-1">
                      {entry.header.split(";").map((part) => part.trim()).filter(Boolean).map((part, i) => {
                        const spaceIdx = part.indexOf(" ");
                        const directive = spaceIdx > 0 ? part.slice(0, spaceIdx) : part;
                        const values = spaceIdx > 0 ? part.slice(spaceIdx + 1) : "";
                        return (
                          <div key={i} className="flex items-baseline gap-2 text-[11px] font-data">
                            <span className="text-lv-cyan font-semibold shrink-0 min-w-[140px]">{directive}</span>
                            <span className="text-muted-foreground break-all">{values}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-2 border-t border-border">
            <span className="text-[10px] text-muted-foreground">
              {page * PREVIEW_PAGE_SIZE + 1}–{Math.min((page + 1) * PREVIEW_PAGE_SIZE, filtered.length)} of {filtered.length}
            </span>
            <div className="flex items-center gap-1">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setPage(Math.max(0, page - 1))}
                disabled={page === 0}
                className="h-6 px-2 text-xs"
              >
                Prev
              </Button>
              {Array.from({ length: totalPages }, (_, i) => (
                <Button
                  key={i}
                  variant={i === page ? "default" : "ghost"}
                  size="sm"
                  onClick={() => setPage(i)}
                  className="h-6 w-6 p-0 text-xs"
                >
                  {i + 1}
                </Button>
              ))}
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
                disabled={page >= totalPages - 1}
                className="h-6 px-2 text-xs"
              >
                Next
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

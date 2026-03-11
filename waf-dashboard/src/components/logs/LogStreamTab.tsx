import { Fragment, useState, useEffect, useCallback } from "react";
import { SortableTableHead } from "@/components/SortableTableHead";
import { formatNumber, formatTime, formatDate, countryFlag } from "@/lib/format";
import { downloadJSON } from "@/lib/download";
import type { GeneralLogEvent, GeneralLogsResponse } from "@/lib/api";

import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  ChevronDown,
  ChevronRight,
  ChevronLeft,
  ChevronsLeft,
  ChevronsRight,
  ChevronsDownUp,
  Download,
  Columns3,
  Check,
} from "lucide-react";

import type { SortKey } from "./helpers";
import { statusBadge, formatDuration, formatBytes } from "./helpers";
import { LogDetailPanel } from "./LogDetailPanel";

// ─── Column Definitions ─────────────────────────────────────────────

type ColumnId = "time" | "status" | "method" | "service" | "uri" | "latency" | "size" | "country" | "protocol" | "tls" | "headers";

interface ColumnDef {
  id: ColumnId;
  label: string;
  defaultVisible: boolean;
}

const ALL_COLUMNS: ColumnDef[] = [
  { id: "time",     label: "Time",     defaultVisible: true },
  { id: "status",   label: "Status",   defaultVisible: true },
  { id: "method",   label: "Method",   defaultVisible: true },
  { id: "service",  label: "Service",  defaultVisible: true },
  { id: "uri",      label: "URI",      defaultVisible: true },
  { id: "latency",  label: "Latency",  defaultVisible: true },
  { id: "size",     label: "Size",     defaultVisible: true },
  { id: "country",  label: "Country",  defaultVisible: false },
  { id: "protocol", label: "Protocol", defaultVisible: false },
  { id: "tls",      label: "TLS",      defaultVisible: false },
  { id: "headers",  label: "Headers",  defaultVisible: true },
];

const STORAGE_KEY = "waf-log-columns";
const DEFAULT_VISIBLE = new Set(ALL_COLUMNS.filter((c) => c.defaultVisible).map((c) => c.id));

function loadColumnVisibility(): Set<ColumnId> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const arr = JSON.parse(raw) as ColumnId[];
      if (Array.isArray(arr) && arr.length > 0) return new Set(arr);
    }
  } catch { /* ignore */ }
  return new Set(DEFAULT_VISIBLE);
}

function saveColumnVisibility(visible: Set<ColumnId>): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify([...visible]));
  } catch { /* ignore */ }
}

// ─── Stable key for a log event ─────────────────────────────────────

function eventKey(evt: GeneralLogEvent, idx: number): string {
  return `${evt.timestamp}-${evt.status}-${idx}`;
}

// ─── Props ──────────────────────────────────────────────────────────

export interface LogStreamTabProps {
  response: GeneralLogsResponse | null;
  loading: boolean;
  sortState: { key: SortKey | null; direction: "asc" | "desc" | null };
  toggleSort: (key: SortKey) => void;
  sortedData: GeneralLogEvent[];
  page: number;
  totalPages: number;
  setPage: (p: number) => void;
  expanded: Set<string>;
  toggleExpand: (key: string) => void;
  collapseAll: () => void;
}

// ─── Component ──────────────────────────────────────────────────────

export default function LogStreamTab({
  response, loading, sortState, toggleSort, sortedData,
  page, totalPages, setPage,
  expanded, toggleExpand, collapseAll,
}: LogStreamTabProps) {
  const [visibleCols, setVisibleCols] = useState<Set<ColumnId>>(DEFAULT_VISIBLE);

  // Load from localStorage on mount (client-only to avoid SSR mismatch)
  useEffect(() => {
    setVisibleCols(loadColumnVisibility());
  }, []);

  const toggleColumn = useCallback((id: ColumnId) => {
    setVisibleCols((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        // Don't allow hiding all columns — keep at least 2
        if (next.size <= 2) return prev;
        next.delete(id);
      } else {
        next.add(id);
      }
      saveColumnVisibility(next);
      return next;
    });
  }, []);

  const isVisible = useCallback((id: ColumnId) => visibleCols.has(id), [visibleCols]);

  // Total visible columns + 1 for expand chevron
  const colSpan = visibleCols.size + 1;

  return (
    <div className="space-y-3">
      {/* Toolbar */}
      {response && (
        <div className="flex items-center justify-between">
          <span className="text-xs text-muted-foreground">
            {formatNumber(response.total)} results
          </span>
          <div className="flex gap-1">
            <Popover>
              <PopoverTrigger asChild>
                <Button
                  variant="ghost"
                  size="xs"
                  className="text-muted-foreground hover:text-foreground"
                  title="Toggle columns"
                >
                  <Columns3 className="h-3 w-3 mr-1" />
                  Columns
                </Button>
              </PopoverTrigger>
              <PopoverContent align="end" className="w-44 p-1">
                {ALL_COLUMNS.map((col) => (
                  <button
                    key={col.id}
                    className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-xs hover:bg-muted/50 transition-colors"
                    onClick={() => toggleColumn(col.id)}
                  >
                    <span className="w-4 h-4 flex items-center justify-center">
                      {isVisible(col.id) && <Check className="h-3 w-3 text-lv-cyan" />}
                    </span>
                    {col.label}
                  </button>
                ))}
              </PopoverContent>
            </Popover>
            <Button
              variant="ghost"
              size="xs"
              className="text-muted-foreground hover:text-foreground"
              onClick={() => downloadJSON(sortedData, `logs-page-${page}.json`)}
              title="Export current page as JSON"
            >
              <Download className="h-3 w-3 mr-1" />
              Page
            </Button>
            {expanded.size > 0 && (
              <Button
                variant="ghost"
                size="xs"
                className="text-muted-foreground hover:text-foreground"
                onClick={collapseAll}
                title="Collapse all expanded rows"
              >
                <ChevronsDownUp className="h-3 w-3 mr-1" />
                Collapse ({expanded.size})
              </Button>
            )}
          </div>
        </div>
      )}

      {/* Table */}
      <div className="rounded-lg border border-border overflow-hidden">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-8" />
                {isVisible("time") && <SortableTableHead sortKey="time" activeKey={sortState.key} direction={sortState.direction} onSort={toggleSort} className="w-[130px]">Time</SortableTableHead>}
                {isVisible("status") && <SortableTableHead sortKey="status" activeKey={sortState.key} direction={sortState.direction} onSort={toggleSort} className="w-[70px]">Status</SortableTableHead>}
                {isVisible("method") && <SortableTableHead sortKey="method" activeKey={sortState.key} direction={sortState.direction} onSort={toggleSort} className="w-[70px]">Method</SortableTableHead>}
                {isVisible("service") && <SortableTableHead sortKey="service" activeKey={sortState.key} direction={sortState.direction} onSort={toggleSort}>Service</SortableTableHead>}
                {isVisible("uri") && <TableHead className="text-xs">URI</TableHead>}
                {isVisible("latency") && <SortableTableHead sortKey="duration" activeKey={sortState.key} direction={sortState.direction} onSort={toggleSort} className="w-[80px]">Latency</SortableTableHead>}
                {isVisible("size") && <SortableTableHead sortKey="size" activeKey={sortState.key} direction={sortState.direction} onSort={toggleSort} className="w-[70px]">Size</SortableTableHead>}
                {isVisible("country") && <TableHead className="text-xs w-[60px]">Country</TableHead>}
                {isVisible("protocol") && <TableHead className="text-xs w-[80px]">Protocol</TableHead>}
                {isVisible("tls") && <TableHead className="text-xs w-[70px]">TLS</TableHead>}
                {isVisible("headers") && <TableHead className="text-xs w-[60px]">Headers</TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && !response ? (
                Array.from({ length: 10 }).map((_, i) => (
                  <TableRow key={i}>
                    <TableCell />
                    {Array.from({ length: visibleCols.size }).map((_, j) => (
                      <TableCell key={j}><Skeleton className="h-4 w-full" /></TableCell>
                    ))}
                  </TableRow>
                ))
              ) : sortedData.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={colSpan} className="py-8 text-center text-sm text-muted-foreground">
                    No log entries found
                  </TableCell>
                </TableRow>
              ) : (
                sortedData.map((evt, i) => {
                  const key = eventKey(evt, i);
                  const isExpanded = expanded.has(key);
                  return (
                    <Fragment key={key}>
                      <TableRow
                        className="cursor-pointer hover:bg-muted/50"
                        onClick={() => toggleExpand(key)}
                      >
                        <TableCell className="w-8">
                          {isExpanded ? (
                            <ChevronDown className="h-4 w-4 text-muted-foreground" />
                          ) : (
                            <ChevronRight className="h-4 w-4 text-muted-foreground" />
                          )}
                        </TableCell>
                        {isVisible("time") && (
                          <TableCell className="font-data text-xs text-muted-foreground whitespace-nowrap">
                            {formatDate(evt.timestamp)} {formatTime(evt.timestamp)}
                          </TableCell>
                        )}
                        {isVisible("status") && <TableCell>{statusBadge(evt.status)}</TableCell>}
                        {isVisible("method") && (
                          <TableCell>
                            <span className="font-data text-xs">{evt.method}</span>
                          </TableCell>
                        )}
                        {isVisible("service") && (
                          <TableCell className="text-xs max-w-[200px] truncate" title={evt.service}>
                            {evt.service}
                          </TableCell>
                        )}
                        {isVisible("uri") && (
                          <TableCell className="font-data text-xs max-w-[300px] truncate text-muted-foreground" title={evt.uri}>
                            {evt.uri}
                          </TableCell>
                        )}
                        {isVisible("latency") && (
                          <TableCell className="font-data text-xs">
                            <span className={evt.duration >= 1 ? "text-lv-red" : evt.duration >= 0.1 ? "text-lv-peach" : "text-muted-foreground"}>
                              {formatDuration(evt.duration)}
                            </span>
                          </TableCell>
                        )}
                        {isVisible("size") && (
                          <TableCell className="font-data text-xs text-muted-foreground">
                            {formatBytes(evt.size)}
                          </TableCell>
                        )}
                        {isVisible("country") && (
                          <TableCell className="text-xs">
                            {evt.country ? (
                              <span title={evt.country}>{countryFlag(evt.country)} {evt.country}</span>
                            ) : (
                              <span className="text-muted-foreground">--</span>
                            )}
                          </TableCell>
                        )}
                        {isVisible("protocol") && (
                          <TableCell className="font-data text-xs text-muted-foreground">
                            {evt.protocol}
                          </TableCell>
                        )}
                        {isVisible("tls") && (
                          <TableCell className="text-xs">
                            {evt.tls ? (
                              <span className="text-lv-green" title={`${evt.tls.version} / ${evt.tls.proto}`}>
                                {evt.tls.version.replace("TLS ", "")}
                              </span>
                            ) : (
                              <span className="text-muted-foreground">--</span>
                            )}
                          </TableCell>
                        )}
                        {isVisible("headers") && (
                          <TableCell>
                            <HeaderDots headers={evt.security_headers} />
                          </TableCell>
                        )}
                      </TableRow>
                      {isExpanded && (
                        <TableRow className="hover:bg-transparent">
                          <TableCell colSpan={colSpan} className="bg-lovelace-950/50 p-0">
                            <LogDetailPanel event={evt} />
                          </TableCell>
                        </TableRow>
                      )}
                    </Fragment>
                  );
                })
              )}
            </TableBody>
          </Table>
        </div>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <span className="text-xs text-muted-foreground">
            Page {page} of {totalPages}
          </span>
          <div className="flex items-center gap-1">
            <Button
              variant="outline"
              size="icon"
              onClick={() => setPage(1)}
              disabled={page <= 1}
              title="First page"
            >
              <ChevronsLeft className="h-4 w-4" />
            </Button>
            <Button
              variant="outline"
              size="icon"
              onClick={() => setPage(Math.max(1, page - 1))}
              disabled={page <= 1}
              title="Previous page"
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <Button
              variant="outline"
              size="icon"
              onClick={() => setPage(Math.min(totalPages, page + 1))}
              disabled={page >= totalPages}
              title="Next page"
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
            <Button
              variant="outline"
              size="icon"
              onClick={() => setPage(totalPages)}
              disabled={page >= totalPages}
              title="Last page"
            >
              <ChevronsRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Header Dots (compact presence indicator) ───────────────────────

function HeaderDots({ headers }: { headers: GeneralLogEvent["security_headers"] }) {
  const present = [
    headers.has_csp,
    headers.has_hsts,
    headers.has_x_content_type_options,
    headers.has_x_frame_options,
    headers.has_referrer_policy,
  ];
  const count = present.filter(Boolean).length;
  const total = present.length;

  return (
    <div className="flex items-center gap-0.5" title={`${count}/${total} security headers`}>
      {present.map((p, i) => (
        <div
          key={i}
          className={`h-1.5 w-1.5 rounded-full ${p ? "bg-lv-green" : "bg-lv-red/40"}`}
        />
      ))}
    </div>
  );
}

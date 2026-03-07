import { Fragment } from "react";
import { SortableTableHead } from "@/components/SortableTableHead";
import { formatNumber, formatTime, formatDate, countryFlag } from "@/lib/format";
import { downloadJSON } from "@/lib/download";
import type { GeneralLogEvent, GeneralLogsResponse } from "@/lib/api";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
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
} from "lucide-react";

import type { SortKey } from "./helpers";
import { statusBadge, formatDuration, formatBytes } from "./helpers";
import { LogDetailPanel } from "./LogDetailPanel";

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
  serviceFilter: string;
  setServiceFilter: (v: string) => void;
  methodFilter: string;
  setMethodFilter: (v: string) => void;
  statusFilter: string;
  setStatusFilter: (v: string) => void;
  levelFilter: string;
  setLevelFilter: (v: string) => void;
  missingHeaderFilter: string;
  setMissingHeaderFilter: (v: string) => void;
  uriFilter: string;
  setUriFilter: (v: string) => void;
  hasFilters: boolean;
  clearFilters: () => void;
}

// ─── Component ──────────────────────────────────────────────────────

export default function LogStreamTab({
  response, loading, sortState, toggleSort, sortedData,
  page, totalPages, setPage,
  expanded, toggleExpand, collapseAll,
  serviceFilter, setServiceFilter,
  methodFilter, setMethodFilter,
  statusFilter, setStatusFilter,
  levelFilter, setLevelFilter,
  missingHeaderFilter, setMissingHeaderFilter,
  uriFilter, setUriFilter,
  hasFilters, clearFilters,
}: LogStreamTabProps) {
  return (
    <div className="space-y-3">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <Input
          placeholder="Service..."
          value={serviceFilter}
          onChange={(e) => setServiceFilter(e.target.value)}
          className="h-8 w-40 text-xs"
        />
        <Select value={methodFilter || "__all__"} onValueChange={(v) => setMethodFilter(v === "__all__" ? "" : v)}>
          <SelectTrigger className="h-8 w-28 text-xs">
            <SelectValue placeholder="Method" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="__all__">All</SelectItem>
            {["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"].map((m) => (
              <SelectItem key={m} value={m}>{m}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={statusFilter || "__all__"} onValueChange={(v) => setStatusFilter(v === "__all__" ? "" : v)}>
          <SelectTrigger className="h-8 w-28 text-xs">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="__all__">All</SelectItem>
            <SelectItem value="2xx">2xx</SelectItem>
            <SelectItem value="3xx">3xx</SelectItem>
            <SelectItem value="4xx">4xx</SelectItem>
            <SelectItem value="5xx">5xx</SelectItem>
            <SelectItem value="200">200</SelectItem>
            <SelectItem value="301">301</SelectItem>
            <SelectItem value="302">302</SelectItem>
            <SelectItem value="304">304</SelectItem>
            <SelectItem value="400">400</SelectItem>
            <SelectItem value="403">403</SelectItem>
            <SelectItem value="404">404</SelectItem>
            <SelectItem value="429">429</SelectItem>
            <SelectItem value="500">500</SelectItem>
            <SelectItem value="502">502</SelectItem>
            <SelectItem value="503">503</SelectItem>
          </SelectContent>
        </Select>
        <Select value={levelFilter || "__all__"} onValueChange={(v) => setLevelFilter(v === "__all__" ? "" : v)}>
          <SelectTrigger className="h-8 w-24 text-xs">
            <SelectValue placeholder="Level" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="__all__">All</SelectItem>
            <SelectItem value="info">info</SelectItem>
            <SelectItem value="error">error</SelectItem>
          </SelectContent>
        </Select>
        <Select value={missingHeaderFilter || "__all__"} onValueChange={(v) => setMissingHeaderFilter(v === "__all__" ? "" : v)}>
          <SelectTrigger className="h-8 w-36 text-xs">
            <SelectValue placeholder="Missing Header" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="__all__">None</SelectItem>
            <SelectItem value="csp">Missing CSP</SelectItem>
            <SelectItem value="hsts">Missing HSTS</SelectItem>
            <SelectItem value="xcto">Missing X-Content-Type-Options</SelectItem>
            <SelectItem value="xfo">Missing X-Frame-Options</SelectItem>
            <SelectItem value="referrer-policy">Missing Referrer-Policy</SelectItem>
            <SelectItem value="permissions-policy">Missing Permissions-Policy</SelectItem>
          </SelectContent>
        </Select>
        <Input
          placeholder="URI contains..."
          value={uriFilter}
          onChange={(e) => setUriFilter(e.target.value)}
          className="h-8 w-40 text-xs"
        />
        {hasFilters && (
          <Button variant="ghost" size="sm" className="h-8 text-xs" onClick={clearFilters}>
            Clear
          </Button>
        )}
        {response && (
          <div className="ml-auto flex items-center gap-2">
            <span className="text-xs text-muted-foreground">
              {formatNumber(response.total)} results
            </span>
            <div className="flex gap-1">
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
      </div>

      {/* Table */}
      <div className="rounded-lg border border-border overflow-hidden">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-8" />
                <SortableTableHead sortKey="time" activeKey={sortState.key} direction={sortState.direction} onSort={toggleSort} className="w-[130px]">Time</SortableTableHead>
                <SortableTableHead sortKey="status" activeKey={sortState.key} direction={sortState.direction} onSort={toggleSort} className="w-[70px]">Status</SortableTableHead>
                <SortableTableHead sortKey="method" activeKey={sortState.key} direction={sortState.direction} onSort={toggleSort} className="w-[70px]">Method</SortableTableHead>
                <SortableTableHead sortKey="service" activeKey={sortState.key} direction={sortState.direction} onSort={toggleSort}>Service</SortableTableHead>
                <TableHead className="text-xs">URI</TableHead>
                <SortableTableHead sortKey="duration" activeKey={sortState.key} direction={sortState.direction} onSort={toggleSort} className="w-[80px]">Latency</SortableTableHead>
                <SortableTableHead sortKey="size" activeKey={sortState.key} direction={sortState.direction} onSort={toggleSort} className="w-[70px]">Size</SortableTableHead>
                <TableHead className="text-xs w-[60px]">Headers</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && !response ? (
                Array.from({ length: 10 }).map((_, i) => (
                  <TableRow key={i}>
                    <TableCell />
                    {Array.from({ length: 8 }).map((_, j) => (
                      <TableCell key={j}><Skeleton className="h-4 w-full" /></TableCell>
                    ))}
                  </TableRow>
                ))
              ) : sortedData.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={9} className="py-8 text-center text-sm text-muted-foreground">
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
                        <TableCell className="font-mono text-xs text-muted-foreground whitespace-nowrap">
                          {formatDate(evt.timestamp)} {formatTime(evt.timestamp)}
                        </TableCell>
                        <TableCell>{statusBadge(evt.status)}</TableCell>
                        <TableCell>
                          <span className="font-mono text-xs">{evt.method}</span>
                        </TableCell>
                        <TableCell className="text-xs max-w-[200px] truncate" title={evt.service}>
                          {evt.service}
                        </TableCell>
                        <TableCell className="font-mono text-xs max-w-[300px] truncate text-muted-foreground" title={evt.uri}>
                          {evt.uri}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          <span className={evt.duration >= 1 ? "text-red-400" : evt.duration >= 0.1 ? "text-amber-400" : "text-muted-foreground"}>
                            {formatDuration(evt.duration)}
                          </span>
                        </TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          {formatBytes(evt.size)}
                        </TableCell>
                        <TableCell>
                          <HeaderDots headers={evt.security_headers} />
                        </TableCell>
                      </TableRow>
                      {isExpanded && (
                        <TableRow className="hover:bg-transparent">
                          <TableCell colSpan={9} className="bg-navy-950/50 p-0">
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
          className={`h-1.5 w-1.5 rounded-full ${p ? "bg-emerald-400" : "bg-red-400/40"}`}
        />
      ))}
    </div>
  );
}

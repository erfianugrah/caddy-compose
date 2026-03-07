import { SortableTableHead } from "@/components/SortableTableHead";
import { formatNumber, formatTime, formatDate, countryFlag } from "@/lib/format";
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
import { ArrowLeft, ArrowRight } from "lucide-react";

import type { SortKey } from "./helpers";
import { statusBadge, formatDuration, formatBytes, DetailRow, HeaderRow } from "./helpers";

// ─── Props ──────────────────────────────────────────────────────────

export interface LogStreamTabProps {
  response: GeneralLogsResponse | null;
  loading: boolean;
  sortState: { key: string | null; direction: "asc" | "desc" | null };
  toggleSort: (key: SortKey) => void;
  sortedData: GeneralLogEvent[];
  page: number;
  totalPages: number;
  setPage: (p: number) => void;
  expandedIdx: number | null;
  setExpandedIdx: (i: number | null) => void;
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
  page, totalPages, setPage, expandedIdx, setExpandedIdx,
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
        <Select value={methodFilter} onValueChange={setMethodFilter}>
          <SelectTrigger className="h-8 w-28 text-xs">
            <SelectValue placeholder="Method" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="">All</SelectItem>
            {["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"].map((m) => (
              <SelectItem key={m} value={m}>{m}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="h-8 w-28 text-xs">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="">All</SelectItem>
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
        <Select value={levelFilter} onValueChange={setLevelFilter}>
          <SelectTrigger className="h-8 w-24 text-xs">
            <SelectValue placeholder="Level" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="">All</SelectItem>
            <SelectItem value="info">info</SelectItem>
            <SelectItem value="error">error</SelectItem>
          </SelectContent>
        </Select>
        <Select value={missingHeaderFilter} onValueChange={setMissingHeaderFilter}>
          <SelectTrigger className="h-8 w-36 text-xs">
            <SelectValue placeholder="Missing Header" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="">None</SelectItem>
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
          <span className="ml-auto text-xs text-muted-foreground">
            {formatNumber(response.total)} results
          </span>
        )}
      </div>

      {/* Table */}
      <div className="rounded-lg border border-border overflow-hidden">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <SortableTableHead sortKey="time" label="Time" sortState={sortState} onSort={toggleSort} className="w-[130px]" />
                <SortableTableHead sortKey="status" label="Status" sortState={sortState} onSort={toggleSort} className="w-[70px]" />
                <SortableTableHead sortKey="method" label="Method" sortState={sortState} onSort={toggleSort} className="w-[70px]" />
                <SortableTableHead sortKey="service" label="Service" sortState={sortState} onSort={toggleSort} />
                <TableHead className="text-xs">URI</TableHead>
                <SortableTableHead sortKey="duration" label="Latency" sortState={sortState} onSort={toggleSort} className="w-[80px]" />
                <SortableTableHead sortKey="size" label="Size" sortState={sortState} onSort={toggleSort} className="w-[70px]" />
                <TableHead className="text-xs w-[60px]">Headers</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && !response ? (
                Array.from({ length: 10 }).map((_, i) => (
                  <TableRow key={i}>
                    {Array.from({ length: 8 }).map((_, j) => (
                      <TableCell key={j}><Skeleton className="h-4 w-full" /></TableCell>
                    ))}
                  </TableRow>
                ))
              ) : sortedData.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="py-8 text-center text-sm text-muted-foreground">
                    No log entries found
                  </TableCell>
                </TableRow>
              ) : (
                sortedData.map((evt, i) => (
                  <>
                    <TableRow
                      key={i}
                      className="cursor-pointer hover:bg-muted/50"
                      onClick={() => setExpandedIdx(expandedIdx === i ? null : i)}
                    >
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
                    {expandedIdx === i && (
                      <TableRow key={`${i}-detail`}>
                        <TableCell colSpan={8} className="bg-muted/30 p-4">
                          <LogDetail event={evt} />
                        </TableCell>
                      </TableRow>
                    )}
                  </>
                ))
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
          <div className="flex gap-1">
            <Button
              variant="outline" size="sm" disabled={page <= 1}
              onClick={() => setPage(page - 1)}
            >
              <ArrowLeft className="h-3.5 w-3.5" />
            </Button>
            <Button
              variant="outline" size="sm" disabled={page >= totalPages}
              onClick={() => setPage(page + 1)}
            >
              <ArrowRight className="h-3.5 w-3.5" />
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

// ─── Log Detail (expanded row) ──────────────────────────────────────

function LogDetail({ event: evt }: { event: GeneralLogEvent }) {
  return (
    <div className="grid gap-4 text-xs sm:grid-cols-2">
      <div className="space-y-2">
        <h4 className="font-medium text-foreground">Request</h4>
        <dl className="space-y-1">
          <DetailRow label="Client IP" value={`${evt.client_ip}${evt.country ? ` ${countryFlag(evt.country)} ${evt.country}` : ""}`} />
          <DetailRow label="Method" value={evt.method} />
          <DetailRow label="URI" value={evt.uri} mono />
          <DetailRow label="Protocol" value={evt.protocol} />
          <DetailRow label="Service" value={evt.service} />
          <DetailRow label="User-Agent" value={evt.user_agent} mono />
        </dl>
      </div>
      <div className="space-y-2">
        <h4 className="font-medium text-foreground">Response</h4>
        <dl className="space-y-1">
          <DetailRow label="Status" value={String(evt.status)} />
          <DetailRow label="Size" value={formatBytes(evt.size)} />
          <DetailRow label="Duration" value={formatDuration(evt.duration)} />
          <DetailRow label="Level" value={evt.level || "info"} />
          <DetailRow label="Logger" value={evt.logger || ""} mono />
        </dl>
        <h4 className="font-medium text-foreground mt-3">Security Headers</h4>
        <dl className="space-y-1">
          <HeaderRow label="CSP" present={evt.security_headers.has_csp} value={evt.security_headers.csp} />
          <HeaderRow label="HSTS" present={evt.security_headers.has_hsts} value={evt.security_headers.hsts} />
          <HeaderRow label="X-Content-Type-Options" present={evt.security_headers.has_x_content_type_options} value={evt.security_headers.x_content_type_options} />
          <HeaderRow label="X-Frame-Options" present={evt.security_headers.has_x_frame_options} value={evt.security_headers.x_frame_options} />
          <HeaderRow label="Referrer-Policy" present={evt.security_headers.has_referrer_policy} value={evt.security_headers.referrer_policy} />
          <HeaderRow label="CORS Origin" present={evt.security_headers.has_cors_origin} value={evt.security_headers.cors_origin} />
          <HeaderRow label="Permissions-Policy" present={evt.security_headers.has_permissions_policy} value={evt.security_headers.permissions_policy} />
        </dl>
      </div>
    </div>
  );
}

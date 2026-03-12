import { useState, useEffect, useMemo } from "react";
import { useTableSort } from "@/hooks/useTableSort";
import { SortableTableHead } from "@/components/SortableTableHead";
import { Shield, AlertTriangle } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { fetchTopBlockedIPs, type TopBlockedIP } from "@/lib/api";
import { T } from "@/lib/typography";
import { formatDateTime } from "@/lib/format";
import { TablePagination, paginateArray } from "../TablePagination";
import { CountryLabel } from "./CountryLabel";

const ANALYTICS_PAGE_SIZE = 10;

export function TopBlockedIPsPanel({ hours, refreshKey }: { hours?: number; refreshKey: number }) {
  const [data, setData] = useState<TopBlockedIP[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);

  useEffect(() => {
    setLoading(true);
    setPage(1);
    fetchTopBlockedIPs(hours)
      .then(setData)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [hours, refreshKey]);

  if (error) {
    return (
      <Alert variant="destructive">
        <AlertTriangle className="h-4 w-4" />
        <AlertTitle>Error</AlertTitle>
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }

  const ipSortComparators = useMemo(() => ({
    ip: (a: TopBlockedIP, b: TopBlockedIP) => a.client_ip.localeCompare(b.client_ip),
    country: (a: TopBlockedIP, b: TopBlockedIP) => (a.country ?? "").localeCompare(b.country ?? ""),
    events: (a: TopBlockedIP, b: TopBlockedIP) => a.total - b.total,
    blocked: (a: TopBlockedIP, b: TopBlockedIP) => a.blocked - b.blocked,
    block_rate: (a: TopBlockedIP, b: TopBlockedIP) => a.block_rate - b.block_rate,
    first_seen: (a: TopBlockedIP, b: TopBlockedIP) => a.first_seen.localeCompare(b.first_seen),
    last_seen: (a: TopBlockedIP, b: TopBlockedIP) => a.last_seen.localeCompare(b.last_seen),
  }), []);
  const ipSort = useTableSort(data, ipSortComparators);
  const { items: pageData, totalPages } = paginateArray(ipSort.sortedData, page, ANALYTICS_PAGE_SIZE);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-lv-red" />
          <CardTitle className={T.cardTitle}>Top Blocked IPs</CardTitle>
        </div>
        <CardDescription>IP addresses with the most blocked events</CardDescription>
      </CardHeader>
      <CardContent className="p-0 overflow-x-auto">
        {loading ? (
          <div className="space-y-2 p-6">
            {[...Array(8)].map((_, i) => (
              <Skeleton key={i} className="h-8 w-full" />
            ))}
          </div>
        ) : data.length > 0 ? (
          <>
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <SortableTableHead sortKey="ip" activeKey={ipSort.sortState.key} direction={ipSort.sortState.direction} onSort={ipSort.toggleSort}>IP Address</SortableTableHead>
                <SortableTableHead sortKey="country" activeKey={ipSort.sortState.key} direction={ipSort.sortState.direction} onSort={ipSort.toggleSort}>Country</SortableTableHead>
                <SortableTableHead sortKey="events" activeKey={ipSort.sortState.key} direction={ipSort.sortState.direction} onSort={ipSort.toggleSort} className="text-right">Events</SortableTableHead>
                <SortableTableHead sortKey="blocked" activeKey={ipSort.sortState.key} direction={ipSort.sortState.direction} onSort={ipSort.toggleSort} className="text-right">Blocked</SortableTableHead>
                <SortableTableHead sortKey="block_rate" activeKey={ipSort.sortState.key} direction={ipSort.sortState.direction} onSort={ipSort.toggleSort}>Block Rate</SortableTableHead>
                <SortableTableHead sortKey="first_seen" activeKey={ipSort.sortState.key} direction={ipSort.sortState.direction} onSort={ipSort.toggleSort}>First Seen</SortableTableHead>
                <SortableTableHead sortKey="last_seen" activeKey={ipSort.sortState.key} direction={ipSort.sortState.direction} onSort={ipSort.toggleSort}>Last Seen</SortableTableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {pageData.map((ip) => (
                <TableRow key={ip.client_ip}>
                  <TableCell className="font-data text-xs">
                    <a
                      href={`/analytics?tab=ip&q=${encodeURIComponent(ip.client_ip)}`}
                      className="text-lv-cyan hover:underline"
                    >
                      {ip.client_ip}
                    </a>
                  </TableCell>
                  <TableCell className="text-xs">
                    <CountryLabel code={ip.country ?? ""} />
                  </TableCell>
                  <TableCell className="text-right tabular-nums text-xs">
                    {ip.total.toLocaleString()}
                  </TableCell>
                  <TableCell className="text-right tabular-nums text-xs text-lv-red">
                    {ip.blocked.toLocaleString()}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-12 overflow-hidden rounded-full bg-lovelace-800">
                        <div
                          className={`h-full rounded-full transition-all ${
                            ip.block_rate > 50
                              ? "bg-lv-red"
                              : ip.block_rate > 20
                                ? "bg-lv-peach"
                                : "bg-lv-green"
                          }`}
                          style={{ width: `${Math.min(ip.block_rate, 100)}%` }}
                        />
                      </div>
                      <span className="text-xs tabular-nums text-muted-foreground">
                        {ip.block_rate.toFixed(1)}%
                      </span>
                    </div>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {formatDateTime(ip.first_seen)}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {formatDateTime(ip.last_seen)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <TablePagination page={page} totalPages={totalPages} onPageChange={setPage} totalItems={data.length} />
          </>
        ) : (
          <div className="py-8 text-center text-xs text-muted-foreground">
            No blocked IP data available
          </div>
        )}
      </CardContent>
    </Card>
  );
}

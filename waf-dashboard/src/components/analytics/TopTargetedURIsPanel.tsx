import { useState, useEffect, useMemo } from "react";
import { useTableSort } from "@/hooks/useTableSort";
import { SortableTableHead } from "@/components/SortableTableHead";
import { Target, AlertTriangle } from "lucide-react";
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
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { fetchTopTargetedURIs, type TopTargetedURI } from "@/lib/api";
import { T } from "@/lib/typography";
import { TablePagination, paginateArray } from "../TablePagination";

const ANALYTICS_PAGE_SIZE = 10;

export function TopTargetedURIsPanel({ hours, refreshKey }: { hours?: number; refreshKey: number }) {
  const [data, setData] = useState<TopTargetedURI[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);

  useEffect(() => {
    setLoading(true);
    setPage(1);
    fetchTopTargetedURIs(hours)
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

  const uriSortComparators = useMemo(() => ({
    uri: (a: TopTargetedURI, b: TopTargetedURI) => a.uri.localeCompare(b.uri),
    total: (a: TopTargetedURI, b: TopTargetedURI) => a.total - b.total,
    blocked: (a: TopTargetedURI, b: TopTargetedURI) => a.blocked - b.blocked,
  }), []);
  const uriSort = useTableSort(data, uriSortComparators);
  const { items: pageData, totalPages } = paginateArray(uriSort.sortedData, page, ANALYTICS_PAGE_SIZE);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Target className="h-4 w-4 text-neon-amber" />
          <CardTitle className={T.cardTitle}>Top Targeted URIs</CardTitle>
        </div>
        <CardDescription>Most-hit URIs across all services</CardDescription>
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
                <SortableTableHead sortKey="uri" activeKey={uriSort.sortState.key} direction={uriSort.sortState.direction} onSort={uriSort.toggleSort} className="max-w-[300px]">URI</SortableTableHead>
                <SortableTableHead sortKey="total" activeKey={uriSort.sortState.key} direction={uriSort.sortState.direction} onSort={uriSort.toggleSort} className="text-right">Total</SortableTableHead>
                <SortableTableHead sortKey="blocked" activeKey={uriSort.sortState.key} direction={uriSort.sortState.direction} onSort={uriSort.toggleSort} className="text-right">Blocked</SortableTableHead>
                <TableHead>Services</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {pageData.map((uri, idx) => (
                <TableRow key={idx}>
                  <TableCell className="max-w-[300px] truncate font-mono text-xs" title={uri.uri}>
                    {uri.uri}
                  </TableCell>
                  <TableCell className="text-right tabular-nums text-xs">
                    {uri.total.toLocaleString()}
                  </TableCell>
                  <TableCell className="text-right tabular-nums text-xs text-neon-pink">
                    {uri.blocked.toLocaleString()}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {uri.services.slice(0, 3).map((s) => (
                        <Badge key={s} variant="outline" className={T.badgeMono}>
                          {s}
                        </Badge>
                      ))}
                      {uri.services.length > 3 && (
                        <Badge variant="secondary" className={T.badgeMono}>
                          +{uri.services.length - 3}
                        </Badge>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <TablePagination page={page} totalPages={totalPages} onPageChange={setPage} totalItems={data.length} />
          </>
        ) : (
          <div className="py-8 text-center text-xs text-muted-foreground">
            No URI data available
          </div>
        )}
      </CardContent>
    </Card>
  );
}

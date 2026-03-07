import { useState, useEffect, useMemo } from "react";
import { useTableSort } from "@/hooks/useTableSort";
import { SortableTableHead } from "@/components/SortableTableHead";
import { Globe, AlertTriangle } from "lucide-react";
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
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { fetchTopCountries, type CountryCount } from "@/lib/api";
import { T } from "@/lib/typography";
import { formatNumber } from "@/lib/format";
import { TablePagination, paginateArray } from "../TablePagination";
import { CountryLabel } from "./CountryLabel";

const ANALYTICS_PAGE_SIZE = 10;

export function TopCountriesPanel({ hours, refreshKey }: { hours?: number; refreshKey: number }) {
  const [data, setData] = useState<CountryCount[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);

  useEffect(() => {
    setLoading(true);
    setPage(1);
    fetchTopCountries(hours)
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

  const maxCount = data.length > 0 ? Math.max(...data.map((c) => c.count)) : 1;
  const countrySortComparators = useMemo(() => ({
    country: (a: CountryCount, b: CountryCount) => a.country.localeCompare(b.country),
    total: (a: CountryCount, b: CountryCount) => a.count - b.count,
    blocked: (a: CountryCount, b: CountryCount) => a.blocked - b.blocked,
    block_rate: (a: CountryCount, b: CountryCount) => {
      const rateA = a.count > 0 ? a.blocked / a.count : 0;
      const rateB = b.count > 0 ? b.blocked / b.count : 0;
      return rateA - rateB;
    },
  }), []);
  const countrySort = useTableSort(data, countrySortComparators);
  const { items: pageData, totalPages } = paginateArray(countrySort.sortedData, page, ANALYTICS_PAGE_SIZE);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Globe className="h-4 w-4 text-neon-cyan" />
          <CardTitle className={T.cardTitle}>Top Countries</CardTitle>
        </div>
        <CardDescription>Request origins by country code</CardDescription>
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
                <SortableTableHead sortKey="country" activeKey={countrySort.sortState.key} direction={countrySort.sortState.direction} onSort={countrySort.toggleSort}>Country</SortableTableHead>
                <TableHead>Requests</TableHead>
                <SortableTableHead sortKey="total" activeKey={countrySort.sortState.key} direction={countrySort.sortState.direction} onSort={countrySort.toggleSort} className="text-right">Total</SortableTableHead>
                <SortableTableHead sortKey="blocked" activeKey={countrySort.sortState.key} direction={countrySort.sortState.direction} onSort={countrySort.toggleSort} className="text-right">Blocked</SortableTableHead>
                <SortableTableHead sortKey="block_rate" activeKey={countrySort.sortState.key} direction={countrySort.sortState.direction} onSort={countrySort.toggleSort} className="text-right">Block Rate</SortableTableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {pageData.map((c) => {
                const blockRate = c.count > 0 ? (c.blocked / c.count) * 100 : 0;
                return (
                  <TableRow key={c.country}>
                    <TableCell className="text-xs">
                      <CountryLabel code={c.country} />
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <div className="h-2 w-24 overflow-hidden rounded-full bg-navy-800">
                          <div
                            className="h-full rounded-full bg-neon-cyan/70 transition-all"
                            style={{ width: `${(c.count / maxCount) * 100}%` }}
                          />
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="text-right tabular-nums text-xs">
                      {formatNumber(c.count)}
                    </TableCell>
                    <TableCell className="text-right tabular-nums text-xs text-neon-pink">
                      {c.blocked > 0 ? formatNumber(c.blocked) : "-"}
                    </TableCell>
                    <TableCell className="text-right">
                      <span className={`text-xs tabular-nums ${
                        blockRate > 50 ? "text-neon-pink" : blockRate > 20 ? "text-neon-amber" : "text-muted-foreground"
                      }`}>
                        {blockRate > 0 ? `${blockRate.toFixed(1)}%` : "-"}
                      </span>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
          <TablePagination page={page} totalPages={totalPages} onPageChange={setPage} totalItems={data.length} />
          </>
        ) : (
          <div className="py-8 text-center text-xs text-muted-foreground">
            No country data available. GeoIP data requires Cf-Ipcountry headers or an MMDB database.
          </div>
        )}
      </CardContent>
    </Card>
  );
}

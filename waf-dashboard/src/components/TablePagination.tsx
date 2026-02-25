import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from "lucide-react";
import { Button } from "@/components/ui/button";

interface TablePaginationProps {
  page: number;
  totalPages: number;
  onPageChange: (page: number) => void;
  /** Optional: total item count to display "X items" */
  totalItems?: number;
}

/**
 * Compact pagination control for tables.
 * Matches the existing style from EventsTable / OverviewDashboard.
 */
export function TablePagination({ page, totalPages, onPageChange, totalItems }: TablePaginationProps) {
  if (totalPages <= 1) return null;

  return (
    <div className="flex items-center justify-between px-4 py-3 border-t border-navy-800">
      <span className="text-xs text-muted-foreground">
        Page {page} of {totalPages}
        {totalItems != null && <span className="ml-2">({totalItems.toLocaleString()} items)</span>}
      </span>
      <div className="flex items-center gap-1">
        <Button
          variant="outline"
          size="icon"
          className="h-7 w-7"
          onClick={() => onPageChange(1)}
          disabled={page <= 1}
        >
          <ChevronsLeft className="h-3.5 w-3.5" />
        </Button>
        <Button
          variant="outline"
          size="icon"
          className="h-7 w-7"
          onClick={() => onPageChange(Math.max(1, page - 1))}
          disabled={page <= 1}
        >
          <ChevronLeft className="h-3.5 w-3.5" />
        </Button>
        <Button
          variant="outline"
          size="icon"
          className="h-7 w-7"
          onClick={() => onPageChange(Math.min(totalPages, page + 1))}
          disabled={page >= totalPages}
        >
          <ChevronRight className="h-3.5 w-3.5" />
        </Button>
        <Button
          variant="outline"
          size="icon"
          className="h-7 w-7"
          onClick={() => onPageChange(totalPages)}
          disabled={page >= totalPages}
        >
          <ChevronsRight className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  );
}

/** Helper hook-like function: paginate an array client-side. */
export function paginateArray<T>(data: T[], page: number, pageSize: number): { items: T[]; totalPages: number } {
  const totalPages = Math.max(1, Math.ceil(data.length / pageSize));
  const start = (page - 1) * pageSize;
  const items = data.slice(start, start + pageSize);
  return { items, totalPages };
}

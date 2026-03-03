import { ArrowUp, ArrowDown, ArrowUpDown } from "lucide-react";
import { TableHead } from "@/components/ui/table";
import { cn } from "@/lib/utils";
import type { SortDirection } from "@/hooks/useTableSort";

interface SortableTableHeadProps {
  /** Column sort key */
  sortKey: string;
  /** Current active sort key */
  activeKey: string | null;
  /** Current sort direction */
  direction: SortDirection;
  /** Called when header is clicked */
  onSort: (key: string) => void;
  /** Additional className for the <th> */
  className?: string;
  /** Optional title tooltip */
  title?: string;
  children: React.ReactNode;
}

/**
 * A table header cell that is clickable and shows sort direction indicators.
 * Renders a subtle arrow icon: up for asc, down for desc, up-down for unsorted.
 */
export function SortableTableHead({
  sortKey,
  activeKey,
  direction,
  onSort,
  className,
  title,
  children,
}: SortableTableHeadProps) {
  const isActive = activeKey === sortKey && direction !== null;

  return (
    <TableHead
      className={cn(
        "cursor-pointer select-none transition-colors hover:text-foreground",
        isActive && "text-foreground",
        className,
      )}
      title={title}
      onClick={() => onSort(sortKey)}
    >
      <span className="inline-flex items-center gap-1">
        {children}
        {isActive ? (
          direction === "asc" ? (
            <ArrowUp className="h-3 w-3 text-neon-cyan" />
          ) : (
            <ArrowDown className="h-3 w-3 text-neon-cyan" />
          )
        ) : (
          <ArrowUpDown className="h-3 w-3 opacity-30" />
        )}
      </span>
    </TableHead>
  );
}

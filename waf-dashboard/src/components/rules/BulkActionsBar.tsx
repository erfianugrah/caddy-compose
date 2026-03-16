import { ArrowUpToLine, ArrowDownToLine } from "lucide-react";
import { Button } from "@/components/ui/button";

// ─── Shared bulk actions bar ────────────────────────────────────────
// Rendered above the rule table when one or more rows are selected.

interface BulkActionsBarProps {
  selectedCount: number;
  filteredCount: number;
  totalCount: number;
  isFiltered: boolean;
  bulkBusy: boolean;
  onEnable: () => void;
  onDisable: () => void;
  onDelete: () => void;
  onBulkMoveToPosition: (pos: number) => void;
  /** If provided, renders "Move to Top / Bottom" buttons. */
  onBulkMoveToEdge?: (edge: "top" | "bottom") => void;
  onSelectAll: () => void;
  onClear: () => void;
}

export function BulkActionsBar({
  selectedCount,
  filteredCount,
  totalCount,
  isFiltered,
  bulkBusy,
  onEnable,
  onDisable,
  onDelete,
  onBulkMoveToPosition,
  onBulkMoveToEdge,
  onSelectAll,
  onClear,
}: BulkActionsBarProps) {
  return (
    <div className="flex items-center gap-2 px-4 py-2 border-b border-lv-cyan/30 bg-lv-cyan/5">
      <span className="text-xs font-medium text-lv-cyan mr-2">
        {selectedCount} selected
      </span>
      <Button variant="outline" size="xs" onClick={onEnable} disabled={bulkBusy}>
        Enable
      </Button>
      <Button variant="outline" size="xs" onClick={onDisable} disabled={bulkBusy}>
        Disable
      </Button>
      <Button variant="outline" size="xs" className="text-lv-red hover:text-lv-red" onClick={onDelete} disabled={bulkBusy}>
        Delete
      </Button>
      {!isFiltered && (
        <>
          {onBulkMoveToEdge && (
            <>
              <span className="mx-1 h-4 w-px bg-border" />
              <Button variant="outline" size="xs" onClick={() => onBulkMoveToEdge("top")} disabled={bulkBusy}>
                <ArrowUpToLine className="h-3 w-3 mr-1" />
                Move to Top
              </Button>
              <Button variant="outline" size="xs" onClick={() => onBulkMoveToEdge("bottom")} disabled={bulkBusy}>
                <ArrowDownToLine className="h-3 w-3 mr-1" />
                Move to Bottom
              </Button>
            </>
          )}
          <form
            className="inline-flex items-center gap-1 ml-2"
            onSubmit={(e) => {
              e.preventDefault();
              const input = (e.target as HTMLFormElement).elements.namedItem("bulkPos") as HTMLInputElement;
              const pos = parseInt(input.value, 10);
              if (!isNaN(pos) && pos >= 1) {
                onBulkMoveToPosition(pos);
                input.value = "";
              }
            }}
          >
            <span className="text-xs text-muted-foreground">Move to #</span>
            <input
              name="bulkPos"
              type="number"
              min={1}
              max={totalCount}
              className="w-[50px] h-6 bg-transparent border border-border rounded px-1 text-xs text-center outline-none focus:border-lv-cyan"
              placeholder="#"
            />
          </form>
        </>
      )}
      <div className="ml-auto flex items-center gap-2">
        <Button variant="ghost" size="xs" onClick={onSelectAll} className="text-xs text-muted-foreground">
          Select All ({filteredCount})
        </Button>
        <Button variant="ghost" size="xs" onClick={onClear} className="text-xs text-muted-foreground">
          Clear
        </Button>
      </div>
    </div>
  );
}

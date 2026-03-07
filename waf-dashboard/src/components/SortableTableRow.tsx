import { useCallback } from "react";
import { useSortable } from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import { GripVertical } from "lucide-react";
import { TableRow, TableCell } from "@/components/ui/table";

// ─── Sortable Table Row ─────────────────────────────────────────────

export function SortableTableRow({
  id,
  disabled,
  children,
  className,
  rowRef,
}: {
  id: string;
  disabled?: boolean;
  children: React.ReactNode;
  className?: string;
  rowRef?: React.Ref<HTMLTableRowElement>;
}) {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id, disabled });

  const style: React.CSSProperties = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.5 : undefined,
    position: "relative",
    zIndex: isDragging ? 10 : undefined,
  };

  // Merge refs if rowRef is provided
  const mergedRef = useCallback(
    (node: HTMLTableRowElement | null) => {
      setNodeRef(node);
      if (typeof rowRef === "function") rowRef(node);
      else if (rowRef && "current" in rowRef) (rowRef as React.MutableRefObject<HTMLTableRowElement | null>).current = node;
    },
    [setNodeRef, rowRef],
  );

  return (
    <TableRow ref={mergedRef} style={style} className={className} {...attributes}>
      <TableCell className="w-[52px] px-1">
        <div className="flex items-center gap-0.5">
          {!disabled ? (
            <button
              className="cursor-grab active:cursor-grabbing p-0.5 text-muted-foreground/50 hover:text-muted-foreground touch-none"
              {...listeners}
              tabIndex={-1}
            >
              <GripVertical className="h-3.5 w-3.5" />
            </button>
          ) : (
            <span className="p-0.5 w-[18px]" />
          )}
        </div>
      </TableCell>
      {children}
    </TableRow>
  );
}

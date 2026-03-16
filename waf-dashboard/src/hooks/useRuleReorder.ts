import { useCallback } from "react";
import { arrayMove } from "@dnd-kit/sortable";
import type { DragEndEvent } from "@dnd-kit/core";

// ─── Generic rule reorder hook ──────────────────────────────────────
// Extracts all drag/move/bulk-move operations shared by PolicyEngine
// and RateLimitsPanel into a single parameterized hook.

interface UseRuleReorderOptions<T> {
  items: T[];
  setItems: React.Dispatch<React.SetStateAction<T[]>>;
  getId: (item: T) => string;
  reorderApi: (ids: string[]) => Promise<T[]>;
  pageSize: number;
  page: number;
  setPage: (page: number) => void;
  setError: (msg: string) => void;
  autoDeploy: (msg: string) => Promise<void>;
  selected?: Set<string>;
  setSelected?: React.Dispatch<React.SetStateAction<Set<string>>>;
}

export function useRuleReorder<T>({
  items,
  setItems,
  getId,
  reorderApi,
  pageSize,
  page,
  setPage,
  setError,
  autoDeploy,
  selected,
  setSelected,
}: UseRuleReorderOptions<T>) {
  /** Optimistic update + API call + rollback-on-error. */
  const applyReorder = useCallback(
    async (newItems: T[], msg: string, clearSelection = false) => {
      const prev = items;
      setItems(newItems);
      try {
        const result = await reorderApi(newItems.map(getId));
        setItems(result);
        if (clearSelection && setSelected) setSelected(new Set());
        await autoDeploy(msg);
      } catch (err: unknown) {
        setItems(prev);
        setError(err instanceof Error ? err.message : "Reorder failed");
      }
    },
    [items, setItems, getId, reorderApi, autoDeploy, setError, setSelected],
  );

  const handleDragEnd = useCallback(
    async (event: DragEndEvent) => {
      const { active, over } = event;
      if (!over || active.id === over.id) return;

      const activeId = active.id as string;
      const overId = over.id as string;

      // Multi-drag: if the dragged item is in a multi-selection, move all as a group.
      if (selected && selected.size > 1 && selected.has(activeId)) {
        const overIdx = items.findIndex((i) => getId(i) === overId);
        if (overIdx === -1) return;

        const remaining = items.filter((i) => !selected.has(getId(i)));
        const moved = items.filter((i) => selected.has(getId(i)));
        const targetInRemaining = remaining.findIndex((i) => getId(i) === overId);
        const insertIdx = targetInRemaining === -1 ? overIdx : targetInRemaining;
        const newItems = [...remaining.slice(0, insertIdx), ...moved, ...remaining.slice(insertIdx)];
        await applyReorder(newItems, `${moved.length} rules reordered`);
        return;
      }

      // Single-drag: reorder within the current page.
      const pageStartIdx = (page - 1) * pageSize;
      const pageIds = items.slice(pageStartIdx, pageStartIdx + pageSize).map(getId);
      const oldIdx = pageIds.indexOf(activeId);
      const newIdx = pageIds.indexOf(overId);
      if (oldIdx === -1 || newIdx === -1) return;

      const newItems = [...items];
      const pageSlice = newItems.splice(pageStartIdx, pageIds.length);
      const reorderedPage = arrayMove(pageSlice, oldIdx, newIdx);
      newItems.splice(pageStartIdx, 0, ...reorderedPage);
      await applyReorder(newItems, "Rules reordered");
    },
    [items, getId, selected, page, pageSize, applyReorder],
  );

  const handleMoveToEdge = useCallback(
    async (id: string, edge: "top" | "bottom") => {
      const idx = items.findIndex((i) => getId(i) === id);
      if (idx === -1) return;
      if (edge === "top" && idx === 0) return;
      if (edge === "bottom" && idx === items.length - 1) return;

      const newItems = [...items];
      const [item] = newItems.splice(idx, 1);
      if (edge === "top") {
        newItems.unshift(item);
        setPage(1);
      } else {
        newItems.push(item);
        setPage(Math.ceil(newItems.length / pageSize));
      }
      await applyReorder(newItems, `Rule moved to ${edge}`);
    },
    [items, getId, pageSize, setPage, applyReorder],
  );

  const handleMoveToPosition = useCallback(
    async (id: string, targetPos: number) => {
      const fromIdx = items.findIndex((i) => getId(i) === id);
      if (fromIdx === -1) return;
      const toIdx = Math.max(0, Math.min(items.length - 1, targetPos - 1));
      if (fromIdx === toIdx) return;

      const newItems = [...items];
      const [item] = newItems.splice(fromIdx, 1);
      newItems.splice(toIdx, 0, item);
      setPage(Math.ceil((toIdx + 1) / pageSize));
      await applyReorder(newItems, `Rule moved to position ${toIdx + 1}`);
    },
    [items, getId, pageSize, setPage, applyReorder],
  );

  const handleBulkMoveToPosition = useCallback(
    async (targetPos: number) => {
      if (!selected || selected.size === 0) return;
      const remaining = items.filter((i) => !selected.has(getId(i)));
      const moved = items.filter((i) => selected.has(getId(i)));
      const insertIdx = Math.max(0, Math.min(remaining.length, targetPos - 1));
      const newItems = [...remaining.slice(0, insertIdx), ...moved, ...remaining.slice(insertIdx)];
      setPage(Math.ceil((insertIdx + 1) / pageSize));
      await applyReorder(newItems, `${moved.length} rules moved to position ${insertIdx + 1}`, true);
    },
    [items, getId, selected, pageSize, setPage, applyReorder],
  );

  const handleBulkMoveToEdge = useCallback(
    async (edge: "top" | "bottom") => {
      if (!selected || selected.size === 0) return;
      const remaining = items.filter((i) => !selected.has(getId(i)));
      const moved = items.filter((i) => selected.has(getId(i)));
      const newItems = edge === "top" ? [...moved, ...remaining] : [...remaining, ...moved];
      setPage(edge === "top" ? 1 : Math.ceil(newItems.length / pageSize));
      await applyReorder(newItems, `${moved.length} rules moved to ${edge}`, true);
    },
    [items, getId, selected, pageSize, setPage, applyReorder],
  );

  return {
    handleDragEnd,
    handleMoveToEdge,
    handleMoveToPosition,
    handleBulkMoveToPosition,
    handleBulkMoveToEdge,
  };
}

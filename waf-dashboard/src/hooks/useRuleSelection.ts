import { useState, useCallback, useRef } from "react";

// ─── Generic rule selection hook ────────────────────────────────────
// Shift-click range selection, select-all-visible, and clear.

export function useRuleSelection<T extends { id: string }>(
  pagedItems: T[],
  filteredItems: T[],
) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const lastSelectedRef = useRef<number | null>(null);

  const toggleSelect = useCallback(
    (id: string, index: number, shiftKey: boolean) => {
      setSelected((prev) => {
        const next = new Set(prev);
        if (shiftKey && lastSelectedRef.current !== null) {
          const start = Math.min(lastSelectedRef.current, index);
          const end = Math.max(lastSelectedRef.current, index);
          for (let i = start; i <= end; i++) {
            next.add(pagedItems[i].id);
          }
        } else {
          if (next.has(id)) next.delete(id);
          else next.add(id);
        }
        lastSelectedRef.current = index;
        return next;
      });
    },
    [pagedItems],
  );

  const selectAllVisible = useCallback(() => {
    setSelected(new Set(filteredItems.map((item) => item.id)));
  }, [filteredItems]);

  const clearSelection = useCallback(() => setSelected(new Set()), []);

  return { selected, setSelected, toggleSelect, selectAllVisible, clearSelection };
}

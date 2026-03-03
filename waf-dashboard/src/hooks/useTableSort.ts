import { useState, useMemo, useCallback } from "react";

export type SortDirection = "asc" | "desc" | null;

export interface SortState<K extends string = string> {
  key: K | null;
  direction: SortDirection;
}

/**
 * Generic table sort hook. Manages sort key + direction state and provides
 * a memoized sorted copy of the data array.
 *
 * Usage:
 *   const { sortState, toggleSort, sortedData } = useTableSort(data, {
 *     time: (a, b) => a.timestamp.localeCompare(b.timestamp),
 *     score: (a, b) => a.score - b.score,
 *   });
 *
 * Clicking the same column cycles: asc -> desc -> none (reset).
 * Clicking a different column starts with desc (most useful default for
 * numeric/time data) — override via `defaultDirection`.
 */
export function useTableSort<T, K extends string = string>(
  data: T[],
  comparators: Partial<Record<K, (a: T, b: T) => number>>,
  options?: { defaultDirection?: SortDirection },
) {
  const defaultDir = options?.defaultDirection ?? "desc";
  const [sortState, setSortState] = useState<SortState<K>>({
    key: null,
    direction: null,
  });

  const toggleSort = useCallback(
    (key: K) => {
      setSortState((prev) => {
        if (prev.key !== key) {
          return { key, direction: defaultDir };
        }
        // cycle: defaultDir -> opposite -> null
        if (prev.direction === defaultDir) {
          return { key, direction: defaultDir === "desc" ? "asc" : "desc" };
        }
        return { key: null, direction: null };
      });
    },
    [defaultDir],
  );

  const sortedData = useMemo(() => {
    if (!sortState.key || !sortState.direction) return data;
    const cmp = comparators[sortState.key];
    if (!cmp) return data;
    const dir = sortState.direction === "asc" ? 1 : -1;
    return [...data].sort((a, b) => cmp(a, b) * dir);
  }, [data, sortState, comparators]);

  const resetSort = useCallback(() => {
    setSortState({ key: null, direction: null });
  }, []);

  return { sortState, toggleSort, sortedData, resetSort } as const;
}

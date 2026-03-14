import { useRef, useCallback } from "react";

/**
 * Hook that prevents stale responses from updating state when rapid
 * requests fire concurrently. Uses a generation counter — each new
 * request increments the counter, and responses check if their
 * generation is still current before applying state updates.
 *
 * Usage:
 *   const guard = useStaleSafeRequest();
 *   const load = useCallback(async () => {
 *     const gen = guard.next();
 *     setLoading(true);
 *     try {
 *       const data = await fetchSomething();
 *       if (!guard.isCurrent(gen)) return;
 *       setData(data);
 *     } catch (err) {
 *       if (!guard.isCurrent(gen)) return;
 *       setError(err);
 *     } finally {
 *       if (!guard.isCurrent(gen)) return;
 *       setLoading(false);
 *     }
 *   }, []);
 */
export function useStaleSafeRequest() {
  const genRef = useRef(0);

  const next = useCallback(() => ++genRef.current, []);
  const isCurrent = useCallback((gen: number) => gen === genRef.current, []);

  return { next, isCurrent };
}

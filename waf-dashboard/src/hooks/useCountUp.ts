import { useState, useEffect, useRef } from "react";

// ─── Count-up animation hook ────────────────────────────────────────

export function useCountUp(target: number, duration = 800): number {
  const [current, setCurrent] = useState(0);
  const rafRef = useRef<number>(0);
  const prevTargetRef = useRef(0);

  useEffect(() => {
    const startVal = prevTargetRef.current;
    if (target === startVal) {
      setCurrent(target);
      return;
    }
    const startTime = performance.now();

    const animate = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setCurrent(Math.round(startVal + (target - startVal) * eased));
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(animate);
      }
    };

    rafRef.current = requestAnimationFrame(animate);
    return () => {
      cancelAnimationFrame(rafRef.current);
      prevTargetRef.current = target;
    };
  }, [target, duration]);

  return current;
}

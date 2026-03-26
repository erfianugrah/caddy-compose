import { useState, useEffect } from "react";
import {
  type RuleCategory,
  getCRSCategories,
  refreshCRSCategories,
} from "@/lib/api";

// ─── useCRSCategories ───────────────────────────────────────────────
//
// Hook that returns live CRS categories from the API. On first mount
// (across all component instances), triggers a single fetch from
// /api/crs/rules. Returns the compile-time fallback synchronously,
// then re-renders with API data once loaded. Subsequent mounts reuse
// the cached result without another fetch.

let _refreshPromise: Promise<void> | null = null;

export function useCRSCategories(): RuleCategory[] {
  const [categories, setCategories] = useState<RuleCategory[]>(getCRSCategories);

  useEffect(() => {
    if (!_refreshPromise) {
      _refreshPromise = refreshCRSCategories().catch(() => {
        // Reset so the next mount retries instead of permanently using the
        // failed promise. The fallback categories remain active until success.
        _refreshPromise = null;
      });
    }
    _refreshPromise?.then(() => {
      setCategories(getCRSCategories());
    });
  }, []);

  return categories;
}

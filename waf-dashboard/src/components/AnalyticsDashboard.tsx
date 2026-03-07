import { useState, useEffect } from "react";
import { T } from "@/lib/typography";
import { IPLookupPanel } from "./analytics/IPLookupPanel";

// Re-export subcomponents for external consumers
export { CountryLabel } from "./analytics/CountryLabel";
export { TopBlockedIPsPanel } from "./analytics/TopBlockedIPsPanel";
export { TopTargetedURIsPanel } from "./analytics/TopTargetedURIsPanel";
export { TopCountriesPanel } from "./analytics/TopCountriesPanel";

// ─── IP Lookup Page ─────────────────────────────────────────────────

export default function AnalyticsDashboard() {
  const [initialIP, setInitialIP] = useState<string | undefined>();

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const qParam = params.get("q");

    if (qParam) {
      setInitialIP(qParam);
      history.replaceState(null, "", window.location.pathname);
    }
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className={T.pageTitle}>IP Lookup</h2>
        <p className={T.pageDescription}>
          Look up any IP address to see its WAF event history, timeline, and service breakdown.
        </p>
      </div>

      <IPLookupPanel initialIP={initialIP} />
    </div>
  );
}

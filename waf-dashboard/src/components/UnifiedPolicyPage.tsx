import { useState, useEffect } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Shield, Gauge, Download, Upload } from "lucide-react";
import { exportExclusions, importExclusions, type Exclusion } from "@/lib/api";
import { downloadJSON } from "@/lib/download";
import PolicyEngine from "./PolicyEngine";
import RateLimitsPanel from "./RateLimitsPanel";

type PolicyTab = "rules" | "rate-limits";

export default function UnifiedPolicyPage() {
  const [activeTab, setActiveTab] = useState<PolicyTab>("rules");

  // Read ?tab= from URL on mount (Astro MPA — must use useEffect, not useState initializer).
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const tab = params.get("tab");
    if (tab === "rate-limits") {
      setActiveTab("rate-limits");
    }
    // Also handle legacy /policy?from_event=1 — always show rules tab.
    if (params.get("from_event")) {
      setActiveTab("rules");
    }
  }, []);

  // Update URL when tab changes (without full navigation).
  const handleTabChange = (value: string) => {
    const tab = value as PolicyTab;
    setActiveTab(tab);
    const url = new URL(window.location.href);
    if (tab === "rules") {
      url.searchParams.delete("tab");
    } else {
      url.searchParams.set("tab", tab);
    }
    history.replaceState(null, "", url.toString());
  };

  const handleExport = async () => {
    try {
      const data = await exportExclusions();
      downloadJSON(data, "waf-exclusions.json");
    } catch {
      // PolicyEngine shows its own errors; this is a convenience shortcut
    }
  };

  const handleImport = () => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json";
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const parsed = JSON.parse(text);
        const exclusions = Array.isArray(parsed) ? parsed : parsed.exclusions;
        if (!Array.isArray(exclusions)) return;
        await importExclusions(exclusions as Exclusion[]);
        window.location.reload();
      } catch {
        // ignore — PolicyEngine handles import errors in its own flow
      }
    };
    input.click();
  };

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Policy Engine</h1>
        <p className="text-sm text-muted-foreground">
          WAF rules, rate limits, and policy management.
        </p>
      </div>

      <Tabs value={activeTab} onValueChange={handleTabChange}>
        <div className="flex items-center justify-between">
          <TabsList>
            <TabsTrigger value="rules" className="gap-1.5">
              <Shield className="h-3.5 w-3.5" />
              WAF Rules
            </TabsTrigger>
            <TabsTrigger value="rate-limits" className="gap-1.5">
              <Gauge className="h-3.5 w-3.5" />
              Rate Limits
            </TabsTrigger>
          </TabsList>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleExport}>
              <Download className="h-3.5 w-3.5" />
              Export
            </Button>
            <Button variant="outline" size="sm" onClick={handleImport}>
              <Upload className="h-3.5 w-3.5" />
              Import
            </Button>
          </div>
        </div>

        {/* key={activeTab} forces remount on tab switch, ensuring fresh data
            after deleting rules in the other tab (no stale cache). */}
        <TabsContent value="rules" className="mt-4">
          <PolicyEngine key={`rules-${activeTab}`} />
        </TabsContent>

        <TabsContent value="rate-limits" className="mt-4">
          <RateLimitsPanel key={`rl-${activeTab}`} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

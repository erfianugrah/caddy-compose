import { useState, useEffect } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Shield, Gauge } from "lucide-react";
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

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Policy Engine</h1>
        <p className="text-sm text-muted-foreground">
          WAF rules, rate limits, and policy management.
        </p>
      </div>

      <Tabs value={activeTab} onValueChange={handleTabChange}>
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

        <TabsContent value="rules" className="mt-4">
          <PolicyEngine />
        </TabsContent>

        <TabsContent value="rate-limits" className="mt-4">
          <RateLimitsPanel />
        </TabsContent>
      </Tabs>
    </div>
  );
}

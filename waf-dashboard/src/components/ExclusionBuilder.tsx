import { useState, useEffect, useMemo } from "react";
import { Copy, Check, Shield, FileCode, Plus, Trash2 } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { fetchServices, type ServiceDetail } from "@/lib/api";

interface Exclusion {
  id: string;
  service: string;
  uri: string;
  ruleId: string;
  description: string;
}

function generateSecRule(exclusion: Exclusion): string {
  const { service, uri, ruleId } = exclusion;

  // Generate a SecRule exclusion for pre-crs.conf
  if (uri && ruleId) {
    return `# Exclusion: ${exclusion.description || `${service} - ${uri}`}
SecRule REQUEST_URI "@streq ${uri}" \\
    "id:${Date.now() % 100000 + 10000},\\
    phase:1,\\
    pass,\\
    t:none,\\
    nolog,\\
    ctl:ruleRemoveById=${ruleId},\\
    chain"
    SecRule &REQUEST_HEADERS:Host "@gt 0" \\
        "t:none"`;
  }

  if (ruleId && !uri) {
    return `# Exclusion: Disable rule ${ruleId} for ${service}
SecRuleRemoveById ${ruleId}`;
  }

  if (uri && !ruleId) {
    return `# Exclusion: Skip all CRS rules for ${uri} on ${service}
SecRule REQUEST_URI "@streq ${uri}" \\
    "id:${Date.now() % 100000 + 10000},\\
    phase:1,\\
    pass,\\
    t:none,\\
    nolog,\\
    ctl:ruleEngine=Off"`;
  }

  return `# No specific exclusion configured for ${service}`;
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback for non-secure contexts
      const textarea = document.createElement("textarea");
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <Button variant="ghost" size="sm" onClick={handleCopy}>
      {copied ? (
        <Check className="h-3.5 w-3.5 text-neon-green" />
      ) : (
        <Copy className="h-3.5 w-3.5" />
      )}
      <span className="text-xs">{copied ? "Copied" : "Copy"}</span>
    </Button>
  );
}

export default function ExclusionBuilder() {
  const [services, setServices] = useState<ServiceDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Builder state
  const [selectedService, setSelectedService] = useState<string>("");
  const [exclusions, setExclusions] = useState<Exclusion[]>([]);
  const [selectedUri, setSelectedUri] = useState<string>("");
  const [selectedRule, setSelectedRule] = useState<string>("");

  useEffect(() => {
    fetchServices()
      .then((data) => {
        setServices(data);
        if (data.length > 0) {
          setSelectedService(data[0].service);
        }
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  const activeService = useMemo(
    () => services.find((s) => s.service === selectedService),
    [services, selectedService]
  );

  const addExclusion = () => {
    if (!selectedService) return;

    const newExclusion: Exclusion = {
      id: crypto.randomUUID?.() ?? String(Date.now()),
      service: selectedService,
      uri: selectedUri,
      ruleId: selectedRule,
      description: `${selectedService}${selectedUri ? ` ${selectedUri}` : ""}${selectedRule ? ` rule:${selectedRule}` : ""}`,
    };

    setExclusions((prev) => [...prev, newExclusion]);
    setSelectedUri("");
    setSelectedRule("");
  };

  const removeExclusion = (id: string) => {
    setExclusions((prev) => prev.filter((e) => e.id !== id));
  };

  const fullConfig = useMemo(() => {
    if (exclusions.length === 0) return "";
    return (
      `# WAF Exclusions - Generated ${new Date().toISOString()}\n` +
      `# Place in pre-crs.conf or equivalent\n\n` +
      exclusions.map(generateSecRule).join("\n\n")
    );
  }, [exclusions]);

  if (error) {
    return (
      <Card className="max-w-md">
        <CardHeader>
          <CardTitle className="text-neon-pink">Error</CardTitle>
          <CardDescription>{error}</CardDescription>
        </CardHeader>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">Exclusion Builder</h2>
        <p className="text-sm text-muted-foreground">
          Build ModSecurity/CRS exclusion rules based on observed WAF events.
          Generated rules go in your pre-crs.conf file.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Left panel: Builder */}
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <Shield className="h-4 w-4 text-neon-green" />
                Build Exclusion
              </CardTitle>
              <CardDescription>
                Select a service and pick URIs/rules to exclude
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Service selector */}
              <div className="space-y-2">
                <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  Service
                </label>
                {loading ? (
                  <Skeleton className="h-9 w-full" />
                ) : (
                  <Select
                    value={selectedService}
                    onValueChange={setSelectedService}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select a service" />
                    </SelectTrigger>
                    <SelectContent>
                      {services.map((s) => (
                        <SelectItem key={s.service} value={s.service}>
                          {s.service}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              </div>

              {/* Top triggered URIs for selected service */}
              {activeService && (
                <>
                  <div className="space-y-2">
                    <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      URI Pattern (optional)
                    </label>
                    <Select value={selectedUri} onValueChange={setSelectedUri}>
                      <SelectTrigger>
                        <SelectValue placeholder="Select a URI or leave empty" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="">Any URI</SelectItem>
                        {(activeService.top_uris ?? []).map((u) => (
                          <SelectItem key={u.uri} value={u.uri}>
                            {u.uri} ({u.count} hits)
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      Rule ID (optional)
                    </label>
                    <Select
                      value={selectedRule}
                      onValueChange={setSelectedRule}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select a rule or leave empty" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="">All Rules</SelectItem>
                        {(activeService.top_rules ?? []).map((r) => (
                          <SelectItem key={r.rule_id} value={r.rule_id}>
                            {r.rule_id} - {r.rule_msg} ({r.count})
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </>
              )}

              <Button onClick={addExclusion} disabled={!selectedService}>
                <Plus className="h-4 w-4" />
                Add Exclusion
              </Button>
            </CardContent>
          </Card>

          {/* Exclusion list */}
          {exclusions.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">
                  Exclusions ({exclusions.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {exclusions.map((exc) => (
                  <div
                    key={exc.id}
                    className="flex items-center justify-between rounded-md border border-border bg-navy-950 px-3 py-2"
                  >
                    <div className="flex items-center gap-2 text-xs">
                      <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                        {exc.service}
                      </Badge>
                      {exc.uri && (
                        <code className="text-neon-cyan">{exc.uri}</code>
                      )}
                      {exc.ruleId && (
                        <Badge
                          variant="secondary"
                          className="text-[10px] px-1.5 py-0 font-mono"
                        >
                          {exc.ruleId}
                        </Badge>
                      )}
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 text-muted-foreground hover:text-neon-pink"
                      onClick={() => removeExclusion(exc.id)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}
        </div>

        {/* Right panel: Generated config */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileCode className="h-4 w-4 text-neon-cyan" />
                <CardTitle className="text-sm">Generated Config</CardTitle>
              </div>
              {fullConfig && <CopyButton text={fullConfig} />}
            </div>
            <CardDescription>
              SecRule exclusions for pre-crs.conf
            </CardDescription>
          </CardHeader>
          <Separator />
          <CardContent className="p-0">
            {exclusions.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-center">
                <Shield className="mb-3 h-8 w-8 text-muted-foreground/50" />
                <p className="text-sm text-muted-foreground">
                  No exclusions added yet.
                </p>
                <p className="text-xs text-muted-foreground/70">
                  Use the builder on the left to create exclusion rules.
                </p>
              </div>
            ) : (
              <div className="relative">
                <pre className="overflow-auto p-4 text-xs leading-relaxed">
                  <code className="text-neon-green/90">{fullConfig}</code>
                </pre>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

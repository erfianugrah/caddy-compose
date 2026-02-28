import { useState, useEffect, useCallback, useRef } from "react";
import {
  Shield,
  ShieldOff,
  Save,
  Rocket,
  Loader2,
  AlertTriangle,
  Check,
  Info,
  Plus,
  Trash2,
  Eye,
  ChevronDown,
  ChevronRight,
  Globe,
  Copy,
  Download,
  Upload,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Textarea } from "@/components/ui/textarea";
import { T } from "@/lib/typography";
import {
  getCSPConfig,
  updateCSPConfig,
  deployCSP,
  previewCSP,
  fetchServices,
  type CSPConfig,
  type CSPPolicy,
  type CSPServiceConfig,
  type CSPPreviewResponse,
  type ServiceDetail,
} from "@/lib/api";

// ─── Constants ──────────────────────────────────────────────────────

/** CSP source values with descriptions from CSP Level 3 spec (W3C) + MDN */
interface CSPSourceDef {
  value: string;
  desc: string;
  category: "keyword" | "scheme" | "special";
}

const CSP_SOURCES: CSPSourceDef[] = [
  // Keywords (single-quoted in CSP headers)
  { value: "'self'", desc: "Same origin only — matches the document's scheme, host, and port", category: "keyword" },
  { value: "'none'", desc: "Blocks all sources for this directive — no resources allowed", category: "keyword" },
  { value: "'unsafe-inline'", desc: "Allows inline <script>, <style>, event handlers, and javascript: URLs", category: "keyword" },
  { value: "'unsafe-eval'", desc: "Allows eval(), Function(), setTimeout(string), and similar dynamic code execution", category: "keyword" },
  { value: "'strict-dynamic'", desc: "Trust propagates to scripts loaded by already-trusted scripts (nonce/hash). Ignores host/scheme allowlists", category: "keyword" },
  { value: "'wasm-unsafe-eval'", desc: "Allows WebAssembly compilation (compileStreaming, compile, instantiate) without enabling JS eval()", category: "keyword" },
  { value: "'unsafe-hashes'", desc: "Allows hash-matched inline event handlers (onclick, etc.) and style attributes", category: "keyword" },
  { value: "'report-sample'", desc: "Includes the first 40 characters of the blocked resource in CSP violation reports", category: "keyword" },
  { value: "'inline-speculation-rules'", desc: "Allows inline <script type=\"speculationrules\"> for navigation prefetch/prerender", category: "keyword" },

  // Schemes (unquoted, with trailing colon)
  { value: "https:", desc: "Any URL using the HTTPS scheme", category: "scheme" },
  { value: "http:", desc: "Any URL using the HTTP scheme (insecure)", category: "scheme" },
  { value: "data:", desc: "Resources loaded via data: URIs (e.g., base64-encoded images)", category: "scheme" },
  { value: "blob:", desc: "Resources loaded via blob: URIs (e.g., Blob/File API objects)", category: "scheme" },
  { value: "mediastream:", desc: "Resources loaded via mediastream: URIs (e.g., getUserMedia)", category: "scheme" },
  { value: "filesystem:", desc: "Resources loaded via filesystem: URIs (File System API)", category: "scheme" },
  { value: "wss:", desc: "WebSocket connections over TLS (secure WebSocket)", category: "scheme" },
  { value: "ws:", desc: "WebSocket connections (insecure)", category: "scheme" },

  // Special / wildcard
  { value: "*", desc: "Allows any URL except data:, blob:, and filesystem: schemes", category: "special" },
];

const SOURCE_CATEGORY_LABELS: Record<CSPSourceDef["category"], string> = {
  keyword: "Keywords",
  scheme: "Schemes",
  special: "Wildcard",
};

/** CSP directive metadata: field key, display name, description, MDN-based tooltip */
const CSP_DIRECTIVES = [
  {
    key: "default_src", label: "default-src",
    desc: "Fallback for other fetch directives",
    tip: "Serves as the fallback for all other fetch directives. If a specific directive (e.g., script-src) is not set, the browser uses default-src instead.",
  },
  {
    key: "script_src", label: "script-src",
    desc: "JavaScript + WASM sources",
    tip: "Controls valid sources for JavaScript and WebAssembly. Falls back to default-src. Also serves as fallback for script-src-elem and script-src-attr.",
  },
  {
    key: "style_src", label: "style-src",
    desc: "Stylesheet sources",
    tip: "Controls valid sources for CSS stylesheets. Falls back to default-src. Also serves as fallback for style-src-elem and style-src-attr.",
  },
  {
    key: "img_src", label: "img-src",
    desc: "Image + favicon sources",
    tip: "Specifies valid sources for images and favicons. Falls back to default-src.",
  },
  {
    key: "font_src", label: "font-src",
    desc: "Font sources (@font-face)",
    tip: "Specifies valid sources for fonts loaded using @font-face. Falls back to default-src.",
  },
  {
    key: "connect_src", label: "connect-src",
    desc: "Fetch / XHR / WebSocket / EventSource",
    tip: "Restricts URLs for fetch(), XMLHttpRequest, WebSocket, EventSource, and sendBeacon(). Falls back to default-src.",
  },
  {
    key: "media_src", label: "media-src",
    desc: "Audio / video / track sources",
    tip: "Specifies valid sources for <audio>, <video>, and <track> elements. Falls back to default-src.",
  },
  {
    key: "frame_src", label: "frame-src",
    desc: "Iframe / frame sources",
    tip: "Specifies valid sources for nested browsing contexts (<iframe>, <frame>). Falls back to child-src, then default-src.",
  },
  {
    key: "worker_src", label: "worker-src",
    desc: "Worker / SharedWorker / ServiceWorker",
    tip: "Specifies valid sources for Worker, SharedWorker, and ServiceWorker scripts. Falls back to child-src, then script-src, then default-src.",
  },
  {
    key: "object_src", label: "object-src",
    desc: "Plugin / embed sources",
    tip: "Specifies valid sources for <object> and <embed> elements. Falls back to default-src. Recommended: set to 'none' to block plugins.",
  },
  {
    key: "child_src", label: "child-src",
    desc: "Worker + frame fallback",
    tip: "Defines valid sources for web workers and nested browsing contexts. Serves as fallback for frame-src and worker-src. Falls back to default-src.",
  },
  {
    key: "manifest_src", label: "manifest-src",
    desc: "Web app manifest sources",
    tip: "Specifies valid sources for application manifest files (PWA manifests). Falls back to default-src.",
  },
  {
    key: "base_uri", label: "base-uri",
    desc: "Restricts <base> element URLs",
    tip: "Restricts the URLs that can be used in a document's <base> element. Does NOT fall back to default-src.",
  },
  {
    key: "form_action", label: "form-action",
    desc: "Form submission targets",
    tip: "Restricts the URLs that can be used as the target of form submissions. Does NOT fall back to default-src.",
  },
  {
    key: "frame_ancestors", label: "frame-ancestors",
    desc: "Who can embed this page",
    tip: "Specifies valid parents that may embed this page using <frame>, <iframe>, <object>, or <embed>. Setting to 'none' is similar to X-Frame-Options: DENY. Does NOT fall back to default-src.",
  },
] as const;

type DirectiveKey = (typeof CSP_DIRECTIVES)[number]["key"];

// ─── CSP Source Tag Input ───────────────────────────────────────────

/**
 * Tag/pill input with a dropdown of CSP source keywords + free text entry.
 * Similar to PipeTagInput but with a keyword popover.
 */
function CSPSourceInput({
  values,
  onChange,
  placeholder,
}: {
  values: string[];
  onChange: (values: string[]) => void;
  placeholder?: string;
}) {
  const [inputValue, setInputValue] = useState("");
  const [showDropdown, setShowDropdown] = useState(false);
  const wrapperRef = useRef<HTMLDivElement>(null);

  const addValue = (raw: string) => {
    const cleaned = raw.trim();
    if (!cleaned || values.includes(cleaned)) {
      setInputValue("");
      return;
    }
    onChange([...values, cleaned]);
    setInputValue("");
  };

  const removeValue = (val: string) => {
    onChange(values.filter((v) => v !== val));
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      addValue(inputValue);
    } else if (e.key === "Backspace" && inputValue === "" && values.length > 0) {
      removeValue(values[values.length - 1]);
    } else if (e.key === "Escape") {
      setShowDropdown(false);
    }
  };

  const handlePaste = (e: React.ClipboardEvent) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData("text");
    const newVals = pasted.split(/[\s,]+/).filter(Boolean);
    const unique = [...new Set([...values, ...newVals])];
    onChange(unique);
  };

  // Close dropdown on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (wrapperRef.current && !wrapperRef.current.contains(e.target as Node)) {
        setShowDropdown(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const unusedSources = CSP_SOURCES.filter((s) => !values.includes(s.value));
  const filtered = inputValue
    ? unusedSources.filter((s) =>
        s.value.toLowerCase().includes(inputValue.toLowerCase()) ||
        s.desc.toLowerCase().includes(inputValue.toLowerCase()))
    : unusedSources;

  // Group filtered sources by category
  const grouped = (["keyword", "scheme", "special"] as const)
    .map((cat) => ({ cat, items: filtered.filter((s) => s.category === cat) }))
    .filter((g) => g.items.length > 0);

  return (
    <div ref={wrapperRef} className="relative">
      <div className="flex flex-wrap items-center gap-1.5 rounded-md border border-input bg-background px-2 py-1.5 text-sm focus-within:ring-1 focus-within:ring-ring min-h-[36px]">
        {values.map((val) => {
          const def = CSP_SOURCES.find((s) => s.value === val);
          const pill = (
            <span
              key={val}
              className="inline-flex items-center gap-1 rounded bg-navy-800 border border-border px-2 py-0.5 text-xs font-mono text-neon-cyan"
            >
              {val}
              <button
                type="button"
                onClick={() => removeValue(val)}
                className="ml-0.5 rounded-full p-0.5 hover:bg-accent hover:text-neon-pink"
              >
                <span className="sr-only">Remove</span>
                <svg className="h-2.5 w-2.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </span>
          );
          return def ? (
            <Tooltip key={val}>
              <TooltipTrigger asChild>{pill}</TooltipTrigger>
              <TooltipContent side="top" className="max-w-xs text-xs">{def.desc}</TooltipContent>
            </Tooltip>
          ) : pill;
        })}
        <input
          type="text"
          value={inputValue}
          onChange={(e) => {
            setInputValue(e.target.value);
            setShowDropdown(true);
          }}
          onFocus={() => setShowDropdown(true)}
          onKeyDown={handleKeyDown}
          onPaste={handlePaste}
          onBlur={() => {
            // Delay to allow dropdown click
            setTimeout(() => {
              if (inputValue.trim()) addValue(inputValue);
              setShowDropdown(false);
            }, 200);
          }}
          placeholder={values.length === 0 ? (placeholder ?? "Add source...") : ""}
          className="flex-1 min-w-[100px] bg-transparent text-xs font-mono outline-none placeholder:text-muted-foreground"
        />
      </div>
      {showDropdown && grouped.length > 0 && (
        <div className="absolute z-50 mt-1 max-h-64 w-full overflow-auto rounded-md border border-border bg-navy-950 shadow-lg">
          {grouped.map(({ cat, items }) => (
            <div key={cat}>
              <div className="px-3 py-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground bg-navy-900/50 sticky top-0">
                {SOURCE_CATEGORY_LABELS[cat]}
              </div>
              {items.map((src) => (
                <button
                  key={src.value}
                  type="button"
                  onMouseDown={(e) => {
                    e.preventDefault();
                    addValue(src.value);
                    setShowDropdown(false);
                  }}
                  className="flex w-full items-start gap-3 px-3 py-1.5 text-xs hover:bg-accent cursor-pointer"
                >
                  <span className="font-mono text-foreground shrink-0">{src.value}</span>
                  <span className="text-muted-foreground text-[10px] leading-tight">{src.desc}</span>
                </button>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Directive Editor ───────────────────────────────────────────────

function DirectiveEditor({
  policy,
  onChange,
  compact,
}: {
  policy: CSPPolicy;
  onChange: (policy: CSPPolicy) => void;
  compact?: boolean;
}) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const getValues = (key: DirectiveKey): string[] => {
    return (policy[key] as string[] | undefined) ?? [];
  };

  const setValues = (key: DirectiveKey, values: string[]) => {
    onChange({ ...policy, [key]: values.length > 0 ? values : undefined });
  };

  const toggleExpand = (key: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  // Show all directives that have values, plus allow expanding empty ones
  const activeDirectives = CSP_DIRECTIVES.filter((d) => (getValues(d.key).length > 0));
  const inactiveDirectives = CSP_DIRECTIVES.filter((d) => (getValues(d.key).length === 0));

  return (
    <div className="space-y-3">
      {/* Active directives (have values) */}
      {activeDirectives.map((d) => (
        <div key={d.key} className="space-y-1">
          <div className="flex items-center justify-between">
            <Tooltip>
              <TooltipTrigger asChild>
                <Label className={`${T.formLabel} cursor-help border-b border-dotted border-muted-foreground/40`}>{d.label}</Label>
              </TooltipTrigger>
              <TooltipContent side="top" className="max-w-sm text-xs">{d.tip}</TooltipContent>
            </Tooltip>
            {!compact && (
              <span className={T.muted}>{d.desc}</span>
            )}
          </div>
          <CSPSourceInput
            values={getValues(d.key)}
            onChange={(v) => setValues(d.key, v)}
            placeholder={`Add ${d.label} sources...`}
          />
        </div>
      ))}

      {/* Collapsed inactive directives */}
      {inactiveDirectives.length > 0 && (
        <div className="space-y-2">
          <button
            type="button"
            onClick={() => {
              if (expanded.has("_inactive")) {
                setExpanded((prev) => { const n = new Set(prev); n.delete("_inactive"); return n; });
              } else {
                setExpanded((prev) => new Set(prev).add("_inactive"));
              }
            }}
            className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
          >
            {expanded.has("_inactive") ? (
              <ChevronDown className="h-3 w-3" />
            ) : (
              <ChevronRight className="h-3 w-3" />
            )}
            {inactiveDirectives.length} more directive{inactiveDirectives.length !== 1 ? "s" : ""}
          </button>
          {expanded.has("_inactive") && (
            <div className="space-y-3 pl-4 border-l border-border">
              {inactiveDirectives.map((d) => (
                <div key={d.key} className="space-y-1">
                  <div className="flex items-center justify-between">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Label className={`${T.formLabel} cursor-help border-b border-dotted border-muted-foreground/40`}>{d.label}</Label>
                      </TooltipTrigger>
                      <TooltipContent side="top" className="max-w-sm text-xs">{d.tip}</TooltipContent>
                    </Tooltip>
                    {!compact && (
                      <span className={T.muted}>{d.desc}</span>
                    )}
                  </div>
                  <CSPSourceInput
                    values={getValues(d.key)}
                    onChange={(v) => setValues(d.key, v)}
                    placeholder={`Add ${d.label} sources...`}
                  />
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Boolean directives + raw escape hatch */}
      <Separator />
      <div className="flex items-center justify-between">
        <div>
          <Label className={T.formLabel}>upgrade-insecure-requests</Label>
          {!compact && (
            <p className={T.muted}>Upgrade HTTP to HTTPS for sub-resources</p>
          )}
        </div>
        <Switch
          checked={policy.upgrade_insecure_requests ?? false}
          onCheckedChange={(checked) => onChange({ ...policy, upgrade_insecure_requests: checked })}
        />
      </div>

      <div className="space-y-1">
        <Label className={T.formLabel}>Raw Directives</Label>
        {!compact && (
          <p className={T.muted}>Appended verbatim (for exotic directives not listed above)</p>
        )}
        <Textarea
          value={policy.raw_directives ?? ""}
          onChange={(e) => onChange({ ...policy, raw_directives: e.target.value || undefined })}
          placeholder="e.g. report-uri /csp-report"
          className="text-xs font-mono h-16"
        />
      </div>
    </div>
  );
}

// ─── Service Config Card ────────────────────────────────────────────

function ServiceCard({
  name,
  config,
  onChange,
  onRemove,
  previewHeader,
}: {
  name: string;
  config: CSPServiceConfig;
  onChange: (cfg: CSPServiceConfig) => void;
  onRemove: () => void;
  previewHeader?: string;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 cursor-pointer" onClick={() => setExpanded(!expanded)}>
            {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            <CardTitle className={T.cardTitle}>{name}</CardTitle>
            <Badge variant="outline" className="text-[10px]">{config.mode}</Badge>
            {config.report_only && <Badge variant="outline" className="text-[10px] text-amber-400">report-only</Badge>}
            {config.inherit && <Badge variant="outline" className="text-[10px] text-neon-cyan">inherit</Badge>}
          </div>
          <div className="flex items-center gap-1">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="sm" onClick={onRemove}>
                  <Trash2 className="h-3.5 w-3.5 text-muted-foreground hover:text-neon-pink" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Remove service override</TooltipContent>
            </Tooltip>
          </div>
        </div>
        {/* Inline preview */}
        {previewHeader && config.mode !== "none" && (
          <p className="mt-1 text-[10px] font-mono text-muted-foreground truncate max-w-full" title={previewHeader}>
            {previewHeader}
          </p>
        )}
      </CardHeader>
      {expanded && (
        <CardContent className="space-y-4 pt-0">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="space-y-1">
              <Label className={T.formLabel}>Mode</Label>
              <Select value={config.mode} onValueChange={(v) => onChange({ ...config, mode: v as CSPServiceConfig["mode"] })}>
                <SelectTrigger className="h-8 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="set">set (overwrite upstream)</SelectItem>
                  <SelectItem value="default">default (only if missing)</SelectItem>
                  <SelectItem value="none">none (no CSP)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center gap-2">
              <Switch
                id={`ro-${name}`}
                checked={config.report_only}
                onCheckedChange={(checked) => onChange({ ...config, report_only: checked })}
              />
              <Label htmlFor={`ro-${name}`} className="text-xs">Report-Only</Label>
            </div>
            <div className="flex items-center gap-2">
              <Switch
                id={`inh-${name}`}
                checked={config.inherit}
                onCheckedChange={(checked) => onChange({ ...config, inherit: checked })}
              />
              <Label htmlFor={`inh-${name}`} className="text-xs">Inherit Global</Label>
            </div>
          </div>

          {config.mode !== "none" && (
            <>
              <Separator />
              <DirectiveEditor
                policy={config.policy}
                onChange={(policy) => onChange({ ...config, policy })}
                compact
              />
            </>
          )}
        </CardContent>
      )}
    </Card>
  );
}

// ─── Preview Panel ──────────────────────────────────────────────────

const PREVIEW_PAGE_SIZE = 10;

/** Split a raw CSP header string into colored directive segments */
function CSPHeaderFormatted({ header }: { header: string }) {
  const parts = header.split(";").map((p) => p.trim()).filter(Boolean);
  return (
    <span className="text-[10px] font-mono leading-relaxed">
      {parts.map((part, i) => {
        const spaceIdx = part.indexOf(" ");
        const directive = spaceIdx > 0 ? part.slice(0, spaceIdx) : part;
        const values = spaceIdx > 0 ? part.slice(spaceIdx) : "";
        return (
          <span key={i}>
            {i > 0 && <span className="text-muted-foreground/40">; </span>}
            <span className="text-neon-cyan">{directive}</span>
            <span className="text-muted-foreground">{values}</span>
          </span>
        );
      })}
    </span>
  );
}

function PreviewPanel({ preview }: { preview: CSPPreviewResponse | null }) {
  const [copied, setCopied] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [filter, setFilter] = useState("");
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());

  if (!preview || Object.keys(preview.services).length === 0) {
    return (
      <Card>
        <CardContent className="p-6">
          <p className={T.muted}>No services configured. Add a service override or configure global defaults to see previews.</p>
        </CardContent>
      </Card>
    );
  }

  const copyHeader = (service: string, header: string) => {
    navigator.clipboard.writeText(header).catch(() => {});
    setCopied(service);
    setTimeout(() => setCopied(null), 2000);
  };

  const toggleRow = (service: string) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(service)) next.delete(service);
      else next.add(service);
      return next;
    });
  };

  const allEntries = Object.entries(preview.services)
    .sort(([a], [b]) => a.localeCompare(b));
  const filtered = filter
    ? allEntries.filter(([name]) => name.toLowerCase().includes(filter.toLowerCase()))
    : allEntries;
  const totalPages = Math.ceil(filtered.length / PREVIEW_PAGE_SIZE);
  const paged = filtered.slice(page * PREVIEW_PAGE_SIZE, (page + 1) * PREVIEW_PAGE_SIZE);

  // Reset page if filter changes and page is out of bounds
  if (page >= totalPages && totalPages > 0) setPage(0);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Eye className="h-4 w-4 text-neon-cyan" />
            <CardTitle className={T.cardTitle}>CSP Header Preview</CardTitle>
            <Badge variant="outline" className="text-[10px]">{filtered.length} service{filtered.length !== 1 ? "s" : ""}</Badge>
          </div>
          {allEntries.length > PREVIEW_PAGE_SIZE && (
            <Input
              value={filter}
              onChange={(e) => { setFilter(e.target.value); setPage(0); }}
              placeholder="Filter services..."
              className="h-7 w-48 text-xs"
            />
          )}
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div className="divide-y divide-border">
          {paged.map(([service, entry]) => {
            const isExpanded = expandedRows.has(service);
            return (
              <div key={service} className="group">
                <div className="flex items-center gap-3 px-4 py-2 hover:bg-accent/30 transition-colors">
                  {/* Service name + badges */}
                  <div className="flex items-center gap-2 min-w-[180px] shrink-0">
                    <span className="text-xs font-medium font-mono">{service}</span>
                    <Badge
                      variant="outline"
                      className={`text-[9px] ${entry.mode === "none" ? "text-muted-foreground" : entry.mode === "default" ? "text-amber-400" : "text-neon-green"}`}
                    >
                      {entry.mode}
                    </Badge>
                    {entry.report_only && (
                      <Badge variant="outline" className="text-[9px] text-amber-400">RO</Badge>
                    )}
                  </div>

                  {/* Header preview (truncated) */}
                  <div className="flex-1 min-w-0">
                    {entry.header ? (
                      <button
                        type="button"
                        onClick={() => toggleRow(service)}
                        className={`text-left w-full ${isExpanded ? "" : "truncate"} block`}
                      >
                        <CSPHeaderFormatted header={entry.header} />
                      </button>
                    ) : (
                      <span className="text-[10px] text-muted-foreground/60 italic">
                        {entry.mode === "none" ? "CSP disabled" : "Empty policy"}
                      </span>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-1 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                    {entry.header && (
                      <>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => toggleRow(service)}
                              className="h-6 w-6 p-0"
                            >
                              {isExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>{isExpanded ? "Collapse" : "Expand full header"}</TooltipContent>
                        </Tooltip>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyHeader(service, entry.header)}
                              className="h-6 w-6 p-0"
                            >
                              {copied === service ? (
                                <Check className="h-3 w-3 text-neon-green" />
                              ) : (
                                <Copy className="h-3 w-3" />
                              )}
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>Copy header</TooltipContent>
                        </Tooltip>
                      </>
                    )}
                  </div>
                </div>

                {/* Expanded: full header with directive breakdown */}
                {isExpanded && entry.header && (
                  <div className="px-4 pb-3 bg-navy-950/50">
                    <div className="rounded border border-border p-3 space-y-1">
                      {entry.header.split(";").map((part) => part.trim()).filter(Boolean).map((part, i) => {
                        const spaceIdx = part.indexOf(" ");
                        const directive = spaceIdx > 0 ? part.slice(0, spaceIdx) : part;
                        const values = spaceIdx > 0 ? part.slice(spaceIdx + 1) : "";
                        return (
                          <div key={i} className="flex items-baseline gap-2 text-[11px] font-mono">
                            <span className="text-neon-cyan font-semibold shrink-0 min-w-[140px]">{directive}</span>
                            <span className="text-muted-foreground break-all">{values}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-2 border-t border-border">
            <span className="text-[10px] text-muted-foreground">
              {page * PREVIEW_PAGE_SIZE + 1}–{Math.min((page + 1) * PREVIEW_PAGE_SIZE, filtered.length)} of {filtered.length}
            </span>
            <div className="flex items-center gap-1">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setPage(Math.max(0, page - 1))}
                disabled={page === 0}
                className="h-6 px-2 text-xs"
              >
                Prev
              </Button>
              {Array.from({ length: totalPages }, (_, i) => (
                <Button
                  key={i}
                  variant={i === page ? "default" : "ghost"}
                  size="sm"
                  onClick={() => setPage(i)}
                  className="h-6 w-6 p-0 text-xs"
                >
                  {i + 1}
                </Button>
              ))}
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
                disabled={page >= totalPages - 1}
                className="h-6 px-2 text-xs"
              >
                Next
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Main CSP Panel ─────────────────────────────────────────────────

export default function CSPPanel() {
  const [config, setConfig] = useState<CSPConfig | null>(null);
  const [services, setServices] = useState<ServiceDetail[]>([]);
  const [preview, setPreview] = useState<CSPPreviewResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [deployStep, setDeployStep] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);

  // Working copies
  const [enabled, setEnabled] = useState(true);
  const [globalDefaults, setGlobalDefaults] = useState<CSPPolicy>({});
  const [serviceConfigs, setServiceConfigs] = useState<Record<string, CSPServiceConfig>>({});

  const loadData = useCallback(() => {
    setLoading(true);
    setError(null);
    Promise.all([getCSPConfig(), fetchServices(), previewCSP()])
      .then(([cfg, svcs, prev]) => {
        setConfig(cfg);
        setEnabled(cfg.enabled !== false);
        setGlobalDefaults(cfg.global_defaults);
        setServiceConfigs(cfg.services);
        setServices(svcs);
        setPreview(prev);
        setDirty(false);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const successTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const showSuccess = (msg: string) => {
    if (successTimerRef.current) clearTimeout(successTimerRef.current);
    setSuccessMsg(msg);
    successTimerRef.current = setTimeout(() => setSuccessMsg(null), 4000);
  };
  useEffect(() => () => { if (successTimerRef.current) clearTimeout(successTimerRef.current); }, []);

  const markDirty = () => setDirty(true);

  const buildConfig = (): CSPConfig => ({
    enabled,
    global_defaults: globalDefaults,
    services: serviceConfigs,
  });

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    try {
      const updated = await updateCSPConfig(buildConfig());
      setConfig(updated);
      setEnabled(updated.enabled !== false);
      setGlobalDefaults(updated.global_defaults);
      setServiceConfigs(updated.services);
      setDirty(false);
      // Refresh preview
      const prev = await previewCSP();
      setPreview(prev);
      showSuccess("CSP config saved");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  const handleDeploy = async () => {
    setError(null);
    try {
      setDeployStep("Saving config...");
      await updateCSPConfig(buildConfig());
      setDeployStep("Generating CSP files & reloading Caddy...");
      const result = await deployCSP();
      setDirty(false);
      // Refresh preview
      const prev = await previewCSP();
      setPreview(prev);
      if (result.reloaded) {
        showSuccess(`CSP deployed (${result.files.length} files) and Caddy reloaded`);
      } else {
        showSuccess(`CSP files written (${result.files.length}) — Caddy reload may be needed`);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Deploy failed");
    } finally {
      setDeployStep(null);
    }
  };

  const handleGlobalChange = (policy: CSPPolicy) => {
    setGlobalDefaults(policy);
    markDirty();
  };

  const handleServiceChange = (name: string, cfg: CSPServiceConfig) => {
    setServiceConfigs((prev) => ({ ...prev, [name]: cfg }));
    markDirty();
  };

  const handleServiceRemove = (name: string) => {
    setServiceConfigs((prev) => {
      const next = { ...prev };
      delete next[name];
      return next;
    });
    markDirty();
  };

  const handleAddService = (name: string) => {
    if (serviceConfigs[name]) return;
    setServiceConfigs((prev) => ({
      ...prev,
      [name]: {
        mode: "set",
        report_only: false,
        inherit: true,
        policy: {},
      },
    }));
    markDirty();
  };

  const handleExport = () => {
    try {
      const data = buildConfig();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "csp-config.json";
      a.click();
      URL.revokeObjectURL(url);
      showSuccess("CSP configuration exported");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Export failed");
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
        const data = JSON.parse(text) as CSPConfig;
        if (data.enabled !== undefined) setEnabled(data.enabled !== false);
        if (data.global_defaults) setGlobalDefaults(data.global_defaults);
        if (data.services) setServiceConfigs(data.services);
        setDirty(true);
        showSuccess("CSP config imported — save or deploy to apply");
      } catch (err: unknown) {
        setError("Failed to parse config: " + (err instanceof Error ? err.message : "unknown error"));
      }
    };
    input.click();
  };

  // All known service hosts
  const allHosts = Array.from(
    new Set([
      ...Object.keys(serviceConfigs),
      ...services.map((s) => s.service),
    ])
  ).sort();
  const unconfiguredHosts = allHosts.filter((h) => !serviceConfigs[h]);

  // ── Loading state ──
  if (loading) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className={T.pageTitle}>Content Security Policy</h2>
          <p className={T.pageDescription}>Per-service CSP header management</p>
        </div>
        <div className="space-y-4">
          {[...Array(3)].map((_, i) => (
            <Card key={i}>
              <CardContent className="p-6">
                <Skeleton className="h-24 w-full" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  return (
    <TooltipProvider delayDuration={200}>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className={T.pageTitle}>Content Security Policy</h2>
            <p className={T.pageDescription}>
              Configure CSP headers per service. Inherit from global defaults or override individually.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant={enabled ? "outline" : "destructive"}
                  size="sm"
                  onClick={() => { setEnabled(!enabled); markDirty(); }}
                >
                  {enabled ? (
                    <><Shield className="h-3.5 w-3.5" /> Enabled</>
                  ) : (
                    <><ShieldOff className="h-3.5 w-3.5" /> Disabled</>
                  )}
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                {enabled
                  ? "CSP is active. Click to disable all CSP headers across all services."
                  : "CSP is disabled. All services will have no CSP headers. Click to re-enable."}
              </TooltipContent>
            </Tooltip>
            <Separator orientation="vertical" className="h-6" />
            <Button variant="outline" size="sm" onClick={handleExport}>
              <Download className="h-3.5 w-3.5" />
              Export
            </Button>
            <Button variant="outline" size="sm" onClick={handleImport}>
              <Upload className="h-3.5 w-3.5" />
              Import
            </Button>
            <Button size="sm" variant="outline" onClick={handleSave} disabled={!dirty || saving}>
              <Save className="h-3.5 w-3.5" />
              {saving ? "Saving..." : "Save"}
            </Button>
            <Button size="sm" onClick={handleDeploy} disabled={deployStep !== null}>
              {deployStep ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Rocket className="h-3.5 w-3.5" />
              )}
              {deployStep ?? "Save & Deploy"}
            </Button>
          </div>
        </div>

        {/* CSP disabled banner */}
        {!enabled && (
          <Alert variant="destructive">
            <ShieldOff className="h-4 w-4" />
            <AlertTitle>CSP Disabled</AlertTitle>
            <AlertDescription>
              All CSP headers are disabled. Deploy to remove CSP headers from all services.
              Your configuration is preserved and will be restored when re-enabled.
            </AlertDescription>
          </Alert>
        )}

        {/* Alerts */}
        {error && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {successMsg && (
          <Alert variant="success">
            <Check className="h-4 w-4" />
            <AlertTitle>Success</AlertTitle>
            <AlertDescription>{successMsg}</AlertDescription>
          </Alert>
        )}
        {dirty && (
          <Alert>
            <Info className="h-4 w-4" />
            <AlertTitle>Unsaved Changes</AlertTitle>
            <AlertDescription>
              Click "Save & Deploy" to write CSP files and reload Caddy.
            </AlertDescription>
          </Alert>
        )}

        {/* Global Defaults */}
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Globe className="h-4 w-4 text-neon-cyan" />
              <CardTitle className={T.cardTitle}>Global Defaults</CardTitle>
            </div>
            <p className={T.muted}>
              Baseline CSP policy inherited by services with "Inherit Global" enabled.
            </p>
          </CardHeader>
          <CardContent>
            <DirectiveEditor
              policy={globalDefaults}
              onChange={handleGlobalChange}
            />
          </CardContent>
        </Card>

        {/* Service Overrides */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className={T.sectionHeading}>Service Overrides</h3>
              <p className={T.muted}>
                Per-service CSP configuration. Services without overrides get no CSP header by default.
              </p>
            </div>
            {unconfiguredHosts.length > 0 && (
              <Select onValueChange={handleAddService}>
                <SelectTrigger className="w-[200px] h-8 text-xs">
                  <Plus className="h-3 w-3 mr-1" />
                  <SelectValue placeholder="Add service..." />
                </SelectTrigger>
                <SelectContent>
                  {unconfiguredHosts.map((host) => (
                    <SelectItem key={host} value={host} className="text-xs">
                      {host}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </div>

          {Object.keys(serviceConfigs).length === 0 && (
            <Card>
              <CardContent className="p-6 text-center">
                <p className={T.muted}>No service overrides configured. Use the dropdown above to add one.</p>
              </CardContent>
            </Card>
          )}

          {Object.entries(serviceConfigs)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([name, cfg]) => (
              <ServiceCard
                key={name}
                name={name}
                config={cfg}
                onChange={(c) => handleServiceChange(name, c)}
                onRemove={() => handleServiceRemove(name)}
                previewHeader={preview?.services[name]?.header}
              />
            ))}
        </div>

        {/* Preview */}
        <PreviewPanel preview={preview} />
      </div>
    </TooltipProvider>
  );
}

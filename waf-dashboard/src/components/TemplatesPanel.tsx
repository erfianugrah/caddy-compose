import { useState, useEffect, useCallback, useRef } from "react";
import {
  BookOpen,
  Rocket,
  Loader2,
  Check,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import { T } from "@/lib/typography";
import {
  listTemplates,
  applyTemplate,
  deployConfig,
  type RuleTemplate,
} from "@/lib/api";

// ─── Category Badge Colors ──────────────────────────────────────────

const CATEGORY_COLORS: Record<string, string> = {
  security: "bg-red-500/10 text-red-400 border-red-500/20",
  cache: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  cors: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
  custom: "bg-purple-500/10 text-purple-400 border-purple-500/20",
};

// ─── Template Card ──────────────────────────────────────────────────

function TemplateCard({
  template,
  onApply,
  applying,
}: {
  template: RuleTemplate;
  onApply: () => void;
  applying: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const colorClass = CATEGORY_COLORS[template.category] || CATEGORY_COLORS.custom;

  return (
    <Card className="flex flex-col">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-2">
          <CardTitle className="text-sm leading-snug">{template.name}</CardTitle>
          <Badge variant="outline" className={`shrink-0 text-[10px] ${colorClass}`}>
            {template.category}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col gap-3">
        <p className={`${T.muted} flex-1`}>{template.description}</p>

        <div className="flex items-center justify-between">
          <span className={T.muted}>
            {template.rules.length} rule{template.rules.length !== 1 ? "s" : ""}
          </span>
          <div className="flex items-center gap-1.5">
            {template.rules.length > 0 && (
              <Button
                variant="ghost"
                size="sm"
                className="h-7 text-xs text-muted-foreground"
                onClick={() => setExpanded(!expanded)}
              >
                {expanded ? (
                  <ChevronUp className="mr-1 h-3 w-3" />
                ) : (
                  <ChevronDown className="mr-1 h-3 w-3" />
                )}
                Preview
              </Button>
            )}
            <Button size="sm" className="h-7 text-xs" onClick={onApply} disabled={applying}>
              {applying ? (
                <Loader2 className="mr-1 h-3 w-3 animate-spin" />
              ) : (
                <Rocket className="mr-1 h-3 w-3" />
              )}
              Apply
            </Button>
          </div>
        </div>

        {/* Preview rules */}
        {expanded && template.rules.length > 0 && (
          <>
            <Separator />
            <div className="space-y-1.5 max-h-48 overflow-y-auto">
              {template.rules.map((rule, i) => (
                <div
                  key={rule.id || i}
                  className="flex items-center justify-between rounded border px-2.5 py-1.5 text-xs"
                >
                  <span className="font-medium truncate mr-2">{rule.name}</span>
                  <Badge variant="outline" className="shrink-0 text-[10px]">
                    {rule.type}
                  </Badge>
                </div>
              ))}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Component ──────────────────────────────────────────────────────

export default function TemplatesPanel() {
  const [templates, setTemplates] = useState<RuleTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [applyingId, setApplyingId] = useState<string | null>(null);
  const [flash, setFlash] = useState<{ type: "success" | "error"; msg: string } | null>(null);

  const flashTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const showFlash = useCallback((type: "success" | "error", msg: string) => {
    if (flashTimerRef.current) clearTimeout(flashTimerRef.current);
    setFlash({ type, msg });
    flashTimerRef.current = setTimeout(() => setFlash(null), 4000);
  }, []);
  useEffect(() => () => { if (flashTimerRef.current) clearTimeout(flashTimerRef.current); }, []);

  const requestGenRef = useRef(0);

  useEffect(() => {
    const gen = ++requestGenRef.current;
    listTemplates()
      .then((data) => {
        if (gen !== requestGenRef.current) return;
        setTemplates(data);
      })
      .catch((err) => {
        if (gen !== requestGenRef.current) return;
        showFlash("error", err instanceof Error ? err.message : "Failed to load templates");
      })
      .finally(() => {
        if (gen !== requestGenRef.current) return;
        setLoading(false);
      });
  }, [showFlash]);

  const handleApply = async (id: string) => {
    setApplyingId(id);
    try {
      const result = await applyTemplate(id);
      await deployConfig();
      showFlash("success", `Template applied — ${result.created} rule${result.created !== 1 ? "s" : ""} created & deployed`);
    } catch (err: unknown) {
      showFlash("error", err instanceof Error ? err.message : "Failed to apply template");
    } finally {
      setApplyingId(null);
    }
  };

  if (loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-48" />
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-48 w-full" />
          ))}
        </div>
      </div>
    );
  }

  // Group templates by category
  const categories: string[] = [];
  const byCategory = new Map<string, RuleTemplate[]>();
  for (const t of templates) {
    const cat = t.category || "custom";
    if (!byCategory.has(cat)) {
      categories.push(cat);
      byCategory.set(cat, []);
    }
    byCategory.get(cat)!.push(t);
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className={T.pageTitle}>Rule Templates</h2>
        <p className={T.muted}>
          Pre-built rule sets you can apply with one click. {templates.length} template{templates.length !== 1 ? "s" : ""} available.
        </p>
      </div>

      {/* Flash */}
      {flash && (
        <Alert variant={flash.type === "error" ? "destructive" : "default"}>
          {flash.type === "success" ? <Check className="h-4 w-4" /> : null}
          <AlertDescription>{flash.msg}</AlertDescription>
        </Alert>
      )}

      {templates.length === 0 && (
        <Card>
          <CardContent className="py-12 text-center">
            <BookOpen className="mx-auto h-10 w-10 text-muted-foreground/50 mb-3" />
            <p className={T.muted}>No templates available.</p>
          </CardContent>
        </Card>
      )}

      {/* Template grid grouped by category */}
      {categories.map((cat) => (
        <div key={cat} className="space-y-3">
          <h3 className={`${T.sectionHeading} capitalize`}>{cat}</h3>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {byCategory.get(cat)!.map((tmpl) => (
              <TemplateCard
                key={tmpl.id}
                template={tmpl}
                onApply={() => handleApply(tmpl.id)}
                applying={applyingId === tmpl.id}
              />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

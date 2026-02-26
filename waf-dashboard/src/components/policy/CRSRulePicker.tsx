import { useState, useMemo } from "react";
import { Search, Check } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { CRSRule } from "@/lib/api";
import { RuleIdTagInput, parseRuleIds, joinRuleIds } from "./TagInputs";

// ─── CRS Rule Picker (searchable dropdown) ──────────────────────────

export function CRSRulePicker({
  rules,
  categories,
  selectedRuleIds,
  onSelect,
}: {
  rules: CRSRule[];
  categories: { id: string; name: string }[];
  selectedRuleIds: string;
  onSelect: (ruleIds: string) => void;
}) {
  const [search, setSearch] = useState("");
  const [open, setOpen] = useState(false);
  const ids = parseRuleIds(selectedRuleIds);

  const filteredRules = useMemo(() => {
    if (!search) return rules.slice(0, 50);
    const q = search.toLowerCase();
    return rules.filter(
      (r) =>
        r.id.includes(q) ||
        r.description.toLowerCase().includes(q) ||
        r.category.toLowerCase().includes(q)
    ).slice(0, 50);
  }, [rules, search]);

  const categoryMap = useMemo(() => {
    const m: Record<string, string> = {};
    for (const c of categories) m[c.id] = c.name;
    return m;
  }, [categories]);

  const toggleRule = (ruleId: string) => {
    if (ids.includes(ruleId)) {
      onSelect(joinRuleIds(ids.filter((id) => id !== ruleId)));
    } else {
      onSelect(joinRuleIds([...ids, ruleId]));
    }
  };

  return (
    <div className="space-y-1.5">
      <Label className="text-xs uppercase tracking-wider text-muted-foreground">
        Rule ID / Range
      </Label>
      <RuleIdTagInput
        value={selectedRuleIds}
        onChange={onSelect}
        placeholder="Type rule IDs (Enter to add) or browse below"
      />
      <div className="relative">
        <button
          type="button"
          className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
          onClick={() => setOpen(!open)}
        >
          <Search className="h-3 w-3" />
          {open ? "Hide" : "Browse"} CRS rule catalog
        </button>

        {open && (
          <div className="mt-1.5 rounded-md border border-border bg-popover shadow-lg">
            <div className="p-2 border-b border-border">
              <Input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search by ID, description, or category..."
                className="h-8 text-xs"
                autoFocus
              />
            </div>
            <div className="max-h-[300px] overflow-y-auto p-1">
              {filteredRules.length > 0 ? (
                filteredRules.map((rule) => {
                  const isSelected = ids.includes(rule.id);
                  return (
                    <button
                      key={rule.id}
                      className={`flex w-full items-start gap-2 rounded px-2 py-1.5 text-left text-xs hover:bg-accent ${isSelected ? "bg-accent/50" : ""}`}
                      onClick={() => toggleRule(rule.id)}
                    >
                      <span className="shrink-0 font-mono text-neon-cyan">{rule.id}</span>
                      <div className="min-w-0 flex-1">
                        <p className="truncate">{rule.description}</p>
                        <p className="text-muted-foreground">
                          {categoryMap[rule.category] ?? rule.category}
                          {rule.severity && (
                            <Badge variant="outline" className="ml-1.5 text-xs px-1 py-0">
                              {rule.severity}
                            </Badge>
                          )}
                        </p>
                      </div>
                      {isSelected && (
                        <Check className="h-3.5 w-3.5 shrink-0 text-neon-green" />
                      )}
                    </button>
                  );
                })
              ) : (
                <p className="px-2 py-3 text-center text-xs text-muted-foreground">
                  No rules found
                </p>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

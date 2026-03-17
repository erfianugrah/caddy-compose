import { useMemo } from "react";
import { ShieldOff } from "lucide-react";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { CRS_CATEGORIES, type RuleCategory } from "@/lib/api";

// ─── Category Toggles ───────────────────────────────────────────────
// Allows disabling entire CRS rule categories (by prefix).
// disabled_categories is an array of 3-4 digit CRS rule ID prefixes
// (e.g., ["942", "941"] disables all SQLi and XSS rules).
//
// Per-service overrides replace the global list (not merge).

/** Group categories into inbound vs outbound for visual separation.
 *  Custom rules (9100) are inbound request-phase rules, not outbound.
 *  Outbound categories are response-phase CRS rules (950-956). */
const OUTBOUND_PREFIXES = new Set(["950", "951", "952", "953", "954", "955", "956"]);
const INBOUND_CATEGORIES = CRS_CATEGORIES.filter(
  (c) => !OUTBOUND_PREFIXES.has(c.prefix),
);
const OUTBOUND_CATEGORIES = CRS_CATEGORIES.filter(
  (c) => OUTBOUND_PREFIXES.has(c.prefix),
);

interface CategoryTogglesProps {
  disabled: string[];
  onChange: (disabled: string[]) => void;
  compact?: boolean;
}

export function CategoryToggles({ disabled, onChange, compact }: CategoryTogglesProps) {
  const disabledSet = useMemo(() => new Set(disabled), [disabled]);

  const toggle = (prefix: string) => {
    if (disabledSet.has(prefix)) {
      onChange(disabled.filter((p) => p !== prefix));
    } else {
      onChange([...disabled, prefix]);
    }
  };

  const enableAll = () => onChange([]);
  const disableAllInbound = () => {
    const inboundPrefixes = INBOUND_CATEGORIES.map((c) => c.prefix);
    const outboundDisabled = disabled.filter(
      (p) => !inboundPrefixes.includes(p),
    );
    onChange([...outboundDisabled, ...inboundPrefixes]);
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldOff className="h-3.5 w-3.5 text-lv-peach" />
          <Label className="text-xs font-medium">Disabled Categories</Label>
          {disabled.length > 0 && (
            <Badge variant="outline" className="text-[10px] text-lv-peach border-lv-peach/30">
              {disabled.length} disabled
            </Badge>
          )}
        </div>
        {disabled.length > 0 && (
          <button
            onClick={enableAll}
            className="text-[10px] text-muted-foreground hover:text-foreground transition-colors"
          >
            Enable all
          </button>
        )}
      </div>

      {/* Inbound categories */}
      <div className="space-y-1.5">
        <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">
          Inbound (Request)
        </span>
        <CategoryGrid
          categories={INBOUND_CATEGORIES}
          disabledSet={disabledSet}
          onToggle={toggle}
          compact={compact}
        />
      </div>

      {/* Outbound categories */}
      <div className="space-y-1.5">
        <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">
          Outbound (Response)
        </span>
        <CategoryGrid
          categories={OUTBOUND_CATEGORIES}
          disabledSet={disabledSet}
          onToggle={toggle}
          compact={compact}
        />
      </div>

      <p className="text-[10px] text-muted-foreground">
        Disabled categories skip all CRS rules with matching ID prefixes.
        {!compact && " Per-service overrides replace the global list (not merge)."}
      </p>
    </div>
  );
}

// ─── Category Grid ──────────────────────────────────────────────────

function CategoryGrid({
  categories,
  disabledSet,
  onToggle,
  compact,
}: {
  categories: RuleCategory[];
  disabledSet: Set<string>;
  onToggle: (prefix: string) => void;
  compact?: boolean;
}) {
  return (
    <div className={`grid gap-1.5 ${compact ? "grid-cols-3" : "grid-cols-4"}`}>
      {categories.map((cat) => {
        const isDisabled = disabledSet.has(cat.prefix);
        return (
          <button
            key={cat.prefix}
            onClick={() => onToggle(cat.prefix)}
            title={`${cat.name} (${cat.prefix}xxx)`}
            className={`rounded-md border px-2 py-1.5 text-xs transition-all text-left ${
              isDisabled
                ? "border-lv-red/30 bg-lv-red/10 text-lv-red line-through opacity-70"
                : "border-border bg-lovelace-950 text-foreground hover:border-lv-cyan/30 hover:bg-lv-cyan/5"
            }`}
          >
            <span className="font-data text-[10px] text-muted-foreground">
              {cat.prefix}
            </span>
            <span className="ml-1">{cat.shortName}</span>
          </button>
        );
      })}
    </div>
  );
}

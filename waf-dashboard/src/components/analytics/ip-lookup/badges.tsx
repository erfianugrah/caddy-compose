import { CheckCircle2, XCircle, AlertCircle, HelpCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";

// ─── Shared Badge Components ────────────────────────────────────────

export function ROABadge({ validity }: { validity: string }) {
  const config: Record<string, { icon: typeof CheckCircle2; color: string; label: string }> = {
    valid: { icon: CheckCircle2, color: "bg-lv-green/20 border-lv-green/30 text-lv-green", label: "ROA Valid" },
    invalid: { icon: XCircle, color: "border-lv-red/50 text-lv-red", label: "ROA Invalid" },
    unknown: { icon: HelpCircle, color: "bg-lv-peach/20 border-lv-peach/30 text-lv-peach", label: "ROA Unknown" },
    not_found: { icon: AlertCircle, color: "border-muted-foreground/50 text-muted-foreground", label: "No ROA" },
  };
  const c = config[validity] ?? config.unknown;
  const Icon = c.icon;
  return (
    <Badge variant="outline" className={`text-[10px] px-1.5 py-0 gap-0.5 ${c.color}`}>
      <Icon className="h-2.5 w-2.5" />
      {c.label}
    </Badge>
  );
}

export function ReputationStatusBadge({ status }: { status: string }) {
  const config: Record<string, { color: string; label: string }> = {
    clean: { color: "bg-lv-green/20 border-lv-green/30 text-lv-green", label: "Clean" },
    known_good: { color: "border-lv-green/50 text-lv-green", label: "Known Good" },
    suspicious: { color: "bg-lv-peach/20 border-lv-peach/30 text-lv-peach", label: "Suspicious" },
    malicious: { color: "border-lv-red/50 text-lv-red", label: "Malicious" },
  };
  const c = config[status] ?? { color: "", label: status };
  return (
    <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${c.color}`}>
      {c.label}
    </Badge>
  );
}

export function OrgTypeBadge({ type }: { type: string }) {
  const labels: Record<string, string> = {
    isp: "ISP",
    hosting: "Hosting",
    education: "Education",
    government: "Government",
    business: "Business",
  };
  return (
    <Badge variant="outline" className="text-[10px] px-1.5 py-0 font-data">
      {labels[type] ?? type}
    </Badge>
  );
}

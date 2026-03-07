import { Badge } from "@/components/ui/badge";
import { CheckCircle2, XCircle } from "lucide-react";

// ─── Types ──────────────────────────────────────────────────────────

export type SortKey = "time" | "status" | "duration" | "size" | "service" | "method";
export type ViewTab = "logs" | "summary" | "headers";

// ─── Formatting Helpers ─────────────────────────────────────────────

export function statusColor(status: number): string {
  if (status >= 500) return "text-red-400";
  if (status >= 400) return "text-amber-400";
  if (status >= 300) return "text-blue-400";
  if (status >= 200) return "text-emerald-400";
  return "text-muted-foreground";
}

export function statusBadge(status: number) {
  if (status >= 500) return <Badge variant="destructive" className="font-mono text-xs">{status}</Badge>;
  if (status >= 400) return <Badge className="bg-amber-500/20 text-amber-400 font-mono text-xs border-amber-500/30">{status}</Badge>;
  if (status >= 300) return <Badge className="bg-blue-500/20 text-blue-400 font-mono text-xs border-blue-500/30">{status}</Badge>;
  return <Badge className="bg-emerald-500/20 text-emerald-400 font-mono text-xs border-emerald-500/30">{status}</Badge>;
}

export function formatDuration(seconds: number): string {
  if (seconds >= 1) return `${seconds.toFixed(2)}s`;
  if (seconds >= 0.001) return `${(seconds * 1000).toFixed(1)}ms`;
  return `${(seconds * 1_000_000).toFixed(0)}us`;
}

export function formatBytes(bytes: number): string {
  if (bytes >= 1_048_576) return `${(bytes / 1_048_576).toFixed(1)} MB`;
  if (bytes >= 1_024) return `${(bytes / 1_024).toFixed(1)} KB`;
  return `${bytes} B`;
}

export function headerCheckIcon(present: boolean) {
  return present
    ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
    : <XCircle className="h-3.5 w-3.5 text-red-400/60" />;
}

// ─── Stat Card ──────────────────────────────────────────────────────

export function StatCard({ label, value, icon, accent }: {
  label: string;
  value: string;
  icon: React.ReactNode;
  accent?: "red" | "amber" | "green";
}) {
  const accentClass = accent === "red" ? "border-red-500/30 bg-red-500/5" : "";
  return (
    <div className={`rounded-xl border bg-card text-card-foreground shadow ${accentClass}`}>
      <div className="flex items-center gap-3 p-3">
        {icon}
        <div className="min-w-0">
          <p className="text-xs text-muted-foreground truncate">{label}</p>
          <p className="text-lg font-semibold font-mono">{value}</p>
        </div>
      </div>
    </div>
  );
}

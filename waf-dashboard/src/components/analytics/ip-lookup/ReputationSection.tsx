import { Shield, ShieldCheck, ShieldAlert, ShieldX } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { ReputationInfo, ReputationEntry } from "@/lib/api";
import { T } from "@/lib/typography";
import { ReputationStatusBadge } from "./badges";

export function ReputationSection({ reputation }: { reputation: ReputationInfo }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-lv-cyan" />
          <CardTitle className={T.cardTitle}>Reputation</CardTitle>
          <ReputationStatusBadge status={reputation.status} />
        </div>
        <CardDescription>
          Aggregated from {reputation.sources?.length ?? 0} source{(reputation.sources?.length ?? 0) !== 1 ? "s" : ""}
          {reputation.ipsum_listed && " + IPsum blocklist"}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {reputation.ipsum_listed && (
          <div className="flex items-center gap-2 rounded-md bg-lv-red/10 border border-lv-red/30 px-3 py-2">
            <ShieldX className="h-4 w-4 text-lv-red shrink-0" />
            <div>
              <p className="text-xs font-medium text-lv-red">IPsum Blocklisted</p>
              <p className="text-[10px] text-muted-foreground">This IP is on the active IPsum blocklist</p>
            </div>
          </div>
        )}

        {reputation.sources && reputation.sources.length > 0 && (
          <div className="space-y-2">
            {reputation.sources.map((entry, idx) => (
              <ReputationSourceRow key={idx} entry={entry} />
            ))}
          </div>
        )}

        {(!reputation.sources || reputation.sources.length === 0) && !reputation.ipsum_listed && (
          <p className="text-xs text-muted-foreground py-2">
            No reputation data available from external sources.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function ReputationSourceRow({ entry }: { entry: ReputationEntry }) {
  const sourceLabels: Record<string, string> = {
    greynoise: "GreyNoise",
    stopforumspam: "StopForumSpam",
  };

  const StatusIcon = entry.status === "benign" ? ShieldCheck
    : entry.status === "malicious" ? ShieldX
    : entry.status === "noisy" ? ShieldAlert
    : Shield;

  const statusColor = entry.status === "benign" ? "text-lv-green"
    : entry.status === "malicious" ? "text-lv-red"
    : entry.status === "noisy" ? "text-lv-peach"
    : "text-muted-foreground";

  return (
    <div className="flex items-center justify-between rounded-md bg-lovelace-950 px-3 py-2">
      <div className="flex items-center gap-2">
        <StatusIcon className={`h-3.5 w-3.5 shrink-0 ${statusColor}`} />
        <div>
          <p className="text-xs font-medium">{sourceLabels[entry.source] ?? entry.source}</p>
          {entry.name && (
            <p className="text-[10px] text-muted-foreground">
              Known as: {entry.name}
            </p>
          )}
        </div>
      </div>
      <div className="flex items-center gap-2">
        <Badge
          variant="outline"
          className={`text-[10px] px-1.5 py-0 ${
            entry.status === "benign" ? "bg-lv-green/20 border-lv-green/30 text-lv-green"
            : entry.status === "malicious" ? "border-lv-red/50 text-lv-red"
            : entry.status === "noisy" ? "bg-lv-peach/20 border-lv-peach/30 text-lv-peach"
            : ""
          }`}
        >
          {entry.status}
        </Badge>
        {entry.last_seen && (
          <span className="text-[10px] text-muted-foreground">{entry.last_seen}</span>
        )}
      </div>
    </div>
  );
}

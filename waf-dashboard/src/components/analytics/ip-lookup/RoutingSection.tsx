import { Radio } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { RoutingInfo, NetworkType } from "@/lib/api";
import { T } from "@/lib/typography";
import { ROABadge, OrgTypeBadge } from "./badges";

export function RoutingSection({ routing, netType }: { routing: RoutingInfo; netType?: NetworkType }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <Radio className="h-4 w-4 text-lv-cyan" />
          <CardTitle className={T.cardTitle}>BGP Routing</CardTitle>
          {routing.roa_validity && <ROABadge validity={routing.roa_validity} />}
        </div>
        <CardDescription>
          {routing.is_announced ? "Prefix is BGP-announced" : "Prefix is not announced"}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {routing.is_announced ? (
          <div className="grid grid-cols-2 gap-x-4 gap-y-3">
            {routing.as_number && (
              <div>
                <p className="text-[10px] text-muted-foreground">AS Number</p>
                <p className="text-xs font-data font-medium">AS{routing.as_number}</p>
              </div>
            )}
            {routing.as_name && (
              <div className="col-span-2">
                <p className="text-[10px] text-muted-foreground">AS Name</p>
                <p className="text-xs font-medium">{routing.as_name}</p>
              </div>
            )}
            {routing.route && (
              <div>
                <p className="text-[10px] text-muted-foreground">Route Prefix</p>
                <p className="text-xs font-data font-medium">{routing.route}</p>
              </div>
            )}
            {routing.rir && (
              <div>
                <p className="text-[10px] text-muted-foreground">RIR</p>
                <p className="text-xs font-data font-medium uppercase">{routing.rir}</p>
              </div>
            )}
            {routing.alloc_date && (
              <div>
                <p className="text-[10px] text-muted-foreground">Allocation Date</p>
                <p className="text-xs font-data font-medium">{routing.alloc_date}</p>
              </div>
            )}
            {routing.roa_validity && (
              <div>
                <p className="text-[10px] text-muted-foreground">RPKI/ROA</p>
                <div className="flex items-center gap-1.5">
                  <p className="text-xs font-data font-medium">{routing.roa_validity}</p>
                  {(routing.roa_count ?? 0) > 0 && (
                    <span className="text-[10px] text-muted-foreground">
                      ({routing.roa_count} ROA{(routing.roa_count ?? 0) > 1 ? "s" : ""})
                    </span>
                  )}
                </div>
              </div>
            )}
            {netType && (
              <div className="col-span-2 flex flex-wrap gap-1.5 pt-1">
                {netType.org_type && <OrgTypeBadge type={netType.org_type} />}
                {netType.is_anycast && (
                  <Badge variant="outline" className="text-[10px] px-1.5 py-0 bg-lv-peach/20 border-lv-peach/30 text-lv-peach">
                    Anycast
                  </Badge>
                )}
                {netType.is_dc && (
                  <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-purple-500/50 text-lv-purple">
                    Datacenter
                  </Badge>
                )}
              </div>
            )}
          </div>
        ) : (
          <p className="text-xs text-muted-foreground py-2">
            This IP is not currently announced in BGP routing tables.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

import { Fragment, useState, useEffect } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { fetchServices, type ServiceDetail } from "@/lib/api";
import { T } from "@/lib/typography";

function BlockRateBar({ rate }: { rate: number }) {
  const color =
    rate > 50
      ? "bg-neon-pink"
      : rate > 20
        ? "bg-neon-amber"
        : "bg-neon-green";
  return (
    <div className="flex items-center gap-2">
      <div className="h-2 w-16 overflow-hidden rounded-full bg-navy-800">
        <div
          className={`h-full rounded-full ${color} transition-all`}
          style={{ width: `${Math.min(rate, 100)}%` }}
        />
      </div>
      <span className="text-xs tabular-nums text-muted-foreground">
        {rate.toFixed(1)}%
      </span>
    </div>
  );
}

function ServiceDetailPanel({ service }: { service: ServiceDetail }) {
  return (
    <div className="grid gap-4 p-4 md:grid-cols-2">
      {/* Top URIs */}
      <div>
        <h4 className={`mb-2 ${T.sectionLabel}`}>
          Top Triggered URIs
        </h4>
        <div className="space-y-1">
          {(service.top_uris ?? []).slice(0, 8).map((u) => (
            <div
              key={u.uri}
              className="flex items-center justify-between rounded-md bg-navy-950 px-3 py-1.5 text-xs"
            >
              <code className="max-w-[200px] truncate text-foreground" title={u.uri}>
                {u.uri}
              </code>
              <div className="flex items-center gap-2">
                <span className="tabular-nums text-muted-foreground">
                  {u.count}
                </span>
                {u.blocked > 0 && (
                  <Badge variant="destructive" className="text-xs px-1.5 py-0">
                    {u.blocked} blocked
                  </Badge>
                )}
              </div>
            </div>
          ))}
          {(service.top_uris ?? []).length === 0 && (
            <p className="text-xs text-muted-foreground">No URI data</p>
          )}
        </div>
      </div>

      {/* Top Rules */}
      <div>
        <h4 className={`mb-2 ${T.sectionLabel}`}>
          Top Triggered Rules
        </h4>
        <div className="space-y-1">
          {(service.top_rules ?? []).slice(0, 8).map((r) => (
            <div
              key={r.rule_id}
              className="flex items-center justify-between rounded-md bg-navy-950 px-3 py-1.5 text-xs"
            >
              <div className="flex items-center gap-2">
                <Badge variant="outline" className={T.badgeMono}>
                  {r.rule_id}
                </Badge>
                <span className="max-w-[180px] truncate text-muted-foreground">
                  {r.rule_msg}
                </span>
              </div>
              <span className="tabular-nums text-foreground">{r.count}</span>
            </div>
          ))}
          {(service.top_rules ?? []).length === 0 && (
            <p className="text-xs text-muted-foreground">No rule data</p>
          )}
        </div>
      </div>
    </div>
  );
}

export default function ServicesList() {
  const [services, setServices] = useState<ServiceDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  useEffect(() => {
    fetchServices()
      .then(setServices)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  const toggleExpand = (service: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(service)) next.delete(service);
      else next.add(service);
      return next;
    });
  };

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
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className={T.pageTitle}>Services</h2>
          <p className={T.pageDescription}>
            Per-service WAF event breakdown. Click a row to expand details.
          </p>
        </div>
      </div>

      <Card>
        <CardContent className="p-0 overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-8" />
                <TableHead>Service</TableHead>
                <TableHead className="text-right">Total</TableHead>
                <TableHead className="text-right">Blocked</TableHead>
                <TableHead className="text-right">Logged</TableHead>
                <TableHead>Block Rate</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading &&
                [...Array(5)].map((_, i) => (
                  <TableRow key={i}>
                    <TableCell />
                    <TableCell>
                      <Skeleton className="h-4 w-32" />
                    </TableCell>
                    <TableCell>
                      <Skeleton className="ml-auto h-4 w-12" />
                    </TableCell>
                    <TableCell>
                      <Skeleton className="ml-auto h-4 w-12" />
                    </TableCell>
                    <TableCell>
                      <Skeleton className="ml-auto h-4 w-12" />
                    </TableCell>
                    <TableCell>
                      <Skeleton className="h-4 w-20" />
                    </TableCell>
                  </TableRow>
                ))}

              {!loading &&
                services.map((svc) => (
                  <Fragment key={svc.service}>
                    <TableRow
                      className="cursor-pointer"
                      onClick={() => toggleExpand(svc.service)}
                    >
                      <TableCell className="w-8">
                        {expanded.has(svc.service) ? (
                          <ChevronDown className="h-4 w-4 text-muted-foreground" />
                        ) : (
                          <ChevronRight className="h-4 w-4 text-muted-foreground" />
                        )}
                      </TableCell>
                      <TableCell className="font-medium">
                        {svc.service}
                      </TableCell>
                      <TableCell className="text-right tabular-nums">
                        {svc.total_events.toLocaleString()}
                      </TableCell>
                      <TableCell className="text-right tabular-nums text-neon-pink">
                        {svc.blocked.toLocaleString()}
                      </TableCell>
                      <TableCell className="text-right tabular-nums text-neon-green">
                        {svc.logged.toLocaleString()}
                      </TableCell>
                      <TableCell>
                        <BlockRateBar rate={svc.block_rate} />
                      </TableCell>
                    </TableRow>
                    {expanded.has(svc.service) && (
                      <TableRow
                        key={`${svc.service}-detail`}
                        className="hover:bg-transparent"
                      >
                        <TableCell colSpan={6} className="bg-navy-950/50 p-0">
                          <ServiceDetailPanel service={svc} />
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                ))}

              {!loading && services.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={6}
                    className="py-8 text-center text-muted-foreground"
                  >
                    No services found. WAF events will appear here once traffic
                    is processed.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

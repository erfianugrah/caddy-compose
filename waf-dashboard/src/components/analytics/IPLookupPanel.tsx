import { useState, useEffect, useCallback, useRef } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import {
  Search,
  Globe,
  AlertTriangle,
  MapPin,
  Building2,
  Network,
  Clock3,
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Radio,
  Server,
  Bug,
  ExternalLink,
  CheckCircle2,
  XCircle,
  AlertCircle,
  HelpCircle,
} from "lucide-react";
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
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  lookupIP,
  type IPLookupData,
  type GeoIPInfo,
  type IPIntelligence,
  type RoutingInfo,
  type ReputationInfo,
  type ReputationEntry,
  type ShodanInfo,
  type NetworkType,
} from "@/lib/api";
import { ACTION_COLORS, CHART_TOOLTIP_STYLE } from "@/lib/utils";
import { T } from "@/lib/typography";
import { formatDateTime, countryFlag } from "@/lib/format";
import { EventTypeBadge } from "../EventTypeBadge";
import { EventDetailModal } from "../EventDetailModal";
import { TablePagination } from "../TablePagination";
import type { WAFEvent } from "@/lib/api";

const chartTooltipStyle = CHART_TOOLTIP_STYLE;

/** Format ISO hour string for multi-day IP timeline X-axis. */
function formatIPTimelineTick(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
  } catch {
    return ts;
  }
}

/** Format ISO hour string for tooltip (includes time). */
function formatIPTimelineTooltip(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleString("en-US", {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false,
    });
  } catch {
    return ts;
  }
}

const IP_EVENTS_PAGE_SIZE = 20;

export function IPLookupPanel({ initialIP }: { initialIP?: string }) {
  const [query, setQuery] = useState(initialIP ?? "");
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<IPLookupData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [eventsPage, setEventsPage] = useState(1);
  const [eventsLoading, setEventsLoading] = useState(false);
  const autoSearched = useRef(false);

  // Event detail modal
  const [selectedEvent, setSelectedEvent] = useState<WAFEvent | null>(null);
  const [modalOpen, setModalOpen] = useState(false);

  const handleSearch = useCallback(() => {
    const ip = query.trim();
    if (!ip) return;
    setLoading(true);
    setError(null);
    setEventsPage(1);
    lookupIP(ip, IP_EVENTS_PAGE_SIZE, 0)
      .then(setData)
      .catch((err) => {
        setError(err.message);
        setData(null);
      })
      .finally(() => setLoading(false));
  }, [query]);

  // Paginate events server-side
  const handleEventsPageChange = useCallback((newPage: number) => {
    if (!data) return;
    setEventsPage(newPage);
    setEventsLoading(true);
    const offset = (newPage - 1) * IP_EVENTS_PAGE_SIZE;
    lookupIP(data.ip, IP_EVENTS_PAGE_SIZE, offset)
      .then((result) => {
        // Keep summary data, update only events
        setData((prev) => prev ? { ...prev, recent_events: result.recent_events } : result);
      })
      .catch((err) => { console.error("IP lookup pagination failed:", err); })
      .finally(() => setEventsLoading(false));
  }, [data]);

  // Sync query state when initialIP prop arrives (it may be undefined on first render)
  useEffect(() => {
    if (initialIP && !autoSearched.current) {
      setQuery(initialIP);
    }
  }, [initialIP]);

  // Auto-trigger lookup when initialIP is provided and query has been synced
  useEffect(() => {
    if (initialIP && query === initialIP && !autoSearched.current) {
      autoSearched.current = true;
      handleSearch();
    }
  }, [initialIP, query, handleSearch]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") handleSearch();
  };

  return (
    <div className="space-y-4">
      {/* Search bar */}
      <Card>
        <CardContent className="p-4">
          <div className="flex items-center gap-3">
            <Search className="h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Enter IP address (e.g., 192.168.1.100)"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              className="flex-1"
            />
            <Button
              onClick={handleSearch}
              disabled={!query.trim() || loading}
              size="sm"
            >
              {loading ? "Searching..." : "Lookup"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Lookup Failed</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {loading && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card>
            <CardContent className="p-6">
              <div className="space-y-3">
                {[...Array(5)].map((_, i) => (
                  <Skeleton key={i} className="h-5 w-full" />
                ))}
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-6">
              <Skeleton className="h-[200px] w-full" />
            </CardContent>
          </Card>
        </div>
      )}

      {data && !loading && (
        <div className="space-y-4">
          {/* IP Details + Timeline */}
          <div className="grid gap-4 lg:grid-cols-2">
            {/* IP Details Card */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Globe className="h-4 w-4 text-lv-cyan" />
                  <CardTitle className="text-sm font-data">{data.ip}</CardTitle>
                  {data.geoip?.country && (
                    <span className="text-sm" title={data.geoip.country}>
                      {countryFlag(data.geoip.country)} {data.geoip.country}
                    </span>
                  )}
                  {/* Overall reputation badge */}
                  {data.intelligence?.reputation && (
                    <ReputationStatusBadge status={data.intelligence.reputation.status} />
                  )}
                </div>
                <CardDescription>IP intelligence and event summary</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* GeoIP Intelligence */}
                {data.geoip && <GeoIPSection geoip={data.geoip} />}

                {/* Event stats */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-1">
                    <p className={T.formLabel}>First Seen</p>
                    <p className="text-sm font-medium">
                      {formatDateTime(data.first_seen)}
                    </p>
                  </div>
                  <div className="space-y-1">
                    <p className={T.formLabel}>Last Seen</p>
                    <p className="text-sm font-medium">
                      {formatDateTime(data.last_seen)}
                    </p>
                  </div>
                  <div className="space-y-1">
                    <p className={T.formLabel}>Total Security Events</p>
                    <p className="text-sm font-bold text-lv-cyan">
                      {data.total_events.toLocaleString()}
                    </p>
                  </div>
                  <div className="space-y-1">
                    <p className={T.formLabel}>Blocked</p>
                    <p className="text-sm font-bold text-lv-red">
                      {data.blocked_count.toLocaleString()}
                    </p>
                  </div>
                </div>

                {/* Per-service breakdown */}
                {data.services.length > 0 && (
                  <div className="space-y-2">
                    <p className={T.formLabel}>Per-Service Breakdown</p>
                    <div className="space-y-1">
                      {data.services.map((svc) => (
                        <div
                          key={svc.service}
                          className="flex items-center justify-between rounded-md bg-lovelace-950 px-3 py-1.5 text-xs"
                        >
                          <span className="font-medium">{svc.service}</span>
                          <div className="flex items-center gap-3">
                            <span className="tabular-nums text-muted-foreground">
                              {svc.total} total
                            </span>
                            {svc.total_blocked > 0 && (
                              <Badge
                                variant="destructive"
                                className="text-xs px-1.5 py-0"
                              >
                                {svc.total_blocked} blocked
                              </Badge>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Event Timeline for this IP */}
            <Card>
              <CardHeader>
                <CardTitle className={T.cardTitle}>Event Timeline</CardTitle>
                <CardDescription>Events from this IP over time</CardDescription>
              </CardHeader>
              <CardContent>
                {data.timeline.length > 0 ? (
                  <ResponsiveContainer width="100%" height={300}>
                    <AreaChart
                      data={data.timeline}
                      margin={{ top: 5, right: 10, left: 0, bottom: 0 }}
                    >
                      <defs>
                        <linearGradient id="ipGradBlocked" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor={ACTION_COLORS.total_blocked} stopOpacity={0.3} />
                          <stop offset="95%" stopColor={ACTION_COLORS.total_blocked} stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="ipGradLogged" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor={ACTION_COLORS.logged} stopOpacity={0.3} />
                          <stop offset="95%" stopColor={ACTION_COLORS.logged} stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#414457" vertical={false} />
                      <XAxis dataKey="hour" stroke="#bdbdc1" fontSize={T.chartAxisTick} tickLine={false} axisLine={false} tickFormatter={formatIPTimelineTick} interval="preserveStartEnd" />
                      <YAxis stroke="#bdbdc1" fontSize={T.chartAxisTick} tickLine={false} axisLine={false} />
                      <Tooltip {...chartTooltipStyle} labelFormatter={formatIPTimelineTooltip} />
                      <Area type="monotone" dataKey="total_blocked" stroke={ACTION_COLORS.total_blocked} fill="url(#ipGradBlocked)" strokeWidth={2} name="Total Blocked" />
                      <Area type="monotone" dataKey="logged" stroke={ACTION_COLORS.logged} fill="url(#ipGradLogged)" strokeWidth={2} />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <p className="py-8 text-center text-xs text-muted-foreground">
                    No timeline data available
                  </p>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Intelligence Sections */}
          {data.intelligence && (
            <div className="grid gap-4 lg:grid-cols-2">
              {/* Routing / BGP Section */}
              {data.intelligence.routing && (
                <RoutingSection routing={data.intelligence.routing} netType={data.intelligence.network_type} />
              )}

              {/* Reputation Section */}
              {data.intelligence.reputation && (
                <ReputationSection reputation={data.intelligence.reputation} />
              )}

              {/* Shodan Section */}
              {data.intelligence.shodan && (
                <ShodanSection shodan={data.intelligence.shodan} ip={data.ip} />
              )}
            </div>
          )}

          {/* Recent Events for this IP */}
          {data.events_total > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className={T.cardTitle}>Security Events</CardTitle>
                <CardDescription>
                  {data.events_total.toLocaleString()} events from {data.ip} — click a row to inspect
                </CardDescription>
              </CardHeader>
              <CardContent className="p-0 overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead>Time</TableHead>
                      <TableHead>Service</TableHead>
                      <TableHead>Method</TableHead>
                      <TableHead>URI</TableHead>
                      <TableHead>Rule</TableHead>
                      <TableHead>Status</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {eventsLoading ? (
                      [...Array(5)].map((_, i) => (
                        <TableRow key={i}>
                          <TableCell colSpan={6}><Skeleton className="h-6 w-full" /></TableCell>
                        </TableRow>
                      ))
                    ) : (
                      data.recent_events.map((evt, idx) => (
                        <TableRow
                          key={evt.id || idx}
                          className="cursor-pointer"
                          onClick={() => {
                            setSelectedEvent(evt);
                            setModalOpen(true);
                          }}
                        >
                          <TableCell className="whitespace-nowrap text-xs">
                            {formatDateTime(evt.timestamp)}
                          </TableCell>
                          <TableCell className="text-xs">{evt.service}</TableCell>
                          <TableCell>
                            <Badge variant="outline" className={T.badgeMono}>
                              {evt.method}
                            </Badge>
                          </TableCell>
                          <TableCell className="max-w-[200px] truncate text-xs font-data" title={evt.uri}>
                            {evt.uri}
                          </TableCell>
                          <TableCell>
                            {evt.rule_id ? (
                              <Badge variant="outline" className={T.badgeMono}>
                                {evt.rule_id}
                              </Badge>
                            ) : (
                              <span className="text-xs text-muted-foreground">-</span>
                            )}
                          </TableCell>
                          <TableCell>
                            <EventTypeBadge eventType={evt.event_type} />
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
                <TablePagination
                  page={eventsPage}
                  totalPages={Math.max(1, Math.ceil(data.events_total / IP_EVENTS_PAGE_SIZE))}
                  onPageChange={handleEventsPageChange}
                  totalItems={data.events_total}
                />
              </CardContent>
            </Card>
          )}

          {/* Event Detail Modal */}
          <EventDetailModal event={selectedEvent} open={modalOpen} onOpenChange={setModalOpen} />
        </div>
      )}

      {!data && !loading && !error && (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16">
            <Search className="mb-3 h-8 w-8 text-muted-foreground/50" />
            <p className="text-sm text-muted-foreground">
              Enter an IP address above to view its WAF event history
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── GeoIP Intelligence Section ─────────────────────────────────────

const SOURCE_LABELS: Record<string, string> = {
  cf_header: "Cloudflare",
  mmdb: "MMDB",
  api: "API",
};

function GeoIPSection({ geoip }: { geoip: GeoIPInfo }) {
  const hasLocation = geoip.city || geoip.region || geoip.country;
  const hasNetwork = geoip.asn || geoip.org || geoip.network;
  if (!hasLocation && !hasNetwork) return null;

  return (
    <div className="rounded-lg border border-border/50 bg-lovelace-950/50 p-3 space-y-2.5">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium text-muted-foreground">GeoIP Intelligence</p>
        {geoip.source && (
          <Badge variant="outline" className="text-[10px] px-1.5 py-0 font-data">
            {SOURCE_LABELS[geoip.source] ?? geoip.source}
          </Badge>
        )}
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-2">
        {/* Location */}
        {hasLocation && (
          <>
            {(geoip.city || geoip.region) && (
              <div className="flex items-start gap-1.5">
                <MapPin className="h-3.5 w-3.5 text-muted-foreground mt-0.5 shrink-0" />
                <div>
                  <p className="text-[10px] text-muted-foreground">Location</p>
                  <p className="text-xs font-medium">
                    {[geoip.city, geoip.region].filter(Boolean).join(", ")}
                  </p>
                </div>
              </div>
            )}
            {geoip.continent && (
              <div className="flex items-start gap-1.5">
                <Globe className="h-3.5 w-3.5 text-muted-foreground mt-0.5 shrink-0" />
                <div>
                  <p className="text-[10px] text-muted-foreground">Continent</p>
                  <p className="text-xs font-medium">{geoip.continent}</p>
                </div>
              </div>
            )}
            {geoip.timezone && (
              <div className="flex items-start gap-1.5">
                <Clock3 className="h-3.5 w-3.5 text-muted-foreground mt-0.5 shrink-0" />
                <div>
                  <p className="text-[10px] text-muted-foreground">Timezone</p>
                  <p className="text-xs font-medium font-data">{geoip.timezone}</p>
                </div>
              </div>
            )}
          </>
        )}
        {/* Network */}
        {geoip.asn && (
          <div className="flex items-start gap-1.5">
            <Network className="h-3.5 w-3.5 text-muted-foreground mt-0.5 shrink-0" />
            <div>
              <p className="text-[10px] text-muted-foreground">ASN</p>
              <p className="text-xs font-medium font-data">{geoip.asn}</p>
            </div>
          </div>
        )}
        {geoip.org && (
          <div className="flex items-start gap-1.5">
            <Building2 className="h-3.5 w-3.5 text-muted-foreground mt-0.5 shrink-0" />
            <div>
              <p className="text-[10px] text-muted-foreground">Organization</p>
              <p className="text-xs font-medium">{geoip.org}</p>
              {geoip.as_domain && (
                <p className="text-[10px] text-muted-foreground font-data">{geoip.as_domain}</p>
              )}
            </div>
          </div>
        )}
        {geoip.network && (
          <div className="flex items-start gap-1.5">
            <Globe className="h-3.5 w-3.5 text-muted-foreground mt-0.5 shrink-0" />
            <div>
              <p className="text-[10px] text-muted-foreground">Network</p>
              <p className="text-xs font-medium font-data">{geoip.network}</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Routing / BGP Section ──────────────────────────────────────────

function RoutingSection({ routing, netType }: { routing: RoutingInfo; netType?: NetworkType }) {
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
            {/* Network type badges */}
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

// ─── Reputation Section ─────────────────────────────────────────────

function ReputationSection({ reputation }: { reputation: ReputationInfo }) {
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

// ─── Shodan Section ─────────────────────────────────────────────────

function ShodanSection({ shodan, ip }: { shodan: ShodanInfo; ip: string }) {
  const hasVulns = shodan.vulns && shodan.vulns.length > 0;
  return (
    <Card className={hasVulns ? "border-lv-red/30" : ""}>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Server className="h-4 w-4 text-lv-cyan" />
            <CardTitle className={T.cardTitle}>Shodan InternetDB</CardTitle>
            {hasVulns && (
              <Badge variant="destructive" className="text-[10px] px-1.5 py-0">
                {shodan.vulns!.length} CVE{shodan.vulns!.length > 1 ? "s" : ""}
              </Badge>
            )}
          </div>
          <a
            href={`https://internetdb.shodan.io/${ip}`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-muted-foreground hover:text-foreground"
          >
            <ExternalLink className="h-3.5 w-3.5" />
          </a>
        </div>
        <CardDescription>Open ports, services, and known vulnerabilities</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {/* Hostnames */}
        {shodan.hostnames && shodan.hostnames.length > 0 && (
          <div>
            <p className="text-[10px] text-muted-foreground mb-1">Hostnames</p>
            <div className="flex flex-wrap gap-1">
              {shodan.hostnames.map((h) => (
                <Badge key={h} variant="outline" className="text-[10px] px-1.5 py-0 font-data">
                  {h}
                </Badge>
              ))}
            </div>
          </div>
        )}

        {/* Ports */}
        {shodan.ports && shodan.ports.length > 0 && (
          <div>
            <p className="text-[10px] text-muted-foreground mb-1">
              Open Ports ({shodan.ports.length})
            </p>
            <div className="flex flex-wrap gap-1">
              {shodan.ports.map((p) => (
                <Badge key={p} variant="secondary" className="text-[10px] px-1.5 py-0 font-data tabular-nums">
                  {p}
                </Badge>
              ))}
            </div>
          </div>
        )}

        {/* Tags */}
        {shodan.tags && shodan.tags.length > 0 && (
          <div>
            <p className="text-[10px] text-muted-foreground mb-1">Tags</p>
            <div className="flex flex-wrap gap-1">
              {shodan.tags.map((t) => (
                <Badge key={t} variant="outline" className="text-[10px] px-1.5 py-0">
                  {t}
                </Badge>
              ))}
            </div>
          </div>
        )}

        {/* CPEs */}
        {shodan.cpes && shodan.cpes.length > 0 && (
          <div>
            <p className="text-[10px] text-muted-foreground mb-1">CPEs</p>
            <div className="flex flex-wrap gap-1">
              {shodan.cpes.map((c) => (
                <Badge key={c} variant="outline" className="text-[10px] px-1.5 py-0 font-data">
                  {c.replace("cpe:/", "")}
                </Badge>
              ))}
            </div>
          </div>
        )}

        {/* Vulnerabilities */}
        {hasVulns && (
          <div>
            <p className="text-[10px] text-muted-foreground mb-1 flex items-center gap-1">
              <Bug className="h-3 w-3 text-lv-red" />
              Known Vulnerabilities
            </p>
            <div className="flex flex-wrap gap-1">
              {shodan.vulns!.map((v) => (
                <a
                  key={v}
                  href={`https://nvd.nist.gov/vuln/detail/${v}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex"
                >
                  <Badge variant="destructive" className="text-[10px] px-1.5 py-0 font-data hover:bg-lv-red-bright">
                    {v}
                  </Badge>
                </a>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Shared Badge Components ────────────────────────────────────────

function ROABadge({ validity }: { validity: string }) {
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

function ReputationStatusBadge({ status }: { status: string }) {
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

function OrgTypeBadge({ type }: { type: string }) {
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

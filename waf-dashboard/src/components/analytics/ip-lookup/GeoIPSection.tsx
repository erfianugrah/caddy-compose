import { MapPin, Globe, Building2, Network, Clock3 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { GeoIPInfo } from "@/lib/api";

const SOURCE_LABELS: Record<string, string> = {
  cf_header: "Cloudflare",
  mmdb: "MMDB",
  api: "API",
};

export function GeoIPSection({ geoip }: { geoip: GeoIPInfo }) {
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

import { Server, Bug, ExternalLink } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { ShodanInfo } from "@/lib/api";
import { T } from "@/lib/typography";

export function ShodanSection({ shodan, ip }: { shodan: ShodanInfo; ip: string }) {
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

import { ExternalLink } from "lucide-react";
import { formatNumber } from "@/lib/format";
import type { HeaderCompliance } from "@/lib/api";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

// ─── Header Metadata ────────────────────────────────────────────────

interface HeaderMeta {
  key: keyof HeaderCompliance;
  label: string;
  shortLabel: string;
  spec: string;
  specUrl: string;
  recommendation: string;
}

const HEADERS: HeaderMeta[] = [
  {
    key: "csp_rate",
    label: "Content-Security-Policy",
    shortLabel: "CSP",
    spec: "W3C CSP Level 3",
    specUrl: "https://www.w3.org/TR/CSP3/",
    recommendation: "Define allowed sources for scripts, styles, and other resources to prevent XSS attacks.",
  },
  {
    key: "hsts_rate",
    label: "Strict-Transport-Security",
    shortLabel: "HSTS",
    spec: "RFC 6797",
    specUrl: "https://datatracker.ietf.org/doc/html/rfc6797",
    recommendation: "Set max-age >= 31536000 (1 year). Include includeSubDomains and consider preload.",
  },
  {
    key: "x_content_type_options_rate",
    label: "X-Content-Type-Options",
    shortLabel: "X-CTO",
    spec: "Fetch Standard",
    specUrl: "https://fetch.spec.whatwg.org/#x-content-type-options-header",
    recommendation: "Set to 'nosniff' to prevent MIME-type sniffing attacks.",
  },
  {
    key: "x_frame_options_rate",
    label: "X-Frame-Options",
    shortLabel: "X-FO",
    spec: "RFC 7034",
    specUrl: "https://datatracker.ietf.org/doc/html/rfc7034",
    recommendation: "Set to 'DENY' or 'SAMEORIGIN'. Prefer CSP frame-ancestors for modern browsers.",
  },
  {
    key: "referrer_policy_rate",
    label: "Referrer-Policy",
    shortLabel: "Referrer",
    spec: "W3C Referrer Policy",
    specUrl: "https://www.w3.org/TR/referrer-policy/",
    recommendation: "Use 'strict-origin-when-cross-origin' or stricter to limit referrer information leakage.",
  },
  {
    key: "cors_origin_rate",
    label: "Access-Control-Allow-Origin",
    shortLabel: "CORS",
    spec: "Fetch Standard (CORS)",
    specUrl: "https://fetch.spec.whatwg.org/#http-cors-protocol",
    recommendation: "Only set when cross-origin access is needed. Avoid wildcard '*' with credentials.",
  },
  {
    key: "permissions_policy_rate",
    label: "Permissions-Policy",
    shortLabel: "Perm-Policy",
    spec: "W3C Permissions Policy",
    specUrl: "https://www.w3.org/TR/permissions-policy/",
    recommendation: "Restrict browser features like camera, microphone, and geolocation to limit attack surface.",
  },
];

// ─── Helpers ────────────────────────────────────────────────────────

function complianceColor(rate: number): string {
  if (rate >= 0.95) return "text-emerald-400";
  if (rate >= 0.8) return "text-emerald-400/70";
  if (rate >= 0.5) return "text-amber-400";
  if (rate >= 0.2) return "text-orange-400";
  return "text-red-400";
}

function barColor(rate: number): string {
  if (rate >= 0.95) return "bg-emerald-500";
  if (rate >= 0.8) return "bg-emerald-500/70";
  if (rate >= 0.5) return "bg-amber-500";
  if (rate >= 0.2) return "bg-orange-500";
  return "bg-red-500";
}

function gradeLabel(rate: number): string {
  if (rate >= 0.95) return "A";
  if (rate >= 0.8) return "B";
  if (rate >= 0.5) return "C";
  if (rate >= 0.2) return "D";
  return "F";
}

// ─── Props ──────────────────────────────────────────────────────────

export interface HeaderComplianceTabProps {
  compliance: HeaderCompliance[];
}

// ─── Component ──────────────────────────────────────────────────────

export default function HeaderComplianceTab({ compliance }: HeaderComplianceTabProps) {
  if (!compliance || compliance.length === 0) {
    return (
      <Card>
        <CardContent className="py-8 text-center text-sm text-muted-foreground">
          No data available — logs may still be loading
        </CardContent>
      </Card>
    );
  }

  // Compute aggregate rates across all services
  const totalRequests = compliance.reduce((sum, c) => sum + c.total, 0);
  const aggregates = HEADERS.map((h) => {
    const weightedSum = compliance.reduce((sum, c) => sum + (c[h.key] as number) * c.total, 0);
    return { header: h, rate: totalRequests > 0 ? weightedSum / totalRequests : 0 };
  });

  return (
    <TooltipProvider delayDuration={200}>
      <div className="space-y-4">
        {/* Aggregate Overview Cards */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
          {aggregates.map(({ header, rate }) => (
            <Tooltip key={header.key}>
              <TooltipTrigger asChild>
                <Card className="cursor-default">
                  <CardContent className="p-3">
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-xs text-muted-foreground truncate">{header.shortLabel}</span>
                      <span className={`text-xs font-bold ${complianceColor(rate)}`}>
                        {gradeLabel(rate)}
                      </span>
                    </div>
                    <div className="h-1.5 rounded-full bg-muted/30 overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all ${barColor(rate)}`}
                        style={{ width: `${Math.max(rate * 100, 1)}%` }}
                      />
                    </div>
                    <div className={`mt-1 text-right font-mono text-xs ${complianceColor(rate)}`}>
                      {(rate * 100).toFixed(0)}%
                    </div>
                  </CardContent>
                </Card>
              </TooltipTrigger>
              <TooltipContent side="bottom" className="max-w-xs">
                <p className="font-medium">{header.label}</p>
                <p className="text-xs text-muted-foreground mt-1">{header.recommendation}</p>
                <a
                  href={header.specUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-xs text-neon-cyan hover:underline mt-1"
                >
                  {header.spec}
                  <ExternalLink className="h-2.5 w-2.5" />
                </a>
              </TooltipContent>
            </Tooltip>
          ))}
        </div>

        {/* Per-Service Table */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Per-Service Compliance</CardTitle>
            <p className="text-xs text-muted-foreground">
              Percentage of responses including each security header. Hover column headers for spec references.
            </p>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-xs">Service</TableHead>
                    <TableHead className="text-xs text-right">Requests</TableHead>
                    {HEADERS.map((h) => (
                      <Tooltip key={h.key}>
                        <TooltipTrigger asChild>
                          <TableHead className="text-xs text-center cursor-help">
                            <span className="border-b border-dotted border-muted-foreground/50">
                              {h.shortLabel}
                            </span>
                          </TableHead>
                        </TooltipTrigger>
                        <TooltipContent side="top" className="max-w-xs">
                          <p className="font-medium">{h.label}</p>
                          <p className="text-xs text-muted-foreground mt-1">{h.recommendation}</p>
                          <a
                            href={h.specUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 text-xs text-neon-cyan hover:underline mt-1"
                          >
                            {h.spec}
                            <ExternalLink className="h-2.5 w-2.5" />
                          </a>
                        </TooltipContent>
                      </Tooltip>
                    ))}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {compliance.map((c) => (
                    <TableRow key={c.service}>
                      <TableCell className="text-xs font-medium">{c.service}</TableCell>
                      <TableCell className="text-xs text-right font-mono">{formatNumber(c.total)}</TableCell>
                      {HEADERS.map((h) => {
                        const rate = c[h.key] as number;
                        return (
                          <TableCell key={h.key} className="text-center px-2">
                            <div className="flex flex-col items-center gap-0.5">
                              <span className={`font-mono text-xs ${complianceColor(rate)}`}>
                                {(rate * 100).toFixed(0)}%
                              </span>
                              <div className="w-full h-1 rounded-full bg-muted/30 overflow-hidden">
                                <div
                                  className={`h-full rounded-full ${barColor(rate)}`}
                                  style={{ width: `${Math.max(rate * 100, 1)}%` }}
                                />
                              </div>
                            </div>
                          </TableCell>
                        );
                      })}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* RFC Reference Legend */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Security Header Reference</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-3 sm:grid-cols-2">
              {HEADERS.map((h) => (
                <div key={h.key} className="flex items-start gap-3 text-xs">
                  <div className="shrink-0 w-5 text-center">
                    <span className={`font-bold ${complianceColor(aggregates.find((a) => a.header.key === h.key)?.rate ?? 0)}`}>
                      {gradeLabel(aggregates.find((a) => a.header.key === h.key)?.rate ?? 0)}
                    </span>
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5">
                      <span className="font-medium text-foreground">{h.label}</span>
                      <a
                        href={h.specUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-muted-foreground hover:text-neon-cyan transition-colors"
                      >
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>
                    <p className="text-muted-foreground mt-0.5">{h.recommendation}</p>
                    <span className="text-muted-foreground/60">{h.spec}</span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </TooltipProvider>
  );
}

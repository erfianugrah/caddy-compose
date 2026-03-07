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

import { pctClass } from "./helpers";

// ─── Props ──────────────────────────────────────────────────────────

export interface HeaderComplianceTabProps {
  compliance: HeaderCompliance[];
}

// ─── Component ──────────────────────────────────────────────────────

const HEADERS = [
  { key: "csp_rate" as const, label: "CSP" },
  { key: "hsts_rate" as const, label: "HSTS" },
  { key: "x_content_type_options_rate" as const, label: "X-CTO" },
  { key: "x_frame_options_rate" as const, label: "X-FO" },
  { key: "referrer_policy_rate" as const, label: "Ref-Policy" },
  { key: "cors_origin_rate" as const, label: "CORS" },
  { key: "permissions_policy_rate" as const, label: "Perm-Policy" },
];

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

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium">Security Header Compliance by Service</CardTitle>
        <p className="text-xs text-muted-foreground">
          Percentage of responses that include each security header
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
                  <TableHead key={h.key} className="text-xs text-center">{h.label}</TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {compliance.map((c) => (
                <TableRow key={c.service}>
                  <TableCell className="text-xs font-medium">{c.service}</TableCell>
                  <TableCell className="text-xs text-right font-mono">{formatNumber(c.total)}</TableCell>
                  {HEADERS.map((h) => {
                    const rate = c[h.key];
                    return (
                      <TableCell key={h.key} className="text-center">
                        <span className={`font-mono text-xs ${pctClass(rate)}`}>
                          {(rate * 100).toFixed(0)}%
                        </span>
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
  );
}

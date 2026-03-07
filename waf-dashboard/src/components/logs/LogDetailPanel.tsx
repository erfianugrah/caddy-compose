import { Download, Search, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { GeneralLogEvent } from "@/lib/api";
import { countryFlag } from "@/lib/format";
import { T } from "@/lib/typography";
import { downloadJSON } from "@/lib/download";
import { formatDuration, formatBytes, headerCheckIcon } from "./helpers";

// ─── RFC / Spec References ──────────────────────────────────────────

const HEADER_SPECS: Record<string, { label: string; url: string; spec: string }> = {
  csp: {
    label: "Content-Security-Policy",
    url: "https://www.w3.org/TR/CSP3/",
    spec: "W3C CSP Level 3",
  },
  hsts: {
    label: "Strict-Transport-Security",
    url: "https://datatracker.ietf.org/doc/html/rfc6797",
    spec: "RFC 6797",
  },
  xcto: {
    label: "X-Content-Type-Options",
    url: "https://fetch.spec.whatwg.org/#x-content-type-options-header",
    spec: "Fetch Standard",
  },
  xfo: {
    label: "X-Frame-Options",
    url: "https://datatracker.ietf.org/doc/html/rfc7034",
    spec: "RFC 7034",
  },
  referrer: {
    label: "Referrer-Policy",
    url: "https://www.w3.org/TR/referrer-policy/",
    spec: "W3C Referrer Policy",
  },
  cors: {
    label: "Access-Control-Allow-Origin",
    url: "https://fetch.spec.whatwg.org/#http-cors-protocol",
    spec: "Fetch Standard (CORS)",
  },
  permissions: {
    label: "Permissions-Policy",
    url: "https://www.w3.org/TR/permissions-policy/",
    spec: "W3C Permissions Policy",
  },
};

// ─── Header Detail Row ──────────────────────────────────────────────

function HeaderDetailRow({ specKey, present, value }: {
  specKey: string;
  present: boolean;
  value?: string;
}) {
  const spec = HEADER_SPECS[specKey];
  if (!spec) return null;

  return (
    <div className="flex items-start gap-2">
      <div className="w-56 shrink-0 flex items-center gap-1.5">
        {headerCheckIcon(present)}
        <a
          href={spec.url}
          target="_blank"
          rel="noopener noreferrer"
          className="text-muted-foreground hover:text-neon-cyan transition-colors"
          title={spec.spec}
          onClick={(e) => e.stopPropagation()}
        >
          {spec.label}
          <ExternalLink className="inline ml-1 h-2.5 w-2.5 opacity-50" />
        </a>
      </div>
      <div className="font-mono break-all min-w-0">
        {present ? (
          <span className="text-foreground">{value || "present"}</span>
        ) : (
          <span className="text-red-400/60">missing</span>
        )}
      </div>
    </div>
  );
}

// ─── Detail Field ───────────────────────────────────────────────────

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-2">
      <span className="text-muted-foreground shrink-0">{label}:</span>
      {children}
    </div>
  );
}

// ─── Main Component ─────────────────────────────────────────────────

export function LogDetailPanel({ event: evt }: { event: GeneralLogEvent }) {
  const eventKey = `${evt.timestamp}-${evt.method}-${evt.uri}`;

  return (
    <div className="space-y-3 p-4">
      {/* Action Buttons */}
      <div className="flex justify-end gap-1.5">
        <a
          href={`/analytics?tab=ip&q=${encodeURIComponent(evt.client_ip)}`}
          onClick={(e) => e.stopPropagation()}
          className="inline-flex"
        >
          <Button
            variant="ghost"
            size="xs"
            className="text-muted-foreground hover:text-foreground"
            tabIndex={-1}
          >
            <Search className="h-3 w-3 mr-1" />
            IP Lookup
          </Button>
        </a>
        <a
          href={`/events?service=${encodeURIComponent(evt.service)}&ip=${encodeURIComponent(evt.client_ip)}`}
          onClick={(e) => e.stopPropagation()}
          className="inline-flex"
        >
          <Button
            variant="ghost"
            size="xs"
            className="text-muted-foreground hover:text-foreground"
            tabIndex={-1}
          >
            <ExternalLink className="h-3 w-3 mr-1" />
            Security Events
          </Button>
        </a>
        <Button
          variant="ghost"
          size="xs"
          className="text-muted-foreground hover:text-foreground"
          onClick={(e) => {
            e.stopPropagation();
            downloadJSON(evt, `log-${eventKey}.json`);
          }}
        >
          <Download className="h-3 w-3 mr-1" />
          Export JSON
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {/* Request Details */}
        <div className="space-y-2">
          <h4 className={T.sectionLabel}>Request Details</h4>
          <div className="space-y-1 rounded-md bg-navy-950 p-3 text-xs">
            <Field label="Client">
              <a
                href={`/analytics?tab=ip&q=${encodeURIComponent(evt.client_ip)}`}
                className="text-neon-cyan hover:underline"
                onClick={(e) => e.stopPropagation()}
              >
                {evt.client_ip}
              </a>
              {evt.country && (
                <span className="text-muted-foreground ml-1">
                  ({countryFlag(evt.country)} {evt.country})
                </span>
              )}
            </Field>
            <Field label="Method">
              <span className="font-medium text-neon-cyan">{evt.method}</span>
            </Field>
            <Field label="URI">
              <code className="break-all text-foreground">{evt.uri}</code>
            </Field>
            <Field label="Protocol">
              <span className="text-foreground">{evt.protocol}</span>
            </Field>
            <Field label="Service">
              <span className="text-foreground">{evt.service}</span>
            </Field>
            {evt.user_agent && (
              <Field label="User-Agent">
                <code className="break-all text-foreground">{evt.user_agent}</code>
              </Field>
            )}
          </div>
        </div>

        {/* Response Details */}
        <div className="space-y-2">
          <h4 className={T.sectionLabel}>Response Details</h4>
          <div className="space-y-1 rounded-md bg-navy-950 p-3 text-xs">
            <Field label="Status">
              <span className={evt.status >= 400 ? "text-neon-pink" : "text-neon-green"}>
                {evt.status}
              </span>
            </Field>
            <Field label="Size">
              <span className="text-foreground font-mono">{formatBytes(evt.size)}</span>
            </Field>
            <Field label="Latency">
              <span className={
                evt.duration >= 1 ? "text-red-400 font-medium" :
                evt.duration >= 0.1 ? "text-amber-400" :
                "text-neon-green"
              }>
                {formatDuration(evt.duration)}
              </span>
            </Field>
            <Field label="Level">
              <span className={evt.level === "error" ? "text-red-400" : "text-foreground"}>
                {evt.level || "info"}
              </span>
            </Field>
            {evt.logger && (
              <Field label="Logger">
                <code className="text-foreground font-mono">{evt.logger}</code>
              </Field>
            )}
          </div>
        </div>
      </div>

      {/* Security Headers */}
      <div className="space-y-2">
        <h4 className={T.sectionLabel}>Security Headers</h4>
        <div className="space-y-1 rounded-md bg-navy-950 p-3 text-xs">
          <HeaderDetailRow specKey="csp" present={evt.security_headers.has_csp} value={evt.security_headers.csp} />
          <HeaderDetailRow specKey="hsts" present={evt.security_headers.has_hsts} value={evt.security_headers.hsts} />
          <HeaderDetailRow specKey="xcto" present={evt.security_headers.has_x_content_type_options} value={evt.security_headers.x_content_type_options} />
          <HeaderDetailRow specKey="xfo" present={evt.security_headers.has_x_frame_options} value={evt.security_headers.x_frame_options} />
          <HeaderDetailRow specKey="referrer" present={evt.security_headers.has_referrer_policy} value={evt.security_headers.referrer_policy} />
          <HeaderDetailRow specKey="cors" present={evt.security_headers.has_cors_origin} value={evt.security_headers.cors_origin} />
          <HeaderDetailRow specKey="permissions" present={evt.security_headers.has_permissions_policy} value={evt.security_headers.permissions_policy} />
        </div>
      </div>
    </div>
  );
}

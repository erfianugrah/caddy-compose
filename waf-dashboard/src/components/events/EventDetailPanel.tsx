import { useState } from "react";
import {
  ChevronDown,
  ChevronRight,
  Download,
  ShieldPlus,
  ExternalLink,
  Search,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { WAFEvent } from "@/lib/api";
import { countryFlag } from "@/lib/format";
import { T } from "@/lib/typography";
import { downloadJSON } from "@/lib/download";
import {
  formatSeverity,
  parseMatchedData,
  HighlightedText,
  isPolicyRuleEvent,
  policyRuleLink,
} from "./helpers";

/** Collapsible section for the detail panel. */
function ExpandableSection({ title, children }: { title: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="space-y-2">
      <button
        onClick={() => setOpen(!open)}
        className={`flex items-center gap-1 ${T.sectionLabel} hover:text-foreground transition-colors`}
      >
        {open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
        {title}
      </button>
      {open && <div className="pl-4">{children}</div>}
    </div>
  );
}

export function EventDetailPanel({ event, hideActions = false, viewInEventsHref }: { event: WAFEvent; hideActions?: boolean; viewInEventsHref?: string }) {
  // Only show "Create Exception" for CRS WAF events (not rate-limited or policy-engine-managed)
  const isWafEvent = event.event_type !== "rate_limited"
    && !event.event_type?.startsWith("policy_");

  return (
    <div className="space-y-3 p-4">
      {!hideActions && (
        <div className="flex justify-end gap-1.5">
          {viewInEventsHref && (
            <a
              href={viewInEventsHref}
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
                View in Security Events
              </Button>
            </a>
          )}
          {isWafEvent && (
            <a
              href="/policy?from_event=1"
              onClick={(e) => {
                e.stopPropagation();
                sessionStorage.setItem("waf:prefill-event", JSON.stringify(event));
              }}
              className="inline-flex"
            >
              <Button
                variant="ghost"
                size="xs"
                className="text-neon-cyan hover:text-neon-green"
                tabIndex={-1}
              >
                <ShieldPlus className="h-3 w-3 mr-1" />
                Create Exception
              </Button>
            </a>
          )}
          <a
            href={`/analytics?tab=ip&q=${encodeURIComponent(event.client_ip)}`}
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
          <Button
            variant="ghost"
            size="xs"
            className="text-muted-foreground hover:text-foreground"
            onClick={(e) => {
              e.stopPropagation();
              downloadJSON(event, `event-${event.id}.json`);
            }}
          >
            <Download className="h-3 w-3 mr-1" />
            Export JSON
          </Button>
        </div>
      )}
      <div className="grid gap-4 md:grid-cols-2">
        <div className="space-y-2">
          <h4 className={T.sectionLabel}>
            Request Details
          </h4>
          <div className="space-y-1 rounded-md bg-navy-950 p-3 text-xs">
            <div className="flex gap-2">
              <span className="text-muted-foreground">Event ID:</span>
              <code className="text-muted-foreground/70 font-mono select-all">{event.id}</code>
            </div>
            <div className="flex gap-2">
              <span className="text-muted-foreground">Method:</span>
              <span className="font-medium text-neon-cyan">{event.method}</span>
            </div>
            <div className="flex gap-2">
              <span className="text-muted-foreground">URI:</span>
              <code className="break-all text-foreground">{event.uri}</code>
            </div>
            <div className="flex gap-2">
              <span className="text-muted-foreground">Client:</span>
              <a
                href={`/analytics?q=${encodeURIComponent(event.client_ip)}`}
                className="text-neon-cyan hover:underline"
              >
                {event.client_ip}
              </a>
              {event.country && event.country !== "XX" && (
                <span className="text-muted-foreground">
                  ({countryFlag(event.country)} {event.country})
                </span>
              )}
            </div>
            <div className="flex gap-2">
              <span className="text-muted-foreground">Status:</span>
              <span
                className={
                  event.status >= 400 ? "text-neon-pink" : "text-neon-green"
                }
              >
                {event.status}
              </span>
            </div>
          </div>
        </div>

        <div className="space-y-2">
          <h4 className={T.sectionLabel}>
            {event.event_type === "rate_limited" ? "Rate Limit Details"
              : event.event_type?.startsWith("policy_") ? "Policy Engine Match"
              : event.blocked_by === "anomaly_inbound" || event.blocked_by === "anomaly_outbound"
                ? "Anomaly Score Block"
                : "Rule Match"}
          </h4>
          <div className="space-y-1 rounded-md bg-navy-950 p-3 text-xs">
            {event.event_type === "rate_limited" ? (
              <>
                <div className="flex gap-2">
                  <span className="text-muted-foreground">Action:</span>
                  <span className="text-yellow-400 font-medium">Rate Limited ({event.status || 429})</span>
                </div>
                <div className="flex gap-2">
                  <span className="text-muted-foreground">Response:</span>
                  <span className="text-neon-pink">{event.status || 429} Too Many Requests</span>
                </div>
                {event.tags && event.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1 pt-1">
                    <span className="text-muted-foreground">Tags:</span>
                    {event.tags.map((tag) => (
                      <span key={tag} className="inline-flex items-center rounded bg-neon-cyan/10 border border-neon-cyan/30 px-2 py-0.5 text-xs font-mono text-neon-cyan">
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
                {event.user_agent && (
                  <div className="flex gap-2">
                    <span className="text-muted-foreground">User-Agent:</span>
                    <code className="break-all text-foreground">{event.user_agent}</code>
                  </div>
                )}
              </>
            ) : event.event_type?.startsWith("policy_") ? (
              <>
                {/* Policy engine event — tag-aware display */}
                <div className="flex gap-2">
                  <span className="text-muted-foreground">Action:</span>
                  <span className="text-neon-pink font-medium">
                    Policy {event.event_type.replace("policy_", "").replace(/^\w/, (c) => c.toUpperCase())} ({event.status || 403})
                  </span>
                </div>
                {event.tags && event.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1 pt-1">
                    <span className="text-muted-foreground">Tags:</span>
                    {event.tags.map((tag) => (
                      <span key={tag} className="inline-flex items-center rounded bg-neon-cyan/10 border border-neon-cyan/30 px-2 py-0.5 text-xs font-mono text-neon-cyan">
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
                {event.rule_msg && (
                  <div className="flex gap-2">
                    <span className="text-muted-foreground">Rule:</span>
                    {isPolicyRuleEvent(event) && policyRuleLink(event.rule_msg) ? (
                      <a href={policyRuleLink(event.rule_msg)!} className="text-emerald-400 hover:text-emerald-300 hover:underline transition-colors" onClick={(e) => e.stopPropagation()}>
                        {event.rule_id ? `${event.rule_id} — ` : ""}{event.rule_msg}
                      </a>
                    ) : (
                      <span className="text-foreground">{event.rule_id ? `${event.rule_id} — ` : ""}{event.rule_msg}</span>
                    )}
                  </div>
                )}
                {event.user_agent && (
                  <div className="flex gap-2">
                    <span className="text-muted-foreground">User-Agent:</span>
                    <code className="break-all text-foreground">{event.user_agent}</code>
                  </div>
                )}
              </>
            ) : (
              <>
                {/* Anomaly score block: show the blocking reason prominently */}
                {(event.blocked_by === "anomaly_inbound" || event.blocked_by === "anomaly_outbound") && (
                  <div className="flex gap-2 items-center pb-1 mb-1 border-b border-navy-800">
                    <span className="text-muted-foreground">Blocked By:</span>
                    <span className="text-neon-pink font-medium">
                      {event.blocked_by === "anomaly_inbound"
                        ? `Inbound Anomaly Score (${event.anomaly_score}) exceeded threshold`
                        : `Outbound Anomaly Score (${event.outbound_anomaly_score}) exceeded threshold`}
                    </span>
                  </div>
                )}

                {/* Scores */}
                {(event.anomaly_score > 0 || event.outbound_anomaly_score > 0) && (
                  <div className="flex gap-4">
                    {event.anomaly_score > 0 && (
                      <div className="flex gap-2">
                        <span className="text-muted-foreground">Inbound Score:</span>
                        <span className={
                          event.anomaly_score >= 25 ? "text-neon-pink font-bold" :
                          event.anomaly_score >= 10 ? "text-neon-amber font-medium" :
                          "text-neon-cyan"
                        }>
                          {event.anomaly_score}
                        </span>
                      </div>
                    )}
                    {event.outbound_anomaly_score > 0 && (
                      <div className="flex gap-2">
                        <span className="text-muted-foreground">Outbound Score:</span>
                        <span className={
                          event.outbound_anomaly_score >= 25 ? "text-neon-pink font-bold" :
                          event.outbound_anomaly_score >= 10 ? "text-neon-amber font-medium" :
                          "text-neon-cyan"
                        }>
                          {event.outbound_anomaly_score}
                        </span>
                      </div>
                    )}
                  </div>
                )}

                {/* Primary rule — labeled differently for anomaly vs direct blocks */}
                {event.rule_id > 0 && (
                  <>
                    {(event.blocked_by === "anomaly_inbound" || event.blocked_by === "anomaly_outbound") && (
                      <div className="text-xs uppercase tracking-wider text-muted-foreground/60 pt-1">
                        Highest Severity Rule
                      </div>
                    )}
                    <div className="flex gap-2 items-center">
                      <span className="text-muted-foreground">Rule ID:</span>
                      {isPolicyRuleEvent(event) && policyRuleLink(event.rule_msg) ? (
                        <a href={policyRuleLink(event.rule_msg)!} className="inline-flex items-center gap-1 group" onClick={(e) => e.stopPropagation()}>
                          <Badge variant="outline" className={`${T.badgeMono} group-hover:border-emerald-500/50 group-hover:text-emerald-400 transition-colors`}>
                            {event.rule_id}
                          </Badge>
                          <ExternalLink className="h-3 w-3 text-muted-foreground group-hover:text-emerald-400 transition-colors" />
                        </a>
                      ) : (
                        <Badge variant="outline" className={T.badgeMono}>
                          {event.rule_id}
                        </Badge>
                      )}
                    </div>
                    <div className="flex gap-2">
                      <span className="text-muted-foreground">Message:</span>
                      {isPolicyRuleEvent(event) && policyRuleLink(event.rule_msg) ? (
                        <a href={policyRuleLink(event.rule_msg)!} className="text-emerald-400 hover:text-emerald-300 hover:underline transition-colors" onClick={(e) => e.stopPropagation()}>
                          {event.rule_msg}
                        </a>
                      ) : (
                        <span className="text-foreground">{event.rule_msg || "N/A"}</span>
                      )}
                    </div>
                    <div className="flex gap-2">
                      <span className="text-muted-foreground">Severity:</span>
                      {(() => {
                        const sev = formatSeverity(event.severity);
                        return <span className={sev.color}>{sev.label}</span>;
                      })()}
                    </div>
                  </>
                )}

                {/* Matched data with parsing and highlighting */}
                {event.matched_data && (() => {
                  const parsed = parseMatchedData(event.matched_data);
                  if (parsed) {
                    return (
                      <div className="space-y-1">
                        <div className="flex gap-2">
                          <span className="text-muted-foreground">Variable:</span>
                          <code className="text-neon-cyan">{parsed.variable}</code>
                        </div>
                        <div className="flex gap-2">
                          <span className="text-muted-foreground">Trigger:</span>
                          <code className="text-neon-amber">{parsed.trigger}</code>
                        </div>
                        <div className="flex gap-2 items-start">
                          <span className="text-muted-foreground shrink-0">Full Value:</span>
                          <code className="break-all text-foreground/80">
                            <HighlightedText text={parsed.fullValue} highlight={parsed.trigger} />
                          </code>
                        </div>
                      </div>
                    );
                  }
                  return (
                    <div className="flex gap-2">
                      <span className="text-muted-foreground">Matched:</span>
                      <code className="break-all text-neon-amber">{event.matched_data}</code>
                    </div>
                  );
                })()}

                {event.rule_tags && event.rule_tags.length > 0 && (
                  <div className="flex flex-wrap gap-1 pt-1">
                    <span className="text-muted-foreground">Tags:</span>
                    {event.rule_tags.map((tag) => (
                      <Badge key={tag} variant="outline" className={`${T.badgeMono} text-muted-foreground`}>
                        {tag}
                      </Badge>
                    ))}
                  </div>
                )}
                {event.tags && event.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1 pt-1">
                    <span className="text-muted-foreground">Labels:</span>
                    {event.tags.map((tag) => (
                      <span key={tag} className="inline-flex items-center rounded bg-neon-cyan/10 border border-neon-cyan/30 px-2 py-0.5 text-xs font-mono text-neon-cyan">
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </div>

      {/* All Matched Rules (when multiple rules fired) */}
      {event.matched_rules && event.matched_rules.length > 1 && (
        <ExpandableSection title={`All Matched Rules (${event.matched_rules.length})`}>
          <div className="space-y-3">
            {event.matched_rules.map((rule) => {
              const sev = formatSeverity(rule.severity);
              const parsed = rule.matched_data ? parseMatchedData(rule.matched_data) : null;
              return (
                <div key={rule.id} className="rounded border border-navy-800 bg-navy-950/50 p-2 space-y-1 text-xs">
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className={T.badgeMono}>{rule.id}</Badge>
                    <span className={sev.color + " text-xs font-medium"}>{sev.label}</span>
                    <span className="text-foreground/80 truncate">{rule.msg}</span>
                  </div>
                  {parsed ? (
                    <div className="pl-2 space-y-0.5">
                      <div className="flex gap-2">
                        <span className="text-muted-foreground">Variable:</span>
                        <code className="text-neon-cyan">{parsed.variable}</code>
                      </div>
                      <div className="flex gap-2 items-start">
                        <span className="text-muted-foreground shrink-0">Value:</span>
                        <code className="break-all text-foreground/80">
                          <HighlightedText text={parsed.fullValue} highlight={parsed.trigger} />
                        </code>
                      </div>
                    </div>
                  ) : rule.matched_data ? (
                    <div className="pl-2">
                      <code className="break-all text-neon-amber text-xs">{rule.matched_data}</code>
                    </div>
                  ) : null}
                  {rule.file && (
                    <div className="pl-2 text-xs text-muted-foreground/60">{rule.file}</div>
                  )}
                </div>
              );
            })}
          </div>
        </ExpandableSection>
      )}

      {/* Request Context */}
      {(event.request_args && Object.keys(event.request_args).length > 0) ||
       event.request_body ||
       (event.request_headers && Object.keys(event.request_headers).length > 0) ? (
        <ExpandableSection title="Request Context">
          <div className="space-y-3">
            {event.request_args && Object.keys(event.request_args).length > 0 && (
              <div className="space-y-1">
                <h5 className={T.sectionLabel}>Query / Form Args</h5>
                <div className="rounded border border-navy-800 bg-navy-950/50 p-2">
                  {Object.entries(event.request_args).map(([key, value]) => {
                    const trigger = event.matched_data ? parseMatchedData(event.matched_data)?.trigger : undefined;
                    return (
                      <div key={key} className="flex gap-1 text-xs">
                        <span className="text-neon-cyan shrink-0">{key}:</span>
                        <code className="break-all text-foreground/80">
                          {trigger ? <HighlightedText text={value} highlight={trigger} /> : value}
                        </code>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {event.request_body && (
              <div className="space-y-1">
                <h5 className={T.sectionLabel}>Request Body</h5>
                <div className="rounded border border-navy-800 bg-navy-950/50 p-2">
                  <pre className="text-xs text-foreground/80 whitespace-pre-wrap break-all">
                    {(() => {
                      const trigger = event.matched_data ? parseMatchedData(event.matched_data)?.trigger : undefined;
                      return trigger
                        ? <HighlightedText text={event.request_body} highlight={trigger} />
                        : event.request_body;
                    })()}
                  </pre>
                </div>
              </div>
            )}

            {event.request_headers && Object.keys(event.request_headers).length > 0 && (
              <div className="space-y-1">
                <h5 className={T.sectionLabel}>Headers</h5>
                <div className="rounded border border-navy-800 bg-navy-950/50 p-2 font-mono text-xs">
                  {Object.entries(event.request_headers).map(([k, v]) => {
                    const value = Array.isArray(v) ? v.join(", ") : v;
                    const trigger = event.matched_data ? parseMatchedData(event.matched_data)?.trigger : undefined;
                    return (
                      <div key={k} className="flex gap-0 leading-relaxed">
                        <span className="text-neon-cyan shrink-0">{k}</span>
                        <span className="text-muted-foreground/50">:&nbsp;</span>
                        <span className="text-foreground/80 break-all">
                          {trigger ? <HighlightedText text={value} highlight={trigger} /> : value}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </ExpandableSection>
      ) : null}
    </div>
  );
}

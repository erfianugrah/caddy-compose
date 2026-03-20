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
  TruncatedCode,
  CopyBtn,
  isPolicyRuleEvent,
  policyRuleLink,
} from "./helpers";

/** Collapsible section for the detail panel. */
function ExpandableSection({ title, children, defaultOpen = false }: { title: string; children: React.ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
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

/** Find the highest-severity matched rule for detect_block summary. */
function highestSeverityRule(rules: WAFEvent["matched_rules"]): NonNullable<WAFEvent["matched_rules"]>[number] | null {
  if (!rules || rules.length === 0) return null;
  return rules.reduce((best, r) => {
    // Lower severity number = higher severity (2=critical, 3=error, 4=warning, 5=notice)
    if (r.severity > 0 && (best.severity === 0 || r.severity < best.severity)) return r;
    return best;
  }, rules[0]);
}

/** CRS/anomaly event details — shown for detect_block, logged, and legacy events. */
function CRSEventDetails({ event }: { event: WAFEvent }) {
  const isAnomaly = event.blocked_by === "anomaly_inbound" || event.blocked_by === "anomaly_outbound";
  const isDetectBlock = event.event_type === "detect_block";

  // For detect_block events: derive summary from highest severity matched rule
  // when the event itself doesn't carry a primary rule_id
  const summaryRule = isDetectBlock && event.rule_id === 0
    ? highestSeverityRule(event.matched_rules)
    : null;

  return (
    <>
      {/* Anomaly score block: show the blocking reason prominently */}
      {isAnomaly && (
        <div className="flex gap-2 items-center pb-1 mb-1 border-b border-lovelace-800">
          <span className="text-muted-foreground">Blocked By:</span>
          <span className="text-lv-red font-medium">
            {event.blocked_by === "anomaly_inbound"
              ? `Inbound Anomaly Score (${event.anomaly_score}) exceeded threshold`
              : `Outbound Anomaly Score (${event.outbound_anomaly_score}) exceeded threshold`}
          </span>
        </div>
      )}

      {/* Detect block summary — highest severity rule from matched_rules */}
      {isDetectBlock && summaryRule && (
        <div className="flex gap-2 items-center pb-1 mb-1 border-b border-lovelace-800">
          <span className="text-muted-foreground">Highest Severity:</span>
          <Badge variant="outline" className={T.badgeMono}>
            {summaryRule.name || summaryRule.id}
          </Badge>
          <span className={formatSeverity(summaryRule.severity).color + " text-xs font-medium"}>
            {formatSeverity(summaryRule.severity).label}
          </span>
          <span className="text-foreground/80 truncate text-xs">{summaryRule.msg}</span>
        </div>
      )}

      {/* Scores */}
      {(event.anomaly_score > 0 || event.outbound_anomaly_score > 0) && (
        <div className="flex gap-4">
          {event.anomaly_score > 0 && (
            <div className="flex gap-2">
              <span className="text-muted-foreground">Inbound Score:</span>
              <span className={
                event.anomaly_score >= 25 ? "text-lv-red font-bold" :
                event.anomaly_score >= 10 ? "text-lv-peach font-medium" :
                "text-lv-cyan"
              }>
                {event.anomaly_score}
              </span>
            </div>
          )}
          {event.outbound_anomaly_score > 0 && (
            <div className="flex gap-2">
              <span className="text-muted-foreground">Outbound Score:</span>
              <span className={
                event.outbound_anomaly_score >= 25 ? "text-lv-red font-bold" :
                event.outbound_anomaly_score >= 10 ? "text-lv-peach font-medium" :
                "text-lv-cyan"
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
          {isAnomaly && (
            <div className="text-xs uppercase tracking-wider text-muted-foreground/60 pt-1">
              Highest Severity Rule
            </div>
          )}
          <div className="flex gap-2 items-center">
            <span className="text-muted-foreground">Rule ID:</span>
            {isPolicyRuleEvent(event) && policyRuleLink(event.rule_msg) ? (
              <a href={policyRuleLink(event.rule_msg)!} className="inline-flex items-center gap-1 group" onClick={(e) => e.stopPropagation()}>
                <Badge variant="outline" className={`${T.badgeMono} group-hover:border-lv-green/50 group-hover:text-lv-green transition-colors`}>
                  {event.rule_id}
                </Badge>
                <ExternalLink className="h-3 w-3 text-muted-foreground group-hover:text-lv-green transition-colors" />
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
              <a href={policyRuleLink(event.rule_msg)!} className="text-lv-green hover:text-lv-green-bright hover:underline transition-colors" onClick={(e) => e.stopPropagation()}>
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
              <div className="flex gap-2 items-center">
                <span className="text-muted-foreground">Variable:</span>
                <code className="text-lv-cyan">{parsed.variable}</code>
                <CopyBtn text={parsed.variable} />
              </div>
              <div className="flex gap-2 items-center">
                <span className="text-muted-foreground">Trigger:</span>
                <TruncatedCode value={parsed.trigger} className="text-lv-peach" />
                <CopyBtn text={parsed.trigger} />
              </div>
              <div className="flex gap-2 items-start">
                <span className="text-muted-foreground shrink-0">Full Value:</span>
                <TruncatedCode value={parsed.fullValue} className="text-foreground/80" />
                <CopyBtn text={parsed.fullValue} />
              </div>
            </div>
          );
        }
        return (
          <div className="flex gap-2 items-start">
            <span className="text-muted-foreground">Matched:</span>
            <TruncatedCode value={event.matched_data} className="text-lv-peach" />
            <CopyBtn text={event.matched_data} />
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
      {/* Only show Labels that aren't already in rule_tags */}
      {(() => {
        const ruleTagSet = new Set(event.rule_tags ?? []);
        const uniqueLabels = (event.tags ?? []).filter((t) => !ruleTagSet.has(t));
        return uniqueLabels.length > 0 ? (
          <div className="flex flex-wrap gap-1 pt-1">
            <span className="text-muted-foreground">Labels:</span>
            {uniqueLabels.map((tag) => (
              <span key={tag} className="inline-flex items-center rounded bg-lv-cyan/10 border border-lv-cyan/30 px-2 py-0.5 text-xs font-data text-lv-cyan">
                {tag}
              </span>
            ))}
          </div>
        ) : null;
      })()}
    </>
  );
}

export function EventDetailPanel({ event, hideActions = false, viewInEventsHref }: { event: WAFEvent; hideActions?: boolean; viewInEventsHref?: string }) {
  // Show "Create Exception" for any event where an exception makes sense:
  // - detect_block / policy_block / policy_skip / logged / blocked → user may want to allow or tune
  // - NOT rate_limited (handled by rate limit rules, not WAF exceptions)
  // - NOT policy_allow (already allowed, no exception needed)
  const isWafEvent = event.event_type !== "rate_limited"
    && event.event_type !== "policy_allow";

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
                className="text-lv-cyan hover:text-lv-green"
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
          <div className="space-y-1 rounded-md bg-lovelace-950 p-3 text-xs overflow-hidden">
            {(event.request_id || event.id) && (
              <div className="flex gap-2 items-center">
                <span className="text-muted-foreground">Request ID:</span>
                <code className="text-muted-foreground/70 font-data select-all">{event.request_id || event.id}</code>
                <CopyBtn text={event.request_id || event.id} />
                <a
                  href={`/logs?request_id=${encodeURIComponent(event.request_id || event.id)}`}
                  onClick={(e) => e.stopPropagation()}
                  className="text-[10px] text-lv-cyan hover:text-lv-green hover:underline"
                >
                  View in General Logs
                </a>
              </div>
            )}
            <div className="flex gap-2 items-center">
              <span className="text-muted-foreground">Method:</span>
              <span className="font-medium text-lv-cyan">{event.method}</span>
              <CopyBtn text={event.method} />
            </div>
            <div className="flex gap-2 items-start">
              <span className="text-muted-foreground shrink-0">URI:</span>
              <div className="min-w-0 flex-1">
                <TruncatedCode value={event.uri} className="text-foreground" />
              </div>
              <CopyBtn text={event.uri} />
            </div>
            <div className="flex gap-2 items-center">
              <span className="text-muted-foreground">Client:</span>
              <a
                href={`/analytics?q=${encodeURIComponent(event.client_ip)}`}
                className="text-lv-cyan hover:underline"
              >
                {event.client_ip}
              </a>
              <CopyBtn text={event.client_ip} />
              {event.country && event.country !== "XX" && (
                <span className="text-muted-foreground">
                  ({countryFlag(event.country)} {event.country})
                </span>
              )}
            </div>
            <div className="flex gap-2 items-center">
              <span className="text-muted-foreground">Status:</span>
              <span
                className={
                  event.status >= 400 ? "text-lv-red" : "text-lv-green"
                }
              >
                {event.status}
              </span>
              <CopyBtn text={String(event.status)} />
            </div>
            {event.ja4 && (
              <div className="flex gap-2 items-center">
                <span className="text-muted-foreground">JA4:</span>
                <code className="text-xs text-lv-cyan font-data">{event.ja4}</code>
                <CopyBtn text={event.ja4} />
              </div>
            )}
            {(event.challenge_bot_score !== undefined && event.challenge_bot_score > 0) && (
              <div className="flex gap-2 items-center">
                <span className="text-muted-foreground">Bot Score:</span>
                <span className={event.challenge_bot_score >= 70 ? "text-lv-red font-semibold" : event.challenge_bot_score >= 40 ? "text-lv-yellow" : "text-lv-green"}>
                  {event.challenge_bot_score}/100
                </span>
              </div>
            )}
            {event.challenge_jti && (
              <div className="flex gap-2 items-center">
                <span className="text-muted-foreground">Challenge Token:</span>
                <code className="text-xs text-muted-foreground/70 font-data">{event.challenge_jti}</code>
                <CopyBtn text={event.challenge_jti} />
              </div>
            )}
          </div>
        </div>

        <div className="space-y-2">
          <h4 className={T.sectionLabel}>
            {event.event_type === "ddos_blocked" || event.event_type === "ddos_jailed"
              ? "DDoS Mitigator"
              : event.event_type === "rate_limited" ? "Rate Limit Details"
              : event.event_type === "detect_block" || event.event_type === "logged" ? "Rule Match"
              : event.event_type?.startsWith("challenge_") ? "Challenge Details"
              : event.event_type?.startsWith("policy_") ? "Policy Engine Match"
              : event.blocked_by === "anomaly_inbound" || event.blocked_by === "anomaly_outbound"
                ? "Anomaly Score Block"
                : "Rule Match"}
          </h4>
          <div className="space-y-1 rounded-md bg-lovelace-950 p-3 text-xs overflow-hidden">
            {(event.event_type === "ddos_blocked" || event.event_type === "ddos_jailed") ? (
              <>
                <div className="flex gap-2">
                  <span className="text-muted-foreground">Action:</span>
                  <span className="text-lv-purple font-medium">
                    {event.event_type === "ddos_jailed" ? "Auto-Jailed (behavioral anomaly)" : "Blocked (IP in jail)"}
                  </span>
                </div>
                {event.ddos_score && (
                  <div className="flex gap-2">
                    <span className="text-muted-foreground">Anomaly Score:</span>
                    <span className="text-lv-peach font-medium">{event.ddos_score}</span>
                  </div>
                )}
                {event.ddos_fingerprint && (
                  <div className="flex gap-2 items-center">
                    <span className="text-muted-foreground">Fingerprint:</span>
                    <code className="text-muted-foreground/70 font-data">{event.ddos_fingerprint}</code>
                    <CopyBtn text={event.ddos_fingerprint} />
                  </div>
                )}
                <div className="flex gap-2">
                  <span className="text-muted-foreground">Response:</span>
                  <span className="text-lv-red">403 Forbidden</span>
                </div>
                {event.user_agent && (
                  <div className="flex gap-2 items-start">
                    <span className="text-muted-foreground shrink-0">User-Agent:</span>
                    <TruncatedCode value={event.user_agent} className="text-foreground" />
                    <CopyBtn text={event.user_agent} />
                  </div>
                )}
                {event.tags && event.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1 pt-1">
                    <span className="text-muted-foreground">Tags:</span>
                    {event.tags.map((tag) => (
                      <span key={tag} className="inline-flex items-center rounded bg-lv-purple/10 border border-lv-purple/30 px-2 py-0.5 text-xs font-data text-lv-purple">
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
              </>
            ) : event.event_type === "rate_limited" ? (
              <>
                <div className="flex gap-2">
                  <span className="text-muted-foreground">Action:</span>
                  <span className="text-lv-peach font-medium">Rate Limited ({event.status || 429})</span>
                </div>
                <div className="flex gap-2">
                  <span className="text-muted-foreground">Response:</span>
                  <span className="text-lv-red">{event.status || 429} Too Many Requests</span>
                </div>
                {event.tags && event.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1 pt-1">
                    <span className="text-muted-foreground">Tags:</span>
                    {event.tags.map((tag) => (
                      <span key={tag} className="inline-flex items-center rounded bg-lv-cyan/10 border border-lv-cyan/30 px-2 py-0.5 text-xs font-data text-lv-cyan">
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
                {event.user_agent && (
                  <div className="flex gap-2 items-start">
                    <span className="text-muted-foreground shrink-0">User-Agent:</span>
                    <TruncatedCode value={event.user_agent} className="text-foreground" />
                    <CopyBtn text={event.user_agent} />
                  </div>
                )}
              </>
            ) : event.event_type?.startsWith("challenge_") ? (
              <>
                {/* Challenge event — show rule name, difficulty, bot score */}
                <div className="flex gap-2">
                  <span className="text-muted-foreground">Action:</span>
                  <span className={`font-medium ${event.event_type === "challenge_failed" ? "text-lv-red" : event.event_type === "challenge_passed" ? "text-lv-green" : "text-lv-yellow"}`}>
                    {event.event_type?.replace("challenge_", "Challenge ").replace(/^\w/, (c) => c.toUpperCase())}
                  </span>
                </div>
                {event.rule_msg && (
                  <div className="flex gap-2">
                    <span className="text-muted-foreground">Rule:</span>
                    <span className="text-foreground">{event.rule_msg}</span>
                  </div>
                )}
                {event.challenge_bot_score !== undefined && event.challenge_bot_score > 0 && (
                  <div className="flex gap-2">
                    <span className="text-muted-foreground">Bot Score:</span>
                    <span className={event.challenge_bot_score >= 70 ? "text-lv-red font-semibold" : event.challenge_bot_score >= 40 ? "text-lv-yellow" : "text-lv-green"}>
                      {event.challenge_bot_score}/100
                    </span>
                  </div>
                )}
                {event.challenge_jti && (
                  <div className="flex gap-2">
                    <span className="text-muted-foreground">Token ID:</span>
                    <code className="text-muted-foreground/70 font-data">{event.challenge_jti}</code>
                  </div>
                )}
                {event.tags && event.tags.length > 0 && (
                  <div className="flex gap-2 flex-wrap">
                    <span className="text-muted-foreground">Tags:</span>
                    {event.tags.map((tag) => (
                      <span key={tag} className="inline-flex items-center rounded bg-lv-yellow/20 border border-lv-yellow/30 px-1.5 py-0 text-[10px] font-semibold uppercase text-lv-yellow">
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
              </>
            ) : event.event_type?.startsWith("policy_") ? (
              <>
                {/* Policy engine event — tag-aware display */}
                <div className="flex gap-2">
                  <span className="text-muted-foreground">Action:</span>
                  <span className={`font-medium ${event.event_type === "policy_skip" ? "text-lv-cyan" : event.event_type === "policy_allow" ? "text-lv-green" : "text-lv-red"}`}>
                    {`Policy ${event.event_type?.replace("policy_", "").replace(/^\w/, (c) => c.toUpperCase())} (${event.status || 403})`}
                  </span>
                </div>
                {event.rule_msg && (
                  <div className="flex gap-2">
                    <span className="text-muted-foreground">Rule:</span>
                    {isPolicyRuleEvent(event) && policyRuleLink(event.rule_msg) ? (
                      <a href={policyRuleLink(event.rule_msg)!} className="text-lv-green hover:text-lv-green-bright hover:underline transition-colors" onClick={(e) => e.stopPropagation()}>
                        {event.rule_msg}
                      </a>
                    ) : (
                      <span className="text-foreground">{event.rule_msg}</span>
                    )}
                  </div>
                )}
                {/* For skip events: extract skipped rule IDs and show inline as pills */}
                {event.event_type === "policy_skip" && event.rule_msg && (() => {
                  const match = event.rule_msg.match(/Skip\s+([\d,\s.]+)/);
                  if (!match) return null;
                  const ids = match[1].split(/[,\s]+/).filter((s) => /^\d+$/.test(s));
                  if (ids.length === 0) return null;
                  return (
                    <div className="flex gap-2 items-center flex-wrap">
                      <span className="text-muted-foreground shrink-0">Skipped Rules:</span>
                      {ids.map((id) => (
                        <span key={id} className="inline-flex items-center rounded-md bg-lv-cyan/10 border border-lv-cyan/20 px-2 py-0.5 text-xs font-data text-lv-cyan">
                          {id}
                        </span>
                      ))}
                    </div>
                  );
                })()}
                {event.tags && event.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1 pt-1">
                    <span className="text-muted-foreground">Tags:</span>
                    {event.tags.map((tag) => (
                      <span key={tag} className="inline-flex items-center rounded bg-muted/50 px-2 py-0.5 text-xs font-data text-muted-foreground">
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
                {event.user_agent && (
                  <div className="flex gap-2 items-start">
                    <span className="text-muted-foreground shrink-0">User-Agent:</span>
                    <TruncatedCode value={event.user_agent} className="text-foreground" />
                    <CopyBtn text={event.user_agent} />
                  </div>
                )}
              </>
            ) : (
              <CRSEventDetails event={event} />
            )}
          </div>
        </div>
      </div>

      {/* All Matched Rules — deduplicated against the primary rule shown above */}
      {event.matched_rules && event.matched_rules.length > 0 && (() => {
        // For non-detect_block events, skip the first matched rule if it duplicates
        // the primary rule already displayed in the right column.
        const isDetectLike = event.event_type === "detect_block" || event.event_type === "logged";
        const dedupedRules = !isDetectLike && event.rule_id > 0
          ? event.matched_rules.filter((r) => r.id !== event.rule_id)
          : event.matched_rules;
        if (dedupedRules.length === 0) return null;
        return (
        <ExpandableSection title={`All Matched Rules (${dedupedRules.length})`} defaultOpen={isDetectLike}>
          <div className="space-y-3">
            {dedupedRules.map((rule, idx) => {
              const sev = formatSeverity(rule.severity);
              const ruleId = rule.name || (rule.id > 0 ? String(rule.id) : null);
              const parsed = rule.matched_data ? parseMatchedData(rule.matched_data) : null;
              return (
                <div key={rule.name || rule.id || idx} className="rounded border border-lovelace-800 bg-lovelace-950/50 p-2 space-y-1.5 text-xs">
                  <div className="flex items-center gap-2 flex-wrap">
                    {ruleId && <Badge variant="outline" className={T.badgeMono}>{ruleId}</Badge>}
                    {/* Show numeric ID separately when name is a non-numeric string */}
                    {rule.name && rule.id > 0 && rule.name !== String(rule.id) && (
                      <Badge variant="outline" className={`${T.badgeMono} text-muted-foreground/60`}>{rule.id}</Badge>
                    )}
                    <span className={sev.color + " text-xs font-medium"}>{sev.label}</span>
                    <span className="text-foreground/80 truncate" title={rule.msg}>{rule.msg}</span>
                  </div>
                  {/* Per-condition match details (detect rules via plugin v0.11+) */}
                  {rule.matches && rule.matches.length > 0 ? (
                    <div className="pl-2 space-y-1">
                      {rule.matches.map((m, mIdx) => (
                        <div key={mIdx} className="space-y-0.5">
                          <div className="flex gap-2 items-center">
                            <span className="text-muted-foreground shrink-0">Variable:</span>
                            <code className="text-lv-cyan break-all">{m.var_name}</code>
                            <CopyBtn text={m.var_name} />
                            {m.operator && (
                              <Badge variant="outline" className="text-[10px] px-1 py-0 text-muted-foreground">{m.operator}</Badge>
                            )}
                          </div>
                          {m.matched_data && (
                            <div className="flex gap-2 items-start">
                              <span className="text-muted-foreground shrink-0">Matched:</span>
                              <TruncatedCode value={m.matched_data} className="text-lv-peach" />
                              <CopyBtn text={m.matched_data} />
                            </div>
                          )}
                          {m.value && m.value !== m.matched_data && (
                            <div className="flex gap-2 items-start">
                              <span className="text-muted-foreground shrink-0">Full Value:</span>
                              <TruncatedCode value={m.value} className="text-foreground/70" />
                              <CopyBtn text={m.value} />
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : parsed ? (
                    <div className="pl-2 space-y-0.5">
                      <div className="flex gap-2 items-center">
                        <span className="text-muted-foreground">Variable:</span>
                        <code className="text-lv-cyan">{parsed.variable}</code>
                        <CopyBtn text={parsed.variable} />
                      </div>
                      <div className="flex gap-2 items-start">
                        <span className="text-muted-foreground shrink-0">Value:</span>
                        <TruncatedCode value={parsed.fullValue} className="text-foreground/80" />
                        <CopyBtn text={parsed.fullValue} />
                      </div>
                    </div>
                  ) : rule.matched_data ? (
                    <div className="pl-2 flex gap-2 items-start">
                      <TruncatedCode value={rule.matched_data} className="text-lv-peach" />
                      <CopyBtn text={rule.matched_data} />
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
        );
      })()}

      {/* Request Context */}
      {(event.request_args && Object.keys(event.request_args).length > 0) ||
       event.request_body ||
       (event.request_headers && Object.keys(event.request_headers).length > 0) ? (
        <ExpandableSection title="Request Context">
          <div className="space-y-3">
            {event.request_args && Object.keys(event.request_args).length > 0 && (
              <div className="space-y-1">
                <h5 className={T.sectionLabel}>Query / Form Args</h5>
                <div className="rounded border border-lovelace-800 bg-lovelace-950/50 p-2">
                  {Object.entries(event.request_args).map(([key, value]) => {
                    const trigger = event.matched_data ? parseMatchedData(event.matched_data)?.trigger : undefined;
                    return (
                      <div key={key} className="flex gap-1 text-xs">
                        <span className="text-lv-cyan shrink-0">{key}:</span>
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
                <div className="rounded border border-lovelace-800 bg-lovelace-950/50 p-2">
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
                <div className="rounded border border-lovelace-800 bg-lovelace-950/50 p-2 font-data text-xs">
                  {Object.entries(event.request_headers).map(([k, v]) => {
                    const value = Array.isArray(v) ? v.join(", ") : v;
                    const trigger = event.matched_data ? parseMatchedData(event.matched_data)?.trigger : undefined;
                    return (
                      <div key={k} className="flex gap-0 leading-relaxed">
                        <span className="text-lv-cyan shrink-0">{k}</span>
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

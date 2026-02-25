import { Fragment } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ShieldPlus, Download, ExternalLink, Search } from "lucide-react";
import { EventDetailPanel } from "@/components/EventsTable";
import { EventTypeBadge } from "@/components/EventTypeBadge";
import { formatTime, formatDate } from "@/lib/format";
import type { WAFEvent } from "@/lib/api";

interface EventDetailModalProps {
  event: WAFEvent | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/**
 * Full-screen event detail modal — wraps `EventDetailPanel` in a Dialog
 * with header summary and quick-action buttons.
 *
 * Used by OverviewDashboard and AnalyticsDashboard for CF-style
 * click-to-inspect event drill-down.
 */
export function EventDetailModal({ event, open, onOpenChange }: EventDetailModalProps) {
  if (!event) return null;

  const isWafEvent =
    event.event_type !== "ipsum_blocked" &&
    event.event_type !== "rate_limited" &&
    event.event_type !== "honeypot" &&
    event.event_type !== "scanner" &&
    !event.event_type?.startsWith("policy_");

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="w-[95vw] max-w-[1200px] max-h-[90vh] overflow-y-auto p-0">
        {/* Header */}
        <div className="sticky top-0 z-10 border-b border-navy-800 bg-card px-6 py-4">
          <DialogHeader>
            <div className="flex items-center justify-between gap-4">
              <div className="flex items-center gap-3 min-w-0">
                <EventTypeBadge eventType={event.event_type} blocked={event.blocked} />
                <DialogTitle className="text-sm font-mono truncate">
                  {event.method} {event.uri}
                </DialogTitle>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <span className="text-xs text-muted-foreground whitespace-nowrap">
                  {formatTime(event.timestamp)} &middot; {formatDate(event.timestamp)}
                </span>
                <Badge variant="outline" className="text-[10px] font-mono px-1.5 py-0">
                  {event.service}
                </Badge>
              </div>
            </div>
            <DialogDescription className="sr-only">
              Event detail for {event.method} {event.uri}
            </DialogDescription>
          </DialogHeader>

          {/* Action buttons */}
          <div className="flex items-center gap-2 mt-3">
            <a
              href={`/events?type=${encodeURIComponent(event.event_type)}&ip=${encodeURIComponent(event.client_ip)}`}
              className="inline-flex"
            >
              <Button variant="outline" size="xs" className="text-xs">
                <ExternalLink className="h-3 w-3 mr-1" />
                View in Events
              </Button>
            </a>
            <a
              href={`/analytics?q=${encodeURIComponent(event.client_ip)}`}
              className="inline-flex"
            >
              <Button variant="outline" size="xs" className="text-xs">
                <Search className="h-3 w-3 mr-1" />
                IP Lookup
              </Button>
            </a>
            {isWafEvent && (
              <a
                href="/policy?from_event=1"
                onClick={() => {
                  sessionStorage.setItem("waf:prefill-event", JSON.stringify(event));
                }}
                className="inline-flex"
              >
                <Button variant="outline" size="xs" className="text-xs text-neon-cyan hover:text-neon-green">
                  <ShieldPlus className="h-3 w-3 mr-1" />
                  Create Exception
                </Button>
              </a>
            )}
            <Button
              variant="ghost"
              size="xs"
              className="text-xs text-muted-foreground hover:text-foreground ml-auto"
              onClick={() => {
                const blob = new Blob([JSON.stringify(event, null, 2)], { type: "application/json" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = `event-${event.id}.json`;
                a.click();
                URL.revokeObjectURL(url);
              }}
            >
              <Download className="h-3 w-3 mr-1" />
              Export JSON
            </Button>
          </div>
        </div>

        {/* Detail panel body */}
        <div className="px-2 pb-4">
          <EventDetailPanel event={event} />
        </div>
      </DialogContent>
    </Dialog>
  );
}

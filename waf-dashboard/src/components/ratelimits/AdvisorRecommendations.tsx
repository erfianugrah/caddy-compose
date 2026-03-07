import {
  Zap,
  ArrowRight,
} from "lucide-react";
import {
  Card,
  CardContent,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Slider } from "@/components/ui/slider";
import type { RateAdvisorResponse, AdvisorRecommendation } from "@/lib/api";
import {
  ConfidenceBadge,
  DistributionHistogram,
  ImpactCurve,
  TimeOfDayChart,
} from "../AdvisorCharts";

// ─── Props ──────────────────────────────────────────────────────────

export interface AdvisorRecommendationsProps {
  data: RateAdvisorResponse;
  threshold: number;
  maxRate: number;
  window: string;
  service: string;
  affectedClients: number;
  affectedRequests: number;
  onThresholdChange: (value: number) => void;
  onCreateRule: () => void;
}

// ─── Recommendation Banner ──────────────────────────────────────────

function RecommendationBanner({
  rec,
  window,
  onApply,
}: {
  rec: AdvisorRecommendation;
  window: string;
  onApply: () => void;
}) {
  return (
    <div className="flex items-center justify-between rounded-lg border border-neon-cyan/30 bg-neon-cyan/5 px-5 py-4">
      <div className="flex items-center gap-3">
        <Zap className="h-5 w-5 text-neon-cyan shrink-0" />
        <div>
          <div className="text-sm">
            <span className="text-muted-foreground">Recommended threshold: </span>
            <span className="font-mono font-semibold text-neon-cyan text-base">{rec.threshold}</span>
            <span className="text-muted-foreground"> req/{window} </span>
            <ConfidenceBadge confidence={rec.confidence} />
          </div>
          <div className="text-xs text-muted-foreground mt-0.5">
            {rec.method.toUpperCase()}-based — would affect{" "}
            <span className="font-mono">{rec.affected_clients}</span> client{rec.affected_clients !== 1 ? "s" : ""},{" "}
            <span className="font-mono">{rec.affected_requests.toLocaleString()}</span> requests
          </div>
        </div>
      </div>
      <Button
        variant="outline"
        size="sm"
        className="shrink-0"
        onClick={onApply}
      >
        Apply
      </Button>
    </div>
  );
}

// ─── Create Rule Action ─────────────────────────────────────────────

function CreateRuleAction({
  threshold,
  window,
  service,
  onCreateRule,
}: {
  threshold: number;
  window: string;
  service: string;
  onCreateRule: () => void;
}) {
  return (
    <div className="flex items-center justify-between rounded-lg border border-neon-green/30 bg-neon-green/5 px-5 py-4">
      <div className="text-sm">
        <span className="text-muted-foreground">Create a rule that limits clients to </span>
        <span className="font-mono font-medium text-neon-cyan">{threshold}</span>
        <span className="text-muted-foreground"> requests per </span>
        <span className="font-mono font-medium text-neon-cyan">{window}</span>
        {service && (
          <>
            <span className="text-muted-foreground"> on </span>
            <span className="font-mono font-medium text-neon-cyan">{service}</span>
          </>
        )}
        <span className="text-muted-foreground">
          ? Starts in <span className="text-neon-yellow">monitor mode</span> — switch to deny when confident.
        </span>
      </div>
      <Button size="sm" onClick={onCreateRule} className="gap-1.5 shrink-0 ml-4">
        Create Rule <ArrowRight className="h-3.5 w-3.5" />
      </Button>
    </div>
  );
}

// ─── Threshold + Charts ─────────────────────────────────────────────

function ThresholdCard({
  data,
  threshold,
  maxRate,
  window,
  onThresholdChange,
}: {
  data: RateAdvisorResponse;
  threshold: number;
  maxRate: number;
  window: string;
  onThresholdChange: (value: number) => void;
}) {
  return (
    <Card>
      <CardContent className="p-5 space-y-4">
        <div className="flex items-center justify-between gap-4">
          <div className="space-y-1.5">
            <Label className="text-xs text-muted-foreground">Rate Limit Threshold</Label>
            <div className="flex items-center gap-2">
              <Input
                type="number"
                min={1}
                max={maxRate}
                value={threshold}
                onChange={(e) => onThresholdChange(Number(e.target.value) || 1)}
                className="w-24 tabular-nums"
              />
              <span className="text-sm text-muted-foreground">req / {window}</span>
            </div>
          </div>
          {/* Percentile display — high contrast */}
          <div className="flex items-center gap-4 tabular-nums font-mono">
            {([
              { label: "P50", value: data.percentiles.p50, highlight: false },
              { label: "P75", value: data.percentiles.p75, highlight: false },
              { label: "P90", value: data.percentiles.p90, highlight: false },
              { label: "P95", value: data.percentiles.p95, highlight: true },
              { label: "P99", value: data.percentiles.p99, highlight: false },
            ] as const).map(({ label, value, highlight }) => (
              <span key={label} className={highlight ? "text-neon-yellow" : ""}>
                <span className={`text-xs mr-1 ${highlight ? "text-neon-yellow/70" : "text-muted-foreground"}`}>{label}</span>
                <span className={`text-sm font-medium ${highlight ? "font-semibold" : "text-foreground"}`}>{value}</span>
              </span>
            ))}
          </div>
        </div>
        <Slider
          min={1}
          max={maxRate}
          step={1}
          value={[threshold]}
          onValueChange={([v]) => onThresholdChange(v)}
          className="py-1"
        />
        {/* Distribution histogram */}
        {data.histogram && data.histogram.length > 0 && (
          <div className="pt-3">
            <div className="text-xs text-muted-foreground mb-2">
              Client rate distribution <span className="text-neon-yellow">(yellow line = threshold</span>, <span className="text-red-400">red = above)</span>
            </div>
            <DistributionHistogram histogram={data.histogram} threshold={threshold} />
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Impact Card ────────────────────────────────────────────────────

function ImpactCard({
  data,
  threshold,
  affectedClients,
  affectedRequests,
}: {
  data: RateAdvisorResponse;
  threshold: number;
  affectedClients: number;
  affectedRequests: number;
}) {
  return (
    <Card>
      <CardContent className="p-5 space-y-3">
        <div>
          <div className="text-xs font-medium mb-0.5">Impact Sensitivity</div>
          <p className="text-xs text-muted-foreground">
            % of clients/requests affected as threshold changes
          </p>
        </div>
        {data.impact_curve && data.impact_curve.length >= 2 ? (
          <ImpactCurve curve={data.impact_curve} threshold={threshold} />
        ) : (
          <div className="text-xs text-muted-foreground/50 py-8 text-center">Not enough data</div>
        )}
        <div className="flex items-center gap-4 text-xs pt-2 border-t border-border">
          <div>
            <span className="text-muted-foreground">Clients: </span>
            <span className="font-mono text-neon-cyan">{affectedClients}/{data.unique_clients}</span>
            <span className="text-muted-foreground"> ({data.unique_clients > 0 ? ((affectedClients / data.unique_clients) * 100).toFixed(1) : 0}%)</span>
          </div>
          <div>
            <span className="text-muted-foreground">Reqs: </span>
            <span className="font-mono text-pink-400">{affectedRequests.toLocaleString()}/{data.total_requests.toLocaleString()}</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Composite ──────────────────────────────────────────────────────

export function AdvisorRecommendations({
  data,
  threshold,
  maxRate,
  window,
  service,
  affectedClients,
  affectedRequests,
  onThresholdChange,
  onCreateRule,
}: AdvisorRecommendationsProps) {
  const rec = data.recommendation;

  return (
    <>
      {/* Recommendation banner */}
      {rec && (
        <RecommendationBanner
          rec={rec}
          window={window}
          onApply={() => onThresholdChange(rec.threshold)}
        />
      )}

      {/* Create Rule action */}
      {threshold > 0 && (
        <CreateRuleAction
          threshold={threshold}
          window={window}
          service={service}
          onCreateRule={onCreateRule}
        />
      )}

      {/* Threshold + Histogram + Impact Curve */}
      <div className="grid gap-5 lg:grid-cols-2">
        <ThresholdCard
          data={data}
          threshold={threshold}
          maxRate={maxRate}
          window={window}
          onThresholdChange={onThresholdChange}
        />
        <ImpactCard
          data={data}
          threshold={threshold}
          affectedClients={affectedClients}
          affectedRequests={affectedRequests}
        />
      </div>

      {/* Time-of-Day Baselines */}
      {data.time_of_day_baselines && data.time_of_day_baselines.length >= 2 && (
        <Card>
          <CardContent className="p-5 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs font-medium mb-0.5">Traffic by Hour of Day</div>
                <p className="text-xs text-muted-foreground">
                  Median &amp; P95 request rates per client, per hour
                </p>
              </div>
              <div className="flex items-center gap-4 text-xs text-muted-foreground">
                <span className="flex items-center gap-1.5">
                  <span className="inline-block w-2.5 h-2.5 rounded-sm" style={{ background: "rgba(34,211,238,0.5)" }} />
                  Median
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="inline-block w-2.5 h-2.5 rounded-sm" style={{ background: "rgba(34,211,238,0.15)" }} />
                  P95
                </span>
              </div>
            </div>
            <TimeOfDayChart baselines={data.time_of_day_baselines} />
          </CardContent>
        </Card>
      )}
    </>
  );
}

import { Settings2, Loader2, Check } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { RateLimitGlobalConfig } from "@/lib/api";
import { T } from "@/lib/typography";

// ─── Global Settings Panel ──────────────────────────────────────────

export interface GlobalSettingsPanelProps {
  config: RateLimitGlobalConfig;
  onChange: (config: RateLimitGlobalConfig) => void;
  onSave: () => void;
  saving: boolean;
  dirty: boolean;
}

export function GlobalSettingsPanel({ config, onChange, onSave, saving, dirty }: GlobalSettingsPanelProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className={`${T.cardTitle} flex items-center gap-2`}>
          <Settings2 className="h-4 w-4" />
          Global Settings
        </CardTitle>
        <CardDescription>Shared rate limiting configuration applied to all rules.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <div className="space-y-2">
            <Label>Jitter</Label>
            <Input
              type="number"
              min={0}
              max={1}
              step={0.05}
              value={config.jitter}
              onChange={(e) => onChange({ ...config, jitter: parseFloat(e.target.value) || 0 })}
              className="tabular-nums"
            />
            <p className="text-xs text-muted-foreground">Randomization factor (0-1) to spread burst traffic.</p>
          </div>
          <div className="space-y-2">
            <Label>Sweep Interval</Label>
            <Select value={config.sweep_interval || "1m"} onValueChange={(v) => onChange({ ...config, sweep_interval: v })}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="30s">30 seconds</SelectItem>
                <SelectItem value="1m">1 minute</SelectItem>
                <SelectItem value="5m">5 minutes</SelectItem>
                <SelectItem value="10m">10 minutes</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">How often to clean up expired rate limit entries.</p>
          </div>
        </div>

        <Separator />

        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Switch
              checked={config.distributed}
              onCheckedChange={(v) => onChange({ ...config, distributed: v })}
            />
            <Label>Distributed Rate Limiting</Label>
          </div>
          <p className="text-xs text-muted-foreground">
            Enable distributed rate limiting across multiple Caddy instances using shared state.
          </p>
          {config.distributed && (
            <div className="grid gap-4 sm:grid-cols-3 pl-4 border-l-2 border-neon-cyan/20">
              <div className="space-y-2">
                <Label>Read Interval</Label>
                <Select value={config.read_interval || "5s"} onValueChange={(v) => onChange({ ...config, read_interval: v })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1s">1 second</SelectItem>
                    <SelectItem value="5s">5 seconds</SelectItem>
                    <SelectItem value="10s">10 seconds</SelectItem>
                    <SelectItem value="30s">30 seconds</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Write Interval</Label>
                <Select value={config.write_interval || "5s"} onValueChange={(v) => onChange({ ...config, write_interval: v })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1s">1 second</SelectItem>
                    <SelectItem value="5s">5 seconds</SelectItem>
                    <SelectItem value="10s">10 seconds</SelectItem>
                    <SelectItem value="30s">30 seconds</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Purge Age</Label>
                <Select value={config.purge_age || "24h"} onValueChange={(v) => onChange({ ...config, purge_age: v })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1h">1 hour</SelectItem>
                    <SelectItem value="6h">6 hours</SelectItem>
                    <SelectItem value="24h">24 hours</SelectItem>
                    <SelectItem value="72h">72 hours</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          )}
        </div>

        {dirty && (
          <div className="flex justify-end">
            <Button size="sm" onClick={onSave} disabled={saving}>
              {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
              {saving ? "Saving..." : "Save Global Settings"}
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

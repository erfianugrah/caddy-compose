import { AlertTriangle, Check, Loader2 } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

// ─── Shared status alert banners ────────────────────────────────────
// Used by PolicyEngine and RateLimitsPanel for error/success/deploy feedback.

interface StatusAlertsProps {
  error: string | null;
  successMsg: string | null;
  deployStep: string | null;
  /** Optional extra content rendered after the success message. */
  successExtra?: React.ReactNode;
}

export function StatusAlerts({ error, successMsg, deployStep, successExtra }: StatusAlertsProps) {
  return (
    <>
      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {successMsg && (
        <Alert variant="success">
          <Check className="h-4 w-4" />
          <AlertTitle>Success</AlertTitle>
          <AlertDescription className="flex items-center gap-3">
            {successMsg}
            {successExtra}
          </AlertDescription>
        </Alert>
      )}
      {deployStep && (
        <Alert>
          <Loader2 className="h-4 w-4 animate-spin" />
          <AlertTitle>Deploying</AlertTitle>
          <AlertDescription>{deployStep}</AlertDescription>
        </Alert>
      )}
    </>
  );
}

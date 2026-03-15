// ─── API Module Barrel ──────────────────────────────────────────────
// Re-exports all domain modules for backward compatibility.
// Components can import from "@/lib/api" or from specific modules.

export * from "./shared";
export * from "./waf-events";
export * from "./analytics";
export * from "./exclusions";
export * from "./config";
export * from "./rate-limits";
export * from "./blocklist";
export * from "./csp";
export * from "./general-logs";
export * from "./managed-lists";
export * from "./security-headers";
export * from "./cors";
export * from "./default-rules";
export * from "./backup";


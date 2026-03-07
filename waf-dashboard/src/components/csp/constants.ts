/** CSP source values with descriptions from CSP Level 3 spec (W3C) + MDN */
export interface CSPSourceDef {
  value: string;
  desc: string;
  category: "keyword" | "scheme" | "special";
}

export const CSP_SOURCES: CSPSourceDef[] = [
  // Keywords (single-quoted in CSP headers)
  { value: "'self'", desc: "Same origin only — matches the document's scheme, host, and port", category: "keyword" },
  { value: "'none'", desc: "Blocks all sources for this directive — no resources allowed", category: "keyword" },
  { value: "'unsafe-inline'", desc: "Allows inline <script>, <style>, event handlers, and javascript: URLs", category: "keyword" },
  { value: "'unsafe-eval'", desc: "Allows eval(), Function(), setTimeout(string), and similar dynamic code execution", category: "keyword" },
  { value: "'strict-dynamic'", desc: "Trust propagates to scripts loaded by already-trusted scripts (nonce/hash). Ignores host/scheme allowlists", category: "keyword" },
  { value: "'wasm-unsafe-eval'", desc: "Allows WebAssembly compilation (compileStreaming, compile, instantiate) without enabling JS eval()", category: "keyword" },
  { value: "'unsafe-hashes'", desc: "Allows hash-matched inline event handlers (onclick, etc.) and style attributes", category: "keyword" },
  { value: "'report-sample'", desc: "Includes the first 40 characters of the blocked resource in CSP violation reports", category: "keyword" },
  { value: "'inline-speculation-rules'", desc: "Allows inline <script type=\"speculationrules\"> for navigation prefetch/prerender", category: "keyword" },

  // Schemes (unquoted, with trailing colon)
  { value: "https:", desc: "Any URL using the HTTPS scheme", category: "scheme" },
  { value: "http:", desc: "Any URL using the HTTP scheme (insecure)", category: "scheme" },
  { value: "data:", desc: "Resources loaded via data: URIs (e.g., base64-encoded images)", category: "scheme" },
  { value: "blob:", desc: "Resources loaded via blob: URIs (e.g., Blob/File API objects)", category: "scheme" },
  { value: "mediastream:", desc: "Resources loaded via mediastream: URIs (e.g., getUserMedia)", category: "scheme" },
  { value: "filesystem:", desc: "Resources loaded via filesystem: URIs (File System API)", category: "scheme" },
  { value: "wss:", desc: "WebSocket connections over TLS (secure WebSocket)", category: "scheme" },
  { value: "ws:", desc: "WebSocket connections (insecure)", category: "scheme" },

  // Special / wildcard
  { value: "*", desc: "Allows any URL except data:, blob:, and filesystem: schemes", category: "special" },
];

export const SOURCE_CATEGORY_LABELS: Record<CSPSourceDef["category"], string> = {
  keyword: "Keywords",
  scheme: "Schemes",
  special: "Wildcard",
};

/** CSP directive metadata: field key, display name, description, MDN-based tooltip */
export const CSP_DIRECTIVES = [
  {
    key: "default_src", label: "default-src",
    desc: "Fallback for other fetch directives",
    tip: "Serves as the fallback for all other fetch directives. If a specific directive (e.g., script-src) is not set, the browser uses default-src instead.",
  },
  {
    key: "script_src", label: "script-src",
    desc: "JavaScript + WASM sources",
    tip: "Controls valid sources for JavaScript and WebAssembly. Falls back to default-src. Also serves as fallback for script-src-elem and script-src-attr.",
  },
  {
    key: "style_src", label: "style-src",
    desc: "Stylesheet sources",
    tip: "Controls valid sources for CSS stylesheets. Falls back to default-src. Also serves as fallback for style-src-elem and style-src-attr.",
  },
  {
    key: "img_src", label: "img-src",
    desc: "Image + favicon sources",
    tip: "Specifies valid sources for images and favicons. Falls back to default-src.",
  },
  {
    key: "font_src", label: "font-src",
    desc: "Font sources (@font-face)",
    tip: "Specifies valid sources for fonts loaded using @font-face. Falls back to default-src.",
  },
  {
    key: "connect_src", label: "connect-src",
    desc: "Fetch / XHR / WebSocket / EventSource",
    tip: "Restricts URLs for fetch(), XMLHttpRequest, WebSocket, EventSource, and sendBeacon(). Falls back to default-src.",
  },
  {
    key: "media_src", label: "media-src",
    desc: "Audio / video / track sources",
    tip: "Specifies valid sources for <audio>, <video>, and <track> elements. Falls back to default-src.",
  },
  {
    key: "frame_src", label: "frame-src",
    desc: "Iframe / frame sources",
    tip: "Specifies valid sources for nested browsing contexts (<iframe>, <frame>). Falls back to child-src, then default-src.",
  },
  {
    key: "worker_src", label: "worker-src",
    desc: "Worker / SharedWorker / ServiceWorker",
    tip: "Specifies valid sources for Worker, SharedWorker, and ServiceWorker scripts. Falls back to child-src, then script-src, then default-src.",
  },
  {
    key: "object_src", label: "object-src",
    desc: "Plugin / embed sources",
    tip: "Specifies valid sources for <object> and <embed> elements. Falls back to default-src. Recommended: set to 'none' to block plugins.",
  },
  {
    key: "child_src", label: "child-src",
    desc: "Worker + frame fallback",
    tip: "Defines valid sources for web workers and nested browsing contexts. Serves as fallback for frame-src and worker-src. Falls back to default-src.",
  },
  {
    key: "manifest_src", label: "manifest-src",
    desc: "Web app manifest sources",
    tip: "Specifies valid sources for application manifest files (PWA manifests). Falls back to default-src.",
  },
  {
    key: "base_uri", label: "base-uri",
    desc: "Restricts <base> element URLs",
    tip: "Restricts the URLs that can be used in a document's <base> element. Does NOT fall back to default-src.",
  },
  {
    key: "form_action", label: "form-action",
    desc: "Form submission targets",
    tip: "Restricts the URLs that can be used as the target of form submissions. Does NOT fall back to default-src.",
  },
  {
    key: "frame_ancestors", label: "frame-ancestors",
    desc: "Who can embed this page",
    tip: "Specifies valid parents that may embed this page using <frame>, <iframe>, <object>, or <embed>. Setting to 'none' is similar to X-Frame-Options: DENY. Does NOT fall back to default-src.",
  },
] as const;

export type DirectiveKey = (typeof CSP_DIRECTIVES)[number]["key"];

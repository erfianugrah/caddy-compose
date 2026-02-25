import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { extractPrefillFromEvent, consumePrefillEvent, type EventPrefill } from "./eventPrefill";
import type { WAFEvent } from "@/lib/api";

// ─── extractPrefillFromEvent ────────────────────────────────────────

describe("extractPrefillFromEvent", () => {
  const baseEvent: WAFEvent = {
    id: "tx-001",
    timestamp: "2026-02-22T08:30:00Z",
    service: "radarr.erfi.io",
    method: "POST",
    uri: "/api/v1/upload?token=abc",
    clientIp: "10.0.0.1",
    client_ip: "10.0.0.1",
    country: "US",
    action: "blocked",
    ruleId: 942100,
    rule_id: 942100,
    ruleMsg: "SQL Injection Attack Detected",
    rule_msg: "SQL Injection Attack Detected",
    severity: "CRITICAL",
    anomalyScore: 15,
    anomaly_score: 15,
    matched_rules: [
      { id: 942100, msg: "SQL Injection Attack Detected", severity: "CRITICAL" },
      { id: 942200, msg: "SQL Injection Attack Detected via libinjection", severity: "CRITICAL" },
    ],
    user_agent: "Mozilla/5.0 (compatible; BadBot/1.0)",
    statusCode: 403,
    status_code: 403,
    event_type: "waf",
  };

  it("extracts rule IDs from matched_rules", () => {
    const prefill = extractPrefillFromEvent(baseEvent);
    expect(prefill.ruleIds).toBe("942100 942200");
  });

  it("falls back to primary rule_id when matched_rules is empty", () => {
    const event = { ...baseEvent, matched_rules: [] };
    const prefill = extractPrefillFromEvent(event);
    expect(prefill.ruleIds).toBe("942100");
  });

  it("falls back to primary rule_id when matched_rules is undefined", () => {
    const event = { ...baseEvent, matched_rules: undefined } as WAFEvent;
    const prefill = extractPrefillFromEvent(event);
    expect(prefill.ruleIds).toBe("942100");
  });

  it("deduplicates rule IDs from matched_rules", () => {
    const event = {
      ...baseEvent,
      matched_rules: [
        { id: 942100, msg: "test", severity: "HIGH" },
        { id: 942100, msg: "test2", severity: "HIGH" },
        { id: 942200, msg: "test3", severity: "HIGH" },
      ],
    };
    const prefill = extractPrefillFromEvent(event);
    expect(prefill.ruleIds).toBe("942100 942200");
  });

  it("builds path condition from URI (strips query string)", () => {
    const prefill = extractPrefillFromEvent(baseEvent);
    const pathCond = prefill.conditions.find((c) => c.field === "path");
    expect(pathCond).toBeDefined();
    expect(pathCond!.value).toBe("/api/v1/upload");
    expect(pathCond!.operator).toBe("eq"); // non-trailing-slash = eq
  });

  it("uses begins_with for trailing-slash paths", () => {
    const event = { ...baseEvent, uri: "/socket.io/?transport=polling" };
    const prefill = extractPrefillFromEvent(event);
    const pathCond = prefill.conditions.find((c) => c.field === "path");
    expect(pathCond!.value).toBe("/socket.io/");
    expect(pathCond!.operator).toBe("begins_with");
  });

  it("builds host condition from service", () => {
    const prefill = extractPrefillFromEvent(baseEvent);
    const hostCond = prefill.conditions.find((c) => c.field === "host");
    expect(hostCond).toBeDefined();
    expect(hostCond!.value).toBe("radarr.erfi.io");
    expect(hostCond!.operator).toBe("eq");
  });

  it("builds method condition", () => {
    const prefill = extractPrefillFromEvent(baseEvent);
    const methodCond = prefill.conditions.find((c) => c.field === "method");
    expect(methodCond).toBeDefined();
    expect(methodCond!.value).toBe("POST");
  });

  it("builds IP condition", () => {
    const prefill = extractPrefillFromEvent(baseEvent);
    const ipCond = prefill.conditions.find((c) => c.field === "ip");
    expect(ipCond).toBeDefined();
    expect(ipCond!.value).toBe("10.0.0.1");
    expect(ipCond!.operator).toBe("eq");
  });

  it("builds user_agent condition with contains operator", () => {
    const prefill = extractPrefillFromEvent(baseEvent);
    const uaCond = prefill.conditions.find((c) => c.field === "user_agent");
    expect(uaCond).toBeDefined();
    expect(uaCond!.value).toBe("Mozilla/5.0 (compatible; BadBot/1.0)");
    expect(uaCond!.operator).toBe("contains");
  });

  it("builds country condition", () => {
    const prefill = extractPrefillFromEvent(baseEvent);
    const countryCond = prefill.conditions.find((c) => c.field === "country");
    expect(countryCond).toBeDefined();
    expect(countryCond!.value).toBe("US");
    expect(countryCond!.operator).toBe("eq");
  });

  it("sets action to skip_rule", () => {
    const prefill = extractPrefillFromEvent(baseEvent);
    expect(prefill.action).toBe("skip_rule");
  });

  it("auto-generates a descriptive name", () => {
    const prefill = extractPrefillFromEvent(baseEvent);
    expect(prefill.name).toContain("Skip");
    expect(prefill.name).toContain("942100");
    expect(prefill.name).toContain("/api/v1/upload");
    expect(prefill.name).toContain("radarr.erfi.io");
  });

  it("generates description from rule_msg", () => {
    const prefill = extractPrefillFromEvent(baseEvent);
    expect(prefill.description).toContain("Auto-created from event");
    expect(prefill.description).toContain("SQL Injection Attack Detected");
  });

  it("generates description from event ID when no rule_msg", () => {
    const event = { ...baseEvent, rule_msg: "" };
    const prefill = extractPrefillFromEvent(event);
    expect(prefill.description).toContain("tx-001");
  });

  it("includes the source event reference", () => {
    const prefill = extractPrefillFromEvent(baseEvent);
    expect(prefill.sourceEvent).toBe(baseEvent);
  });

  it("omits conditions for missing event fields", () => {
    const minimalEvent: WAFEvent = {
      id: "tx-002",
      timestamp: "2026-02-22T08:30:00Z",
      service: "",
      method: "",
      uri: "",
      clientIp: "",
      client_ip: "",
      country: "",
      action: "blocked",
      ruleId: 0,
      rule_id: 0,
      ruleMsg: "",
      rule_msg: "",
      severity: "",
      anomalyScore: 0,
      anomaly_score: 0,
      user_agent: "",
      statusCode: 403,
      status_code: 403,
      event_type: "waf",
    };
    const prefill = extractPrefillFromEvent(minimalEvent);
    expect(prefill.conditions).toHaveLength(0);
    expect(prefill.ruleIds).toBe("");
  });

  it("truncates name rule snippet at 3 IDs", () => {
    const event = {
      ...baseEvent,
      matched_rules: [
        { id: 100, msg: "", severity: "" },
        { id: 200, msg: "", severity: "" },
        { id: 300, msg: "", severity: "" },
        { id: 400, msg: "", severity: "" },
        { id: 500, msg: "", severity: "" },
      ],
    };
    const prefill = extractPrefillFromEvent(event);
    expect(prefill.name).toContain("...");
    expect(prefill.ruleIds).toBe("100 200 300 400 500");
  });
});

// ─── consumePrefillEvent ────────────────────────────────────────────

describe("consumePrefillEvent", () => {
  let mockLocation: { search: string; href: string; pathname: string };
  let mockSessionStorage: Map<string, string>;
  let replaceStateCalls: any[];

  beforeEach(() => {
    mockLocation = {
      search: "",
      href: "http://localhost/policy",
      pathname: "/policy",
    };
    mockSessionStorage = new Map();
    replaceStateCalls = [];

    vi.stubGlobal("window", {
      location: mockLocation,
      history: {
        replaceState: (...args: any[]) => replaceStateCalls.push(args),
      },
      sessionStorage: {
        getItem: (key: string) => mockSessionStorage.get(key) ?? null,
        setItem: (key: string, value: string) => mockSessionStorage.set(key, value),
        removeItem: (key: string) => mockSessionStorage.delete(key),
      },
    });

    // URL and URLSearchParams are already available in Node — no need to mock them.

    // Also stub sessionStorage as a top-level global (source code uses `sessionStorage` directly, not `window.sessionStorage`)
    vi.stubGlobal("sessionStorage", {
      getItem: (key: string) => mockSessionStorage.get(key) ?? null,
      setItem: (key: string, value: string) => mockSessionStorage.set(key, value),
      removeItem: (key: string) => mockSessionStorage.delete(key),
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns null when no from_event param", () => {
    mockLocation.search = "";
    expect(consumePrefillEvent()).toBeNull();
  });

  it("returns null when from_event param exists but no sessionStorage data", () => {
    mockLocation.search = "?from_event=1";
    mockLocation.href = "http://localhost/policy?from_event=1";
    expect(consumePrefillEvent()).toBeNull();
  });

  it("returns prefill when from_event param and sessionStorage data exist", () => {
    const event: WAFEvent = {
      id: "tx-001",
      timestamp: "2026-02-22T08:30:00Z",
      service: "radarr.erfi.io",
      method: "GET",
      uri: "/api/test",
      clientIp: "10.0.0.1",
      client_ip: "10.0.0.1",
      country: "US",
      action: "blocked",
      ruleId: 942100,
      rule_id: 942100,
      ruleMsg: "Test",
      rule_msg: "Test",
      severity: "HIGH",
      anomalyScore: 10,
      anomaly_score: 10,
      user_agent: "",
      statusCode: 403,
      status_code: 403,
      event_type: "waf",
    };
    mockSessionStorage.set("waf:prefill-event", JSON.stringify(event));
    mockLocation.search = "?from_event=1";
    mockLocation.href = "http://localhost/policy?from_event=1";

    const result = consumePrefillEvent();
    expect(result).not.toBeNull();
    expect(result!.action).toBe("skip_rule");
    expect(result!.ruleIds).toBe("942100");
  });

  it("removes sessionStorage item after consuming", () => {
    const event: WAFEvent = {
      id: "tx-001",
      timestamp: "2026-02-22T08:30:00Z",
      service: "test.io",
      method: "GET",
      uri: "/test",
      clientIp: "1.2.3.4",
      client_ip: "1.2.3.4",
      country: "",
      action: "blocked",
      ruleId: 100,
      rule_id: 100,
      ruleMsg: "",
      rule_msg: "",
      severity: "",
      anomalyScore: 0,
      anomaly_score: 0,
      user_agent: "",
      statusCode: 403,
      status_code: 403,
      event_type: "waf",
    };
    mockSessionStorage.set("waf:prefill-event", JSON.stringify(event));
    mockLocation.search = "?from_event=1";
    mockLocation.href = "http://localhost/policy?from_event=1";

    consumePrefillEvent();
    expect(mockSessionStorage.has("waf:prefill-event")).toBe(false);
  });

  it("cleans up URL param via replaceState", () => {
    const event: WAFEvent = {
      id: "tx-001",
      timestamp: "2026-02-22T08:30:00Z",
      service: "test.io",
      method: "GET",
      uri: "/test",
      clientIp: "1.2.3.4",
      client_ip: "1.2.3.4",
      country: "",
      action: "blocked",
      ruleId: 100,
      rule_id: 100,
      ruleMsg: "",
      rule_msg: "",
      severity: "",
      anomalyScore: 0,
      anomaly_score: 0,
      user_agent: "",
      statusCode: 403,
      status_code: 403,
      event_type: "waf",
    };
    mockSessionStorage.set("waf:prefill-event", JSON.stringify(event));
    mockLocation.search = "?from_event=1";
    mockLocation.href = "http://localhost/policy?from_event=1";

    consumePrefillEvent();
    expect(replaceStateCalls.length).toBe(1);
  });

  it("returns null on invalid JSON in sessionStorage", () => {
    mockSessionStorage.set("waf:prefill-event", "{invalid json");
    mockLocation.search = "?from_event=1";
    mockLocation.href = "http://localhost/policy?from_event=1";

    expect(consumePrefillEvent()).toBeNull();
  });
});

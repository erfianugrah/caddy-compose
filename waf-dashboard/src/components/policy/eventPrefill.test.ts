import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { extractPrefillFromEvent, consumePrefillEvent, consumeURLPrefill, type EventPrefill } from "./eventPrefill";
import type { WAFEvent } from "@/lib/api";

// ─── extractPrefillFromEvent ────────────────────────────────────────

describe("extractPrefillFromEvent", () => {
  const baseEvent: WAFEvent = {
    id: "tx-001",
    timestamp: "2026-02-22T08:30:00Z",
    service: "app.example.test",
    method: "POST",
    uri: "/api/v1/upload?token=abc",
    client_ip: "10.0.0.1",
    country: "US",
    status: 403,
    blocked: true,
    rule_id: 942100,
    rule_msg: "SQL Injection Attack Detected",
    severity: 5,
    anomaly_score: 15,
    outbound_anomaly_score: 0,
    matched_rules: [
      { id: 942100, msg: "SQL Injection Attack Detected", severity: 5 },
      { id: 942200, msg: "SQL Injection Attack Detected via libinjection", severity: 5 },
    ],
    user_agent: "Mozilla/5.0 (compatible; BadBot/1.0)",
    event_type: "detect_block",
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
        { id: 942100, msg: "test", severity: 4 },
        { id: 942100, msg: "test2", severity: 4 },
        { id: 942200, msg: "test3", severity: 4 },
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
    expect(hostCond!.value).toBe("app.example.test");
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

  it("sets action to allow for blocked events (false positive workflow)", () => {
    const prefill = extractPrefillFromEvent(baseEvent);
    expect(prefill.action).toBe("allow");
  });

  it("sets action to allow for policy_block events", () => {
    const event = { ...baseEvent, event_type: "policy_block" as const, blocked: true };
    const prefill = extractPrefillFromEvent(event);
    expect(prefill.action).toBe("allow");
  });

  it("sets action to detect for policy_skip events", () => {
    const event = { ...baseEvent, event_type: "policy_skip" as const, blocked: false };
    const prefill = extractPrefillFromEvent(event);
    expect(prefill.action).toBe("detect");
  });

  it("sets action to skip for logged events with matched rules (false positives)", () => {
    const event = { ...baseEvent, event_type: "logged" as const, blocked: false };
    const prefill = extractPrefillFromEvent(event);
    expect(prefill.action).toBe("skip");
    expect(prefill.suggestedSkipTargets?.rules).toEqual(["942100", "942200"]);
  });

  it("sets action to block for logged events without matched rules", () => {
    const event = { ...baseEvent, event_type: "logged" as const, blocked: false, matched_rules: [], rule_id: 0 };
    const prefill = extractPrefillFromEvent(event);
    expect(prefill.action).toBe("block");
  });

  it("sets action to allow for detect_block events", () => {
    const event = { ...baseEvent, event_type: "detect_block" as const, blocked: true };
    const prefill = extractPrefillFromEvent(event);
    expect(prefill.action).toBe("allow");
  });

  it("auto-generates a descriptive name with action label", () => {
    const prefill = extractPrefillFromEvent(baseEvent);
    expect(prefill.name).toContain("Allow");
    expect(prefill.name).toContain("942100");
    expect(prefill.name).toContain("/api/v1/upload");
    expect(prefill.name).toContain("app.example.test");
  });

  it("uses rule_msg in name when no rule IDs available (policy events)", () => {
    const event: WAFEvent = {
      ...baseEvent,
      event_type: "policy_block",
      blocked: true,
      rule_id: 0,
      matched_rules: undefined as any,
      rule_msg: "Policy Block: Block bots",
    };
    const prefill = extractPrefillFromEvent(event);
    expect(prefill.name).toContain("Allow");
    expect(prefill.name).toContain("Block bots");
    expect(prefill.name).toContain("/api/v1/upload");
    // Should not have double spaces from missing rule IDs
    expect(prefill.name).not.toMatch(/  /);
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
      client_ip: "",
      country: "",
      status: 403,
      blocked: true,
      rule_id: 0,
      rule_msg: "",
      severity: 0,
      anomaly_score: 0,
      outbound_anomaly_score: 0,
      user_agent: "",
      event_type: "detect_block",
    };
    const prefill = extractPrefillFromEvent(minimalEvent);
    expect(prefill.conditions).toHaveLength(0);
    expect(prefill.ruleIds).toBe("");
  });

  it("truncates name rule snippet at 3 IDs", () => {
    const event = {
      ...baseEvent,
      matched_rules: [
        { id: 100, msg: "", severity: 0 },
        { id: 200, msg: "", severity: 0 },
        { id: 300, msg: "", severity: 0 },
        { id: 400, msg: "", severity: 0 },
        { id: 500, msg: "", severity: 0 },
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
      service: "app.example.test",
      method: "GET",
      uri: "/api/test",
      client_ip: "10.0.0.1",
      country: "US",
      status: 403,
      blocked: true,
      rule_id: 942100,
      rule_msg: "Test",
      severity: 4,
      anomaly_score: 10,
      outbound_anomaly_score: 0,
      user_agent: "",
      event_type: "detect_block",
    };
    mockSessionStorage.set("waf:prefill-event", JSON.stringify(event));
    mockLocation.search = "?from_event=1";
    mockLocation.href = "http://localhost/policy?from_event=1";

    const result = consumePrefillEvent();
    expect(result).not.toBeNull();
    expect(result!.action).toBe("allow"); // blocked event → allow exception
    expect(result!.ruleIds).toBe("942100");
  });

  it("removes sessionStorage item after consuming", () => {
    const event: WAFEvent = {
      id: "tx-001",
      timestamp: "2026-02-22T08:30:00Z",
      service: "test.io",
      method: "GET",
      uri: "/test",
      client_ip: "1.2.3.4",
      country: "",
      status: 403,
      blocked: true,
      rule_id: 100,
      rule_msg: "",
      severity: 0,
      anomaly_score: 0,
      outbound_anomaly_score: 0,
      user_agent: "",
      event_type: "detect_block",
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
      client_ip: "1.2.3.4",
      country: "",
      status: 403,
      blocked: true,
      rule_id: 100,
      rule_msg: "",
      severity: 0,
      anomaly_score: 0,
      outbound_anomaly_score: 0,
      user_agent: "",
      event_type: "detect_block",
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

// ─── consumeURLPrefill ──────────────────────────────────────────────

describe("consumeURLPrefill", () => {
  let mockLocation: { search: string; href: string; pathname: string };
  let replaceStateCalls: any[];

  beforeEach(() => {
    mockLocation = {
      search: "",
      href: "http://localhost/policy",
      pathname: "/policy",
    };
    replaceStateCalls = [];

    vi.stubGlobal("window", {
      location: mockLocation,
      history: {
        replaceState: (...args: any[]) => replaceStateCalls.push(args),
      },
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns null when no action param", () => {
    mockLocation.search = "";
    expect(consumeURLPrefill()).toBeNull();
  });

  it("returns null for invalid action", () => {
    mockLocation.search = "?action=invalid&prefill_path=/test";
    mockLocation.href = "http://localhost/policy?action=invalid&prefill_path=/test";
    expect(consumeURLPrefill()).toBeNull();
  });

  it("returns null when action present but no conditions", () => {
    mockLocation.search = "?action=block";
    mockLocation.href = "http://localhost/policy?action=block";
    expect(consumeURLPrefill()).toBeNull();
  });

  it("returns prefill for challenge action with path and service", () => {
    mockLocation.search = "?action=challenge&prefill_path=%2Fapi%2Fv3%2Fcommand&prefill_service=sonarr.erfi.io";
    mockLocation.href = "http://localhost/policy?action=challenge&prefill_path=%2Fapi%2Fv3%2Fcommand&prefill_service=sonarr.erfi.io";

    const result = consumeURLPrefill();
    expect(result).not.toBeNull();
    expect(result!.action).toBe("challenge");
    expect(result!.conditions).toHaveLength(2);
    expect(result!.conditions[0]).toEqual({ field: "path", operator: "eq", value: "/api/v3/command" });
    expect(result!.conditions[1]).toEqual({ field: "host", operator: "eq", value: "sonarr.erfi.io" });
    expect(result!.name).toContain("Challenge");
    expect(result!.name).toContain("/api/v3/command");
  });

  it("returns prefill for block action with ja4", () => {
    mockLocation.search = "?action=block&prefill_ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd";
    mockLocation.href = "http://localhost/policy?action=block&prefill_ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd";

    const result = consumeURLPrefill();
    expect(result).not.toBeNull();
    expect(result!.action).toBe("block");
    expect(result!.conditions).toHaveLength(1);
    expect(result!.conditions[0].field).toBe("ja4");
    expect(result!.conditions[0].operator).toBe("eq");
    expect(result!.conditions[0].value).toBe("t13d1516h2_8daaf6152771_d8a2da3f94cd");
  });

  it("uses begins_with for paths ending in /", () => {
    mockLocation.search = "?action=challenge&prefill_path=%2Fapi%2Fv3%2F";
    mockLocation.href = "http://localhost/policy?action=challenge&prefill_path=%2Fapi%2Fv3%2F";

    const result = consumeURLPrefill();
    expect(result).not.toBeNull();
    expect(result!.conditions[0].operator).toBe("begins_with");
  });

  it("uses begins_with for paths containing {id}", () => {
    mockLocation.search = "?action=challenge&prefill_path=%2FMediaCover%2F%7Bid%7D%2Fposter-250.jpg";
    mockLocation.href = "http://localhost/policy?action=challenge&prefill_path=%2FMediaCover%2F%7Bid%7D%2Fposter-250.jpg";

    const result = consumeURLPrefill();
    expect(result).not.toBeNull();
    expect(result!.conditions[0].operator).toBe("begins_with");
  });

  it("cleans URL params after consumption", () => {
    mockLocation.search = "?action=block&prefill_path=%2Ftest&prefill_service=test.io";
    mockLocation.href = "http://localhost/policy?action=block&prefill_path=%2Ftest&prefill_service=test.io";

    consumeURLPrefill();
    expect(replaceStateCalls.length).toBe(1);
  });

  it("creates a synthetic sourceEvent with empty id", () => {
    mockLocation.search = "?action=challenge&prefill_path=%2Ftest";
    mockLocation.href = "http://localhost/policy?action=challenge&prefill_path=%2Ftest";

    const result = consumeURLPrefill();
    expect(result).not.toBeNull();
    expect(result!.sourceEvent.id).toBe("");
  });
});

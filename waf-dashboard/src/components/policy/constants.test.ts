import { describe, it, expect } from "vitest";
import {
  QUICK_ACTIONS,
  ALL_EXCLUSION_TYPES,
  RULE_TAGS,
  CONDITION_FIELDS,
  getFieldDef,
  emptyAdvancedForm,
  type AdvancedFormState,
  type QuickActionType,
} from "./constants";

// ─── QUICK_ACTIONS ──────────────────────────────────────────────────

describe("QUICK_ACTIONS", () => {
  it("has exactly 3 actions: allow, block, detect", () => {
    expect(QUICK_ACTIONS).toHaveLength(3);
    const values = QUICK_ACTIONS.map((a) => a.value);
    expect(values).toEqual(["allow", "block", "detect"]);
  });

  it("each action has label, description, and iconName", () => {
    for (const action of QUICK_ACTIONS) {
      expect(action.label).toBeTruthy();
      expect(action.description).toBeTruthy();
      expect(action.iconName).toBeTruthy();
    }
  });
});

// ─── ALL_EXCLUSION_TYPES ────────────────────────────────────────────

describe("ALL_EXCLUSION_TYPES", () => {
  it("has exactly 3 types: allow, block, detect", () => {
    const values = ALL_EXCLUSION_TYPES.map((t) => t.value);
    expect(values).toEqual(["allow", "block", "detect"]);
  });

  it("all types are in the quick group", () => {
    const groups = new Set(ALL_EXCLUSION_TYPES.map((t) => t.group));
    expect(groups).toEqual(new Set(["quick"]));
  });

  it("each type has label and description", () => {
    for (const type of ALL_EXCLUSION_TYPES) {
      expect(type.label).toBeTruthy();
      expect(type.description).toBeTruthy();
    }
  });
});

// ─── RULE_TAGS ──────────────────────────────────────────────────────

describe("RULE_TAGS", () => {
  it("contains common CRS attack tags", () => {
    expect(RULE_TAGS).toContain("attack-sqli");
    expect(RULE_TAGS).toContain("attack-xss");
    expect(RULE_TAGS).toContain("attack-rce");
    expect(RULE_TAGS).toContain("attack-lfi");
  });

  it("contains paranoia level tags", () => {
    expect(RULE_TAGS).toContain("paranoia-level/1");
    expect(RULE_TAGS).toContain("paranoia-level/2");
    expect(RULE_TAGS).toContain("paranoia-level/3");
    expect(RULE_TAGS).toContain("paranoia-level/4");
  });

  it("has no duplicates", () => {
    expect(new Set(RULE_TAGS).size).toBe(RULE_TAGS.length);
  });
});

// ─── CONDITION_FIELDS ───────────────────────────────────────────────

describe("CONDITION_FIELDS", () => {
  it("contains all expected fields", () => {
    const fieldValues = CONDITION_FIELDS.map((f) => f.value);
    expect(fieldValues).toContain("ip");
    expect(fieldValues).toContain("path");
    expect(fieldValues).toContain("host");
    expect(fieldValues).toContain("method");
    expect(fieldValues).toContain("user_agent");
    expect(fieldValues).toContain("header");
    expect(fieldValues).toContain("query");
    expect(fieldValues).toContain("country");
    expect(fieldValues).toContain("cookie");
    expect(fieldValues).toContain("body");
    expect(fieldValues).toContain("args");
    expect(fieldValues).toContain("uri_path");
    expect(fieldValues).toContain("referer");
    expect(fieldValues).toContain("response_header");
    expect(fieldValues).toContain("response_status");
    expect(fieldValues).toContain("http_version");
  });

  it("each field has at least one operator", () => {
    for (const field of CONDITION_FIELDS) {
      expect(field.operators.length).toBeGreaterThan(0);
    }
  });

  it("each field has a placeholder", () => {
    for (const field of CONDITION_FIELDS) {
      expect(field.placeholder).toBeTruthy();
    }
  });

  it("each field has a label", () => {
    for (const field of CONDITION_FIELDS) {
      expect(field.label).toBeTruthy();
    }
  });

  it("no duplicate field values", () => {
    const values = CONDITION_FIELDS.map((f) => f.value);
    expect(new Set(values).size).toBe(values.length);
  });

  it("ip field has ip_match and not_ip_match operators", () => {
    const ip = CONDITION_FIELDS.find((f) => f.value === "ip")!;
    const ops = ip.operators.map((o) => o.value);
    expect(ops).toContain("eq");
    expect(ops).toContain("neq");
    expect(ops).toContain("ip_match");
    expect(ops).toContain("not_ip_match");
  });

  it("path field has in operator for substring match", () => {
    const path = CONDITION_FIELDS.find((f) => f.value === "path")!;
    const ops = path.operators.map((o) => o.value);
    expect(ops).toContain("in");
    expect(ops).toContain("regex");
    expect(ops).toContain("begins_with");
    expect(ops).toContain("ends_with");
  });

  it("method field supports in operator", () => {
    const method = CONDITION_FIELDS.find((f) => f.value === "method")!;
    const ops = method.operators.map((o) => o.value);
    expect(ops).toContain("in");
  });
});

// ─── getFieldDef ────────────────────────────────────────────────────

describe("getFieldDef", () => {
  it("returns the correct field definition for known fields", () => {
    expect(getFieldDef("ip").value).toBe("ip");
    expect(getFieldDef("path").value).toBe("path");
    expect(getFieldDef("host").value).toBe("host");
    expect(getFieldDef("country").value).toBe("country");
  });

  it("returns the first field as fallback for unknown fields", () => {
    // @ts-expect-error testing invalid input
    const result = getFieldDef("nonexistent_field");
    expect(result.value).toBe(CONDITION_FIELDS[0].value);
  });
});

// ─── emptyAdvancedForm ──────────────────────────────────────────────

describe("emptyAdvancedForm", () => {
  it("has correct default values", () => {
    expect(emptyAdvancedForm.name).toBe("");
    expect(emptyAdvancedForm.description).toBe("");
    expect(emptyAdvancedForm.type).toBe("allow");
    expect(emptyAdvancedForm.severity).toBe("");
    expect(emptyAdvancedForm.detect_paranoia_level).toBe(0);
    expect(emptyAdvancedForm.conditions).toEqual([]);
    expect(emptyAdvancedForm.group_operator).toBe("and");
    expect(emptyAdvancedForm.enabled).toBe(true);
  });

  it("is not mutated when spread (defensive copy check)", () => {
    const copy: AdvancedFormState = { ...emptyAdvancedForm, name: "test" };
    expect(emptyAdvancedForm.name).toBe("");
    expect(copy.name).toBe("test");
  });
});

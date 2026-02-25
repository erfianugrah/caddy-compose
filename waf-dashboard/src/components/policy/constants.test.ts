import { describe, it, expect } from "vitest";
import {
  QUICK_ACTIONS,
  ALL_EXCLUSION_TYPES,
  RULE_TAGS,
  CONDITION_FIELDS,
  getFieldDef,
  isById,
  isByTag,
  isTargetType,
  isRuntimeType,
  emptyAdvancedForm,
  type AdvancedFormState,
  type QuickActionType,
} from "./constants";

// ─── QUICK_ACTIONS ──────────────────────────────────────────────────

describe("QUICK_ACTIONS", () => {
  it("has exactly 3 actions: allow, block, skip_rule", () => {
    expect(QUICK_ACTIONS).toHaveLength(3);
    const values = QUICK_ACTIONS.map((a) => a.value);
    expect(values).toEqual(["allow", "block", "skip_rule"]);
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
  it("has all expected exclusion types", () => {
    const values = ALL_EXCLUSION_TYPES.map((t) => t.value);
    expect(values).toContain("allow");
    expect(values).toContain("block");
    expect(values).toContain("skip_rule");
    expect(values).toContain("SecRuleRemoveById");
    expect(values).toContain("SecRuleRemoveByTag");
    expect(values).toContain("SecRuleUpdateTargetById");
    expect(values).toContain("SecRuleUpdateTargetByTag");
    expect(values).toContain("ctl:ruleRemoveById");
    expect(values).toContain("ctl:ruleRemoveByTag");
    expect(values).toContain("ctl:ruleRemoveTargetById");
    expect(values).toContain("ctl:ruleRemoveTargetByTag");
  });

  it("has 3 groups: quick, advanced, runtime", () => {
    const groups = new Set(ALL_EXCLUSION_TYPES.map((t) => t.group));
    expect(groups).toEqual(new Set(["quick", "advanced", "runtime"]));
  });

  it("quick group has 3 items, advanced has 4, runtime has 4", () => {
    const quick = ALL_EXCLUSION_TYPES.filter((t) => t.group === "quick");
    const advanced = ALL_EXCLUSION_TYPES.filter((t) => t.group === "advanced");
    const runtime = ALL_EXCLUSION_TYPES.filter((t) => t.group === "runtime");
    expect(quick).toHaveLength(3);
    expect(advanced).toHaveLength(4);
    expect(runtime).toHaveLength(4);
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

// ─── isById ─────────────────────────────────────────────────────────

describe("isById", () => {
  it("returns true for ById types", () => {
    expect(isById("SecRuleRemoveById")).toBe(true);
    expect(isById("SecRuleUpdateTargetById")).toBe(true);
    expect(isById("ctl:ruleRemoveById")).toBe(true);
    expect(isById("ctl:ruleRemoveTargetById")).toBe(true);
  });

  it("returns false for ByTag types", () => {
    expect(isById("SecRuleRemoveByTag")).toBe(false);
    expect(isById("SecRuleUpdateTargetByTag")).toBe(false);
  });

  it("returns false for quick action types", () => {
    expect(isById("allow")).toBe(false);
    expect(isById("block")).toBe(false);
    expect(isById("skip_rule")).toBe(false);
  });
});

// ─── isByTag ────────────────────────────────────────────────────────

describe("isByTag", () => {
  it("returns true for ByTag types", () => {
    expect(isByTag("SecRuleRemoveByTag")).toBe(true);
    expect(isByTag("SecRuleUpdateTargetByTag")).toBe(true);
    expect(isByTag("ctl:ruleRemoveByTag")).toBe(true);
    expect(isByTag("ctl:ruleRemoveTargetByTag")).toBe(true);
  });

  it("returns false for ById types", () => {
    expect(isByTag("SecRuleRemoveById")).toBe(false);
    expect(isByTag("ctl:ruleRemoveById")).toBe(false);
  });

  it("returns false for quick action types", () => {
    expect(isByTag("allow")).toBe(false);
    expect(isByTag("block")).toBe(false);
  });
});

// ─── isTargetType ───────────────────────────────────────────────────

describe("isTargetType", () => {
  it("returns true for target/update-target types", () => {
    expect(isTargetType("SecRuleUpdateTargetById")).toBe(true);
    expect(isTargetType("SecRuleUpdateTargetByTag")).toBe(true);
    expect(isTargetType("ctl:ruleRemoveTargetById")).toBe(true);
    expect(isTargetType("ctl:ruleRemoveTargetByTag")).toBe(true);
  });

  it("returns false for non-target types", () => {
    expect(isTargetType("SecRuleRemoveById")).toBe(false);
    expect(isTargetType("SecRuleRemoveByTag")).toBe(false);
    expect(isTargetType("allow")).toBe(false);
    expect(isTargetType("block")).toBe(false);
    expect(isTargetType("ctl:ruleRemoveById")).toBe(false);
  });
});

// ─── isRuntimeType ──────────────────────────────────────────────────

describe("isRuntimeType", () => {
  it("returns true for ctl: runtime types", () => {
    expect(isRuntimeType("ctl:ruleRemoveById")).toBe(true);
    expect(isRuntimeType("ctl:ruleRemoveByTag")).toBe(true);
    expect(isRuntimeType("ctl:ruleRemoveTargetById")).toBe(true);
    expect(isRuntimeType("ctl:ruleRemoveTargetByTag")).toBe(true);
  });

  it("returns false for configure-time types", () => {
    expect(isRuntimeType("SecRuleRemoveById")).toBe(false);
    expect(isRuntimeType("SecRuleRemoveByTag")).toBe(false);
    expect(isRuntimeType("SecRuleUpdateTargetById")).toBe(false);
  });

  it("returns false for quick action types", () => {
    expect(isRuntimeType("allow")).toBe(false);
    expect(isRuntimeType("block")).toBe(false);
    expect(isRuntimeType("skip_rule")).toBe(false);
  });

  it("returns false for honeypot and raw", () => {
    expect(isRuntimeType("honeypot")).toBe(false);
    expect(isRuntimeType("raw")).toBe(false);
  });
});

// ─── emptyAdvancedForm ──────────────────────────────────────────────

describe("emptyAdvancedForm", () => {
  it("has correct default values", () => {
    expect(emptyAdvancedForm.name).toBe("");
    expect(emptyAdvancedForm.description).toBe("");
    expect(emptyAdvancedForm.type).toBe("SecRuleRemoveById");
    expect(emptyAdvancedForm.rule_id).toBe("");
    expect(emptyAdvancedForm.rule_tag).toBe("");
    expect(emptyAdvancedForm.variable).toBe("");
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
